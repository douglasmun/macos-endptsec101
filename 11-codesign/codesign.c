/*
 * codesign.c — Endpoint Security CDHash / codesigning-flags policy engine
 *              (ebpf101 ch23 analog for macOS)
 *
 * Subscribes to AUTH_EXEC and evaluates three codesigning rules before
 * allowing a process image to run:
 *
 *   1. CS_DEBUGGED binaries are denied — a debugged image may have had its
 *      code integrity checks disabled, making its CDHash untrustworthy.
 *
 *   2. Binaries under /usr/bin/ or /usr/sbin/ without CS_HARD are denied —
 *      sensitive system tools must enforce code-signing at the kernel level.
 *
 *   3. CDHash allowlist: a compiled-in table of known-good hashes. Any binary
 *      whose CDHash appears in the table is explicitly allowed. All other
 *      binaries are ALLOWED by default to avoid system lockout — only the
 *      two rules above trigger an actual deny.
 *
 * Policy order (first match wins):
 *   1. is_platform_binary → ALLOW immediately (fast-path, no rules applied)
 *   2. CS_DEBUGGED set    → DENY + alert
 *   3. sensitive path and !CS_HARD → DENY + alert
 *   4. CDHash in allowlist → ALLOW
 *   5. default            → ALLOW + log (conservative: avoid system lockout)
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./codesign-monitor
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* ── codesigning flag constants ───────────────────────────────────────────── */
/*
 * These may not be defined in all SDK versions; define them explicitly so
 * the source compiles cleanly against any macOS 10.15+ toolchain.
 */
#define CS_VALID            0x00000001u
#define CS_HARD             0x00000100u
#define CS_KILL             0x00000200u
#define CS_REQUIRE_LV       0x00002000u
#define CS_PLATFORM_BINARY  0x04000000u
#define CS_DEBUGGED         0x10000000u

/* ── CDHash allowlist ─────────────────────────────────────────────────────── */

typedef struct {
    uint8_t     hash[20];   /* SHA-1 CDHash (20 bytes) */
    const char *label;      /* human-readable name, NULL for sentinel */
} cdhash_entry_t;

static const cdhash_entry_t g_allowlist[] = {
    /* Add known-good hashes here at build time, e.g.:
     * { { 0xde, 0xad, 0xbe, 0xef, ... }, "my-trusted-tool" },
     */
    { {0}, NULL }, /* sentinel */
};

static int cdhash_allowed(const uint8_t *hash)
{
    for (int i = 0; g_allowlist[i].label; i++)
        if (memcmp(g_allowlist[i].hash, hash, 20) == 0) return 1;
    return 0;
}

/* ── globals ──────────────────────────────────────────────────────────────── */

static es_client_t     *g_client     = NULL;
static dispatch_queue_t g_main_queue = NULL;
static atomic_int       g_stop       = 0;

/* ── shutdown ─────────────────────────────────────────────────────────────── */

static void do_shutdown(void *ctx __attribute__((unused)))
{
    if (g_client) {
        es_delete_client(g_client);
        g_client = NULL;
    }
    exit(0);
}

static void on_signal(int sig)
{
    (void)sig;
    if (!atomic_exchange(&g_stop, 1))
        dispatch_async_f(g_main_queue, NULL, do_shutdown);
}

/* ── helpers ──────────────────────────────────────────────────────────────── */

static void print_str(const es_string_token_t *s)
{
    if (s && s->data && s->length > 0)
        printf("%.*s", (int)s->length, s->data);
    else
        printf("(null)");
}

static void print_path(const es_file_t *file)
{
    print_str(&file->path);
    if (file->path_truncated)
        printf("...(truncated)");
}

/*
 * Separator-safe prefix match for es_string_token_t paths.
 * plen==1 special case: any absolute path trivially matches "/".
 */
static int path_has_prefix(const es_string_token_t *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (path->length < plen) return 0;
    if (memcmp(path->data, prefix, plen) != 0) return 0;
    return path->length == plen || path->data[plen] == '/' || plen == 1;
}

/*
 * Print a 20-byte CDHash as a 40-character lowercase hex string.
 */
static void print_cdhash(const uint8_t *hash)
{
    for (int i = 0; i < 20; i++)
        printf("%02x", hash[i]);
}

/* ── event handler ────────────────────────────────────────────────────────── */

static void handle_event(es_client_t *client, const es_message_t *msg)
{
    if (msg->event_type != ES_EVENT_TYPE_AUTH_EXEC)
        return;

    const es_process_t *target = msg->event.exec.target;
    pid_t pid = audit_token_to_pid(target->audit_token);
    uint32_t flags = target->codesigning_flags;

    /* Print baseline info for every exec */
    printf("[EXEC] ");
    print_path(target->executable);
    printf(" pid=%d flags=0x%08x cdhash=", pid, flags);
    print_cdhash(target->cdhash);
    printf("\n");
    fflush(stdout);

    /* ── policy ─────────────────────────────────────────────────────────── */

    /* Rule 1: platform binary fast-allow — skip all further checks */
    if (target->is_platform_binary) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    /* Rule 2: CS_DEBUGGED → deny */
    if (flags & CS_DEBUGGED) {
        fprintf(stderr,
                "[ALERT] CS_DEBUGGED binary denied: ");
        fwrite(target->executable->path.data, 1,
               target->executable->path.length, stderr);
        fprintf(stderr, " pid=%d flags=0x%08x cdhash=", pid, flags);
        for (int i = 0; i < 20; i++)
            fprintf(stderr, "%02x", target->cdhash[i]);
        fprintf(stderr, "\n");
        fflush(stderr);
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
        return;
    }

    /* Rule 3: sensitive path without CS_HARD → deny */
    if ((path_has_prefix(&target->executable->path, "/usr/bin/") ||
         path_has_prefix(&target->executable->path, "/usr/sbin/")) &&
        !(flags & CS_HARD)) {
        fprintf(stderr,
                "[ALERT] sensitive binary lacks CS_HARD, denied: ");
        fwrite(target->executable->path.data, 1,
               target->executable->path.length, stderr);
        fprintf(stderr, " pid=%d flags=0x%08x\n", pid, flags);
        fflush(stderr);
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
        return;
    }

    /* Rule 4: CDHash allowlist explicit allow */
    if (cdhash_allowed(target->cdhash)) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    /* Rule 5: default allow (conservative — avoid system lockout) */
    es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
    g_main_queue = dispatch_get_main_queue();
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    es_new_client_result_t res = es_new_client(&g_client,
        ^(es_client_t *c, const es_message_t *msg) {
            handle_event(c, msg);
        });

    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        const char *reason;
        switch (res) {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            reason = "missing endpoint-security entitlement"; break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            reason = "grant Full Disk Access in System Settings → Privacy & Security"; break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            reason = "must run as root (sudo)"; break;
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            reason = "too many ES clients already connected"; break;
        default:
            reason = "internal error"; break;
        }
        fprintf(stderr, "es_new_client: %s\n", reason);
        return 1;
    }

    /* Mute self before subscribing to prevent event feedback loop */
    {
        audit_token_t self_token;
        mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        if (task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                      (task_info_t)&self_token, &count) == KERN_SUCCESS) {
            if (es_mute_process(g_client, &self_token) != ES_RETURN_SUCCESS)
                fprintf(stderr, "warning: failed to mute self — possible event feedback loop\n");
        } else {
            fprintf(stderr, "warning: task_info failed — could not mute self\n");
        }
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_EXEC,
    };

    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("codesign-monitor: enforcing CDHash/codesigning-flags policy — Ctrl-C to stop\n");
    fflush(stdout);

    dispatch_main();
    return 0;
}
