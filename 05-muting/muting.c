/*
 * muting.c — Endpoint Security muting API demo (ebpf101 ch9 filter / ch19 tailcall analog)
 *
 * Subscribes to NOTIFY_EXEC and demonstrates all ES muting modes:
 *   1. Process muting  — silence all events from a specific process (self-mute)
 *   2. PREFIX muting   — silence events from any binary under a path prefix
 *   3. LITERAL muting  — silence events from one exact binary path
 *   4. TARGET_PREFIX   — silence events whose *target* is under a path prefix
 *   5. Muting inversion — flip from denylist to allowlist with es_invert_muting()
 *
 * After printing the muting configuration, it runs in allowlist mode: only
 * processes under /usr/bin are reported. Everything else is silently suppressed.
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./muting
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>

static es_client_t     *g_client     = NULL;
static dispatch_queue_t g_main_queue = NULL;
static atomic_int       g_stop       = 0;

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

static void handle_event(es_client_t *client __attribute__((unused)),
                         const es_message_t *msg)
{
    switch (msg->event_type) {

    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        const es_process_t *target = msg->event.exec.target;
        pid_t pid  = audit_token_to_pid(target->audit_token);
        pid_t ppid = audit_token_to_pid(target->parent_audit_token);
        printf("[EXEC] pid=%-6d ppid=%-6d path=", pid, ppid);
        print_path(target->executable);
        printf("\n");
        fflush(stdout);
        break;
    }

    default:
        break;
    }
}

static void mute_prefix(const char *path)
{
    if (es_mute_path(g_client, path, ES_MUTE_PATH_TYPE_PREFIX) != ES_RETURN_SUCCESS)
        fprintf(stderr, "warning: failed to mute PREFIX %s\n", path);
    else
        printf("  muted PREFIX  %s\n", path);
}

static void mute_literal(const char *path)
{
    if (es_mute_path(g_client, path, ES_MUTE_PATH_TYPE_LITERAL) != ES_RETURN_SUCCESS)
        fprintf(stderr, "warning: failed to mute LITERAL %s\n", path);
    else
        printf("  muted LITERAL %s\n", path);
}

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

    /* Step 1: self-mute */
    {
        audit_token_t self_token;
        mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        if (task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                      (task_info_t)&self_token, &count) == KERN_SUCCESS) {
            if (es_mute_process(g_client, &self_token) != ES_RETURN_SUCCESS)
                fprintf(stderr, "warning: failed to mute self\n");
        } else {
            fprintf(stderr, "warning: task_info failed — could not mute self\n");
        }
    }

    /*
     * Step 2: configure the allowlist before subscribing.
     *
     * es_subscribe() must come AFTER all muting configuration. If subscribe
     * is called first, events are delivered immediately with an empty denylist
     * (nothing suppressed) — the opposite of the intended allowlist behavior.
     * The correct order is: configure muting fully, invert, then subscribe.
     *
     * These mute_path calls add entries to the path denylist. es_invert_muting
     * then flips the semantic so the list becomes an allowlist. Entries added
     * here become the allowlist entries.
     *
     * Symlink note: /tmp resolves to /private/tmp on macOS. ES applies muting
     * after symlink resolution, so muting "/tmp" has no effect — use the
     * resolved path.
     */
    printf("muting: configuring allowlist for /usr/bin/*\n");

    mute_prefix("/usr/bin");
    mute_literal("/usr/sbin/dtrace");

    /*
     * ES_MUTE_INVERSION_TYPE_PATH inverts the path-muting table, which is what
     * the mute_prefix/mute_literal calls above populate. Using
     * ES_MUTE_INVERSION_TYPE_PROCESS would invert only the process-muting table
     * (populated by es_mute_process), leaving the path table in denylist mode
     * and never achieving the allowlist effect.
     */
    if (es_invert_muting(g_client, ES_MUTE_INVERSION_TYPE_PATH) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "warning: es_invert_muting failed — running in denylist mode\n");
    } else {
        printf("muting: inverted — now in allowlist mode (only /usr/bin/* and /usr/sbin/dtrace)\n");
    }

    /* Step 3: subscribe only after muting is fully configured */
    es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC };
    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("muting: monitoring exec — Ctrl-C to stop\n");
    fflush(stdout);

    dispatch_main();
    return 0;
}
