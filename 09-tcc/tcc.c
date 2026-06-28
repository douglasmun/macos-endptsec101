/*
 * tcc.c — Endpoint Security TCC (Transparency, Consent, and Control) monitor
 *         (ebpf101 ch09 analog for macOS privacy permission tracking)
 *
 * Subscribes to ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT to observe
 * Authorization Services decisions, which include TCC privacy grants.
 * TCC rights appear in the right_name field with the prefix
 * "com.apple.TCC." followed by the service name (e.g.
 * "com.apple.TCC.kTCCServiceMicrophone").
 *
 * Also subscribes to ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION to observe
 * the petition (request) side, logging which rights are being requested and
 * by whom.
 *
 * Three detection rules are evaluated on every granted TCC judgement:
 *
 *   Rule 1 — sensitive-grant: A sensitive TCC service (mic/camera/screen/
 *             accessibility/FDA) was granted to a non-platform binary with
 *             no team ID. Unsigned or ad-hoc-signed binaries acquiring
 *             privacy permissions are high-confidence suspicious.
 *
 *   Rule 2 — fda-from-browser: Full Disk Access was granted to a process
 *             whose executable path contains a known browser name substring
 *             (Safari, Chrome, Firefox, etc.). Browsers acquiring FDA is
 *             an unusual pattern often associated with malicious browser
 *             extensions or injected code.
 *
 *   Rule 3 — grant-storm: More than STORM_LIMIT distinct TCC rights were
 *             granted to the same pid within STORM_WINDOW_S seconds.
 *             Legitimate apps request permissions at first launch; rapidly
 *             acquiring many permissions is a malware fingerprint.
 *
 * Key concepts introduced:
 *   - ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT / PETITION and their
 *     event fields (instigator, petitioner, rights/results arrays)
 *   - TCC rights appear as "com.apple.TCC.<service>" in right_name
 *   - es_string_token_t safety (no null termination, use length)
 *   - Per-pid accumulator table with a sliding time window
 *   - Combining is_platform_binary + team_id checks for trust classification
 *
 * Note on ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
 *   This event type was added in a later SDK version than is available in
 *   this build environment. AUTHORIZATION_JUDGEMENT covers the same TCC
 *   grant decisions and is available from macOS 13.0 onwards.
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./tcc
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── constants ────────────────────────────────────────────────────────────── */

#define PATH_BUF         512
#define RIGHT_BUF        256
#define STORM_TABLE_SIZE 64
#define STORM_LIMIT      3
#define STORM_WINDOW_S   30

/* TCC right name prefix used by Authorization Services */
#define TCC_PREFIX       "com.apple.TCC."
#define TCC_PREFIX_LEN   14  /* strlen("com.apple.TCC.") */

/* ── sensitive TCC service suffixes (after "com.apple.TCC.") ─────────────── */

static const char *const k_sensitive_services[] = {
    "kTCCServiceMicrophone",
    "kTCCServiceCamera",
    "kTCCServiceScreenCapture",
    "kTCCServiceAccessibility",
    "kTCCServiceSystemPolicyAllFiles",
    NULL
};

/* ── browser name substrings for rule 2 ──────────────────────────────────── */

static const char *const k_browser_names[] = {
    "Safari",
    "firefox",
    "Chrome",
    "Chromium",
    "Brave",
    "Arc",
    "WebContent",
    NULL
};

/* ── grant storm table ────────────────────────────────────────────────────── */

typedef struct {
    pid_t    pid;
    time_t   window_start;
    uint32_t count;
    char     rights[256];
} storm_entry_t;

static storm_entry_t g_storm[STORM_TABLE_SIZE];

/* ── global ES state ──────────────────────────────────────────────────────── */

static es_client_t      *g_client;
static dispatch_queue_t  g_main_queue;
static atomic_int        g_shutdown;

/* ── helpers ──────────────────────────────────────────────────────────────── */

/*
 * copy_str_token — safely copy an es_string_token_t into a fixed buffer.
 * es_string_token_t.data is NOT null-terminated.
 */
static void copy_str_token(char *buf, size_t bufsz, const es_string_token_t *s)
{
    if (!s || s->length == 0 || !s->data) {
        buf[0] = '\0';
        return;
    }
    size_t n = s->length < bufsz - 1 ? s->length : bufsz - 1;
    memcpy(buf, s->data, n);
    buf[n] = '\0';
}

/*
 * print_path — print es_file_t path, noting truncation.
 */
static void print_path(const es_file_t *file)
{
    if (!file) { printf("(unknown)"); return; }
    printf("%.*s", (int)file->path.length, file->path.data);
    if (file->path_truncated)
        printf(" (truncated)");
}

/*
 * str_token_contains — return 1 if the es_string_token_t data contains needle.
 */
static int str_token_contains(const es_string_token_t *s, const char *needle)
{
    if (!s || s->length == 0 || !s->data)
        return 0;
    size_t nlen = strlen(needle);
    if (nlen > s->length)
        return 0;
    for (size_t i = 0; i + nlen <= s->length; i++) {
        if (memcmp(s->data + i, needle, nlen) == 0)
            return 1;
    }
    return 0;
}

/*
 * right_is_tcc — return 1 if the right_name starts with "com.apple.TCC."
 */
static int right_is_tcc(const es_string_token_t *right)
{
    if (!right || right->length <= TCC_PREFIX_LEN || !right->data)
        return 0;
    return memcmp(right->data, TCC_PREFIX, TCC_PREFIX_LEN) == 0;
}

/*
 * right_service_suffix — return pointer and length of the service part after
 * "com.apple.TCC." within the es_string_token_t data (not null-terminated).
 * Returns NULL if the right is not a TCC right.
 */
static const char *right_service_suffix(const es_string_token_t *right,
                                        size_t *out_len)
{
    if (!right_is_tcc(right))
        return NULL;
    *out_len = right->length - TCC_PREFIX_LEN;
    return right->data + TCC_PREFIX_LEN;
}

/*
 * service_suffix_eq — compare the suffix of a TCC right_name to a C string.
 */
static int service_suffix_eq(const es_string_token_t *right, const char *svc)
{
    size_t slen;
    const char *suffix = right_service_suffix(right, &slen);
    if (!suffix)
        return 0;
    size_t clen = strlen(svc);
    return slen == clen && memcmp(suffix, svc, clen) == 0;
}

/* ── rule helpers ─────────────────────────────────────────────────────────── */

static int is_sensitive_service(const es_string_token_t *right)
{
    for (int i = 0; k_sensitive_services[i]; i++) {
        if (service_suffix_eq(right, k_sensitive_services[i]))
            return 1;
    }
    return 0;
}

static int path_contains_browser(const es_string_token_t *path)
{
    for (int i = 0; k_browser_names[i]; i++) {
        if (str_token_contains(path, k_browser_names[i]))
            return 1;
    }
    return 0;
}

/* ── storm table ──────────────────────────────────────────────────────────── */

/*
 * storm_update — record a TCC right grant for pid.
 * Returns the updated count of distinct rights within the current window.
 */
static uint32_t storm_update(pid_t pid, const char *right_str)
{
    time_t now  = time(NULL);
    int    slot = -1;
    int    oldest = 0;

    for (int i = 0; i < STORM_TABLE_SIZE; i++) {
        if (g_storm[i].pid == pid) {
            slot = i;
            break;
        }
        if (g_storm[i].pid == 0 && slot == -1)
            slot = i;
        if (slot == -1 ||
            g_storm[i].window_start < g_storm[oldest].window_start)
            oldest = i;
    }
    if (slot == -1)
        slot = oldest;

    storm_entry_t *e = &g_storm[slot];

    if (e->pid != pid || (now - e->window_start) > STORM_WINDOW_S) {
        e->pid          = pid;
        e->window_start = now;
        e->count        = 0;
        e->rights[0]    = '\0';
    }

    /*
     * Substring-safe duplicate check: verify the match is a full token.
     * A plain strstr("kTCCServiceCamera", ...) would spuriously match inside
     * "kTCCServiceCameraWithMicrophone". We require the match to be preceded
     * by start-of-string or ',' and followed by ',' or NUL.
     */
    const char *p = e->rights;
    int already_seen = 0;
    size_t rlen = strlen(right_str);
    while ((p = strstr(p, right_str)) != NULL) {
        int pre_ok  = (p == e->rights || *(p - 1) == ',');
        int post_ok = (p[rlen] == '\0' || p[rlen] == ',');
        if (pre_ok && post_ok) { already_seen = 1; break; }
        p += rlen;
    }
    if (!already_seen) {
        e->count++;
        if (e->rights[0] != '\0')
            strncat(e->rights, ",",
                    sizeof(e->rights) - strlen(e->rights) - 1);
        strncat(e->rights, right_str,
                sizeof(e->rights) - strlen(e->rights) - 1);
    }

    return e->count;
}

/* ── shutdown ─────────────────────────────────────────────────────────────── */

static void do_shutdown(void *ctx)
{
    (void)ctx;
    es_delete_client(g_client);
    exit(0);
}

static void on_signal(int sig)
{
    (void)sig;
    if (!atomic_exchange(&g_shutdown, 1))
        dispatch_async_f(g_main_queue, NULL, do_shutdown);
}

/* ── petition handler ─────────────────────────────────────────────────────── */

static void handle_petition(const es_message_t *msg)
{
    const es_event_authorization_petition_t *ev =
        msg->event.authorization_petition;

    /* msg->process is the XPC broker; instigator is the actual requesting app */
    const es_process_t *actor = ev->instigator ? ev->instigator : msg->process;
    pid_t pid = audit_token_to_pid(actor->audit_token);

    for (size_t i = 0; i < ev->right_count; i++) {
        const es_string_token_t *right = &ev->rights[i];
        if (!right_is_tcc(right))
            continue;

        char right_str[RIGHT_BUF];
        copy_str_token(right_str, sizeof(right_str), right);

        printf("[TCC-REQ] right=%s pid=%d path=", right_str, pid);
        print_path(actor->executable);
        printf("\n");
        fflush(stdout);
    }
}

/* ── judgement handler ────────────────────────────────────────────────────── */

static void handle_judgement(const es_message_t *msg)
{
    const es_event_authorization_judgement_t *ev =
        msg->event.authorization_judgement;

    /*
     * instigator is the actual requesting app; petitioner is the XPC broker
     * (e.g., authd). Use instigator to attribute the grant to the real app,
     * matching the convention in handle_petition.
     */
    const es_process_t *actor = ev->instigator ? ev->instigator
                                               : ev->petitioner;
    if (!actor)
        actor = msg->process;

    pid_t pid = audit_token_to_pid(actor->audit_token);

    for (size_t i = 0; i < ev->result_count; i++) {
        const es_authorization_result_t *result = &ev->results[i];
        if (!result->granted)
            continue;
        if (!right_is_tcc(&result->right_name))
            continue;

        const es_file_t *exe = actor->executable;

        char right_str[RIGHT_BUF];
        char path_str[PATH_BUF] = "(unknown)";
        copy_str_token(right_str, sizeof(right_str), &result->right_name);
        if (exe) {
            copy_str_token(path_str, sizeof(path_str), &exe->path);
            /* Append truncation marker so alert lines match the info line */
            if (exe->path_truncated &&
                strlen(path_str) + sizeof("...(truncated)") < PATH_BUF)
                strlcat(path_str, "...(truncated)", sizeof(path_str));
        }

        printf("[TCC] right=%s pid=%d path=", right_str, pid);
        print_path(actor->executable);
        printf("\n");
        fflush(stdout);

        /* ── Rule 1: sensitive grant from unsigned / no-team-id non-platform binary */
        if (is_sensitive_service(&result->right_name) &&
            !actor->is_platform_binary &&
            actor->team_id.length == 0)
        {
            fprintf(stderr,
                "[ALERT] sensitive-grant: right=%s pid=%d path=%s"
                " (non-platform, no team_id)\n",
                right_str, pid, path_str);
            fflush(stderr);
        }

        /* ── Rule 2: FDA acquired by browser-named process */
        if (service_suffix_eq(&result->right_name,
                              "kTCCServiceSystemPolicyAllFiles") &&
            exe && path_contains_browser(&exe->path))
        {
            fprintf(stderr,
                "[ALERT] fda-from-browser: pid=%d path=%s acquired FDA\n",
                pid, path_str);
            fflush(stderr);
        }

        /* ── Rule 3: grant storm */
        uint32_t count = storm_update(pid, right_str);
        if (count > STORM_LIMIT) {
            for (int j = 0; j < STORM_TABLE_SIZE; j++) {
                if (g_storm[j].pid == pid) {
                    fprintf(stderr,
                        "[ALERT] grant-storm: pid=%d acquired %u TCC rights"
                        " in %ds: %s\n",
                        pid, count, STORM_WINDOW_S, g_storm[j].rights);
                    fflush(stderr);
                    break;
                }
            }
        }
    }
}

/* ── event handler ────────────────────────────────────────────────────────── */

static void handle_event(es_client_t *client, const es_message_t *msg)
{
    (void)client;

    switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
        handle_petition(msg);
        break;
    case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
        handle_judgement(msg);
        break;
    default:
        break;
    }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
    g_main_queue = dispatch_get_main_queue();
    atomic_store(&g_shutdown, 0);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    es_new_client_result_t res = es_new_client(&g_client,
        ^(es_client_t *c, const es_message_t *m) {
            handle_event(c, m);
        });
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es_new_client failed: %d\n", res);
        return 1;
    }

    /* mute self */
    audit_token_t self_token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr = task_info(mach_task_self(),
                                 TASK_AUDIT_TOKEN,
                                 (task_info_t)&self_token,
                                 &count);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_info failed: %d\n", kr);
        es_delete_client(g_client);
        return 1;
    }

    if (es_mute_process(g_client, &self_token) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_mute_process failed\n");
        es_delete_client(g_client);
        return 1;
    }

    /* subscribe — muting must be complete before es_subscribe */
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION,
        ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT,
    };
    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS)
    {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("[tcc] subscribed to AUTHORIZATION_PETITION + AUTHORIZATION_JUDGEMENT"
           " — watching TCC grants\n");
    fflush(stdout);

    dispatch_main();
    /* not reached */
    return 0;
}
