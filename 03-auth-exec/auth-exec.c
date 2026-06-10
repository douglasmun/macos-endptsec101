/*
 * auth-exec.c — Endpoint Security auth-exec policy enforcer (ebpf101 ch20/lsm analog)
 *
 * Subscribes to AUTH_EXEC. Every exec on the system requires a verdict before
 * the kernel proceeds. The handler must call es_respond_auth_result() before
 * msg->deadline or the kernel defaults to ALLOW.
 *
 * Policy implemented here: deny execution of a configurable binary by name,
 * unless it is a platform binary (Apple-signed system binary).
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./auth-exec
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/*
 * Binary names to deny. Only leaf filename is matched, not the full path.
 * Two limitations: (1) a renamed copy of the binary escapes — see ch06 for
 * code-identity-based enforcement that survives renaming; (2) any unrelated
 * binary installed under one of these names is equally denied.
 */
static const char *g_deny_list[] = {
    "nc",
    "ncat",
    NULL,
};

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

/*
 * Return the leaf filename component of an es_string_token_t path.
 * The returned pointer points into the token's buffer — valid for the
 * duration of the ES handler callback only.
 */
static const char *leaf_name(const es_string_token_t *path)
{
    if (!path || !path->data || path->length == 0)
        return "";
    const char *start = path->data;
    const char *end   = path->data + path->length;
    const char *slash = end - 1;
    while (slash > start && *slash != '/')
        slash--;
    return (*slash == '/') ? slash + 1 : start;
}

/*
 * Returns 1 if the leaf name of the target binary matches any entry in the
 * deny list, 0 otherwise.
 */
static int should_deny(const es_process_t *target)
{
    const es_string_token_t *path = &target->executable->path;
    const char *name = leaf_name(path);

    /*
     * leaf_name returns a literal "" for an empty/NULL path — a pointer that
     * is not inside the token buffer. Computing a length against the buffer
     * end would underflow, so only proceed when name points into the buffer.
     */
    if (!path->data || path->length == 0 ||
        name < path->data || name > path->data + path->length)
        return 0;

    size_t name_len = (size_t)(path->data + path->length - name);

    for (const char **entry = g_deny_list; *entry != NULL; entry++) {
        size_t entry_len = strlen(*entry);
        if (entry_len == name_len && memcmp(name, *entry, entry_len) == 0)
            return 1;
    }
    return 0;
}

static void handle_event(es_client_t *client,
                         const es_message_t *msg)
{
    switch (msg->event_type) {

    case ES_EVENT_TYPE_AUTH_EXEC: {
        /*
         * For AUTH_EXEC the interesting process is the post-exec target, not
         * msg->process (the pre-exec caller). Same semantics as NOTIFY_EXEC.
         */
        const es_process_t *target = msg->event.exec.target;
        pid_t pid  = audit_token_to_pid(target->audit_token);
        pid_t ppid = audit_token_to_pid(target->parent_audit_token);

        /*
         * Never deny a platform binary — these are Apple-signed system executables.
         * Blocking them can render the system unusable.
         */
        if (target->is_platform_binary) {
            es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
            break;
        }

        es_auth_result_t verdict;
        if (should_deny(target)) {
            verdict = ES_AUTH_RESULT_DENY;
            printf("[DENY]  pid=%-6d ppid=%-6d path=", pid, ppid);
        } else {
            verdict = ES_AUTH_RESULT_ALLOW;
            printf("[ALLOW] pid=%-6d ppid=%-6d path=", pid, ppid);
        }
        print_path(target->executable);
        printf("\n");
        fflush(stdout);

        /* cache=false: always call the handler; cache=true would skip it for
         * repeat execs of the same binary — useful in production, not here. */
        es_respond_auth_result(client, msg, verdict, false);
        break;
    }

    default:
        break;
    }
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

    printf("auth-exec: intercepting all execs — denying: ");
    for (const char **e = g_deny_list; *e != NULL; e++) {
        if (e != g_deny_list) printf(", ");
        printf("%s", *e);
    }
    printf(" — Ctrl-C to stop\n");
    fflush(stdout);

    dispatch_main();
    return 0;
}
