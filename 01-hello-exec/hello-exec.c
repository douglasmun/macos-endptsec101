/*
 * hello-exec.c — Endpoint Security process monitor (eBPF execsnoop analog for macOS)
 *
 * Subscribes to NOTIFY_EXEC, NOTIFY_FORK, and NOTIFY_EXIT events and prints
 * process lifecycle to stdout. Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal (System Settings → Privacy & Security)
 *
 * Build:  make
 * Run:    sudo ./hello-exec
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>

/* ── globals ──────────────────────────────────────────────────────────────── */

static es_client_t     *g_client     = NULL;
static dispatch_queue_t g_main_queue = NULL;

/*
 * Written only from signal context, read from dispatch context — must be atomic.
 * atomic_exchange ensures only one signal invocation schedules the shutdown block.
 */
static atomic_int g_stop = 0;

/* ── shutdown ─────────────────────────────────────────────────────────────── */

/*
 * Runs on the main queue — safe to call es_delete_client() and exit() here.
 * dispatch_async_f requires void (*)(void *); unused context parameter required.
 */
static void do_shutdown(void *ctx __attribute__((unused)))
{
    if (g_client) {
        es_delete_client(g_client);
        g_client = NULL;
    }
    exit(0);
}

/*
 * Signal handler: only set the stop flag and schedule shutdown on the main queue.
 * dispatch_async_f is async-signal-safe; es_delete_client() and exit() are not.
 */
static void on_signal(int sig)
{
    (void)sig;
    if (!atomic_exchange(&g_stop, 1))
        dispatch_async_f(g_main_queue, NULL, do_shutdown);
}

/* ── helpers ──────────────────────────────────────────────────────────────── */

/*
 * es_string_token_t.data is NOT null-terminated — always use the length field.
 */
static void print_str(const es_string_token_t *s)
{
    if (s && s->data && s->length > 0)
        printf("%.*s", (int)s->length, s->data);
    else
        printf("(null)");
}

/*
 * Print path from es_file_t, flagging truncation.
 * es_file_t.path_truncated is set when the path exceeds ~16K characters.
 * A silently truncated path in a security monitor is a correctness hazard.
 */
static void print_path(const es_file_t *file)
{
    print_str(&file->path);
    if (file->path_truncated)
        printf("...(truncated)");
}

/*
 * es_exec_arg_count / es_exec_arg are the correct accessors for argv;
 * do not walk msg->event.exec directly — the layout is version-dependent.
 */
static void print_argv(const es_event_exec_t *exec)
{
    uint32_t argc = es_exec_arg_count(exec);
    for (uint32_t i = 0; i < argc; i++) {
        if (i > 0) printf(" ");
        es_string_token_t arg = es_exec_arg(exec, i);
        print_str(&arg);
    }
}

/* parent_audit_token is PID-reuse-safe; ppid alone can point to the wrong process. */
static pid_t parent_pid(const es_process_t *proc)
{
    return audit_token_to_pid(proc->parent_audit_token);
}

/* ── event handler ────────────────────────────────────────────────────────── */

/*
 * Called on the ES serial queue. Message fields are valid for this call only
 * unless retained. NOTIFY events need no response; AUTH events must respond
 * before msg->deadline or the kernel defaults to ALLOW.
 */
static void handle_event(es_client_t *client __attribute__((unused)),
                         const es_message_t *msg)
{
    switch (msg->event_type) {

    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        /*
         * msg->process  = pre-exec image (the process that called execve).
         * msg->event.exec.target = post-exec image — use this for path/argv.
         * Both share the same pid but have different audit_tokens (the token
         * generation counter increments across exec), so do not mix them.
         */
        const es_process_t *target = msg->event.exec.target;
        pid_t pid  = audit_token_to_pid(target->audit_token);
        pid_t ppid = parent_pid(target);

        printf("[EXEC] pid=%-6d ppid=%-6d path=", pid, ppid);
        print_path(target->executable);
        printf(" argv=[");
        print_argv(&msg->event.exec);
        printf("]\n");
        fflush(stdout);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_FORK: {
        pid_t parent = audit_token_to_pid(msg->process->audit_token);
        pid_t child  = audit_token_to_pid(msg->event.fork.child->audit_token);
        printf("[FORK] parent=%-6d child=%-6d\n", parent, child);
        fflush(stdout);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_EXIT: {
        pid_t pid  = audit_token_to_pid(msg->process->audit_token);
        pid_t ppid = parent_pid(msg->process);
        printf("[EXIT] pid=%-6d ppid=%-6d status=%d\n",
               pid, ppid, msg->event.exit.stat);
        fflush(stdout);
        break;
    }

    default:
        break;
    }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
    /* Assign before registering signals — no race window for on_signal. */
    g_main_queue = dispatch_get_main_queue();

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    /*
     * es_new_client() registers the handler block and returns a client handle.
     * The block runs on an ES-managed serial dispatch queue, not the main queue.
     *
     * Failure codes:
     *   ERR_NOT_ENTITLED   — missing com.apple.developer.endpoint-security.client
     *   ERR_NOT_PERMITTED  — missing Full Disk Access TCC approval
     *   ERR_NOT_PRIVILEGED — not running as root
     */
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

    /*
     * Mute our own process to prevent a feedback loop: argus writing to stdout
     * could trigger write events that feed back into the handler.
     * Must be called after es_new_client() so we have a valid client handle.
     */
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
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    };

    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("hello-exec: monitoring exec/fork/exit — Ctrl-C to stop\n");
    fflush(stdout);

    dispatch_main(); /* parks main thread; ES events arrive on ES queue */
    return 0;        /* unreachable */
}
