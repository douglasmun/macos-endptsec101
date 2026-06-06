/*
 * network.c — Endpoint Security network connection monitor
 *             (ebpf101 ch11/12/13 analog for macOS)
 *
 * Subscribes to NOTIFY_UIPC_CONNECT. Despite the UIPC name (Unix IPC), the
 * domain field distinguishes AF_UNIX, AF_INET, and AF_INET6 connections.
 * Every event carries the responsible process's audit_token — no softirq
 * problem to work around (contrast with ebpf101 ch12→13).
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./network
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/socket.h>

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

    case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: {
        pid_t pid = audit_token_to_pid(msg->process->audit_token);
        pid_t ppid = audit_token_to_pid(msg->process->parent_audit_token);
        const es_event_uipc_connect_t *ev = &msg->event.uipc_connect;

        printf("[CONNECT] pid=%-6d ppid=%-6d ", pid, ppid);

        switch (ev->domain) {

        case AF_UNIX:
            /*
             * ev->file is the Unix socket file being connected to.
             * ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT always provides a file for
             * named Unix sockets; abstract sockets have an empty path.
             */
            printf("AF_UNIX  path=");
            print_path(ev->file);
            printf("\n");
            break;

        case AF_INET:
            /*
             * ES does not deliver the remote sockaddr for INET/INET6 —
             * es_event_uipc_connect_t only carries domain/type/protocol and
             * the socket file (for AF_UNIX). For TCP/IP, only the socket type
             * and protocol are known at connect(2) time from the ES event.
             * The remote address requires a separate mechanism (e.g. dtrace,
             * Network Extension framework). Log what we have.
             */
            printf("AF_INET  type=%d proto=%d\n", ev->type, ev->protocol);
            break;

        case AF_INET6:
            printf("AF_INET6 type=%d proto=%d\n", ev->type, ev->protocol);
            break;

        default:
            printf("domain=%d type=%d proto=%d\n",
                   ev->domain, ev->type, ev->protocol);
            break;
        }

        fflush(stdout);
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
        ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
    };

    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("network: monitoring connect(2) (AF_UNIX/INET/INET6) — Ctrl-C to stop\n");
    fflush(stdout);

    dispatch_main();
    return 0;
}
