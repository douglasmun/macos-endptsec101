/*
 * file-monitor.c — Endpoint Security file event monitor (ebpf101 ch9/10 analog for macOS)
 *
 * Subscribes to NOTIFY_CREATE, NOTIFY_WRITE, NOTIFY_UNLINK, and NOTIFY_RENAME.
 * Demonstrates ES_DESTINATION_TYPE_* for rename events and TARGET_PREFIX muting
 * to suppress noise from high-volume directories.
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./file-monitor
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
    pid_t pid = audit_token_to_pid(msg->process->audit_token);

    switch (msg->event_type) {

    case ES_EVENT_TYPE_NOTIFY_CREATE: {
        printf("[CREATE] pid=%-6d path=", pid);
        /*
         * es_event_create_t.destination_type distinguishes between creating a
         * new file at a new path vs. creating on top of an existing file.
         */
        if (msg->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
            /* print_path checks path_truncated on the dir; filename is bounded by NAME_MAX */
            print_path(msg->event.create.destination.new_path.dir);
            printf("/");
            print_str(&msg->event.create.destination.new_path.filename);
        } else {
            print_path(msg->event.create.destination.existing_file);
        }
        printf("\n");
        fflush(stdout);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_WRITE: {
        printf("[WRITE]  pid=%-6d path=", pid);
        print_path(msg->event.write.target);
        printf("\n");
        fflush(stdout);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_UNLINK: {
        printf("[UNLINK] pid=%-6d path=", pid);
        print_path(msg->event.unlink.target);
        printf("\n");
        fflush(stdout);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_RENAME: {
        printf("[RENAME] pid=%-6d src=", pid);
        print_path(msg->event.rename.source);
        printf(" dst=");
        /*
         * After rename, the destination may be an existing file (which is
         * atomically replaced) or a new path that did not previously exist.
         */
        if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
            print_path(msg->event.rename.destination.existing_file);
        } else {
            /* print_path checks path_truncated on the dir; filename is bounded by NAME_MAX */
            print_path(msg->event.rename.destination.new_path.dir);
            printf("/");
            print_str(&msg->event.rename.destination.new_path.filename);
        }
        printf("\n");
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

    /*
     * ES_MUTE_PATH_TYPE_TARGET_PREFIX mutes by the target of an operation —
     * the path being created/written/renamed — rather than the instigating
     * process. This is the ES analog of an early-return kernel-side filter:
     * suppressed events never cross the delivery queue.
     *
     * Suppress high-frequency noise directories. Resolve symlinks first:
     * muting "/tmp" does not work because ES sees the resolved /private/tmp.
     */
    const char *noisy[] = {
        "/private/tmp",
        "/private/var/folders",
        "/System/Volumes/Data/.Spotlight-V100",
    };
    for (size_t i = 0; i < sizeof(noisy) / sizeof(noisy[0]); i++) {
        if (es_mute_path(g_client, noisy[i],
                         ES_MUTE_PATH_TYPE_TARGET_PREFIX) != ES_RETURN_SUCCESS)
            fprintf(stderr, "warning: failed to mute path %s\n", noisy[i]);
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_RENAME,
    };

    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("file-monitor: monitoring create/write/unlink/rename — Ctrl-C to stop\n");
    fflush(stdout);

    dispatch_main();
    return 0;
}
