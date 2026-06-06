/*
 * lsm-analog.c — Endpoint Security multi-AUTH policy engine
 *                (ebpf101 ch21/xdpfw analog for macOS)
 *
 * Subscribes to AUTH_EXEC, AUTH_CREATE, and AUTH_UNLINK. Evaluates a simple
 * policy on each event using code identity fields unavailable in eBPF:
 *   - Deny exec of binaries not signed by a known team ID (unless platform binary)
 *   - Deny create/unlink inside sensitive system paths
 *   - Allow platform binaries unconditionally
 *
 * Code identity is cryptographically bound to the binary — a renamed or copied
 * binary still carries its original team_id and signing_id. This is the ES
 * advantage over path-based policy.
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./lsm-analog
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
 * Team IDs allowed to execute non-platform binaries. Binaries without a team_id
 * or with an unlisted team_id are denied. Find yours with:
 *   codesign -dvv /usr/bin/ls 2>&1 | grep TeamIdentifier
 *
 * Apple platform binaries bypass this check entirely via is_platform_binary —
 * adding Apple's team ID here would widen policy to unsigned third-party binaries.
 */
static const char *g_allowed_teams[] = {
    "PABRCU3Y4G",  /* Douglas Mun — matches this project's SIGN_ID */
    NULL,
};

/*
 * Path prefixes where create and unlink are denied for non-platform binaries.
 */
static const char *g_protected_prefixes[] = {
    "/etc",
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    "/System",
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
 * Returns 1 if the team_id token matches any entry in g_allowed_teams.
 * team_id is es_string_token_t by value — no null check needed on the pointer.
 */
static int team_id_allowed(es_string_token_t team_id)
{
    if (!team_id.data || team_id.length == 0)
        return 0;
    for (const char **t = g_allowed_teams; *t != NULL; t++) {
        size_t tlen = strlen(*t);
        if (tlen == team_id.length &&
            memcmp(*t, team_id.data, tlen) == 0)
            return 1;
    }
    return 0;
}

/*
 * Returns 1 if path begins with any protected prefix.
 */
static int path_is_protected(const es_string_token_t *path)
{
    if (!path || !path->data || path->length == 0)
        return 0;
    for (const char **p = g_protected_prefixes; *p != NULL; p++) {
        size_t plen = strlen(*p);
        if (path->length >= plen && memcmp(path->data, *p, plen) == 0) {
            /* require a separator so /etcfoo does not match /etc;
             * plen==1 means prefix is "/" — any absolute path matches */
            if (path->length == plen || path->data[plen] == '/' || plen == 1)
                return 1;
        }
    }
    return 0;
}

static void handle_event(es_client_t *client,
                         const es_message_t *msg)
{
    switch (msg->event_type) {

    case ES_EVENT_TYPE_AUTH_EXEC: {
        const es_process_t *target = msg->event.exec.target;
        pid_t pid  = audit_token_to_pid(target->audit_token);
        pid_t ppid = audit_token_to_pid(target->parent_audit_token);

        /* Platform binaries are unconditionally allowed. */
        if (target->is_platform_binary) {
            es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
            break;
        }

        es_auth_result_t verdict;
        if (team_id_allowed(target->team_id)) {
            verdict = ES_AUTH_RESULT_ALLOW;
            printf("[EXEC:ALLOW] pid=%-6d ppid=%-6d team=", pid, ppid);
            print_str(&target->team_id);
        } else {
            verdict = ES_AUTH_RESULT_DENY;
            printf("[EXEC:DENY]  pid=%-6d ppid=%-6d team=", pid, ppid);
            if (target->team_id.length > 0)
                print_str(&target->team_id);
            else
                printf("(none)");
        }
        printf(" path=");
        print_path(target->executable);
        printf("\n");
        fflush(stdout);

        es_respond_auth_result(client, msg, verdict, false);
        break;
    }

    case ES_EVENT_TYPE_AUTH_CREATE: {
        pid_t pid = audit_token_to_pid(msg->process->audit_token);

        /*
         * For policy evaluation: use the directory path for NEW_PATH (sufficient
         * for prefix matching). For logging: use print_path() on the es_file_t *
         * so path_truncated is checked correctly.
         */
        const es_string_token_t *policy_path = NULL;
        const es_file_t         *log_file    = NULL;

        if (msg->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
            log_file    = msg->event.create.destination.existing_file;
            policy_path = &log_file->path;
        } else {
            log_file    = msg->event.create.destination.new_path.dir;
            policy_path = &log_file->path;
        }

        int protected = path_is_protected(policy_path);
        int is_platform = msg->process->is_platform_binary;

        es_auth_result_t verdict = (!protected || is_platform)
                                   ? ES_AUTH_RESULT_ALLOW
                                   : ES_AUTH_RESULT_DENY;

        if (protected) {
            printf("[CREATE:%s] pid=%-6d path=",
                   verdict == ES_AUTH_RESULT_DENY ? "DENY " : "ALLOW",
                   pid);
            print_path(log_file);
            printf("\n");
            fflush(stdout);
        }

        es_respond_auth_result(client, msg, verdict, false);
        break;
    }

    case ES_EVENT_TYPE_AUTH_UNLINK: {
        pid_t pid = audit_token_to_pid(msg->process->audit_token);
        const es_file_t *target = msg->event.unlink.target;

        int protected = path_is_protected(&target->path);
        int is_platform = msg->process->is_platform_binary;

        es_auth_result_t verdict = (!protected || is_platform)
                                   ? ES_AUTH_RESULT_ALLOW
                                   : ES_AUTH_RESULT_DENY;

        if (protected) {
            printf("[UNLINK:%s] pid=%-6d path=",
                   verdict == ES_AUTH_RESULT_DENY ? "DENY " : "ALLOW",
                   pid);
            print_path(target);
            printf("\n");
            fflush(stdout);
        }

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
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_UNLINK,
    };

    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("lsm-analog: enforcing exec team-ID policy + file path policy — Ctrl-C to stop\n");
    fflush(stdout);

    dispatch_main();
    return 0;
}
