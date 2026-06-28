#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

static es_client_t      *g_client     = NULL;
static dispatch_queue_t  g_main_queue = NULL;
static atomic_int        g_running    = 1;

static void copy_str_token(char *dst, size_t dstsz, const es_string_token_t *tok)
{
    size_t n = tok->length < dstsz - 1 ? tok->length : dstsz - 1;
    memcpy(dst, tok->data, n);
    dst[n] = '\0';
}

static const char *g_sensitive_paths[] = {
    "/etc/hosts",
    "/etc/sudoers",
    "/private/etc/hosts",
    "/private/etc/sudoers",
    "/etc/pam.d/sudo",
    "/private/etc/pam.d/sudo",
    "/Library/Application Support/com.apple.TCC/TCC.db",
    "/private/var/db/auth.db",
    NULL,
};

/*
 * is_write_open — AUTH_OPEN delivers kernel FREAD/FWRITE flags in fflag,
 * not open(2) O_ flags. FWRITE is defined in <fcntl.h> as 0x2; test that bit.
 */
static int is_write_open(int32_t fflag)
{
    return (fflag & FWRITE) != 0;
}

static int path_is_sensitive(const es_file_t *file)
{
    /* A truncated path cannot reliably match — conservatively return 0 (allow).
     * A better production policy would deny-by-default on truncated paths,
     * but for this learning chapter we err on the side of no false positives. */
    if (file->path_truncated)
        return 0;
    char buf[512];
    copy_str_token(buf, sizeof(buf), &file->path);
    for (int i = 0; g_sensitive_paths[i]; i++)
        if (strcmp(buf, g_sensitive_paths[i]) == 0) return 1;
    return 0;
}

static int is_browser_process(const es_process_t *proc)
{
    char buf[512];
    copy_str_token(buf, sizeof(buf), &proc->executable->path);
    static const char *browsers[] = { "Safari", "firefox", "Chrome", "Chromium", "Brave", NULL };
    for (int i = 0; browsers[i]; i++)
        if (strstr(buf, browsers[i])) return 1;
    return 0;
}

static void handle_auth_open(es_client_t *client, const es_message_t *msg)
{
    const es_process_t *proc = msg->process;
    const es_file_t    *file = msg->event.open.file;
    int32_t             fflag = msg->event.open.fflag;

    /* fast path: platform binaries always allowed */
    if (proc->is_platform_binary) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    /* read-only opens are safe */
    if (!is_write_open(fflag)) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    /* write open — check if path is sensitive */
    if (!path_is_sensitive(file)) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    /* sensitive write open — log it */
    char filepath[512];
    copy_str_token(filepath, sizeof(filepath), &file->path);

    char procpath[512];
    copy_str_token(procpath, sizeof(procpath), &proc->executable->path);

    pid_t pid = audit_token_to_pid(proc->audit_token);

    printf("[OPEN] fflag=0x%x file=%s%s pid=%d proc=%s\n",
           (unsigned)fflag,
           filepath,
           file->path_truncated ? " (truncated)" : "",
           pid,
           procpath);
    fflush(stdout);

    /* rule: unsigned process writing sensitive file */
    if (proc->team_id.length == 0) {
        fprintf(stderr, "[ALERT] unsigned-sensitive-write: pid=%d file=%s\n", pid, filepath);
        fflush(stderr);
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
        return;
    }

    /* rule: signed non-platform writing TCC.db or sudoers */
    if (strstr(filepath, "TCC.db") || strstr(filepath, "sudoers")) {
        char team[64];
        copy_str_token(team, sizeof(team), &proc->team_id);
        fprintf(stderr, "[ALERT] sensitive-write-by-signed-non-platform: pid=%d team=%s file=%s\n",
                pid, team, filepath);
        fflush(stderr);
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
        return;
    }

    /* rule: browser process writing sensitive file */
    if (is_browser_process(proc)) {
        fprintf(stderr, "[ALERT] browser-process-sensitive-write: pid=%d proc=%s file=%s\n",
                pid, procpath, filepath);
        fflush(stderr);
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
        return;
    }

    es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
}

static void do_shutdown(void *ctx)
{
    (void)ctx;
    if (g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
        g_client = NULL;
    }
    exit(0);
}

static void on_signal(int sig)
{
    (void)sig;
    /* fire once: a second signal must not enqueue do_shutdown again */
    if (atomic_exchange(&g_running, 0))
        dispatch_async_f(g_main_queue, NULL, do_shutdown);
}

int main(void)
{
    g_main_queue = dispatch_get_main_queue();

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    es_new_client_result_t res = es_new_client(&g_client, ^(es_client_t *client,
                                                              const es_message_t *msg) {
        switch (msg->event_type) {
        case ES_EVENT_TYPE_AUTH_OPEN:
            handle_auth_open(client, msg);
            break;
        default:
            break;
        }
    });

    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es_new_client failed: %d\n", res);
        return 1;
    }

    /* mute self to prevent feedback loop */
    audit_token_t self_token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                  (task_info_t)&self_token, &count) == KERN_SUCCESS) {
        es_mute_process(g_client, &self_token);
    }

    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_OPEN };
    es_return_t sub = es_subscribe(g_client, events,
                                   sizeof(events) / sizeof(events[0]));
    if (sub != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed: %d\n", sub);
        es_delete_client(g_client);
        return 1;
    }

    printf("[auth-open] monitoring sensitive file writes — press Ctrl-C to stop\n");
    fflush(stdout);

    dispatch_main();
    return 0;
}
