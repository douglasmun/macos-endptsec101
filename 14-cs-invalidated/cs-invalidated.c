#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <signal.h>
#include <dispatch/dispatch.h>

#define CS_VALID           0x00000001
#define CS_KILL            0x00000200
#define CS_PLATFORM_BINARY 0x04000000

#define INV_TABLE_SIZE 256

/*
 * Key the table on audit_token_t, not pid_t, to avoid false-positive alerts
 * from PID reuse: a new process recycling an invalidated process's PID would
 * otherwise trigger "invalidated-process-exec" spuriously.
 *
 * audit_token_t encodes a generation counter so tokens are unique across
 * fork/exec cycles even when PIDs are reused.
 */
typedef struct inv_entry {
    audit_token_t token;
    int           platform;
    struct inv_entry *next;
} inv_entry_t;

static inv_entry_t *g_inv[INV_TABLE_SIZE];

static int token_eq(const audit_token_t *a, const audit_token_t *b)
{
    return memcmp(a, b, sizeof(audit_token_t)) == 0;
}

static unsigned token_hash(const audit_token_t *t)
{
    /* Simple hash over the raw bytes */
    const uint8_t *p = (const uint8_t *)t;
    unsigned h = 0;
    for (size_t i = 0; i < sizeof(*t); i++)
        h = h * 31 + p[i];
    return h % INV_TABLE_SIZE;
}

static void inv_insert(const audit_token_t *token, int is_platform) {
    unsigned idx = token_hash(token);
    inv_entry_t *e = g_inv[idx];
    while (e) {
        if (token_eq(&e->token, token)) {
            e->platform = is_platform;
            return;
        }
        e = e->next;
    }
    inv_entry_t *n = calloc(1, sizeof(*n));
    if (!n) return;
    n->token    = *token;
    n->platform = is_platform;
    n->next     = g_inv[idx];
    g_inv[idx]  = n;
}

static int inv_lookup(const audit_token_t *token) {
    unsigned idx = token_hash(token);
    inv_entry_t *e = g_inv[idx];
    while (e) {
        if (token_eq(&e->token, token)) return 1;
        e = e->next;
    }
    return 0;
}

static void inv_remove(const audit_token_t *token) {
    unsigned idx = token_hash(token);
    inv_entry_t **pp = &g_inv[idx];
    while (*pp) {
        if (token_eq(&(*pp)->token, token)) {
            inv_entry_t *tmp = *pp;
            *pp = tmp->next;
            free(tmp);
            return;
        }
        pp = &(*pp)->next;
    }
}

static void copy_str_token(char *dst, size_t dsz, const es_string_token_t *tok) {
    size_t len = tok->length < dsz - 1 ? tok->length : dsz - 1;
    memcpy(dst, tok->data, len);
    dst[len] = '\0';
}

static dispatch_queue_t g_main_queue;
static es_client_t *g_client;
static atomic_int g_shutdown;

static void do_shutdown(void *ctx) {
    (void)ctx;
    es_delete_client(g_client);
    exit(0);
}

static void on_signal(int sig) {
    (void)sig;
    if (atomic_exchange(&g_shutdown, 1) == 0)
        dispatch_async_f(g_main_queue, NULL, do_shutdown);
}

static void handle_event(es_client_t *client, const es_message_t *msg) {
    (void)client;

    switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: {
        const audit_token_t *tok = &msg->process->audit_token;
        pid_t pid = audit_token_to_pid(*tok);
        uint32_t flags = msg->process->codesigning_flags;
        int platform = msg->process->is_platform_binary;
        const es_file_t *exe = msg->process->executable;
        char path[512];
        copy_str_token(path, sizeof(path), &exe->path);
        /* Append truncation marker so alerts are not silently incomplete */
        if (exe->path_truncated)
            strlcat(path, "...(truncated)", sizeof(path));

        fprintf(stderr, "[ALERT] cs-invalidated: pid=%d path=%s flags=0x%x\n",
                pid, path, flags);
        if (platform)
            fprintf(stderr, "[CRITICAL] platform-binary-invalidated: pid=%d path=%s\n",
                    pid, path);
        if (!(flags & CS_KILL))
            fprintf(stderr, "[ALERT] invalidated-still-running: pid=%d path=%s\n",
                    pid, path);
        fflush(stderr);

        inv_insert(tok, platform);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        const es_process_t *target = msg->event.exec.target;
        pid_t pid = audit_token_to_pid(target->audit_token);
        const audit_token_t *old_tok = &msg->process->audit_token;

        if (inv_lookup(old_tok)) {
            const es_file_t *exe = target->executable;
            char path[512];
            copy_str_token(path, sizeof(path), &exe->path);
            if (exe->path_truncated)
                strlcat(path, "...(truncated)", sizeof(path));
            fprintf(stderr, "[ALERT] invalidated-process-exec: pid=%d new-path=%s\n",
                    pid, path);
            fflush(stderr);
        }
        inv_remove(old_tok);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_EXIT: {
        const audit_token_t *tok = &msg->process->audit_token;
        pid_t pid = audit_token_to_pid(*tok);
        inv_remove(tok);
        printf("[EXIT] pid=%d\n", pid);
        fflush(stdout);
        break;
    }

    default:
        break;
    }
}

int main(void) {
    g_main_queue = dispatch_get_main_queue();
    atomic_init(&g_shutdown, 0);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    es_new_client_result_t res = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handle_event(c, m);
    });
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es_new_client failed: %d\n", res);
        return 1;
    }

    audit_token_t self_token;
    mach_msg_type_number_t cnt = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                  (task_info_t)&self_token, &cnt) != KERN_SUCCESS) {
        fprintf(stderr, "task_info failed — cannot self-mute, aborting\n");
        es_delete_client(g_client);
        return 1;
    }
    if (es_mute_process(g_client, &self_token) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_mute_process failed — cannot self-mute, aborting\n");
        es_delete_client(g_client);
        return 1;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    };
    if (es_subscribe(g_client, events, sizeof(events) / sizeof(events[0]))
            != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("[cs-invalidated] monitoring started\n");
    fflush(stdout);

    dispatch_main();
}
