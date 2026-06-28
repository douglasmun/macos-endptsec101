#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <signal.h>
#include <time.h>

/* ── pending-install table for rule 3 (install-then-remove) ── */
#define PENDING_TABLE_SIZE 32

/* The dedup/match key for rule 3 is the FULL item_url. Any fixed-size key has a
 * truncation threshold: two distinct item_urls sharing that prefix collapse into
 * one slot, so a later REMOVE clears the wrong install and a genuine persistence
 * removal is missed. We therefore store the exact token bytes (heap copy + byte
 * length) and match on length+memcmp — no threshold exists. item_url is not
 * NUL-terminated, so length is authoritative; an empty slot has key==NULL. */
typedef struct {
    char   *key;      /* malloc'd exact item_url bytes; NULL = empty slot */
    size_t  key_len;
    time_t  install_time;
} pending_install_t;

static pending_install_t g_pending[PENDING_TABLE_SIZE];

static int key_eq(const pending_install_t *slot,
                  const char *bytes, size_t len)
{
    return slot->key && slot->key_len == len &&
           memcmp(slot->key, bytes, len) == 0;
}

static void slot_clear(pending_install_t *slot)
{
    free(slot->key);
    slot->key = NULL;
    slot->key_len = 0;
}

/* ── shutdown machinery ── */
static atomic_int       g_quit;
static dispatch_queue_t g_main_queue;

static void do_shutdown(void *ctx)
{
    (void)ctx;
    exit(0);
}

static void on_signal(int sig)
{
    (void)sig;
    atomic_store(&g_quit, 1);
    dispatch_async_f(g_main_queue, NULL, do_shutdown);
}

/* ── string helpers ── */
static void copy_str_token(char *buf, size_t bufsz, const es_string_token_t *tok)
{
    size_t n = tok->length < bufsz - 1 ? tok->length : bufsz - 1;
    memcpy(buf, tok->data, n);
    buf[n] = '\0';
}

static void print_path(const es_file_t *f)
{
    if (!f) { printf("(null)"); return; }
    if (f->path_truncated)
        printf("%.*s... (truncated)", (int)f->path.length, f->path.data);
    else
        printf("%.*s", (int)f->path.length, f->path.data);
}
/* suppress unused warning — print_path used only in future chapters */
static void (*_print_path_ref)(const es_file_t *) __attribute__((unused)) = print_path;

static const char *btm_type_str(es_btm_item_type_t t)
{
    switch (t) {
        case ES_BTM_ITEM_TYPE_AGENT:      return "LaunchAgent";
        case ES_BTM_ITEM_TYPE_DAEMON:     return "LaunchDaemon";
        case ES_BTM_ITEM_TYPE_LOGIN_ITEM: return "LoginItem";
        case ES_BTM_ITEM_TYPE_APP:        return "App";
        case ES_BTM_ITEM_TYPE_USER_ITEM:  return "UserItem";
        default:                          return "Unknown";
    }
}

/* ── pending-install table helpers ── */
/* key is the exact item_url bytes (not NUL-terminated); len is its byte length. */
static void pending_add(const char *key, size_t len)
{
    if (!key || len == 0) return;
    time_t now = time(NULL);
    /* Dedup on key first: a repeated ADD of the same item_url (installer
     * rewriting a plist) must refresh the existing slot, not allocate a second.
     * Without this, duplicates accumulate — a single REMOVE clears only the
     * first, and oldest-by-install_time eviction can discard a distinct pending
     * item before its REMOVE arrives, suppressing the Rule-3 alert. Matching is
     * on full length+bytes, so no truncation can collapse distinct item_urls. */
    for (int i = 0; i < PENDING_TABLE_SIZE; i++) {
        if (key_eq(&g_pending[i], key, len)) {
            g_pending[i].install_time = now;
            return;
        }
    }
    /* Allocate the replacement BEFORE choosing/clearing a victim slot. If malloc
     * fails after eviction, we would have discarded a valid pending install with
     * nothing to put in its place — a later REMOVE for that item would then miss
     * the Rule-3 alert. Alloc first; only mutate the table once it succeeds. */
    char *copy = malloc(len);
    if (!copy) return;  /* OOM: drop this ADD; leave existing entries intact */
    memcpy(copy, key, len);

    int target = -1;
    for (int i = 0; i < PENDING_TABLE_SIZE; i++) {
        if (g_pending[i].key == NULL) { target = i; break; }
    }
    if (target < 0) {
        /* table full — evict oldest (its key is freed by slot_clear) */
        target = 0;
        for (int i = 1; i < PENDING_TABLE_SIZE; i++) {
            if (g_pending[i].install_time < g_pending[target].install_time)
                target = i;
        }
        slot_clear(&g_pending[target]);
    }
    g_pending[target].key         = copy;
    g_pending[target].key_len     = len;
    g_pending[target].install_time = now;
}

/* returns install_time if found and within 60 s window, 0 otherwise; clears slot */
static time_t pending_remove(const char *key, size_t len)
{
    if (!key || len == 0) return 0;
    time_t now = time(NULL);
    for (int i = 0; i < PENDING_TABLE_SIZE; i++) {
        if (key_eq(&g_pending[i], key, len)) {
            time_t t = g_pending[i].install_time;
            slot_clear(&g_pending[i]);
            /* now >= t guards against a backward clock step: time_t is signed,
             * so now < t would make (now - t) negative and pass the <= 60 test,
             * firing the rule with a nonsensical negative elapsed time. */
            if (now >= t && now - t <= 60)
                return t;
            return 0;
        }
    }
    return 0;
}

/* ── browser-ancestry heuristic ── */
static const char *k_browser_substrings[] = {
    "Safari", "firefox", "Chrome", "Chromium", "Brave", "Arc", NULL
};

static int path_has_browser(const char *path)
{
    for (int i = 0; k_browser_substrings[i]; i++) {
        if (strstr(path, k_browser_substrings[i]))
            return 1;
    }
    return 0;
}

/* ── main event handler ── */
static void handle_event(es_client_t *client, const es_message_t *msg)
{
    (void)client;

    if (msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD) {
        const es_event_btm_launch_item_add_t *ev = msg->event.btm_launch_item_add;
        const es_btm_launch_item_t           *item = ev->item;
        const es_process_t                   *ins  = ev->instigator;
        if (!ins) ins = msg->process;

        /* executable_path is a field on the add-event itself (may be empty);
           item->item_url is the plist/item URL */
        char exec_buf[512]  = "(none)";
        char plist_buf[512] = "(none)";  /* display only — rule-3 key is the full token */
        char ins_path[512]  = "(unknown)";

        if (ev->executable_path.length > 0)
            copy_str_token(exec_buf, sizeof(exec_buf), &ev->executable_path);
        if (item->item_url.length > 0)
            copy_str_token(plist_buf, sizeof(plist_buf), &item->item_url);
        if (ins && ins->executable)
            copy_str_token(ins_path, sizeof(ins_path), &ins->executable->path);

        pid_t pid = ins ? audit_token_to_pid(ins->audit_token) : -1;

        printf("[BTM-ADD] type=%s exec=%s plist=%s pid=%d instigator=%s\n",
               btm_type_str(item->item_type),
               exec_buf, plist_buf, pid, ins_path);
        fflush(stdout);

        /* Rule 1: unsigned LaunchAgent/Daemon install */
        if ((item->item_type == ES_BTM_ITEM_TYPE_AGENT ||
             item->item_type == ES_BTM_ITEM_TYPE_DAEMON) && ins)
        {
            int no_team = (ins->team_id.length == 0);
            if (!ins->is_platform_binary && no_team) {
                fprintf(stderr,
                    "[ALERT] unsigned-persistence: unsigned non-platform process "
                    "(pid=%d, %s) registered %s exec=%s plist=%s\n",
                    pid, ins_path, btm_type_str(item->item_type), exec_buf, plist_buf);
                fflush(stderr);
            }
        }

        /* Rule 2: browser-ancestry heuristic */
        if (path_has_browser(ins_path)) {
            fprintf(stderr,
                "[ALERT] browser-persistence: browser-related process (pid=%d, %s) "
                "registered BTM item type=%s exec=%s\n",
                pid, ins_path, btm_type_str(item->item_type), exec_buf);
            fflush(stderr);
        }

        /* Rule 3: record install keyed on the FULL item_url token (present in
         * both ADD and REMOVE) — not the truncated display copy. */
        if (item->item_url.length > 0)
            pending_add(item->item_url.data, item->item_url.length);

    } else if (msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE) {
        const es_event_btm_launch_item_remove_t *ev   = msg->event.btm_launch_item_remove;
        const es_btm_launch_item_t              *item = ev->item;
        const es_process_t                      *ins  = ev->instigator;
        if (!ins) ins = msg->process;

        char app_buf[512]   = "(none)";
        char plist_buf[512] = "(none)";  /* display only — rule-3 key is the full token */
        char ins_path[512]  = "(unknown)";

        /* BTM_REMOVE has no executable_path field — use item_url and app_url */
        if (item->app_url.length > 0)
            copy_str_token(app_buf, sizeof(app_buf), &item->app_url);
        if (item->item_url.length > 0)
            copy_str_token(plist_buf, sizeof(plist_buf), &item->item_url);
        if (ins && ins->executable)
            copy_str_token(ins_path, sizeof(ins_path), &ins->executable->path);

        pid_t pid = ins ? audit_token_to_pid(ins->audit_token) : -1;

        printf("[BTM-REMOVE] type=%s app=%s plist=%s pid=%d instigator=%s\n",
               btm_type_str(item->item_type),
               app_buf, plist_buf, pid, ins_path);
        fflush(stdout);

        /* Rule 3: install-then-remove within 60 s — keyed on the FULL item_url
         * token, matching the ADD side. */
        if (item->item_url.length > 0) {
            time_t install_t = pending_remove(item->item_url.data,
                                              item->item_url.length);
            if (install_t != 0) {
                time_t now = time(NULL);
                fprintf(stderr,
                    "[ALERT] execute-once-cleanup: BTM item removed %lld s after install "
                    "(plist=%s app=%s, remover pid=%d %s)\n",
                    (long long)(now - install_t), plist_buf, app_buf, pid, ins_path);
                fflush(stderr);
            }
        }
    }
}

int main(void)
{
    g_main_queue = dispatch_get_main_queue();
    atomic_store(&g_quit, 0);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    memset(g_pending, 0, sizeof(g_pending));

    es_client_t *client = NULL;
    es_new_client_result_t res = es_new_client(&client, ^(es_client_t *c, const es_message_t *m) {
        handle_event(c, m);
    });
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es_new_client failed: %d\n", res);
        return 1;
    }

    /* self-mute — fatal if we cannot prevent feedback loop */
    audit_token_t self_token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                  (task_info_t)&self_token, &count) != KERN_SUCCESS) {
        fprintf(stderr, "task_info failed — cannot self-mute, aborting\n");
        es_delete_client(client);
        return 1;
    }
    if (es_mute_process(client, &self_token) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_mute_process failed — cannot self-mute, aborting\n");
        es_delete_client(client);
        return 1;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
    };
    es_return_t sub = es_subscribe(client, events,
                                   sizeof(events) / sizeof(events[0]));
    if (sub != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed: %d\n", sub);
        es_delete_client(client);
        return 1;
    }

    printf("[persistence] monitoring BTM launch item events. Ctrl-C to stop.\n");
    fflush(stdout);

    dispatch_main();
    return 0;
}
