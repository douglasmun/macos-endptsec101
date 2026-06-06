/*
 * unified-agent.c — capstone ES agent combining all prior subsystems
 *
 * Subscribes to a merged event set in a single es_new_client() call:
 *   NOTIFY_FORK, NOTIFY_EXEC, NOTIFY_EXIT       — process tree (ch08)
 *   NOTIFY_WRITE, NOTIFY_UIPC_CONNECT           — IDS counters (ch07)
 *   NOTIFY_TCC_MODIFY                           — privacy grants (ch09)
 *   NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE           — persistence (ch10)
 *   NOTIFY_CS_INVALIDATED                       — runtime integrity (ch14)
 *   AUTH_EXEC, AUTH_OPEN                        — deferred policy (ch03/ch13/ch15)
 *
 * AUTH events are handled with the deferred pattern from ch15: the message is
 * retained on the ES queue and dispatched to a concurrent work queue where
 * policy is evaluated with full cross-subsystem context (ancestry, TCC flags,
 * cs_invalidated, codesign). The snapshot pattern ensures race-free reads:
 * relevant tree state is copied inside the ES handler before dispatch_async.
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./unified-agent
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

/* CS flag not always exposed in public headers */
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000
#endif

/* ── constants ────────────────────────────────────────────────────────────── */

#define TREE_BUCKETS        256
#define STATE_BUCKETS       256
#define PATH_BUF            512
#define ANCESTRY_DEPTH_MAX  8
#define ANCESTRY_STR_MAX    1024

/* IDS thresholds */
#define EXEC_CHAIN_LIMIT    5
#define EXEC_CHAIN_WINDOW_S 10
#define FANOUT_LIMIT        10
#define FANOUT_WINDOW_S     30

/* Deferred AUTH */
#define MIN_WORK_BUDGET_MS  100ULL

/* ── process tree ─────────────────────────────────────────────────────────── */

typedef struct tree_node {
    audit_token_t    token;
    audit_token_t    parent_token;
    pid_t            pid;
    char             path[PATH_BUF];
    int              cs_invalidated;
    struct tree_node *next;
} tree_node_t;

static tree_node_t *g_tree[TREE_BUCKETS];

static uint32_t token_hash(const audit_token_t *tok)
{
    const uint8_t *b = (const uint8_t *)tok;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < sizeof(*tok); i++) {
        h ^= b[i];
        h *= 16777619u;
    }
    return h % TREE_BUCKETS;
}

static int token_eq(const audit_token_t *a, const audit_token_t *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

static tree_node_t *tree_find(const audit_token_t *tok)
{
    uint32_t idx = token_hash(tok);
    for (tree_node_t *n = g_tree[idx]; n; n = n->next)
        if (token_eq(&n->token, tok))
            return n;
    return NULL;
}

static tree_node_t *tree_get_or_create(const audit_token_t *tok, pid_t pid)
{
    tree_node_t *n = tree_find(tok);
    if (n) return n;

    n = calloc(1, sizeof(*n));
    if (!n) return NULL;

    n->token = *tok;
    n->pid   = pid;

    uint32_t idx = token_hash(tok);
    n->next = g_tree[idx];
    g_tree[idx] = n;
    return n;
}

static void tree_remove(const audit_token_t *tok)
{
    uint32_t idx = token_hash(tok);
    tree_node_t **pp = &g_tree[idx];
    while (*pp) {
        if (token_eq(&(*pp)->token, tok)) {
            tree_node_t *dead = *pp;
            *pp = dead->next;
            free(dead);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ── IDS state ────────────────────────────────────────────────────────────── */

typedef struct proc_state {
    audit_token_t      token;
    pid_t              pid;
    char               path[PATH_BUF];
    uint32_t           exec_count;
    time_t             exec_window_start;
    int                wrote_tmp;
    uint32_t           inet_count;
    time_t             inet_window_start;
    struct proc_state *next;
} proc_state_t;

static proc_state_t *g_state[STATE_BUCKETS];

static proc_state_t *state_find(const audit_token_t *tok)
{
    uint32_t idx = token_hash(tok) % STATE_BUCKETS;
    for (proc_state_t *s = g_state[idx]; s; s = s->next)
        if (token_eq(&s->token, tok))
            return s;
    return NULL;
}

static proc_state_t *state_get_or_create(const audit_token_t *tok, pid_t pid)
{
    proc_state_t *s = state_find(tok);
    if (s) return s;

    s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->token              = *tok;
    s->pid                = pid;
    s->exec_window_start  = time(NULL);
    s->inet_window_start  = time(NULL);

    uint32_t idx = token_hash(tok) % STATE_BUCKETS;
    s->next = g_state[idx];
    g_state[idx] = s;
    return s;
}

static void state_remove(const audit_token_t *tok)
{
    uint32_t idx = token_hash(tok) % STATE_BUCKETS;
    proc_state_t **pp = &g_state[idx];
    while (*pp) {
        if (token_eq(&(*pp)->token, tok)) {
            proc_state_t *dead = *pp;
            *pp = dead->next;
            free(dead);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ── globals ──────────────────────────────────────────────────────────────── */

static es_client_t        *g_client     = NULL;
static dispatch_queue_t    g_main_queue = NULL;
static dispatch_queue_t    g_work_queue = NULL;
static atomic_int          g_stop       = 0;
static uint64_t            g_ticks_per_ms = 0;

static _Atomic uint64_t    g_total_evals    = 0;
static _Atomic uint64_t    g_deadline_misses = 0;

/* ── timebase ─────────────────────────────────────────────────────────────── */

static void init_timebase(void)
{
    mach_timebase_info_data_t info;
    mach_timebase_info(&info);
    g_ticks_per_ms = (uint64_t)(1000000ULL * info.denom / info.numer);
}

/* ── helpers ──────────────────────────────────────────────────────────────── */

static void copy_str_token(char *buf, size_t bufsz, const es_string_token_t *s)
{
    if (!s || !s->data || s->length == 0) { buf[0] = '\0'; return; }
    size_t n = s->length < bufsz - 1 ? s->length : bufsz - 1;
    memcpy(buf, s->data, n);
    buf[n] = '\0';
}

static void print_path(const es_file_t *file)
{
    printf("%.*s", (int)file->path.length, file->path.data);
    if (file->path_truncated)
        printf("...(truncated)");
}

static const char *leaf(const char *path)
{
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static int path_has_prefix(const es_string_token_t *path, const char *prefix)
{
    if (!path || !path->data) return 0;
    size_t plen = strlen(prefix);
    if (path->length < plen || memcmp(path->data, prefix, plen) != 0)
        return 0;
    return path->length == plen || path->data[plen] == '/' || plen == 1;
}

/* ── ancestry ─────────────────────────────────────────────────────────────── */

static void ancestry_str(const tree_node_t *start, char *buf, size_t bufsz)
{
    const tree_node_t *stack[ANCESTRY_DEPTH_MAX];
    int depth = 0;
    int missing_root = 0;

    if (!token_eq(&start->token, &start->parent_token)) {
        const audit_token_t *cur = &start->parent_token;
        for (int i = 0; i < ANCESTRY_DEPTH_MAX; i++) {
            tree_node_t *anc = tree_find(cur);
            if (!anc) { missing_root = 1; break; }
            stack[depth++] = anc;
            if (token_eq(&anc->token, &anc->parent_token)) break;
            cur = &anc->parent_token;
        }
    }

    size_t pos = 0;

    if (missing_root) {
        int rc = snprintf(buf + pos, bufsz - pos, "(unknown) \xe2\x86\x92 ");
        if (rc > 0) pos += (size_t)rc;
    }

    for (int i = depth - 1; i >= 0 && pos < bufsz - 1; i--) {
        int rc = snprintf(buf + pos, bufsz - pos,
                          "%s(%d) \xe2\x86\x92 ",
                          leaf(stack[i]->path), stack[i]->pid);
        if (rc > 0) pos += (size_t)rc;
    }

    snprintf(buf + pos, bufsz - pos, "%s(%d)", leaf(start->path), start->pid);
}

/* ── TCC sensitive services ───────────────────────────────────────────────── */

static const char *g_tcc_sensitive[] = {
    "kTCCServiceMicrophone",
    "kTCCServiceCamera",
    "kTCCServiceScreenCapture",
    "kTCCServiceSystemPolicyAllFiles",
    NULL,
};

/* ── AUTH_OPEN sensitive paths ────────────────────────────────────────────── */

static const char *g_sensitive_paths[] = {
    "/etc/hosts",
    "/private/etc/hosts",
    "/etc/sudoers",
    "/private/etc/sudoers",
    "/Library/Application Support/com.apple.TCC/TCC.db",
    "/private/var/db/auth.db",
    NULL,
};

static int is_sensitive_path(const char *path)
{
    for (const char **p = g_sensitive_paths; *p; p++) {
        if (strcmp(path, *p) == 0) return 1;
    }
    return 0;
}

/* ── IDS rules ────────────────────────────────────────────────────────────── */

static void rule_exec_chain(proc_state_t *s)
{
    time_t now = time(NULL);
    if (now < s->exec_window_start ||
        now - s->exec_window_start > EXEC_CHAIN_WINDOW_S) {
        s->exec_count        = 1;
        s->exec_window_start = now;
        return;
    }
    s->exec_count++;
    if (s->exec_count > (uint32_t)EXEC_CHAIN_LIMIT) {
        time_t elapsed = now - s->exec_window_start;
        fprintf(stderr,
                "[ALERT] rule=exec-chain pid=%d %u execs in %lus path=%s\n",
                s->pid, s->exec_count, (unsigned long)elapsed, s->path);
        fflush(stderr);
        s->exec_count        = 0;
        s->exec_window_start = now;
    }
}

static void rule_sensitive_file_write(proc_state_t *s)
{
    if (!s->wrote_tmp) return;
    fprintf(stderr,
            "[ALERT] rule=sensitive-file-write pid=%d wrote /private/tmp then exec'd path=%s\n",
            s->pid, s->path);
    fflush(stderr);
    s->wrote_tmp = 0; /* reset so rule doesn't re-fire on every subsequent exec */
}

static void rule_fanout(proc_state_t *s, time_t now)
{
    if (now < s->inet_window_start ||
        now - s->inet_window_start > FANOUT_WINDOW_S) {
        s->inet_count        = 1;
        s->inet_window_start = now;
        return;
    }
    s->inet_count++;
    if (s->inet_count > (uint32_t)FANOUT_LIMIT) {
        time_t elapsed = now - s->inet_window_start;
        fprintf(stderr,
                "[ALERT] rule=fanout pid=%d %u INET connects in %lus path=%s\n",
                s->pid, s->inet_count, (unsigned long)elapsed, s->path);
        fflush(stderr);
        s->inet_count        = 0;
        s->inet_window_start = now;
    }
}

/* ── shutdown ─────────────────────────────────────────────────────────────── */

static void do_shutdown(void *ctx __attribute__((unused)))
{
    dispatch_barrier_sync(g_work_queue, ^{});
    if (g_client) {
        es_delete_client(g_client);
        g_client = NULL;
    }
    uint64_t total  = atomic_load(&g_total_evals);
    uint64_t misses = atomic_load(&g_deadline_misses);
    fprintf(stderr, "shutdown: evals=%llu deadline-misses=%llu\n",
            (unsigned long long)total, (unsigned long long)misses);
    fflush(stderr);
    exit(0);
}

static void on_signal(int sig)
{
    (void)sig;
    if (!atomic_exchange(&g_stop, 1))
        dispatch_async_f(g_main_queue, NULL, do_shutdown);
}

/* ── deferred AUTH context ────────────────────────────────────────────────── */

typedef struct {
    es_message_t *msg;
    char          ancestry[ANCESTRY_STR_MAX];
    int           cs_invalidated;
} auth_ctx_t;

/* ── AUTH_EXEC evaluator ──────────────────────────────────────────────────── */

static void evaluate_exec_and_respond(auth_ctx_t *ctx)
{
    atomic_fetch_add(&g_total_evals, 1);

    const es_message_t *msg    = ctx->msg;
    const es_process_t *target = msg->event.exec.target;
    pid_t pid = audit_token_to_pid(target->audit_token);
    const es_file_t *exe = target->executable;
    const char *trunc = exe->path_truncated ? "...(truncated)" : "";

    uint64_t now      = mach_absolute_time();
    uint64_t deadline = msg->deadline;

    if (now >= deadline ||
        (deadline - now) < MIN_WORK_BUDGET_MS * g_ticks_per_ms) {
        atomic_fetch_add(&g_deadline_misses, 1);
        fprintf(stderr, "[WARN] deadline-miss AUTH_EXEC pid=%d — denying\n", pid);
        fflush(stderr);
        es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_DENY, false);
        es_release_message(msg);
        return;
    }

    /* Platform binary: fast-allow */
    if (target->is_platform_binary) {
        printf("[AUTH-EXEC] verdict=ALLOW pid=%d path=%.*s%s (platform)\n",
               pid, (int)exe->path.length, exe->path.data, trunc);
        fflush(stdout);
        es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_ALLOW, false);
        es_release_message(msg);
        return;
    }

    /* Deny if process image was invalidated */
    if (ctx->cs_invalidated) {
        fprintf(stderr,
                "[ALERT] AUTH_EXEC DENY: cs_invalidated pid=%d path=%.*s%s ancestry=%s\n",
                pid, (int)exe->path.length, exe->path.data, trunc, ctx->ancestry);
        fflush(stderr);
        printf("[AUTH-EXEC] verdict=DENY pid=%d path=%.*s%s (cs_invalidated)\n",
               pid, (int)exe->path.length, exe->path.data, trunc);
        fflush(stdout);
        es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_DENY, false);
        es_release_message(msg);
        return;
    }

    /* Deny if CS_DEBUGGED */
    if (target->codesigning_flags & CS_DEBUGGED) {
        fprintf(stderr,
                "[ALERT] AUTH_EXEC DENY: CS_DEBUGGED pid=%d path=%.*s%s ancestry=%s\n",
                pid, (int)exe->path.length, exe->path.data, trunc, ctx->ancestry);
        fflush(stderr);
        printf("[AUTH-EXEC] verdict=DENY pid=%d path=%.*s%s (CS_DEBUGGED)\n",
               pid, (int)exe->path.length, exe->path.data, trunc);
        fflush(stdout);
        es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_DENY, false);
        es_release_message(msg);
        return;
    }

    printf("[AUTH-EXEC] verdict=ALLOW pid=%d path=%.*s%s ancestry=%s\n",
           pid, (int)exe->path.length, exe->path.data, trunc, ctx->ancestry);
    fflush(stdout);
    es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_ALLOW, false);
    es_release_message(msg);
}

/* ── AUTH_OPEN evaluator ──────────────────────────────────────────────────── */

static void evaluate_open_and_respond(auth_ctx_t *ctx)
{
    atomic_fetch_add(&g_total_evals, 1);

    const es_message_t *msg     = ctx->msg;
    const es_process_t *proc    = msg->process;
    pid_t pid = audit_token_to_pid(proc->audit_token);
    const es_file_t *file = msg->event.open.file;

    uint64_t now      = mach_absolute_time();
    uint64_t deadline = msg->deadline;

    if (now >= deadline ||
        (deadline - now) < MIN_WORK_BUDGET_MS * g_ticks_per_ms) {
        atomic_fetch_add(&g_deadline_misses, 1);
        fprintf(stderr, "[WARN] deadline-miss AUTH_OPEN pid=%d — allowing\n", pid);
        fflush(stderr);
        es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_ALLOW, false);
        es_release_message(msg);
        return;
    }

    /* Platform binary: fast-allow */
    if (proc->is_platform_binary) {
        es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_ALLOW, false);
        es_release_message(msg);
        return;
    }

    /* Read-only opens: allow */
    uint32_t fflag = msg->event.open.fflag;
    if ((fflag & O_ACCMODE) == O_RDONLY) {
        es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_ALLOW, false);
        es_release_message(msg);
        return;
    }

    /* Write open of sensitive path by non-platform process with no team_id */
    char path_buf[PATH_BUF];
    copy_str_token(path_buf, sizeof(path_buf), &file->path);

    if (is_sensitive_path(path_buf) &&
        !proc->is_platform_binary &&
        proc->team_id.length == 0) {
        fprintf(stderr,
                "[ALERT] AUTH_OPEN DENY: sensitive-write pid=%d path=%s%s ancestry=%s\n",
                pid, path_buf,
                file->path_truncated ? "...(truncated)" : "",
                ctx->ancestry);
        fflush(stderr);
        printf("[AUTH-OPEN] verdict=DENY pid=%d path=%s\n", pid, path_buf);
        fflush(stdout);
        es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_DENY, false);
        es_release_message(msg);
        return;
    }

    printf("[AUTH-OPEN] verdict=ALLOW pid=%d path=%s\n", pid, path_buf);
    fflush(stdout);
    es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_ALLOW, false);
    es_release_message(msg);
}

/* ── event handler ────────────────────────────────────────────────────────── */

static void handle_event(es_client_t *client __attribute__((unused)),
                         const es_message_t *msg)
{
    switch (msg->event_type) {

    /* ── NOTIFY_FORK ────────────────────────────────────────────────────── */
    case ES_EVENT_TYPE_NOTIFY_FORK: {
        const es_process_t *child = msg->event.fork.child;
        pid_t child_pid = audit_token_to_pid(child->audit_token);

        tree_node_t *n = tree_get_or_create(&child->audit_token, child_pid);
        if (!n) break;

        n->parent_token = msg->process->audit_token;
        copy_str_token(n->path, PATH_BUF, &msg->process->executable->path);
        break;
    }

    /* ── NOTIFY_EXEC ────────────────────────────────────────────────────── */
    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        const es_process_t *target = msg->event.exec.target;
        pid_t pid = audit_token_to_pid(target->audit_token);

        /* ── tree migration ── */
        tree_node_t *old = tree_find(&msg->process->audit_token);
        tree_node_t *n   = tree_get_or_create(&target->audit_token, pid);
        if (!n) {
            /* OOM: remove stale pre-exec entry so it doesn't leak.
             * EXIT delivers the final image token; this pre-exec token
             * would never be cleaned up otherwise. */
            if (old) tree_remove(&msg->process->audit_token);
            break;
        }

        if (old && old != n) {
            n->parent_token   = old->parent_token;
            n->cs_invalidated = old->cs_invalidated;
            tree_remove(&msg->process->audit_token);
        } else {
            n->parent_token = target->parent_audit_token;
        }
        copy_str_token(n->path, PATH_BUF, &target->executable->path);

        /* ── IDS state migration ── */
        proc_state_t *old_s = state_find(&msg->process->audit_token);
        proc_state_t *s     = state_get_or_create(&target->audit_token, pid);
        if (old_s) {
            if (s) {
                s->exec_count        = old_s->exec_count;
                s->exec_window_start = old_s->exec_window_start;
                s->wrote_tmp         = old_s->wrote_tmp;
            }
            /* Always remove old entry regardless of whether new alloc succeeded;
             * on OOM the counters are lost but the stale entry must not leak —
             * NOTIFY_EXIT only delivers the final image token, not pre-exec ones. */
            state_remove(&msg->process->audit_token);
        }
        if (s) {
            copy_str_token(s->path, PATH_BUF, &target->executable->path);
            rule_exec_chain(s);
            rule_sensitive_file_write(s);
        }

        /* ── log ── */
        char chain[ANCESTRY_STR_MAX];
        ancestry_str(n, chain, sizeof(chain));
        printf("[EXEC] ");
        print_path(target->executable);
        printf(" pid=%d chain=%s\n", pid, chain);
        fflush(stdout);
        break;
    }

    /* ── NOTIFY_EXIT ────────────────────────────────────────────────────── */
    case ES_EVENT_TYPE_NOTIFY_EXIT: {
        tree_remove(&msg->process->audit_token);
        state_remove(&msg->process->audit_token);
        break;
    }

    /* ── NOTIFY_WRITE ───────────────────────────────────────────────────── */
    case ES_EVENT_TYPE_NOTIFY_WRITE: {
        pid_t pid = audit_token_to_pid(msg->process->audit_token);
        proc_state_t *s = state_get_or_create(&msg->process->audit_token, pid);
        if (!s) break;
        const es_string_token_t *path = &msg->event.write.target->path;
        if (path_has_prefix(path, "/private/tmp"))
            s->wrote_tmp = 1;
        break;
    }

    /* ── NOTIFY_UIPC_CONNECT ────────────────────────────────────────────── */
    case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: {
        pid_t pid = audit_token_to_pid(msg->process->audit_token);
        proc_state_t *s = state_get_or_create(&msg->process->audit_token, pid);
        if (!s) break;
        const es_event_uipc_connect_t *ev = &msg->event.uipc_connect;
        if (ev->domain == AF_INET || ev->domain == AF_INET6) {
            time_t now = time(NULL);
            rule_fanout(s, now);
        }
        break;
    }

    /* ── NOTIFY_AUTHORIZATION_JUDGEMENT (Authorization Services / TCC) ─── */
    case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT: {
        pid_t pid = audit_token_to_pid(msg->process->audit_token);
        const es_event_authorization_judgement_t *ev =
            msg->event.authorization_judgement;

        if (!ev) break;

        for (size_t i = 0; i < ev->result_count; i++) {
            const es_authorization_result_t *r = &ev->results[i];
            if (!r->granted) continue;

            printf("[AUTH-JUDGEMENT] pid=%d right=%.*s\n",
                   pid,
                   (int)r->right_name.length, r->right_name.data);
            fflush(stdout);

            if (!msg->process->is_platform_binary) {
                /* TCC rights are prefixed "com.apple.TCC.kTCCService..." */
                static const char tcc_prefix[] = "com.apple.TCC.";
                size_t tcc_plen = sizeof(tcc_prefix) - 1;
                if (r->right_name.length > tcc_plen &&
                    memcmp(r->right_name.data, tcc_prefix, tcc_plen) == 0) {
                    /* Check if the service suffix matches a sensitive service */
                    const char *suffix_data = r->right_name.data + tcc_plen;
                    size_t suffix_len = r->right_name.length - tcc_plen;
                    for (const char **sv = g_tcc_sensitive; *sv; sv++) {
                        size_t svlen = strlen(*sv);
                        if (suffix_len == svlen &&
                            memcmp(suffix_data, *sv, svlen) == 0) {
                            fprintf(stderr,
                                    "[ALERT] TCC sensitive right=%.*s granted to "
                                    "non-platform pid=%d\n",
                                    (int)r->right_name.length,
                                    r->right_name.data, pid);
                            fflush(stderr);
                            break;
                        }
                    }
                }
            }
        }
        break;
    }

    /* ── NOTIFY_BTM_LAUNCH_ITEM_ADD ─────────────────────────────────────── */
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD: {
        const es_event_btm_launch_item_add_t *ev =
            msg->event.btm_launch_item_add;
        pid_t pid = audit_token_to_pid(msg->process->audit_token);

        char item_url_buf[PATH_BUF] = {0};
        const char *item_url = "(none)";
        if (ev->item && ev->item->item_url.length > 0) {
            copy_str_token(item_url_buf, sizeof(item_url_buf),
                           &ev->item->item_url);
            item_url = item_url_buf;
        }

        printf("[BTM-ADD] pid=%d url=%s\n", pid, item_url);
        fflush(stdout);

        /* Alert: non-platform registrar with no team_id */
        if (!msg->process->is_platform_binary &&
            msg->process->team_id.length == 0) {
            fprintf(stderr,
                    "[ALERT] BTM persistence: unsigned non-platform pid=%d url=%s\n",
                    pid, item_url);
            fflush(stderr);
        }
        break;
    }

    /* ── NOTIFY_BTM_LAUNCH_ITEM_REMOVE ──────────────────────────────────── */
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE: {
        const es_event_btm_launch_item_remove_t *ev =
            msg->event.btm_launch_item_remove;
        pid_t pid = audit_token_to_pid(msg->process->audit_token);

        char item_url_buf[PATH_BUF] = {0};
        const char *item_url = "(none)";
        if (ev->item && ev->item->item_url.length > 0) {
            copy_str_token(item_url_buf, sizeof(item_url_buf),
                           &ev->item->item_url);
            item_url = item_url_buf;
        }

        printf("[BTM-REMOVE] pid=%d url=%s\n", pid, item_url);
        fflush(stdout);
        break;
    }

    /* ── NOTIFY_CS_INVALIDATED ──────────────────────────────────────────── */
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: {
        pid_t pid = audit_token_to_pid(msg->process->audit_token);
        tree_node_t *n = tree_find(&msg->process->audit_token);
        if (n) n->cs_invalidated = 1;

        fprintf(stderr,
                "[ALERT] CS_INVALIDATED pid=%d path=%.*s\n",
                pid,
                (int)msg->process->executable->path.length,
                msg->process->executable->path.data);
        fflush(stderr);
        printf("[CS-INVALIDATED] pid=%d path=%.*s\n",
               pid,
               (int)msg->process->executable->path.length,
               msg->process->executable->path.data);
        fflush(stdout);
        break;
    }

    /* ── AUTH_EXEC ──────────────────────────────────────────────────────── */
    case ES_EVENT_TYPE_AUTH_EXEC: {
        auth_ctx_t *ctx = calloc(1, sizeof(*ctx));
        if (!ctx) {
            /* Allocation failure: deny conservatively */
            es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_DENY, false);
            break;
        }

        /* Snapshot tree state on the ES queue before dispatch */
        tree_node_t *n = tree_find(&msg->process->audit_token);
        if (n) {
            ancestry_str(n, ctx->ancestry, sizeof(ctx->ancestry));
            ctx->cs_invalidated = n->cs_invalidated;
        }

        es_retain_message(msg);
        ctx->msg = (es_message_t *)(uintptr_t)msg;

        dispatch_async(g_work_queue, ^{
            evaluate_exec_and_respond(ctx);
            free(ctx);
        });
        break;
    }

    /* ── AUTH_OPEN ──────────────────────────────────────────────────────── */
    case ES_EVENT_TYPE_AUTH_OPEN: {
        auth_ctx_t *ctx = calloc(1, sizeof(*ctx));
        if (!ctx) {
            es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_ALLOW, false);
            break;
        }

        tree_node_t *n = tree_find(&msg->process->audit_token);
        if (n) {
            ancestry_str(n, ctx->ancestry, sizeof(ctx->ancestry));
            ctx->cs_invalidated = n->cs_invalidated;
        }

        es_retain_message(msg);
        ctx->msg = (es_message_t *)(uintptr_t)msg;

        dispatch_async(g_work_queue, ^{
            evaluate_open_and_respond(ctx);
            free(ctx);
        });
        break;
    }

    default:
        break;
    }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
    init_timebase();

    g_main_queue = dispatch_get_main_queue();
    g_work_queue = dispatch_queue_create("argus.unified.work",
                                         DISPATCH_QUEUE_CONCURRENT);

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
            reason = "grant Full Disk Access in System Settings -> Privacy & Security"; break;
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
                fprintf(stderr, "warning: failed to mute self\n");
        } else {
            fprintf(stderr, "warning: task_info failed — could not mute self\n");
        }
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
        ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT, /* closest available to TCC on this SDK */
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN,
    };

    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    fprintf(stderr, "unified-agent: running — Ctrl-C to stop\n");
    fflush(stderr);

    dispatch_main();
    return 0;
}
