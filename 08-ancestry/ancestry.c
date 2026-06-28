/*
 * ancestry.c — Endpoint Security process provenance tracker
 *              (ebpf101 ch22/iter analog for macOS)
 *
 * ch07-ids knew parent_audit_token per event but couldn't look up ancestors —
 * there was no table of live processes. This chapter builds that table.
 *
 * Subscribes to NOTIFY_FORK, NOTIFY_EXEC, and NOTIFY_EXIT. Maintains a
 * hash table of every live process with its parent_audit_token and executable
 * path. On each EXEC event, walks the ancestor chain and:
 *
 *   - Prints the full provenance line:
 *       launchd(1) → bash(1234) → curl(5678) /usr/bin/curl
 *
 *   - Fires rule_suspicious_ancestry() if a download/script tool is launched
 *     from a browser or script interpreter parent chain.
 *
 * Key concepts introduced over ch07:
 *   - NOTIFY_FORK as the anchor for parent→child linkage. By the time EXEC
 *     fires, the parent may already have exited in a fork+exec pattern — the
 *     FORK event is the only reliable point to capture the relationship.
 *   - Incomplete-tree startup: processes already running at subscribe time
 *     have no FORK event. ancestry_str() labels missing nodes "(unknown)".
 *   - Parent token lookup vs ppid: parent_audit_token is PID-reuse-safe;
 *     a ppid-keyed table would misidentify recycled PIDs.
 *   - Depth cap: unbounded ancestor walks can loop in adversarial scenarios
 *     (a process whose recorded parent token points back to itself via a
 *     stale entry). Cap at ANCESTRY_DEPTH_MAX and stop.
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./ancestry
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── constants ────────────────────────────────────────────────────────────── */

#define TREE_BUCKETS        256
#define PATH_BUF            512
#define ANCESTRY_DEPTH_MAX  8    /* max hops walked; prevents loops on stale entries */
#define ANCESTRY_STR_MAX    1024 /* output buffer for the full chain string */

/* ── process tree node ────────────────────────────────────────────────────── */

typedef struct tree_node {
    audit_token_t   token;               /* key — generation-safe process identity */
    audit_token_t   parent_token;        /* parent's token at fork time */
    pid_t           pid;
    char            path[PATH_BUF];      /* current executable path */
    struct tree_node *next;              /* hash chain */
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

/* ── globals ──────────────────────────────────────────────────────────────── */

static es_client_t     *g_client     = NULL;
static dispatch_queue_t g_main_queue = NULL;
static atomic_int       g_stop       = 0;

/* ── shutdown ─────────────────────────────────────────────────────────────── */

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

/* ── helpers ──────────────────────────────────────────────────────────────── */

static void copy_str_token(char *buf, size_t bufsz, const es_string_token_t *s)
{
    if (!s || !s->data || s->length == 0) { buf[0] = '\0'; return; }
    size_t n = s->length < bufsz - 1 ? s->length : bufsz - 1;
    memcpy(buf, s->data, n);
    buf[n] = '\0';
}

/* Copy a process's executable path, tolerating a NULL executable pointer.
 * ES populates executable for FORK/EXEC in practice, but guarding keeps the
 * derefs at the call sites from being load-bearing. */
static void copy_exec_path(char *buf, size_t bufsz, const es_process_t *proc)
{
    if (proc && proc->executable)
        copy_str_token(buf, bufsz, &proc->executable->path);
    else
        buf[0] = '\0';
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
 * Returns the leaf component of a null-terminated path string (the part after
 * the last '/'). Returns the full string if no '/' is present.
 */
static const char *leaf(const char *path)
{
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

/* ── ancestry ─────────────────────────────────────────────────────────────── */

/*
 * Build "launchd(1) → bash(1234) → start_name(pid)" into buf.
 * Missing ancestors (pre-subscribe processes) are labeled "(unknown)".
 * Capped at ANCESTRY_DEPTH_MAX hops to prevent loops on stale entries.
 */
static void ancestry_str(const tree_node_t *start, char *buf, size_t bufsz)
{
    /*
     * Collect ancestors into a stack so we can print root-first (left to right).
     * Skip the walk when start is launchd (self-parent sentinel) to avoid
     * printing "launchd → launchd". Set missing_root if a parent entry is absent.
     */
    const tree_node_t *stack[ANCESTRY_DEPTH_MAX];
    int depth = 0;
    int missing_root = 0; /* set if walk ends at a missing table entry */

    if (!token_eq(&start->token, &start->parent_token)) {
        const audit_token_t *cur = &start->parent_token;
        for (int i = 0; i < ANCESTRY_DEPTH_MAX; i++) {
            tree_node_t *anc = tree_find(cur);
            if (!anc) { missing_root = 1; break; }
            stack[depth++] = anc;
            /* launchd has itself as parent — this is the root of the tree */
            if (token_eq(&anc->token, &anc->parent_token)) break;
            cur = &anc->parent_token;
        }
    }

    size_t pos = 0;

    /* Prefix only on a missing entry, not on depth==0 — that also covers
     * the launchd case where the self-parent sentinel skipped the walk. */
    /*
     * snprintf returns the would-be length, which exceeds the space written
     * when output is truncated. Clamp pos to bufsz - 1 (the '\0' position)
     * after every advance so bufsz - pos never underflows.
     */
    if (missing_root) {
        int rc = snprintf(buf + pos, bufsz - pos, "(unknown) → ");
        if (rc > 0) {
            pos += (size_t)rc;
            if (pos >= bufsz) pos = bufsz - 1;
        }
    }

    /* Print oldest ancestor first */
    for (int i = depth - 1; i >= 0 && pos < bufsz - 1; i--) {
        int rc = snprintf(buf + pos, bufsz - pos,
                          "%s(%d) → ",
                          leaf(stack[i]->path), stack[i]->pid);
        if (rc < 0) break;
        pos += (size_t)rc;
        if (pos >= bufsz) { pos = bufsz - 1; break; }
    }

    /* Append the process itself (skip if the buffer is already full) */
    if (pos < bufsz - 1)
        snprintf(buf + pos, bufsz - pos, "%s(%d)", leaf(start->path), start->pid);
}

/* ── rules ────────────────────────────────────────────────────────────────── */

/*
 * Leaf names of processes considered download/execution tools.
 * Seeing these spawned from a browser or script interpreter is suspicious.
 */
static const char *g_download_tools[] = {
    "curl", "wget", "python", "python3", "ruby", "perl",
    "osascript", "bash", "sh", "zsh", "nc", "ncat",
    NULL,
};

/*
 * Leaf name substrings of known browser processes. Substring match because
 * browser helpers appear as "Google Chrome Helper", "firefox", etc.
 */
static const char *g_browser_patterns[] = {
    "Safari", "firefox", "Chrome", "Chromium", "Brave", "Arc",
    "Opera", "webkit", "WebContent",
    NULL,
};

static int str_contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

/*
 * Walk the ancestor chain of `node`. If any ancestor's leaf name matches a
 * browser pattern, fire an alert.
 */
static void rule_suspicious_ancestry(const tree_node_t *node,
                                     const char *chain)
{
    /* Only check download/execution tools */
    const char *name = leaf(node->path);
    int is_download_tool = 0;
    for (const char **t = g_download_tools; *t; t++) {
        if (strcmp(name, *t) == 0) { is_download_tool = 1; break; }
    }
    if (!is_download_tool) return;

    /* Walk ancestors looking for a browser */
    const audit_token_t *cur = &node->parent_token;
    for (int i = 0; i < ANCESTRY_DEPTH_MAX; i++) {
        tree_node_t *anc = tree_find(cur);
        if (!anc) break;
        const char *anc_name = leaf(anc->path);
        for (const char **pat = g_browser_patterns; *pat; pat++) {
            if (str_contains(anc_name, *pat)) {
                fprintf(stderr,
                        "[ALERT] browser-spawned-tool: %s launched from browser "
                        "ancestor %s(%d)\n  chain: %s\n",
                        name, anc_name, anc->pid, chain);
                fflush(stderr);
                return;
            }
        }
        if (token_eq(&anc->token, &anc->parent_token)) break;
        cur = &anc->parent_token;
    }
}

/* ── event handler ────────────────────────────────────────────────────────── */

static void handle_event(es_client_t *client __attribute__((unused)),
                         const es_message_t *msg)
{
    switch (msg->event_type) {

    case ES_EVENT_TYPE_NOTIFY_FORK: {
        /*
         * FORK is the canonical moment to record the parent→child link.
         * By the time EXEC fires for the child, the parent may have already
         * exited (in a fork+exec pattern the shell does). Recording here
         * ensures the parent token is captured while the parent is still live.
         */
        const es_process_t *child  = msg->event.fork.child;
        pid_t child_pid = audit_token_to_pid(child->audit_token);

        tree_node_t *n = tree_get_or_create(&child->audit_token, child_pid);
        if (!n) break;

        n->parent_token = msg->process->audit_token;
        /* Path is not yet known for the child — it inherits the parent image
         * until EXEC replaces it. Copy parent path as a placeholder. */
        copy_exec_path(n->path, PATH_BUF, msg->process);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        /*
         * On exec, the audit_token generation counter increments. The new
         * token is in target->audit_token; msg->process->audit_token is the
         * pre-exec (now-stale) token.
         *
         * Migrate the tree node: find the old entry, create the new one,
         * carry the parent link across, then remove the old entry. This is
         * the same migration pattern as ch07-ids for the same reason: without
         * it the ancestry walk breaks after the first exec.
         */
        const es_process_t *target = msg->event.exec.target;
        pid_t pid = audit_token_to_pid(target->audit_token);

        tree_node_t *old = tree_find(&msg->process->audit_token);

        tree_node_t *n = tree_get_or_create(&target->audit_token, pid);
        if (!n) {
            /* OOM: still remove the stale pre-exec node. NOTIFY_EXIT only
             * delivers the post-exec token, so an unremoved pre-exec entry
             * leaks permanently and its stale parent_token pollutes later walks. */
            if (old) tree_remove(&msg->process->audit_token);
            break;
        }

        if (old && old != n) {
            /* Normal exec migration: carry parent link forward, free stale entry.
             * Guard old != n: equal tokens mean tree_remove would free n itself. */
            n->parent_token = old->parent_token;
            tree_remove(&msg->process->audit_token);
        } else {
            /* No FORK observed (process was already running at subscribe time),
             * or pre/post tokens are equal. Use ES's parent_audit_token as fallback. */
            n->parent_token = target->parent_audit_token;
        }

        copy_exec_path(n->path, PATH_BUF, target);

        /* Build and print the ancestry chain */
        char chain[ANCESTRY_STR_MAX];
        ancestry_str(n, chain, sizeof(chain));

        printf("[EXEC] ");
        print_path(target->executable);
        printf("(%d)  chain: %s\n", pid, chain);
        fflush(stdout);

        rule_suspicious_ancestry(n, chain);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_EXIT: {
        tree_remove(&msg->process->audit_token);
        break;
    }

    default:
        break;
    }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

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
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    };

    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("ancestry: tracking process provenance — Ctrl-C to stop\n");
    fflush(stdout);

    dispatch_main();
    return 0;
}
