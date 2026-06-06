/*
 * ids.c — Endpoint Security rule-based IDS (ebpf101 ch23 analog for macOS)
 *
 * "Dumb ES tap, smart C user-space rule engine."
 *
 * Subscribes to NOTIFY_EXEC, NOTIFY_WRITE, and NOTIFY_UIPC_CONNECT. Accumulates
 * per-process state in a hash table keyed by audit_token (generation-safe). On
 * each event, stateful rules fire if their conditions are met:
 *
 *   RULE 1 — suspicious-port:  scaffolding for C2 port detection (4444, 31337,
 *             6667, 50050). Requires a remote port, which ES does not provide in
 *             NOTIFY_UIPC_CONNECT. Needs dtrace or NEFilterDataProvider to supply
 *             port data. Not currently active.
 *   RULE 2 — unsigned-then-connect: alert when a non-platform binary that wrote
 *             to /tmp (or /private/tmp) subsequently opens a network connection
 *   RULE 3 — exec-chain:  alert when a process execs more than 3 times in 5 s
 *             (snapd-style launcher / dropper indicator)
 *   RULE 4 — beaconing:   alert when a process opens INET connections at a
 *             suspiciously regular interval (all inter-arrival gaps within ±30%
 *             of their mean, minimum 5 samples). Detected entirely from
 *             NOTIFY_UIPC_CONNECT timestamps — no remote address needed.
 *   RULE 5 — fan-out:     alert when a process opens more than 10 INET
 *             connections in 30 s (scanner / lateral-movement indicator)
 *
 * Output: human-readable alerts to stderr, JSON event log to stdout.
 *
 * Requires:
 *   - Root (sudo)
 *   - com.apple.developer.endpoint-security.client entitlement
 *   - Full Disk Access for the terminal
 *
 * Build:  make
 * Run:    sudo ./ids
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

/* ── constants ────────────────────────────────────────────────────────────── */

#define STATE_TABLE_BUCKETS  256
#define PATH_BUF             512
#define EXEC_CHAIN_LIMIT     3
#define EXEC_CHAIN_WINDOW_S  5

/* Rule 4 — beaconing */
#define BEACON_RING_SIZE     8   /* timestamps kept per process */
#define BEACON_MIN_SAMPLES   5   /* minimum gaps required to fire */
#define BEACON_VARIANCE_PCT  30  /* gap must be within ±30 % of mean */

/* Rule 5 — fan-out */
#define FANOUT_LIMIT         10  /* distinct INET connects to trigger */
#define FANOUT_WINDOW_S      30  /* rolling window in seconds */

/* Rule 1 scaffolding: C2 ports for future integration with a port data source */
static const uint16_t g_suspicious_ports[] = { 4444, 31337, 6667, 50050, 0 };

/* ── per-process state ────────────────────────────────────────────────────── */

typedef struct proc_state {
    audit_token_t   token;          /* key */
    pid_t           pid;
    char            path[PATH_BUF]; /* executable path at first exec */
    int             wrote_tmp;      /* 1 if process wrote to /tmp */
    int             is_platform;

    /* Rule 3 — exec-chain */
    uint32_t        exec_count;
    time_t          exec_window_start;

    /* Rule 4 — beaconing: ring buffer of the last BEACON_RING_SIZE INET connect times */
    time_t          beacon_ring[BEACON_RING_SIZE];
    uint32_t        beacon_head;    /* next write index */
    uint32_t        beacon_fill;    /* how many slots are populated */

    /* Rule 5 — fan-out: rolling count of INET connects */
    uint32_t        inet_count;
    time_t          inet_window_start;

    struct proc_state *next;        /* hash chain */
} proc_state_t;

static proc_state_t *g_table[STATE_TABLE_BUCKETS];

/*
 * Stable hash over the raw bytes of an audit_token_t.
 */
static uint32_t token_hash(const audit_token_t *tok)
{
    const uint8_t *b = (const uint8_t *)tok;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < sizeof(*tok); i++) {
        h ^= b[i];
        h *= 16777619u;
    }
    return h % STATE_TABLE_BUCKETS;
}

static int token_eq(const audit_token_t *a, const audit_token_t *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

static proc_state_t *state_find(const audit_token_t *tok)
{
    uint32_t idx = token_hash(tok);
    for (proc_state_t *s = g_table[idx]; s; s = s->next)
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

    s->token = *tok;
    s->pid   = pid;
    s->exec_window_start = time(NULL);

    uint32_t idx = token_hash(tok);
    s->next = g_table[idx];
    g_table[idx] = s;
    return s;
}

static void state_remove(const audit_token_t *tok)
{
    uint32_t idx = token_hash(tok);
    proc_state_t **pp = &g_table[idx];
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
    if (!s || !s->data || s->length == 0) {
        buf[0] = '\0';
        return;
    }
    size_t n = s->length < bufsz - 1 ? s->length : bufsz - 1;
    memcpy(buf, s->data, n);
    buf[n] = '\0';
}

static int path_has_prefix(const es_string_token_t *path, const char *prefix)
{
    if (!path || !path->data) return 0;
    size_t plen = strlen(prefix);
    if (path->length < plen || memcmp(path->data, prefix, plen) != 0)
        return 0;
    /* require separator so /tmpfile does not match /tmp;
     * plen==1 means prefix is "/" — any absolute path matches */
    return path->length == plen || path->data[plen] == '/' || plen == 1;
}

/* ── alert / JSON output ──────────────────────────────────────────────────── */

/* Write src to buf as a JSON string value (no surrounding quotes), escaping
 * backslash, double-quote, and control characters. Returns bytes written. */
static size_t json_escape(char *buf, size_t bufsz, const char *src)
{
    size_t n = 0;
    for (; *src && n + 6 < bufsz; src++) {
        unsigned char c = (unsigned char)*src;
        if (c == '\\' || c == '"') {
            buf[n++] = '\\';
            buf[n++] = (char)c;
        } else if (c < 0x20) {
            n += (size_t)snprintf(buf + n, bufsz - n, "\\u%04x", c);
        } else {
            buf[n++] = (char)c;
        }
    }
    if (n < bufsz) buf[n] = '\0';
    return n;
}

static void emit_alert(pid_t pid, const char *rule, const char *detail)
{
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm = gmtime_r(&now, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);

    /* Human-readable alert on stderr */
    fprintf(stderr, "[ALERT] %s rule=%s pid=%-6d %s\n", ts, rule, pid, detail);
    fflush(stderr);

    /* JSON event record on stdout — escape detail to guard against path injection */
    char escaped[512];
    json_escape(escaped, sizeof(escaped), detail);
    printf("{\"ts\":\"%s\",\"rule\":\"%s\",\"pid\":%d,\"detail\":\"%s\"}\n",
           ts, rule, pid, escaped);
    fflush(stdout);
}

/* ── rules ────────────────────────────────────────────────────────────────── */

/*
 * Scaffolding for Rule 1. Not called from the event handler — ES does not
 * deliver the remote port in NOTIFY_UIPC_CONNECT. Activate by wiring in a
 * port source (dtrace socket probe or NEFilterDataProvider) and calling this
 * from handle_event with the resolved port.
 */
static void rule_suspicious_port(pid_t pid, uint16_t port, const char *path)
    __attribute__((unused));
static void rule_suspicious_port(pid_t pid, uint16_t port, const char *path)
{
    for (const uint16_t *p = g_suspicious_ports; *p != 0; p++) {
        if (*p == port) {
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "connect to suspicious port %u path=%s", port, path);
            emit_alert(pid, "suspicious-port", detail);
            return;
        }
    }
}

static void rule_unsigned_then_connect(proc_state_t *s)
{
    if (s->is_platform) return;
    if (!s->wrote_tmp)  return;
    char detail[256];
    snprintf(detail, sizeof(detail),
             "unsigned binary wrote /tmp then opened INET connection path=%s",
             s->path);
    emit_alert(s->pid, "unsigned-then-connect", detail);
}

static void rule_exec_chain(proc_state_t *s)
{
    time_t now = time(NULL);

    /*
     * Guard against clock step-backs (NTP slew, VM resume): if now is before
     * exec_window_start, the subtraction underflows to a large positive value
     * when cast to unsigned, or a large negative signed value — either way the
     * comparison is unreliable. Reset the window conservatively.
     */
    if (now < s->exec_window_start ||
        now - s->exec_window_start > EXEC_CHAIN_WINDOW_S) {
        s->exec_count        = 1;
        s->exec_window_start = now;
        return;
    }

    s->exec_count++;
    if (s->exec_count > EXEC_CHAIN_LIMIT) {
        time_t elapsed = now - s->exec_window_start;
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "%u execs in %lus path=%s",
                 s->exec_count,
                 (unsigned long)elapsed,
                 s->path);
        emit_alert(s->pid, "exec-chain", detail);
        /* Reset so the next window crossing emits exactly one alert, not one per exec */
        s->exec_count        = 0;
        s->exec_window_start = now;
    }
}

/*
 * Rule 4 — beaconing.
 *
 * Records the current time into a ring buffer. Once BEACON_MIN_SAMPLES+1
 * timestamps are present, extracts the N inter-arrival gaps and checks whether
 * all are within BEACON_VARIANCE_PCT% of their mean. A tight cluster of gaps
 * (low variance) is the hallmark of an automated C2 beacon.
 *
 * Integer arithmetic only: mean = sum_of_gaps / N; tolerance = mean * PCT / 100.
 * Each gap must satisfy: |gap - mean| <= tolerance.
 */
static void rule_beaconing(proc_state_t *s, time_t now)
{
    /* Record timestamp into ring */
    s->beacon_ring[s->beacon_head] = now;
    s->beacon_head = (s->beacon_head + 1) % BEACON_RING_SIZE;
    if (s->beacon_fill < BEACON_RING_SIZE)
        s->beacon_fill++;

    uint32_t n = s->beacon_fill;
    if (n < BEACON_MIN_SAMPLES + 1)
        return; /* need at least min_samples+1 timestamps for min_samples gaps */

    /*
     * Reconstruct ordered timestamps from the ring. beacon_head points to the
     * oldest slot (the one just overwritten). Walk from oldest to newest.
     */
    time_t ts[BEACON_RING_SIZE];
    for (uint32_t i = 0; i < n; i++)
        ts[i] = s->beacon_ring[(s->beacon_head + i) % BEACON_RING_SIZE];

    /* Compute gaps and their sum */
    time_t gaps[BEACON_RING_SIZE - 1];
    time_t sum = 0;
    for (uint32_t i = 0; i < n - 1; i++) {
        gaps[i] = ts[i + 1] - ts[i];
        if (gaps[i] < 0) return; /* clock stepped back; skip */
        sum += gaps[i];
    }
    uint32_t ng = n - 1;
    if (sum == 0) return; /* all same second; degenerate */

    time_t mean = sum / (time_t)ng;
    time_t tol  = mean * BEACON_VARIANCE_PCT / 100;

    for (uint32_t i = 0; i < ng; i++) {
        time_t dev = gaps[i] - mean;
        if (dev < 0) dev = -dev;
        if (dev > tol) return; /* gap too irregular */
    }

    char detail[256];
    snprintf(detail, sizeof(detail),
             "%u INET connects at ~%lds intervals path=%s",
             ng + 1, (long)mean, s->path);
    emit_alert(s->pid, "beaconing", detail);

    /* Clear the ring so we don't re-fire on every subsequent connect */
    s->beacon_fill = 0;
    s->beacon_head = 0;
}

/*
 * Rule 5 — fan-out.
 *
 * Counts INET/INET6 connections in a rolling window. Resets the counter when
 * the window expires (same pattern as exec-chain). Fires once per window
 * crossing to avoid alert floods.
 */
static void rule_fanout(proc_state_t *s, time_t now)
{
    if (now < s->inet_window_start ||
        now - s->inet_window_start > FANOUT_WINDOW_S) {
        s->inet_count        = 1;
        s->inet_window_start = now;
        return;
    }

    s->inet_count++;
    if (s->inet_count > FANOUT_LIMIT) {
        time_t elapsed = now - s->inet_window_start;
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "%u INET connects in %lus path=%s",
                 s->inet_count, (unsigned long)elapsed, s->path);
        emit_alert(s->pid, "fan-out", detail);
        s->inet_count        = 0;
        s->inet_window_start = now;
    }
}

/* ── event handler ────────────────────────────────────────────────────────── */

static void handle_event(es_client_t *client __attribute__((unused)),
                         const es_message_t *msg)
{
    switch (msg->event_type) {

    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        const es_process_t *target = msg->event.exec.target;
        pid_t pid = audit_token_to_pid(target->audit_token);

        /*
         * audit_token_t changes generation on every execve(). Creating separate
         * table entries for the pre- and post-exec tokens causes two problems:
         *
         *   1. The exec-chain counter never accumulates — each exec allocates a
         *      fresh entry with exec_count=0, so the limit of 3 is unreachable.
         *   2. The pre-exec entry is never cleaned up — NOTIFY_EXIT fires with
         *      the final image's token, so every intermediate image leaks a
         *      proc_state_t for the lifetime of the monitor.
         *
         * Solution: migrate. On NOTIFY_EXEC, copy the accumulated counters from
         * the old (pre-exec) entry into the new (post-exec) entry, then remove
         * the old entry. All subsequent WRITE and CONNECT events arrive with the
         * post-exec token (msg->process->audit_token of the running process),
         * which now matches the migrated entry. NOTIFY_EXIT removes the final
         * entry when the process terminates.
         */
        proc_state_t *old = state_find(&msg->process->audit_token);

        proc_state_t *s = state_get_or_create(&target->audit_token, pid);
        if (!s) break;

        /* Carry counters forward across the exec boundary */
        if (old) {
            s->exec_count        = old->exec_count;
            s->exec_window_start = old->exec_window_start;
            s->wrote_tmp         = old->wrote_tmp;
            state_remove(&msg->process->audit_token);
        }

        s->is_platform = target->is_platform_binary;
        copy_str_token(s->path, PATH_BUF, &target->executable->path);

        rule_exec_chain(s);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_WRITE: {
        pid_t pid = audit_token_to_pid(msg->process->audit_token);
        proc_state_t *s = state_get_or_create(&msg->process->audit_token, pid);
        if (!s) break;

        /*
         * Update is_platform from the live event — corrects the startup race
         * where a process was already running before the IDS subscribed and
         * never delivered a NOTIFY_EXEC (leaving is_platform=0 by default).
         */
        s->is_platform = msg->process->is_platform_binary;

        const es_string_token_t *path = &msg->event.write.target->path;
        /*
         * ES resolves symlinks before populating es_file_t.path, so /tmp
         * (a symlink to /private/tmp on macOS) is always delivered as
         * /private/tmp/... — the /tmp prefix never matches and is omitted.
         */
        if (path_has_prefix(path, "/private/tmp"))
            s->wrote_tmp = 1;
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: {
        pid_t pid = audit_token_to_pid(msg->process->audit_token);
        proc_state_t *s = state_get_or_create(&msg->process->audit_token, pid);
        if (!s) break;

        s->is_platform = msg->process->is_platform_binary;

        const es_event_uipc_connect_t *ev = &msg->event.uipc_connect;

        /*
         * es_event_uipc_connect_t carries domain/type/protocol and the socket
         * file path (for AF_UNIX only). The remote sockaddr is not available —
         * ES does not provide it. Rule 1 (suspicious-port) is scaffolded but
         * inactive until a source supplying the remote port (dtrace,
         * NEFilterDataProvider) is integrated.
         *
         * Rule 2 fires on any INET/INET6 connect from a suspicious process.
         */
        if (ev->domain == AF_INET || ev->domain == AF_INET6) {
            time_t now = time(NULL);
            rule_unsigned_then_connect(s);
            rule_beaconing(s, now);
            rule_fanout(s, now);
        }
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_EXIT: {
        state_remove(&msg->process->audit_token);
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
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    };

    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    fprintf(stderr, "ids: monitoring exec/write/connect — alerts on stderr, JSON on stdout — Ctrl-C to stop\n");
    fflush(stderr);

    dispatch_main();
    return 0;
}
