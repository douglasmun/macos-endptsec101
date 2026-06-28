/*
 * 15-deferred-auth — deadline-aware deferred AUTH_EXEC using es_retain_message.
 *
 * Key concept: the ES handler returns immediately after retaining the message.
 * All policy evaluation happens on a concurrent background queue. The response
 * is called from the background queue before the kernel deadline expires.
 *
 * es_respond_auth_result is safe to call from any thread.
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <inttypes.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CS flag not always exposed in public headers */
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000
#endif

/* Minimum time budget before we refuse to even start evaluating */
#define MIN_WORK_BUDGET_MS 100ULL

/* ---- globals ------------------------------------------------------------ */

static es_client_t        *g_client      = NULL;
static dispatch_queue_t    g_main_queue  = NULL;
static dispatch_queue_t    g_work_queue  = NULL;
static volatile atomic_int g_running     = 1;

static uint64_t            g_ticks_per_ms = 0;

static _Atomic uint64_t    g_total_evals    = 0;
static _Atomic uint64_t    g_deadline_misses = 0;

/* ---- timebase ----------------------------------------------------------- */

static void init_timebase(void)
{
    mach_timebase_info_data_t info;
    mach_timebase_info(&info);
    /* ticks_per_ms = (1e6 * denom) / numer */
    g_ticks_per_ms = (uint64_t)(1000000ULL * info.denom / info.numer);
}

/* ---- helpers ------------------------------------------------------------ */

static void print_cdhash(const uint8_t *cdhash)
{
    for (int i = 0; i < 20; i++) {
        printf("%02x", cdhash[i]);
    }
}

/* ---- policy ------------------------------------------------------------- */

static es_auth_result_t evaluate_policy(const es_process_t *target)
{
    pid_t pid = audit_token_to_pid(target->audit_token);
    const es_file_t *exe = target->executable;
    const char *trunc = exe->path_truncated ? "...(truncated)" : "";

    /* Fast-allow platform binaries */
    if (target->is_platform_binary) {
        printf("[DEFERRED-AUTH] pid=%d path=%.*s%s verdict=ALLOW (platform) cdhash=",
               pid,
               (int)exe->path.length, exe->path.data, trunc);
        print_cdhash(target->cdhash);
        printf("\n");
        fflush(stdout);
        return ES_AUTH_RESULT_ALLOW;
    }

    /* Deny debugged binaries */
    if (target->codesigning_flags & CS_DEBUGGED) {
        printf("[DEFERRED-AUTH] pid=%d path=%.*s%s verdict=DENY (CS_DEBUGGED) cdhash=",
               pid,
               (int)exe->path.length, exe->path.data, trunc);
        print_cdhash(target->cdhash);
        printf("\n");
        fflush(stdout);
        fprintf(stderr, "[ALERT] CS_DEBUGGED binary blocked: pid=%d path=%.*s%s\n",
                pid,
                (int)exe->path.length, exe->path.data, trunc);
        return ES_AUTH_RESULT_DENY;
    }

    printf("[DEFERRED-AUTH] pid=%d path=%.*s%s verdict=ALLOW cdhash=",
           pid,
           (int)exe->path.length, exe->path.data, trunc);
    print_cdhash(target->cdhash);
    printf("\n");
    fflush(stdout);
    return ES_AUTH_RESULT_ALLOW;
}

/* ---- deferred evaluator ------------------------------------------------- */

static void evaluate_and_respond(const es_message_t *msg)
{
    atomic_fetch_add(&g_total_evals, 1);

    const es_process_t *target = msg->event.exec.target;
    pid_t pid = audit_token_to_pid(target->audit_token);

    /* Check deadline before doing any work */
    uint64_t now      = mach_absolute_time();
    uint64_t deadline = msg->deadline;

    if (now >= deadline ||
        (deadline - now) < MIN_WORK_BUDGET_MS * g_ticks_per_ms) {
        atomic_fetch_add(&g_deadline_misses, 1);
        fprintf(stderr, "[WARN] deadline-miss: pid=%d — denying\n", pid);
        es_respond_auth_result(g_client, msg, ES_AUTH_RESULT_DENY, false);
        es_release_message(msg);
        return;
    }

    /*
     * In a real implementation this is where you would:
     *   - open(target->executable->path.data) + read + hash
     *   - consult a policy database
     *   - do signature verification
     * Here we demonstrate the skeleton with a lightweight check.
     */
    es_auth_result_t verdict = evaluate_policy(target);

    /*
     * Respond BEFORE releasing. After es_respond_auth_result returns, ES may
     * free the kernel-side message. We then release our retain.
     */
    es_respond_auth_result(g_client, msg, verdict, false);
    es_release_message(msg);
}

/* ---- signal handling ---------------------------------------------------- */

static void do_shutdown(void *ctx)
{
    (void)ctx;

    uint64_t evals  = atomic_load(&g_total_evals);
    uint64_t misses = atomic_load(&g_deadline_misses);
    printf("\n[deferred-auth] shutting down — evals=%" PRIu64
           " deadline-misses=%" PRIu64 "\n",
           evals, misses);
    fflush(stdout);

    /*
     * Drain in-flight deferred AUTH workers before tearing down the client.
     * Workers on the concurrent g_work_queue call es_respond_auth_result(g_client,
     * ...) and es_release_message(); deleting the client while one is in flight is
     * a use-after-free. The barrier waits for all queued/running blocks to finish.
     */
    if (g_work_queue)
        dispatch_barrier_sync(g_work_queue, ^{});

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
    atomic_store(&g_running, 0);
    dispatch_async_f(g_main_queue, NULL, do_shutdown);
}

/* ---- ES handler --------------------------------------------------------- */

static void handle_event(es_client_t *client, const es_message_t *msg)
{
    (void)client;

    switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
        /*
         * Retain the message so it remains valid after this callback returns.
         * The background block owns the retain; evaluate_and_respond releases it.
         */
        es_retain_message(msg);
        dispatch_async(g_work_queue, ^{
            evaluate_and_respond(msg);
        });
        /* Return immediately — ES serial queue is now free for the next event */
        break;

    default:
        break;
    }
}

/* ---- main --------------------------------------------------------------- */

int main(void)
{
    init_timebase();

    g_main_queue = dispatch_get_main_queue();
    g_work_queue = dispatch_queue_create("endptsec.deferred",
                                         DISPATCH_QUEUE_CONCURRENT);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    /* Create ES client */
    es_new_client_result_t res = es_new_client(&g_client,
        ^(es_client_t *c, const es_message_t *m) {
            handle_event(c, m);
        });

    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es_new_client failed: %d\n", res);
        return 1;
    }

    /* Mute self — fatal if we cannot prevent feedback loop on the work queue */
    audit_token_t self_token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                  (task_info_t)&self_token, &count) != KERN_SUCCESS) {
        fprintf(stderr, "task_info failed — cannot self-mute, aborting\n");
        es_delete_client(g_client);
        return 1;
    }
    if (es_mute_process(g_client, &self_token) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_mute_process failed — cannot self-mute, aborting\n");
        es_delete_client(g_client);
        return 1;
    }

    /* Subscribe */
    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
    es_return_t sub = es_subscribe(g_client, events,
                                   sizeof(events) / sizeof(events[0]));
    if (sub != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed: %d\n", sub);
        es_delete_client(g_client);
        return 1;
    }

    printf("[deferred-auth] listening — AUTH_EXEC (deferred pattern)\n");
    fflush(stdout);

    dispatch_main();
    /* unreachable */
    return 0;
}
