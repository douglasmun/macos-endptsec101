#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <os/lock.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_PATH "/Users/douglasmun/Develop/macos-endptsec101/12-dynamic-policy/policy.conf"
#define MAX_MUTE_PATHS 64
#define MAX_PATH_LEN   512

static es_client_t        *g_client     = NULL;
static dispatch_queue_t    g_main_queue = NULL;
static atomic_int          g_shutdown   = 0;

/*
 * g_mute_paths and g_mute_count are read on the ES handler queue and written
 * on the main queue by reload_config. Protect all accesses with g_config_lock.
 */
static os_unfair_lock     g_config_lock = OS_UNFAIR_LOCK_INIT;
static char g_mute_paths[MAX_MUTE_PATHS][MAX_PATH_LEN];
static int  g_mute_count = 0;

/* Separator-safe prefix match on es_string_token_t */
static int path_has_prefix(const es_string_token_t *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (path->length < plen) return 0;
    if (memcmp(path->data, prefix, plen) != 0) return 0;
    return path->length == plen || path->data[plen] == '/' || plen == 1;
}

/* Load config from file; returns number of paths loaded.
   Caller is responsible for calling on main queue only. */
static int load_config(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[CONFIG] cannot open %s\n", path);
        return 0;
    }

    int count = 0;
    char line[MAX_PATH_LEN];
    while (fgets(line, sizeof(line), f) && count < MAX_MUTE_PATHS) {
        /* Strip trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        /* Skip empty lines and comments */
        if (len == 0 || line[0] == '#')
            continue;

        strlcpy(g_mute_paths[count], line, MAX_PATH_LEN);
        count++;
    }

    fclose(f);
    g_mute_count = count;
    return count;
}

/* Check whether needle is in the given list */
static int list_contains(char list[MAX_MUTE_PATHS][MAX_PATH_LEN], int count,
                          const char *needle)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(list[i], needle) == 0)
            return 1;
    }
    return 0;
}

/* reload_config — runs on main queue; diffed mute/unmute */
static void reload_config(void *ctx)
{
    (void)ctx;

    /* Snapshot old list under lock */
    char old_paths[MAX_MUTE_PATHS][MAX_PATH_LEN];
    int  old_count;
    os_unfair_lock_lock(&g_config_lock);
    old_count = g_mute_count;
    memcpy(old_paths, g_mute_paths, sizeof(g_mute_paths));
    os_unfair_lock_unlock(&g_config_lock);

    /* Load new list into temporaries first */
    char new_paths[MAX_MUTE_PATHS][MAX_PATH_LEN];
    memset(new_paths, 0, sizeof(new_paths));
    int new_count = 0;

    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) {
        fprintf(stderr, "[CONFIG] cannot open %s\n", CONFIG_PATH);
        return;
    }
    char line[MAX_PATH_LEN];
    while (fgets(line, sizeof(line), f) && new_count < MAX_MUTE_PATHS) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;
        strlcpy(new_paths[new_count++], line, MAX_PATH_LEN);
    }
    fclose(f);

    /* Unmute paths removed from config (ES API calls outside lock) */
    for (int i = 0; i < old_count; i++) {
        if (!list_contains(new_paths, new_count, old_paths[i])) {
            es_return_t r = es_unmute_path(g_client, old_paths[i],
                                           ES_MUTE_PATH_TYPE_PREFIX);
            if (r != ES_RETURN_SUCCESS)
                fprintf(stderr, "[CONFIG] es_unmute_path failed for %s\n",
                        old_paths[i]);
        }
    }

    /* Mute paths added to config (ES API calls outside lock) */
    for (int i = 0; i < new_count; i++) {
        if (!list_contains(old_paths, old_count, new_paths[i])) {
            es_return_t r = es_mute_path(g_client, new_paths[i],
                                         ES_MUTE_PATH_TYPE_PREFIX);
            if (r != ES_RETURN_SUCCESS)
                fprintf(stderr, "[CONFIG] es_mute_path failed for %s\n",
                        new_paths[i]);
        }
    }

    /* Commit new list under lock */
    os_unfair_lock_lock(&g_config_lock);
    memcpy(g_mute_paths, new_paths, sizeof(g_mute_paths));
    g_mute_count = new_count;
    os_unfair_lock_unlock(&g_config_lock);

    printf("[CONFIG] reloaded %d paths\n", new_count);
    fflush(stdout);
}

/* do_shutdown — runs on main queue */
static void do_shutdown(void *ctx)
{
    (void)ctx;
    if (g_client) {
        es_delete_client(g_client);
        g_client = NULL;
    }
    exit(0);
}

static void on_signal(int sig)
{
    (void)sig;
    atomic_store(&g_shutdown, 1);
    dispatch_async_f(g_main_queue, NULL, do_shutdown);
}

static void handle_event(es_client_t *client, const es_message_t *msg)
{
    switch (msg->event_type) {

    case ES_EVENT_TYPE_AUTH_EXEC: {
        const es_process_t *target = msg->event.exec.target;
        const es_string_token_t *exe = &target->executable->path;

        /* Check mute prefix list under lock to avoid race with reload_config */
        os_unfair_lock_lock(&g_config_lock);
        int muted = 0;
        for (int i = 0; i < g_mute_count; i++) {
            if (path_has_prefix(exe, g_mute_paths[i])) {
                muted = 1;
                break;
            }
        }
        os_unfair_lock_unlock(&g_config_lock);

        if (muted) {
            es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
            return;
        }

        /* Allow with logging */
        char path_buf[MAX_PATH_LEN];
        size_t copy_len = exe->length < MAX_PATH_LEN - 1
                          ? exe->length : MAX_PATH_LEN - 1;
        memcpy(path_buf, exe->data, copy_len);
        path_buf[copy_len] = '\0';

        printf("[EXEC] allow pid=%d path=%s\n",
               audit_token_to_pid(target->audit_token), path_buf);
        fflush(stdout);

        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        break;
    }

    case ES_EVENT_TYPE_NOTIFY_WRITE: {
        const es_file_t *file = msg->event.write.target;
        /* A truncated path cannot match CONFIG_PATH — skip to avoid false reload */
        if (file->path_truncated)
            break;
        /* Build null-terminated copy to compare */
        char path_buf[MAX_PATH_LEN];
        size_t copy_len = file->path.length < MAX_PATH_LEN - 1
                          ? file->path.length : MAX_PATH_LEN - 1;
        memcpy(path_buf, file->path.data, copy_len);
        path_buf[copy_len] = '\0';

        if (strcmp(path_buf, CONFIG_PATH) == 0) {
            dispatch_async_f(g_main_queue, NULL, reload_config);
        }
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

    es_new_client_result_t res = es_new_client(&g_client, ^(es_client_t *c,
                                                             const es_message_t *m) {
        handle_event(c, m);
    });

    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es_new_client failed: %d\n", res);
        return 1;
    }

    /* Self-mute */
    audit_token_t self_token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                  (task_info_t)&self_token, &count) == KERN_SUCCESS) {
        es_mute_process(g_client, &self_token);
    }

    /* Initial config load */
    int loaded = load_config(CONFIG_PATH);
    printf("[CONFIG] initial load: %d paths\n", loaded);

    /* Apply initial mutes */
    for (int i = 0; i < g_mute_count; i++) {
        es_return_t r = es_mute_path(g_client, g_mute_paths[i],
                                     ES_MUTE_PATH_TYPE_PREFIX);
        if (r != ES_RETURN_SUCCESS)
            fprintf(stderr, "[CONFIG] es_mute_path failed for %s\n",
                    g_mute_paths[i]);
    }

    /* Subscribe after all muting is configured */
    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_NOTIFY_WRITE,
    };
    if (es_subscribe(g_client, events,
                     sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("[*] dynamic-policy running. Edit %s to update live.\n", CONFIG_PATH);
    fflush(stdout);

    dispatch_main();
    /* unreachable */
    return 0;
}
