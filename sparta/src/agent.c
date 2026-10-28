#include "internal.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct agent node_agent;

static bool patterns_valid(const cJSON *list) {
    if (!cJSON_IsArray(list) || cJSON_GetArraySize(list) > 4096) return false;
    const cJSON *p;
    cJSON_ArrayForEach(p, list) {
        if (!cJSON_IsString(p) || !*p->valuestring || strlen(p->valuestring) > 255) return false;
        /* Matching a pattern against itself validates addresses and domain suffixes. */
        char base[256]; sp_copy(base, sizeof(base), p->valuestring);
        char *slash = strchr(base, '/'); if (slash) *slash = 0;
        const char *target = !strncmp(base, "*.", 2) ? base + 2 : *base == '.' ? base + 1 : base;
        if (!sp_match(p->valuestring, target)) return false;
    }
    return true;
}

static bool state_valid(const cJSON *state) {
    uint64_t value;
    if (!cJSON_IsObject(state) || !sp_integer(cJSON_GetObjectItemCaseSensitive(state, "version"),
        UINT64_C(9007199254740991), &value)) return false;
    const cJSON *users = cJSON_GetObjectItemCaseSensitive(state, "users");
    const cJSON *bl = cJSON_GetObjectItemCaseSensitive(state, "blacklist");
    const cJSON *by = cJSON_GetObjectItemCaseSensitive(bl, "users");
    if (!cJSON_IsArray(users) || cJSON_GetArraySize(users) > SP_MAX_USERS || !cJSON_IsObject(bl) ||
        !cJSON_IsObject(by) || !patterns_valid(cJSON_GetObjectItemCaseSensitive(bl, "global"))) return false;
    const cJSON *u;
    cJSON_ArrayForEach(u, users) {
        const char *id = sp_string(u, "id"), *hash = sp_string(u, "pass_sha256"), *access = sp_string(u, "access");
        if (!id || !*id || strlen(id) > 255 || !hash || strlen(hash) != 64 || !access ||
            (strcmp(access, "allow") && strcmp(access, "blocked") && strcmp(access, "over_quota")) ||
            !sp_integer(cJSON_GetObjectItemCaseSensitive(u, "rate_kbps"), 1000000000, &value)) return false;
        for (const char *p = hash; *p; p++) if (!isxdigit((unsigned char)*p)) return false;
        for (const cJSON *q = u->next; q; q = q->next) {
            const char *other = sp_string(q, "id");
            if (other && !strcmp(id, other)) return false;
        }
    }
    cJSON_ArrayForEach(u, by) if (!patterns_valid(u)) return false;
    return true;
}

static struct counter *counter_locked(struct agent *a, const char *id) {
    size_t n = 0;
    for (struct counter *p = a->counts; p; p = p->next) {
        if (!strcmp(p->id, id)) return p;
        n++;
    }
    if (!*id || strlen(id) > 255 || n >= SP_MAX_USERS) return NULL;
    struct counter *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    sp_copy(p->id, sizeof(p->id), id);
    p->next = a->counts; a->counts = p;
    return p;
}

static bool stored_number(const cJSON *v, uint64_t *out) {
    if (!v) { *out = 0; return true; }
    if (cJSON_IsNumber(v)) return sp_integer(v, SP_COUNTER_MAX, out);
    if (!cJSON_IsString(v) || !*v->valuestring) return false;
    uint64_t n = 0;
    for (const char *p = v->valuestring; *p; p++) {
        if (*p < '0' || *p > '9' || n > (UINT64_MAX - (unsigned)(*p - '0')) / 10) return false;
        n = n * 10 + (unsigned)(*p - '0');
    }
    *out = n; return true;
}

static int load_counts(struct agent *a, const cJSON *v) {
    if (!cJSON_IsObject(v) || !stored_number(cJSON_GetObjectItemCaseSensitive(v, "seq"), &a->seq) ||
        a->seq > UINT64_C(9007199254740991)) return -1;
    const char *names[] = {"unsent", "batch"};
    for (unsigned i = 0; i < 2; i++) {
        const cJSON *map = cJSON_GetObjectItemCaseSensitive(v, names[i]);
        if (!map && i) continue;
        if (!cJSON_IsObject(map)) return -1;
        const cJSON *u;
        cJSON_ArrayForEach(u, map) {
            if (!u->string || !cJSON_IsObject(u)) return -1;
            struct counter *p = counter_locked(a, u->string);
            uint64_t in, out;
            if (!p || !stored_number(cJSON_GetObjectItemCaseSensitive(u, "in"), &in) ||
                !stored_number(cJSON_GetObjectItemCaseSensitive(u, "out"), &out)) return -1;
            if (i) {
                if (!a->seq || in > SP_COUNTER_MAX || out > SP_COUNTER_MAX) return -1;
                p->pending_in = in; p->pending_out = out;
                if (in || out) a->has_pending = true;
            } else { p->in = in; p->out = out; }
        }
    }
    return 0;
}

static cJSON *count_map(struct agent *a, bool pending, bool wire) {
    cJSON *map = cJSON_CreateObject();
    for (struct counter *p = a->counts; p; p = p->next) {
        uint64_t in = pending ? p->pending_in : p->in, out = pending ? p->pending_out : p->out;
        if (!in && !out) continue;
        cJSON *v = cJSON_AddObjectToObject(map, p->id);
        if (wire) {
            cJSON_AddNumberToObject(v, "in", (double)in);
            cJSON_AddNumberToObject(v, "out", (double)out);
        } else {
            char text[32];
            snprintf(text, sizeof(text), "%" PRIu64, in); cJSON_AddStringToObject(v, "in", text);
            snprintf(text, sizeof(text), "%" PRIu64, out); cJSON_AddStringToObject(v, "out", text);
        }
    }
    return map;
}

static int save_counts_locked(struct agent *a) {
    cJSON *v = cJSON_CreateObject();
    char seq[32]; snprintf(seq, sizeof(seq), "%" PRIu64, a->seq);
    cJSON_AddStringToObject(v, "seq", seq);
    cJSON_AddItemToObject(v, "unsent", count_map(a, false, false));
    cJSON_AddItemToObject(v, "batch", count_map(a, true, false));
    char *text = cJSON_PrintUnformatted(v); cJSON_Delete(v);
    int result = text ? sp_save(a, "counters.json", text) : -1;
    free(text);
    return result;
}

int sp_save_counts(struct agent *a) {
    pthread_mutex_lock(&a->lock);
    int result = save_counts_locked(a);
    pthread_mutex_unlock(&a->lock);
    return result;
}

void sp_count(struct agent *a, const char *id, uint64_t in, uint64_t out) {
    pthread_mutex_lock(&a->lock);
    struct counter *p = counter_locked(a, id);
    if (p) {
        p->in = in > UINT64_MAX - p->in ? UINT64_MAX : p->in + in;
        p->out = out > UINT64_MAX - p->out ? UINT64_MAX : p->out + out;
    }
    pthread_mutex_unlock(&a->lock);
}

ssize_t sp_limited_send(struct agent *a, const char *id, int direction, int fd, const void *buf, size_t len) {
    bool datagram = direction >= 2;
    bool empty_datagram = datagram && !len;
    direction &= 1;
    uint64_t rate = sp_rate(a, id);
    if (rate == UINT64_MAX) { errno = EACCES; return -1; }
    pthread_mutex_lock(&a->lock);
    struct counter *p = counter_locked(a, id);
    if (!p) { pthread_mutex_unlock(&a->lock); errno = ENOMEM; return -1; }
    int64_t now = now_ms();
    if (rate) {
        double fresh = p->token_time[direction] ? p->tokens[direction] + (double)(now - p->token_time[direction]) * (double)rate / 1000 : (double)rate;
        p->tokens[direction] = fresh > (double)rate ? (double)rate : fresh;
        p->token_time[direction] = now;
        if ((double)len > p->tokens[direction]) len = datagram ? 0 : (size_t)p->tokens[direction];
    }
    ssize_t n;
    if (!len && !empty_datagram) { errno = ENOBUFS; n = -1; }
    else n = send(fd, buf, len, 0);
    if (n > 0 && rate) p->tokens[direction] -= (double)n;
    pthread_mutex_unlock(&a->lock);
    if (n > 0) sp_count(a, id, direction == 0 ? (uint64_t)n : 0, direction == 1 ? (uint64_t)n : 0);
    return n;
}

static cJSON *ok_answer(bool ok) {
    cJSON *v = cJSON_CreateObject(); cJSON_AddBoolToObject(v, "ok", ok); return v;
}

cJSON *sp_plugin(struct agent *a, const char *path, const cJSON *req, bool authorized) {
    bool auth = !strcmp(path, "/auth"), bypass = !strcmp(path, "/bypass"),
         limiter = !strcmp(path, "/limiter"), observer = !strcmp(path, "/observer");
    if (!auth && !bypass && !limiter && !observer) return NULL;
    if (!authorized) {
        if (!limiter) return ok_answer(bypass || observer);
        cJSON *v = cJSON_CreateObject(); cJSON_AddNumberToObject(v, "in", 1); cJSON_AddNumberToObject(v, "out", 1); return v;
    }
    if (!cJSON_IsObject(req)) {
        if (limiter) { cJSON *v = cJSON_CreateObject(); cJSON_AddNumberToObject(v, "in", 1); cJSON_AddNumberToObject(v, "out", 1); return v; }
        return ok_answer(bypass);
    }
    const char *client = sp_string(req, "client");
    if (auth) {
        const char *user = sp_string(req, "username"), *password = sp_string(req, "password");
        bool allowed = user && password && sp_auth(a, user, password);
        cJSON *v = ok_answer(allowed);
        if (allowed) cJSON_AddStringToObject(v, "id", user);
        return v;
    }
    if (bypass) return ok_answer(!client || sp_denied(a, client, sp_string(req, "host"), sp_string(req, "addr")));
    if (limiter) {
        cJSON *v = cJSON_CreateObject();
        const char *scope = sp_string(req, "scope");
        uint64_t rate = !scope || !strcmp(scope, "client") ? (client ? sp_rate(a, client) : UINT64_MAX) : 0;
        if (rate == UINT64_MAX) rate = 1;
        if (rate) { cJSON_AddNumberToObject(v, "in", (double)rate); cJSON_AddNumberToObject(v, "out", (double)rate); }
        return v;
    }
    const cJSON *events = cJSON_GetObjectItemCaseSensitive(req, "events");
    if (!cJSON_IsArray(events) || cJSON_GetArraySize(events) > 4096) return ok_answer(false);
    const cJSON *e;
    cJSON_ArrayForEach(e, events) {
        const char *kind = sp_string(e, "kind"), *type = sp_string(e, "type"), *id = sp_string(e, "client");
        const cJSON *stats = cJSON_GetObjectItemCaseSensitive(e, "stats");
        if (!kind || strcmp(kind, "handler") || !type || strcmp(type, "stats") || !id || !*id || !cJSON_IsObject(stats)) continue;
        uint64_t in = 0, out = 0;
        const cJSON *iv = cJSON_GetObjectItemCaseSensitive(stats, "inputBytes"), *ov = cJSON_GetObjectItemCaseSensitive(stats, "outputBytes");
        if ((iv && !sp_integer(iv, SP_COUNTER_MAX, &in)) || (ov && !sp_integer(ov, SP_COUNTER_MAX, &out))) continue;
        sp_count(a, id, in, out);
    }
    /* The observer protocol has no event IDs: ambiguous HTTP retries may
       repeat an increment. Hub reports, in contrast, are sequence-idempotent. */
    return ok_answer(true);
}

int sp_agent_init(struct agent *a, const cJSON *cfg) {
    memset(a, 0, sizeof(*a)); a->dirfd = a->lockfd = a->plugin_fd = -1;
    pthread_mutex_init(&a->lock, NULL);
    pthread_cond_init(&a->plugin_done, NULL);
    const char *dir = sp_string(cfg, "state_dir"), *hub = sp_string(cfg, "hub"), *node = sp_string(cfg, "node_id");
    const char *ca = sp_string(cfg, "ca_file"), *listen = sp_string(cfg, "plugin_listen");
    const char *token = getenv("SPARTA_PLUGIN_TOKEN"), *key = getenv("SPARTA_NODE_KEY");
    a->interval = 30;
    uint64_t interval;
    const cJSON *iv = cJSON_GetObjectItemCaseSensitive(cfg, "interval_seconds");
    if ((iv && (!sp_integer(iv, 3600, &interval) || !interval)) || !dir || !*dir ||
        sp_copy(a->dir, sizeof(a->dir), dir) || (hub && sp_copy(a->hub, sizeof(a->hub), hub)) ||
        (node && sp_copy(a->node_id, sizeof(a->node_id), node)) ||
        (ca && sp_copy(a->ca, sizeof(a->ca), ca)) ||
        (token && sp_copy(a->token, sizeof(a->token), token)) || (key && sp_copy(a->key, sizeof(a->key), key)) ||
        parse_address(listen ? listen : "127.0.0.1:8007", &a->plugin_listen, true)) goto fail;
    if (iv) a->interval = (unsigned)interval;
    if (*a->hub && (!*a->node_id || !*a->key)) goto fail;
    if (mkdir(dir, 0700) && errno != EEXIST) goto fail;
    a->dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (a->dirfd < 0) goto fail;
    a->lockfd = openat(a->dirfd, ".agent.lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (a->lockfd < 0 || flock(a->lockfd, LOCK_EX | LOCK_NB)) goto fail;
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/state.json", dir) >= (int)sizeof(path)) goto fail;
    char *text = sp_read_file(path, SP_MAX_JSON);
    if (text) {
        a->state = sp_json(text); free(text);
        if (!state_valid(a->state)) { cJSON_Delete(a->state); a->state = NULL; fputs("State invalid: access remains closed\n", stderr); }
    }
    if (snprintf(path, sizeof(path), "%s/counters.json", dir) >= (int)sizeof(path)) goto fail;
    if (!access(path, F_OK)) {
        text = sp_read_file(path, SP_MAX_JSON);
        cJSON *counts = text ? sp_json(text) : NULL; free(text);
        int result = load_counts(a, counts); cJSON_Delete(counts);
        if (result) goto fail; /* Never silently reset an existing report sequence. */
    }
    const cJSON *params = cJSON_GetObjectItemCaseSensitive(cfg, "node");
    a->params = cJSON_IsObject(params) ? cJSON_Duplicate(params, 1) : cJSON_CreateObject();
    return 0;
fail:
    sp_agent_close(a);
    return -1;
}

void sp_agent_close(struct agent *a) {
    if (a->sync_started) pthread_join(a->sync_thread, NULL);
    if (a->plugin_started) pthread_join(a->plugin_thread, NULL);
    pthread_mutex_lock(&a->lock);
    while (a->plugin_active) pthread_cond_wait(&a->plugin_done, &a->lock);
    pthread_mutex_unlock(&a->lock);
    if (a->plugin_fd >= 0) close(a->plugin_fd);
    if (a->lockfd >= 0) close(a->lockfd);
    if (a->dirfd >= 0) close(a->dirfd);
    cJSON_Delete(a->state); cJSON_Delete(a->params);
    struct counter *p = a->counts;
    while (p) { struct counter *next = p->next; free(p); p = next; }
    pthread_mutex_destroy(&a->lock);
    pthread_cond_destroy(&a->plugin_done);
    memset(a, 0, sizeof(*a)); a->dirfd = a->lockfd = a->plugin_fd = -1;
}

static int hub_request(struct agent *a, const char *method, const char *route, const char *etag,
                        const cJSON *body, struct http_result *out) {
    char url[4608];
    size_t len = strlen(a->hub);
    while (len && a->hub[len - 1] == '/') len--;
    int n = snprintf(url, sizeof(url), "%.*s%s", (int)len, a->hub, route);
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    char *text = body ? cJSON_PrintUnformatted(body) : NULL;
    int result = sp_http(method, url, a->key, etag, text, a->ca, out);
    free(text);
    return result;
}

static void sync_state(struct agent *a) {
    struct http_result result;
    if (hub_request(a, "GET", "/v1/state", a->etag, NULL, &result)) return;
    if (result.status == 200) {
        cJSON *state = sp_json(result.body);
        if (state_valid(state)) {
            pthread_mutex_lock(&a->lock);
            uint64_t old = 0, next = 0;
            sp_integer(cJSON_GetObjectItemCaseSensitive(a->state, "version"), UINT64_C(9007199254740991), &old);
            sp_integer(cJSON_GetObjectItemCaseSensitive(state, "version"), UINT64_C(9007199254740991), &next);
            if (!a->state || next >= old) {
                cJSON_Delete(a->state); a->state = state; state = NULL;
                if (!sp_save(a, "state.json", result.body)) sp_copy(a->etag, sizeof(a->etag), result.etag);
                else {
                    a->etag[0] = 0;
                    /* Invalidate an older offline snapshot if a revocation cannot be saved. */
                    unlinkat(a->dirfd, "state.json", 0); fsync(a->dirfd);
                }
            }
            pthread_mutex_unlock(&a->lock);
        }
        cJSON_Delete(state);
    }
    sp_http_free(&result);
}

static void report(struct agent *a) {
    pthread_mutex_lock(&a->lock);
    if (!a->has_pending) {
        bool any = false;
        for (struct counter *p = a->counts; p; p = p->next) {
            p->pending_in = p->in > SP_COUNTER_MAX ? SP_COUNTER_MAX : p->in;
            p->pending_out = p->out > SP_COUNTER_MAX ? SP_COUNTER_MAX : p->out;
            p->in -= p->pending_in; p->out -= p->pending_out;
            any |= p->pending_in || p->pending_out;
        }
        if (any) {
            struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
            uint64_t clock_seq = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
            a->seq = a->seq + 1 > clock_seq ? a->seq + 1 : clock_seq;
            a->has_pending = true;
        }
    }
    if (!a->has_pending || save_counts_locked(a)) { pthread_mutex_unlock(&a->lock); return; }
    uint64_t seq = a->seq;
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "node", a->node_id);
    cJSON_AddNumberToObject(body, "seq", (double)seq);
    cJSON_AddItemToObject(body, "users", count_map(a, true, true));
    pthread_mutex_unlock(&a->lock);
    struct http_result result;
    if (!hub_request(a, "POST", "/v1/report", NULL, body, &result)) {
        cJSON *ack = sp_json(result.body);
        uint64_t acked;
        if (result.status == 200 && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(ack, "ok")) &&
            sp_integer(cJSON_GetObjectItemCaseSensitive(ack, "acked_seq"), UINT64_C(9007199254740991), &acked) && acked >= seq) {
            pthread_mutex_lock(&a->lock);
            for (struct counter *p = a->counts; p; p = p->next) p->pending_in = p->pending_out = 0;
            a->has_pending = false;
            save_counts_locked(a);
            pthread_mutex_unlock(&a->lock);
        }
        cJSON_Delete(ack); sp_http_free(&result);
    }
    /* A 404 is retained: nginx and the hub can both return it, so dropping a
       charged batch would lose traffic on transient access-list failures. */
    cJSON_Delete(body);
}

static void *sync_loop(void *arg) {
    struct agent *a = arg;
    int64_t next = 0, save = 0;
    while (!stopping) {
        int64_t now = now_ms();
        if (now >= next && *a->hub) {
            if (!a->registered) {
                struct http_result result;
                if (!hub_request(a, "PUT", "/v1/node", NULL, a->params, &result)) {
                    cJSON *ack = sp_json(result.body);
                    a->registered = result.status == 200 && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(ack, "ok"));
                    cJSON_Delete(ack); sp_http_free(&result);
                }
            }
            sync_state(a);
            if (!stopping) report(a);
            next = now_ms() + (int64_t)a->interval * 1000;
        }
        if (now >= save) { sp_save_counts(a); save = now_ms() + 5000; }
        poll(NULL, 0, 100);
    }
    sp_save_counts(a);
    return NULL;
}

static void plugin_connection(struct agent *a, int fd) {
    char headers[HEADER_CAP];
    if (read_headers(fd, headers, sizeof(headers), 5000) < 0) return;
    char method[16], path[128], version[16];
    if (sscanf(headers, "%15s %127s %15s", method, path, version) != 3 || strcmp(method, "POST") || strcmp(version, "HTTP/1.1")) return;
    char *p = strstr(headers, "\r\n"), *authorization = NULL;
    bool bad = false, length_seen = false;
    uint64_t length = 0;
    while (p && *(p += 2) && strncmp(p, "\r\n", 2)) {
        char *end = strstr(p, "\r\n"), *colon = strchr(p, ':');
        if (!end || !colon || colon >= end || p[0] == ' ' || p[0] == '\t') { bad = true; break; }
        *end = 0; *colon++ = 0;
        while (*colon == ' ' || *colon == '\t') colon++;
        if (!strcasecmp(p, "Authorization")) { if (authorization) bad = true; authorization = colon; }
        if (!strcasecmp(p, "Content-Length")) {
            if (length_seen) bad = true;
            length_seen = true;
            cJSON number = {.type = cJSON_String, .valuestring = colon};
            if (!stored_number(&number, &length) || length > 65536) bad = true;
        }
        if (!strcasecmp(p, "Transfer-Encoding")) bad = true;
        p = end;
    }
    unsigned char got[32], want[32]; char bearer[1100];
    snprintf(bearer, sizeof(bearer), "Bearer %s", a->token);
    EVP_Digest(bearer, strlen(bearer), want, NULL, EVP_sha256(), NULL);
    EVP_Digest(authorization ? authorization : "", authorization ? strlen(authorization) : 0, got, NULL, EVP_sha256(), NULL);
    bool authorized = !bad && strlen(a->token) >= 32 && !CRYPTO_memcmp(got, want, 32);
    char *body = NULL; cJSON *req = NULL;
    if (authorized && !bad && length_seen && length <= 65536) {
        body = calloc((size_t)length + 1, 1);
        if (body && !read_exact(fd, body, (size_t)length, 5000) && !memchr(body, 0, (size_t)length)) req = sp_json(body);
    }
    cJSON *answer = sp_plugin(a, path, req, authorized);
    char *text = answer ? cJSON_PrintUnformatted(answer) : NULL;
    char response[256];
    int n = snprintf(response, sizeof(response), "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                     text ? "200 OK" : "404 Not Found", text ? strlen(text) : 0);
    if (n > 0 && !send_all(fd, response, (size_t)n, 5000) && text) send_all(fd, text, strlen(text), 5000);
    free(body); free(text); cJSON_Delete(req); cJSON_Delete(answer);
}

struct plugin_work { struct agent *agent; int fd; };
static void *plugin_worker(void *arg) {
    struct plugin_work *work = arg;
    plugin_connection(work->agent, work->fd);
    close(work->fd);
    pthread_mutex_lock(&work->agent->lock);
    work->agent->plugin_active--;
    pthread_cond_broadcast(&work->agent->plugin_done);
    pthread_mutex_unlock(&work->agent->lock);
    free(work);
    return NULL;
}

static void *plugin_loop(void *arg) {
    struct agent *a = arg;
    while (!stopping) {
        struct pollfd p = {.fd = a->plugin_fd, .events = POLLIN};
        if (poll(&p, 1, 100) <= 0) continue;
        int fd = accept(a->plugin_fd, NULL, NULL);
        if (fd < 0) continue;
        if (set_nonblocking(fd)) { close(fd); continue; }
        pthread_mutex_lock(&a->lock);
        struct plugin_work *work = a->plugin_active < 32 ? malloc(sizeof(*work)) : NULL;
        pthread_t thread;
        if (work) {
            *work = (struct plugin_work){.agent = a, .fd = fd};
            a->plugin_active++;
            if (pthread_create(&thread, NULL, plugin_worker, work)) { a->plugin_active--; free(work); work = NULL; }
            else pthread_detach(thread);
        }
        if (!work) close(fd);
        pthread_mutex_unlock(&a->lock);
    }
    return NULL;
}

int sp_agent_start(struct agent *a, bool plugins) {
    if (plugins) {
        if (strlen(a->token) < 32) return -1;
        a->plugin_fd = bind_socket(&a->plugin_listen, SOCK_STREAM);
        if (a->plugin_fd < 0 || pthread_create(&a->plugin_thread, NULL, plugin_loop, a)) return -1;
        a->plugin_started = true;
        struct address bound;
        if (!socket_address(a->plugin_fd, false, &bound)) fprintf(stderr, "Agent plugins on [%s]:%u\n", bound.host, bound.port);
    }
    if (pthread_create(&a->sync_thread, NULL, sync_loop, a)) return -1;
    a->sync_started = true;
    return 0;
}
