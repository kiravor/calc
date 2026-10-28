#include "internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct profile client_profile;
static pthread_mutex_t lifecycle = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static pthread_t server_thread;
static bool running, ending, ready;
static unsigned bound_port, checks;
static int launch_status;

int sp_client_dial(const struct address *addr) {
    int fd = sp_ws_client_filtered(&client_profile);
    if (fd < 0) return -1; /* Never fall back to a direct dial. */
    if (sp_relay_send(fd, 1, 0, addr, &client_profile)) { close(fd); return -1; }
    /* The eager request also unblocks server-first protocols. The response is
       stripped by the WS stream adapter, while client writes may proceed. */
    return fd;
}

static void on_ready(int status) {
    pthread_mutex_lock(&lifecycle);
    launch_status = status;
    struct address addr;
    if (!status && !socket_address(config.services[0].fd, false, &addr)) bound_port = addr.port;
    ready = true; pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lifecycle);
}

static void *serve(void *unused) { (void)unused; run_server(); return NULL; }

int sparta_start(const char *json, const char *password, const char *node_addr, unsigned port,
                 const char *user, const char *pass, const char *ca, char *error, size_t cap) {
    pthread_mutex_lock(&lifecycle);
    if (error && cap) error[0] = 0;
    if (running || ending || !json || port > 65535 || !user || !pass || (!!*user != !!*pass) ||
        strlen(user) > 255 || strlen(pass) > 255 ||
        sp_profile(json, password, node_addr, ca, &client_profile)) {
        if (error && cap) snprintf(error, cap, "config: invalid profile, credentials or lifecycle state");
        pthread_mutex_unlock(&lifecycle); return -1;
    }
    config = (struct config){.timeout_ms = 180000, .connect_timeout_ms = 10000, .max_clients = 96,
                             .service_count = 1, .embedded = true, .ready = on_ready,
                             .dial_override = sp_client_dial, .udp_override = sp_client_udp,
                             .transport_drain = sp_ws_drain};
    struct service *s = &config.services[0];
    s->fd = -1; s->endpoint.protocol = PROTO_SOCKS5;
    sp_copy(s->endpoint.addr.host, sizeof(s->endpoint.addr.host), "127.0.0.1");
    s->endpoint.addr.port = (uint16_t)port;
    s->endpoint.auth = !!*user;
    sp_copy(s->endpoint.username, sizeof(s->endpoint.username), user);
    sp_copy(s->endpoint.password, sizeof(s->endpoint.password), pass);
    stopping = 0; ready = false; bound_port = 0;
    if (pthread_create(&server_thread, NULL, serve, NULL)) {
        if (error && cap) snprintf(error, cap, "unreachable: cannot start worker");
        pthread_mutex_unlock(&lifecycle); return -1;
    }
    while (!ready) pthread_cond_wait(&changed, &lifecycle);
    if (launch_status) {
        ending = true;
        pthread_mutex_unlock(&lifecycle); pthread_join(server_thread, NULL);
        pthread_mutex_lock(&lifecycle); ending = false;
        OPENSSL_cleanse(&client_profile, sizeof(client_profile));
        pthread_cond_broadcast(&changed); pthread_mutex_unlock(&lifecycle);
        if (error && cap) snprintf(error, cap, "unreachable: cannot bind SOCKS listener");
        return -1;
    }
    running = true;
    pthread_mutex_unlock(&lifecycle);
    return 0;
}

unsigned sparta_port(void) {
    pthread_mutex_lock(&lifecycle);
    unsigned port = running && !ending ? bound_port : 0;
    pthread_mutex_unlock(&lifecycle); return port;
}

void sparta_stop(void) {
    pthread_mutex_lock(&lifecycle);
    while (ending) pthread_cond_wait(&changed, &lifecycle);
    if (!running) { pthread_mutex_unlock(&lifecycle); return; }
    ending = true; stopping = 1;
    while (checks) pthread_cond_wait(&changed, &lifecycle);
    pthread_mutex_unlock(&lifecycle);
    pthread_join(server_thread, NULL);
    pthread_mutex_lock(&lifecycle);
    OPENSSL_cleanse(&client_profile, sizeof(client_profile));
    running = false; ending = false; bound_port = 0;
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lifecycle);
}

int sparta_check(const char *url, unsigned timeout_ms, char *error, size_t cap) {
    pthread_mutex_lock(&lifecycle);
    if (!running || ending || !url || !timeout_ms || timeout_ms > 60000) {
        pthread_mutex_unlock(&lifecycle);
        if (error && cap) snprintf(error, cap, "unreachable: not running or invalid timeout");
        return -1;
    }
    struct profile p = client_profile;
    checks++;
    pthread_mutex_unlock(&lifecycle);
    sp_deadline = now_ms() + timeout_ms;
    int fd = -1, result = -1, saved = EINVAL;
    struct address target;
    if (strncmp(url, "http://", 7)) goto done;
    const char *start = url + 7, *path = strchr(start, '/');
    char authority[300];
    size_t n = path ? (size_t)(path - start) : strlen(start);
    if (n >= sizeof(authority)) goto done;
    memcpy(authority, start, n); authority[n] = 0;
    if (!strchr(authority, ':')) {
        if (n + 3 >= sizeof(authority)) goto done;
        strcat(authority, ":80");
    }
    if (parse_address(authority, &target, false)) goto done;
    for (const char *q = url; *q; q++) if ((unsigned char)*q <= 32 || *q == 127) goto done;
    fd = sp_ws_client(&p);
    if (fd < 0) { saved = errno; goto done; }
    if (sp_relay_send(fd, 1, 0, &target, &p)) { saved = errno; goto done; }
    char request[4096];
    int count = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path ? path : "/", authority);
    if (count < 0 || (size_t)count >= sizeof(request) || send_all(fd, request, (size_t)count, sp_timeout()) || sp_relay_verdict(fd)) {
        saved = errno; goto done;
    }
    char response[HEADER_CAP];
    if (read_headers(fd, response, sizeof(response), sp_timeout()) < 0) { saved = errno; goto done; }
    int code = 0;
    if (sscanf(response, "HTTP/1.%*1[01] %d", &code) == 1 && code == 204) result = 0;
    else saved = EHOSTUNREACH;
done:
    if (fd >= 0) close(fd);
    sp_deadline = 0;
    OPENSSL_cleanse(&p, sizeof(p));
    if (error && cap) {
        if (!result) error[0] = 0;
        else snprintf(error, cap, "%s: tunnel check failed", saved == ETIMEDOUT ? "timeout" :
                      saved == EACCES ? "auth" : saved == EILSEQ ? "tls" : "unreachable");
    }
    pthread_mutex_lock(&lifecycle); checks--; pthread_cond_broadcast(&changed); pthread_mutex_unlock(&lifecycle);
    return result;
}
