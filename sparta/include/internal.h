#ifndef SPARTA_INTERNAL_H
#define SPARTA_INTERNAL_H
#include "gost.h"
#include "sparta.h"
#include "cJSON.h"
#include <pthread.h>
#include <openssl/ssl.h>
#include <stdint.h>

#define SP_MAX_JSON (8 * 1024 * 1024)
#define SP_COUNTER_MAX (UINT64_C(1) << 50)
#define SP_MAX_USERS 4096

struct profile {
    struct address node;
    uint16_t origin_port;
    char host[256], path[2048], user[256], password[256], ca[4096];
};
struct http_result { long status; char *body; size_t len; char etag[256]; };
struct relay_request { int cmd, network; struct address addr; char user[256], password[256]; };
struct counter {
    char id[256];
    uint64_t in, out, pending_in, pending_out;
    double tokens[2];
    int64_t token_time[2];
    struct counter *next;
};
struct agent {
    pthread_mutex_t lock;
    pthread_cond_t plugin_done;
    unsigned plugin_active;
    cJSON *state;
    struct counter *counts;
    uint64_t seq;
    int dirfd, lockfd;
    char dir[4096], token[1024], hub[4096], key[1024], node_id[256], ca[4096];
    char etag[256];
    unsigned interval;
    bool has_pending, registered;
    cJSON *params;
    struct address plugin_listen;
    int plugin_fd;
    pthread_t sync_thread, plugin_thread;
    bool sync_started, plugin_started;
};
extern struct profile client_profile;
extern struct agent node_agent;
extern char node_ws_path[2048];
extern _Thread_local int64_t sp_deadline;
int sp_timeout(void);
int sp_read_datagram(const unsigned char *buf, size_t len, struct address *addr, size_t *header, size_t *payload);

char *sp_read_file(const char *path, size_t max);
cJSON *sp_json(const char *text);
const char *sp_string(const cJSON *obj, const char *key);
bool sp_integer(const cJSON *value, uint64_t max, uint64_t *out);
int sp_copy(char *out, size_t cap, const char *value);
bool sp_valid_host(const char *host);
int sp_profile(const char *json, const char *password, const char *override, const char *ca, struct profile *out);
char *sp_decode_link(const char *link, const char *kind);
int sp_http(const char *method, const char *url, const char *token, const char *etag,
             const char *body, const char *ca, struct http_result *out);
void sp_http_free(struct http_result *out);
int sp_save(struct agent *a, const char *name, const char *data);
bool sp_match(const char *pattern, const char *target);
bool sp_private(const char *host);
bool sp_denied(struct agent *a, const char *user, const char *host, const char *addr);
bool sp_destination_allowed(struct agent *a, const char *user, const char *host, const char *numeric);
int sp_agent_init(struct agent *a, const cJSON *cfg);
void sp_agent_close(struct agent *a);
bool sp_auth(struct agent *a, const char *user, const char *password);
uint64_t sp_rate(struct agent *a, const char *user);
int sp_authorize_target(struct agent *a, const char *user, const struct address *target, int type);
void sp_count(struct agent *a, const char *user, uint64_t in, uint64_t out);
int sp_save_counts(struct agent *a);
ssize_t sp_limited_send(struct agent *a, const char *user, int direction, int fd, const void *buf, size_t len);
cJSON *sp_plugin(struct agent *a, const char *path, const cJSON *req, bool authorized);
int sp_agent_start(struct agent *a, bool plugins);

int sp_ws_client(const struct profile *p);
int sp_ws_client_filtered(const struct profile *p);
int sp_ws_server(int fd, const char *path);
void sp_ws_drain(void);
int sp_relay_send(int fd, int cmd, int network, const struct address *addr, const struct profile *p);
int sp_relay_read(int fd, struct relay_request *out);
int sp_relay_response(int fd, int status, const struct address *addr);
int sp_relay_verdict(int fd);
int sp_client_dial(const struct address *addr);
void sp_client_udp(int control, const struct address *requested);
void sp_node_client(int fd);
int sp_serve_node(const cJSON *cfg);
char *sp_subscription(const char *link, const char *want, const char *ca, int *code);
#endif
