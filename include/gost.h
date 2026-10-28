#ifndef GOST_H
#define GOST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/socket.h>

#define MAX_SERVICES 32
#define MAX_HOPS 8
#define MAX_FLOWS 128
#define HEADER_CAP 32768
#define HOST_CAP 256
#define AUTH_CAP 256

enum protocol { PROTO_AUTO, PROTO_HTTP, PROTO_SOCKS5, PROTO_TCP, PROTO_UDP };

struct address { char host[HOST_CAP]; uint16_t port; };
struct endpoint {
    enum protocol protocol;
    struct address addr;
    struct address target;
    bool auth;
    char username[AUTH_CAP], password[AUTH_CAP];
};
struct service { struct endpoint endpoint; int fd; };
struct config {
    struct service services[MAX_SERVICES];
    struct endpoint hops[MAX_HOPS];
    size_t service_count, hop_count;
    int timeout_ms, connect_timeout_ms;
    unsigned max_clients;
    /* Optional embedded transport; absent hooks retain the standalone proxy. */
    int (*dial_override)(const struct address *addr);
    void (*udp_override)(int control, const struct address *requested);
    void (*client_override)(int fd);
    void (*transport_drain)(void);
    void (*ready)(int status);
    bool embedded;
};

/* HTTP upload framing. No bytes after the first request body reach the origin. */
struct body {
    bool chunked, done;
    uint64_t left;
    unsigned state;
    size_t used, trailer_bytes;
    char line[8192];
};

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
extern _Atomic sig_atomic_t stopping;
extern struct config config;

int parse_address(const char *text, struct address *addr, bool listen);
int parse_endpoint(const char *text, struct endpoint *ep, bool hop);
const char *protocol_name(enum protocol protocol);
int run_server(void);
void handle_client(int fd, const struct endpoint *ep);
void handle_socks5(int fd, const struct endpoint *ep);
void handle_http(int fd, const struct endpoint *ep);
void handle_socks_udp(int control, const struct address *requested);
void *udp_forward(void *arg);

int64_t now_ms(void);
int set_nonblocking(int fd);
int wait_fd(int fd, short events, int64_t deadline);
int read_exact(int fd, void *buf, size_t len, int timeout);
int send_all(int fd, const void *buf, size_t len, int timeout);
int read_headers(int fd, char *buf, size_t cap, int timeout);
int bind_socket(const struct address *addr, int type);
int dial_socket(const struct address *addr, int type, int timeout);
int open_tunnel(const struct address *addr);
int relay(int client, int remote, struct body *body);
int body_consume(struct body *body, const unsigned char *buf, size_t len, size_t *accepted);
int socks_read_address(int fd, unsigned char atyp, struct address *addr);
int socks_pack_address(const struct address *addr, unsigned char *buf, size_t cap);
int socks_unpack_address(const unsigned char *buf, size_t len, struct address *addr, size_t *used);
int socket_address(int fd, bool peer, struct address *addr);
int address_from_sockaddr(const struct sockaddr *sa, socklen_t len, struct address *addr);
bool same_peer(const struct sockaddr_storage *a, const struct sockaddr_storage *b, bool port);
void base64_encode(const unsigned char *src, size_t len, char *dst);
int basic_credentials(const char *value, const struct endpoint *ep);

#endif
