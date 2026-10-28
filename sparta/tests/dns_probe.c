#include "internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned original_lookups;
int __real_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
int __wrap_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **out) {
    if (host && !strcmp(host, "rebind.example")) host = ++original_lookups == 1 ? "93.184.216.34" : "127.0.0.1";
    return __real_getaddrinfo(host, service, hints, out);
}
int __real_connect(int, const struct sockaddr *, socklen_t);
int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (addr->sa_family != AF_INET) { errno = EACCES; return -1; }
    struct sockaddr_in local = *(const struct sockaddr_in *)addr;
    struct in_addr approved;
    inet_pton(AF_INET, "93.184.216.34", &approved);
    if (local.sin_addr.s_addr != approved.s_addr) { errno = EACCES; return -1; }
    inet_pton(AF_INET, "127.0.0.1", &local.sin_addr);
    return __real_connect(fd, (const struct sockaddr *)&local, len);
}
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc != 3) return 2;
    char *text = sp_read_file(argv[1], SP_MAX_JSON);
    cJSON *cfg = text ? sp_json(text) : NULL; free(text);
    struct agent a;
    if (!cfg || sp_agent_init(&a, cfg)) { cJSON_Delete(cfg); return 3; }
    cJSON_Delete(cfg);
    struct address target = {.host = "rebind.example", .port = (uint16_t)strtoul(argv[2], NULL, 10)};
    int fd = sp_authorize_target(&a, "alice", &target, SOCK_STREAM);
    if (fd < 0 || original_lookups != 1) { if (fd >= 0) close(fd); sp_agent_close(&a); return 4; }
    close(fd);
    fd = sp_authorize_target(&a, "alice", &target, SOCK_STREAM);
    int result = fd < 0 && errno == EACCES && original_lookups == 2 ? 0 : 5;
    if (fd >= 0) close(fd);
    sp_agent_close(&a);
    return result;
}
