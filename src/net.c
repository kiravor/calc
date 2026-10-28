#include "gost.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) return -1;
    return 0;
}

int wait_fd(int fd, short events, int64_t deadline) {
    while (!stopping) {
        int64_t left = deadline - now_ms();
        if (left <= 0) { errno = ETIMEDOUT; return -1; }
        struct pollfd p = {.fd = fd, .events = events};
        int n = poll(&p, 1, left > 250 ? 250 : (int)left);
        if (n > 0) {
            if (p.revents & POLLNVAL) { errno = EBADF; return -1; }
            return 0; /* Let recv/send report EOF or the socket error. */
        }
        if (n < 0 && errno != EINTR) return -1;
    }
    errno = ECANCELED;
    return -1;
}

int read_exact(int fd, void *buf, size_t len, int timeout) {
    unsigned char *p = buf;
    int64_t deadline = now_ms() + timeout;
    while (len) {
        if (wait_fd(fd, POLLIN, deadline)) return -1;
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) { if (!n) errno = ECONNRESET; return -1; }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int send_all(int fd, const void *buf, size_t len, int timeout) {
    const unsigned char *p = buf;
    int64_t deadline = now_ms() + timeout;
    while (len) {
        if (wait_fd(fd, POLLOUT, deadline)) return -1;
        ssize_t n = send(fd, p, len, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int read_headers(int fd, char *buf, size_t cap, int timeout) {
    size_t used = 0;
    int64_t deadline = now_ms() + timeout;
    /* Read exactly through CRLFCRLF; tunnel/body bytes stay in the socket. */
    while (used + 1 < cap) {
        if (wait_fd(fd, POLLIN, deadline)) return -1;
        unsigned char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0 || c == 0 || (c < 32 && c != '\r' && c != '\n' && c != '\t') || c == 127)
            return -1;
        buf[used++] = (char)c;
        if (used >= 4 && !memcmp(buf + used - 4, "\r\n\r\n", 4)) {
            buf[used] = '\0';
            return (int)used;
        }
    }
    errno = EMSGSIZE;
    return -1;
}

static int resolve(const struct address *addr, int type, bool passive, struct addrinfo **result) {
    char port[6];
    snprintf(port, sizeof(port), "%u", addr->port);
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = type,
                            .ai_flags = passive ? AI_PASSIVE : 0};
    const char *host = addr->host;
    if (passive && (!*host || !strcmp(host, "*"))) {
        host = "0.0.0.0";
        hints.ai_family = AF_INET;
    }
    if (getaddrinfo(host, port, &hints, result)) { errno = EHOSTUNREACH; return -1; }
    return 0;
}

int bind_socket(const struct address *addr, int type) {
    struct addrinfo *list;
    if (resolve(addr, type, true, &list)) return -1;
    int fd = -1, saved = EADDRNOTAVAIL;
    for (struct addrinfo *p = list; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) { saved = errno; continue; }
        int yes = 1;
        /* Do not permit two UDP services to silently share a port. */
        if (type == SOCK_STREAM) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (p->ai_family == AF_INET6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
        if (!set_nonblocking(fd) && !bind(fd, p->ai_addr, p->ai_addrlen) &&
            (type != SOCK_STREAM || !listen(fd, 128))) break;
        saved = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(list);
    if (fd < 0) errno = saved;
    return fd;
}

int dial_socket(const struct address *addr, int type, int timeout) {
    struct addrinfo *list;
    if (resolve(addr, type, false, &list)) return -1;
    int fd = -1, saved = EHOSTUNREACH;
    int64_t deadline = now_ms() + timeout;
    for (struct addrinfo *p = list; p && !stopping; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) { saved = errno; continue; }
        if (set_nonblocking(fd)) goto next;
        if (!connect(fd, p->ai_addr, p->ai_addrlen)) break;
        if (errno == EINPROGRESS && !wait_fd(fd, POLLOUT, deadline)) {
            int error = 0;
            socklen_t size = sizeof(error);
            if (!getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) && !error) break;
            if (error) errno = error;
        }
next:
        saved = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(list);
    if (fd < 0) errno = saved;
    return fd;
}

int address_from_sockaddr(const struct sockaddr *sa, socklen_t len, struct address *addr) {
    char port[6];
    if (getnameinfo(sa, len, addr->host, sizeof(addr->host), port, sizeof(port),
                    NI_NUMERICHOST | NI_NUMERICSERV)) return -1;
    unsigned value;
    if (sscanf(port, "%u", &value) != 1) return -1;
    addr->port = (uint16_t)value;
    return 0;
}

int socket_address(int fd, bool peer, struct address *addr) {
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    int rc = peer ? getpeername(fd, (struct sockaddr *)&sa, &len) :
                    getsockname(fd, (struct sockaddr *)&sa, &len);
    return rc ? -1 : address_from_sockaddr((struct sockaddr *)&sa, len, addr);
}

bool same_peer(const struct sockaddr_storage *a, const struct sockaddr_storage *b, bool port) {
    if (a->ss_family != b->ss_family) return false;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x = (const void *)a, *y = (const void *)b;
        return x->sin_addr.s_addr == y->sin_addr.s_addr && (!port || x->sin_port == y->sin_port);
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const void *)a, *y = (const void *)b;
        return !memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) &&
               x->sin6_scope_id == y->sin6_scope_id && (!port || x->sin6_port == y->sin6_port);
    }
    return false;
}

int relay(int client, int remote, struct body *body) {
    struct direction {
        int from, to;
        unsigned char buf[32768];
        size_t start, end;
        bool eof, shut;
    } d[2] = {{.from = client, .to = remote}, {.from = remote, .to = client}};
    int64_t last = now_ms();
    while (!stopping) {
        bool finished = true;
        struct pollfd p[2] = {{.fd = client}, {.fd = remote}};
        for (int i = 0; i < 2; i++) {
            if (i == 0 && body && body->done) d[i].eof = true;
            if (d[i].start == d[i].end) {
                d[i].start = d[i].end = 0;
                if (d[i].eof && !d[i].shut) {
                    /* HTTP requests have their own framing; retain the write side. */
                    if (!(i == 0 && body)) shutdown(d[i].to, SHUT_WR);
                    d[i].shut = true;
                }
            }
            if (!d[i].eof && d[i].end < sizeof(d[i].buf)) p[i].events |= POLLIN;
            if (d[i].end > d[i].start) p[1 - i].events |= POLLOUT;
            if (!d[i].eof || d[i].start != d[i].end) finished = false;
        }
        if (finished) return 0;
        if (now_ms() - last >= config.timeout_ms) { errno = ETIMEDOUT; return -1; }
        /* poll reports HUP even with events=0. Ignore inactive directions so
           a half-closed socket cannot spin while the other side is working. */
        for (int i = 0; i < 2; i++) if (!p[i].events) p[i].fd = -1;
        int n = poll(p, 2, 250);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        for (int i = 0; i < 2; i++) {
            if (p[i].revents & (POLLERR | POLLNVAL)) return -1;
            if (d[i].end > d[i].start && (p[1 - i].revents & (POLLOUT | POLLHUP))) {
                ssize_t sent = send(d[i].to, d[i].buf + d[i].start, d[i].end - d[i].start, 0);
                if (sent > 0) { d[i].start += (size_t)sent; last = now_ms(); }
                else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
            }
            if (!d[i].eof && d[i].end < sizeof(d[i].buf) && (p[i].revents & (POLLIN | POLLHUP))) {
                ssize_t got = recv(d[i].from, d[i].buf + d[i].end, sizeof(d[i].buf) - d[i].end, 0);
                if (got == 0) {
                    if (i == 0 && body && !body->done) { errno = EPROTO; return -1; }
                    d[i].eof = true;
                    /* An early final HTTP response must not wait on an unfinished upload. */
                    if (i == 1 && body) { d[0].eof = true; d[0].end = d[0].start; }
                } else if (got > 0) {
                    size_t accepted = (size_t)got;
                    if (i == 0 && body && body_consume(body, d[i].buf + d[i].end, accepted, &accepted))
                        return -1;
                    d[i].end += accepted;
                    last = now_ms();
                } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
            }
        }
    }
    return -1;
}
