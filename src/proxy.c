#include "gost.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

void base64_encode(const unsigned char *src, size_t len, char *dst) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, n = 0;
    while (i < len) {
        size_t left = len - i;
        unsigned a = src[i++], b = left > 1 ? src[i++] : 0, c = left > 2 ? src[i++] : 0;
        dst[n++] = chars[a >> 2];
        dst[n++] = chars[((a & 3) << 4) | (b >> 4)];
        dst[n++] = left > 1 ? chars[((b & 15) << 2) | (c >> 6)] : '=';
        dst[n++] = left > 2 ? chars[c & 63] : '=';
    }
    dst[n] = '\0';
}

static void auth_token(const struct endpoint *ep, char *out) {
    char raw[AUTH_CAP * 2 + 1];
    snprintf(raw, sizeof(raw), "%s:%s", ep->username, ep->password);
    base64_encode((unsigned char *)raw, strlen(raw), out);
}

int basic_credentials(const char *value, const struct endpoint *ep) {
    if (!ep->auth) return 1;
    if (!value || strncasecmp(value, "Basic ", 6)) return 0;
    char token[1024];
    auth_token(ep, token);
    value += 6;
    while (*value == ' ' || *value == '\t') value++;
    size_t n = strlen(token);
    if (strlen(value) != n) return 0;
    unsigned diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (unsigned char)token[i] ^ (unsigned char)value[i];
    return diff == 0;
}

int socks_pack_address(const struct address *addr, unsigned char *buf, size_t cap) {
    unsigned char ip[16];
    size_t n;
    if (inet_pton(AF_INET, addr->host, ip) == 1) {
        n = 5;
        if (cap < n + 2) return -1;
        buf[0] = 1;
        memcpy(buf + 1, ip, 4);
    } else if (inet_pton(AF_INET6, addr->host, ip) == 1) {
        n = 17;
        if (cap < n + 2) return -1;
        buf[0] = 4;
        memcpy(buf + 1, ip, 16);
    } else {
        size_t len = strlen(addr->host);
        if (!len || len > 255 || cap < len + 4) return -1;
        buf[0] = 3;
        buf[1] = (unsigned char)len;
        memcpy(buf + 2, addr->host, len);
        n = len + 2;
    }
    buf[n++] = (unsigned char)(addr->port >> 8);
    buf[n++] = (unsigned char)addr->port;
    return (int)n;
}

int socks_unpack_address(const unsigned char *buf, size_t len, struct address *addr, size_t *used) {
    if (len < 1) return -1;
    size_t n;
    memset(addr, 0, sizeof(*addr));
    if (buf[0] == 1 || buf[0] == 4) {
        n = buf[0] == 1 ? 5 : 17;
        if (len < n + 2 || !inet_ntop(buf[0] == 1 ? AF_INET : AF_INET6, buf + 1,
                                    addr->host, sizeof(addr->host))) return -1;
    } else if (buf[0] == 3) {
        if (len < 2 || !buf[1]) return -1;
        n = (size_t)buf[1] + 2;
        if (len < n + 2) return -1;
        for (size_t i = 2; i < n; i++)
            if (buf[i] <= 32 || buf[i] >= 127 || strchr("/\\:@[]?#", buf[i])) return -1;
        memcpy(addr->host, buf + 2, buf[1]);
    } else return -1;
    addr->port = (uint16_t)(((unsigned)buf[n] << 8) | buf[n + 1]);
    *used = n + 2;
    return 0;
}

int socks_read_address(int fd, unsigned char atyp, struct address *addr) {
    unsigned char buf[260] = {atyp};
    size_t n;
    if (atyp == 1) n = 6;
    else if (atyp == 4) n = 18;
    else if (atyp == 3) {
        if (read_exact(fd, buf + 1, 1, config.timeout_ms) || !buf[1]) return -1;
        n = (size_t)buf[1] + 2;
        if (read_exact(fd, buf + 2, n, config.timeout_ms)) return -1;
        size_t used;
        return socks_unpack_address(buf, n + 2, addr, &used);
    } else return -1;
    if (read_exact(fd, buf + 1, n, config.timeout_ms)) return -1;
    size_t used;
    return socks_unpack_address(buf, n + 1, addr, &used);
}

static int socks_connect(int fd, const struct endpoint *ep, const struct address *target) {
    unsigned char request[520], response[4];
    unsigned char greeting[] = {5, 1, ep->auth ? 2 : 0};
    int timeout = config.connect_timeout_ms;
    if (send_all(fd, greeting, sizeof(greeting), timeout) || read_exact(fd, response, 2, timeout) ||
        response[0] != 5 || response[1] != greeting[2]) { errno = EACCES; return -1; }
    if (ep->auth) {
        size_t u = strlen(ep->username), p = strlen(ep->password);
        request[0] = 1;
        request[1] = (unsigned char)u;
        memcpy(request + 2, ep->username, u);
        request[u + 2] = (unsigned char)p;
        memcpy(request + u + 3, ep->password, p);
        if (send_all(fd, request, u + p + 3, timeout) || read_exact(fd, response, 2, timeout) ||
            response[0] != 1 || response[1] != 0) { errno = EACCES; return -1; }
    }
    request[0] = 5; request[1] = 1; request[2] = 0;
    int n = socks_pack_address(target, request + 3, sizeof(request) - 3);
    if (n < 0 || send_all(fd, request, (size_t)n + 3, timeout) ||
        read_exact(fd, response, 4, timeout)) return -1;
    if (response[0] != 5 || response[1] || response[2]) { errno = ECONNREFUSED; return -1; }
    struct address bound;
    return socks_read_address(fd, response[3], &bound);
}

static int http_connect(int fd, const struct endpoint *ep, const struct address *target) {
    char request[2048], response[HEADER_CAP], token[1024] = "", authority[HOST_CAP + 16];
    snprintf(authority, sizeof(authority), strchr(target->host, ':') ? "[%s]:%u" : "%s:%u",
             target->host, target->port);
    if (ep->auth) auth_token(ep, token);
    int n = snprintf(request, sizeof(request), "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s%s%s\r\n",
                     authority, authority, ep->auth ? "Proxy-Authorization: Basic " : "",
                     token, ep->auth ? "\r\n" : "");
    if (n < 0 || (size_t)n >= sizeof(request) || send_all(fd, request, (size_t)n, config.connect_timeout_ms))
        return -1;
    if (read_headers(fd, response, sizeof(response), config.connect_timeout_ms) < 0) return -1;
    int code;
    if (sscanf(response, "HTTP/1.%*1[01] %d", &code) != 1 || code < 200 || code >= 300) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

int open_tunnel(const struct address *addr) {
    int fd = dial_socket(config.hop_count ? &config.hops[0].addr : addr,
                         SOCK_STREAM, config.connect_timeout_ms);
    if (fd < 0) return -1;
    for (size_t i = 0; i < config.hop_count; i++) {
        const struct address *target = i + 1 < config.hop_count ? &config.hops[i + 1].addr : addr;
        int rc = config.hops[i].protocol == PROTO_HTTP ? http_connect(fd, &config.hops[i], target) :
                                                        socks_connect(fd, &config.hops[i], target);
        if (rc) { int saved = errno; close(fd); errno = saved; return -1; }
    }
    return fd;
}

static int socks_reply(int fd, unsigned char code, int remote) {
    unsigned char response[260] = {5, code, 0, 1, 0, 0, 0, 0, 0, 0};
    int n = 7;
    struct address addr;
    if (!code && remote >= 0 && !socket_address(remote, false, &addr))
        n = socks_pack_address(&addr, response + 3, sizeof(response) - 3);
    return n < 0 ? -1 : send_all(fd, response, (size_t)n + 3, config.timeout_ms);
}

void handle_socks5(int fd, const struct endpoint *ep) {
    unsigned char buf[520];
    if (read_exact(fd, buf, 2, config.timeout_ms) || buf[0] != 5 || !buf[1]) return;
    size_t count = buf[1];
    if (read_exact(fd, buf, count, config.timeout_ms)) return;
    unsigned char method = ep->auth ? 2 : 0;
    bool found = false;
    for (size_t i = 0; i < count; i++) if (buf[i] == method) found = true;
    unsigned char response[] = {5, found ? method : 255};
    if (send_all(fd, response, 2, config.timeout_ms) || !found) return;
    if (ep->auth) {
        if (read_exact(fd, buf, 2, config.timeout_ms) || buf[0] != 1 || !buf[1]) return;
        size_t u = buf[1];
        if (read_exact(fd, buf, u + 1, config.timeout_ms)) return;
        size_t p = buf[u];
        if (read_exact(fd, buf + u, p, config.timeout_ms)) return;
        bool valid = u == strlen(ep->username) && p == strlen(ep->password);
        unsigned diff = 0;
        if (valid) {
            for (size_t i = 0; i < u; i++) diff |= buf[i] ^ (unsigned char)ep->username[i];
            for (size_t i = 0; i < p; i++) diff |= buf[u + i] ^ (unsigned char)ep->password[i];
        }
        unsigned char auth_response[] = {1, valid && !diff ? 0 : 1};
        if (send_all(fd, auth_response, 2, config.timeout_ms) || auth_response[1]) return;
    }
    if (read_exact(fd, buf, 4, config.timeout_ms) || buf[0] != 5 || buf[2]) return;
    unsigned char cmd = buf[1];
    struct address target;
    if (socks_read_address(fd, buf[3], &target)) { socks_reply(fd, 8, -1); return; }
    if (cmd == 3) {
        if (config.hop_count) { socks_reply(fd, 7, -1); return; }
        handle_socks_udp(fd, &target);
        return;
    }
    if (cmd != 1) { socks_reply(fd, 7, -1); return; }
    if (!target.port) { socks_reply(fd, 8, -1); return; }
    int remote = open_tunnel(&target);
    if (remote < 0) {
        unsigned char error = errno == ECONNREFUSED ? 5 : errno == ETIMEDOUT ? 6 :
                              errno == ENETUNREACH ? 3 : errno == EHOSTUNREACH ? 4 : 1;
        socks_reply(fd, error, -1);
        return;
    }
    if (!socks_reply(fd, 0, remote)) relay(fd, remote, NULL);
    close(remote);
}

void handle_client(int fd, const struct endpoint *ep) {
    enum protocol protocol = ep->protocol;
    if (protocol == PROTO_TCP) {
        int remote = open_tunnel(&ep->target);
        if (remote >= 0) { relay(fd, remote, NULL); close(remote); }
        return;
    }
    if (protocol == PROTO_AUTO) {
        unsigned char first;
        if (wait_fd(fd, POLLIN, now_ms() + config.timeout_ms) || recv(fd, &first, 1, MSG_PEEK) != 1) return;
        protocol = first == 5 ? PROTO_SOCKS5 : PROTO_HTTP;
    }
    if (protocol == PROTO_SOCKS5) handle_socks5(fd, ep);
    else if (protocol == PROTO_HTTP) handle_http(fd, ep);
}
