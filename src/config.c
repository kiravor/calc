#include "gost.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *protocol_name(enum protocol p) {
    static const char *names[] = {"auto", "http", "socks5", "tcp", "udp"};
    return names[p];
}

int parse_address(const char *text, struct address *addr, bool listen) {
    const char *port, *host = text;
    size_t n;
    if (*text == '[') {
        const char *end = strchr(text, ']');
        if (!end || end[1] != ':') return -1;
        host++;
        n = (size_t)(end - host);
        port = end + 2;
    } else {
        port = strrchr(text, ':');
        if (!port || memchr(text, ':', (size_t)(port - text))) return -1;
        n = (size_t)(port - text);
        port++;
    }
    if (n >= sizeof(addr->host) || (!listen && n == 0) || !*port) return -1;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)host[i] <= 32 || strchr("/\\?#@[]", host[i])) return -1;
    for (const char *p = port; *p; p++) if (!isdigit((unsigned char)*p)) return -1;
    errno = 0;
    unsigned long number = strtoul(port, NULL, 10);
    if (errno || number > 65535 || (!listen && number == 0)) return -1;
    memcpy(addr->host, host, n);
    addr->host[n] = '\0';
    addr->port = (uint16_t)number;
    return 0;
}

static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode(const char *src, char *out, size_t cap) {
    size_t n = 0;
    while (*src) {
        unsigned char c = (unsigned char)*src++;
        if (c == '%') {
            if (!src[0] || !src[1]) return -1;
            int a = hex_digit((unsigned char)src[0]), b = hex_digit((unsigned char)src[1]);
            if (a < 0 || b < 0) return -1;
            c = (unsigned char)(a * 16 + b);
            src += 2;
        }
        if (c < 32 || c == 127 || n + 1 >= cap) return -1;
        out[n++] = (char)c;
    }
    out[n] = '\0';
    return 0;
}

int parse_endpoint(const char *text, struct endpoint *ep, bool hop) {
    char buf[2048];
    if (strlen(text) >= sizeof(buf)) return -1;
    strcpy(buf, text);
    memset(ep, 0, sizeof(*ep));
    char *authority = buf, *scheme = strstr(buf, "://");
    ep->protocol = PROTO_AUTO;
    if (scheme) {
        *scheme = '\0';
        authority = scheme + 3;
        if (!strcmp(buf, "http")) ep->protocol = PROTO_HTTP;
        else if (!strcmp(buf, "socks5") || !strcmp(buf, "socks")) ep->protocol = PROTO_SOCKS5;
        else if (!strcmp(buf, "tcp") || !strcmp(buf, "forward")) ep->protocol = PROTO_TCP;
        else if (!strcmp(buf, "udp")) ep->protocol = PROTO_UDP;
        else if (strcmp(buf, "auto")) return -1;
    }
    if (strpbrk(authority, "?#")) return -1;
    char *path = strchr(authority, '/');
    if (path) *path++ = '\0';
    char *userinfo = strchr(authority, '@');
    if (userinfo) {
        *userinfo++ = '\0';
        char *pass = strchr(authority, ':');
        if (!pass) return -1;
        *pass++ = '\0';
        if (decode(authority, ep->username, sizeof(ep->username)) ||
            decode(pass, ep->password, sizeof(ep->password)) || !*ep->username ||
            strchr(ep->username, ':')) return -1;
        authority = userinfo;
        ep->auth = true;
    }
    if (parse_address(authority, &ep->addr, !hop)) return -1;
    if (hop) {
        if (ep->protocol != PROTO_HTTP && ep->protocol != PROTO_SOCKS5) return -1;
        if (path && *path) return -1;
    } else if (ep->protocol == PROTO_TCP || ep->protocol == PROTO_UDP) {
        if (ep->auth || !path || parse_address(path, &ep->target, false)) return -1;
    } else if (path && *path) return -1;
    return 0;
}
