#include "gost.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static bool token_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || (c != 0 && strchr("!#$%&'*+-.^_`|~", c));
}

static bool token(const char *s) {
    if (!*s) return false;
    for (; *s; s++) if (!token_char((unsigned char)*s)) return false;
    return true;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
    return s;
}

static int decimal(const char *s, uint64_t *value) {
    if (!*s) return -1;
    uint64_t n = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || n > (UINT64_MAX - (unsigned)(*s - '0')) / 10) return -1;
        n = n * 10 + (unsigned)(*s - '0');
    }
    *value = n;
    return 0;
}

int body_consume(struct body *body, const unsigned char *buf, size_t len, size_t *accepted) {
    size_t i = 0;
    if (!body->chunked) {
        if ((uint64_t)len > body->left) len = (size_t)body->left;
        body->left -= len;
        body->done = !body->left;
        *accepted = len;
        return 0;
    }
    while (i < len && !body->done) {
        if (body->state == 1) {
            size_t n = len - i;
            if ((uint64_t)n > body->left) n = (size_t)body->left;
            body->left -= n;
            i += n;
            if (!body->left) body->state = 2;
            continue;
        }
        unsigned char c = buf[i++];
        if (body->state == 2) { if (c != '\r') return -1; body->state = 3; continue; }
        if (body->state == 3) { if (c != '\n') return -1; body->state = 0; continue; }
        if (body->used + 1 >= sizeof(body->line) || (c < 32 && c != '\r' && c != '\n' && c != '\t') ||
            c == 127 || (body->used && body->line[body->used - 1] == '\r' && c != '\n')) return -1;
        body->line[body->used++] = (char)c;
        if (body->state == 4 && ++body->trailer_bytes > HEADER_CAP) return -1;
        if (c != '\n') continue;
        if (body->used < 2 || body->line[body->used - 2] != '\r') return -1;
        body->line[body->used - 2] = '\0';
        if (body->state == 0) {
            const char *p = body->line;
            uint64_t n = 0;
            unsigned digits = 0;
            while (isxdigit((unsigned char)*p)) {
                unsigned digit = *p <= '9' ? (unsigned)(*p - '0') :
                                 (unsigned)(tolower((unsigned char)*p) - 'a' + 10);
                if (n > (UINT64_MAX - digit) / 16) return -1;
                n = n * 16 + digit;
                digits++;
                p++;
            }
            if (!digits || (*p && *p != ';')) return -1;
            body->left = n;
            body->state = n ? 1 : 4;
        } else {
            if (!body->line[0]) body->done = true;
            else {
                char *colon = strchr(body->line, ':');
                if (!colon) return -1;
                *colon = '\0';
                if (!token(body->line) || !strcasecmp(body->line, "Content-Length") ||
                    !strcasecmp(body->line, "Transfer-Encoding") || !strcasecmp(body->line, "Host") ||
                    !strcasecmp(body->line, "Proxy-Authorization")) return -1;
            }
        }
        body->used = 0;
    }
    *accepted = i;
    return 0;
}

static void http_error(int fd, int code, const char *reason) {
    char response[512];
    int n = snprintf(response, sizeof(response), "HTTP/1.1 %d %s\r\nConnection: close\r\n"
                     "Content-Length: 0\r\n%s\r\n", code, reason,
                     code == 407 ? "Proxy-Authenticate: Basic realm=\"gost-c\"\r\n" : "");
    if (n > 0 && (size_t)n < sizeof(response)) send_all(fd, response, (size_t)n, config.timeout_ms);
}

static int authority(const char *value, struct address *addr, bool require_port) {
    char buf[HOST_CAP + 16];
    if (!*value || strlen(value) >= sizeof(buf)) return -1;
    strcpy(buf, value);
    bool has_port;
    if (buf[0] == '[') {
        char *end = strchr(buf, ']');
        if (!end) return -1;
        has_port = end[1] == ':';
        if (!has_port && end[1]) return -1;
    } else has_port = strchr(buf, ':') != NULL;
    if (!has_port) {
        if (require_port || strlen(buf) + 3 >= sizeof(buf)) return -1;
        strcat(buf, ":80");
    }
    return parse_address(buf, addr, false);
}

struct header { char *name, *value; };

static bool connection_contains(const char *list, const char *name) {
    if (!list) return false;
    size_t n = strlen(name);
    while (*list) {
        while (*list == ',' || *list == ' ' || *list == '\t') list++;
        const char *start = list;
        while (*list && *list != ',') list++;
        const char *end = list;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
        if ((size_t)(end - start) == n && !strncasecmp(start, name, n)) return true;
    }
    return false;
}

void handle_http(int fd, const struct endpoint *ep) {
    char input[HEADER_CAP], output[HEADER_CAP + HOST_CAP + 256];
    if (read_headers(fd, input, sizeof(input), config.timeout_ms) < 0) {
        http_error(fd, errno == EMSGSIZE ? 431 : 400, "Invalid Request Headers");
        return;
    }
    char *line_end = strstr(input, "\r\n");
    if (!line_end) { http_error(fd, 400, "Bad Request"); return; }
    *line_end = '\0';
    char *method = input, *target = strchr(method, ' '), *version;
    if (!target) { http_error(fd, 400, "Bad Request"); return; }
    *target++ = '\0';
    version = strchr(target, ' ');
    if (!version) { http_error(fd, 400, "Bad Request"); return; }
    *version++ = '\0';
    if (!token(method) || strlen(method) > 32 || !*target || strlen(target) > 8192 ||
        (strcmp(version, "HTTP/1.1") && strcmp(version, "HTTP/1.0"))) {
        http_error(fd, 400, "Bad Request"); return;
    }
    for (const char *p = target; *p; p++)
        if ((unsigned char)*p <= 32 || (unsigned char)*p == 127) { http_error(fd, 400, "Bad Request"); return; }
    struct header headers[256];
    size_t count = 0;
    char *host = NULL, *auth = NULL, *connection = NULL, *transfer = NULL, *length = NULL;
    char *p = line_end + 2;
    while (*p && strcmp(p, "\r\n")) {
        char *end = strstr(p, "\r\n"), *colon;
        if (!end || count == 256) goto bad;
        *end = '\0';
        colon = strchr(p, ':');
        if (!colon) goto bad;
        *colon++ = '\0';
        if (!token(p)) goto bad;
        char *value = trim(colon);
        for (char *v = value; *v; v++) if (*v == '\r' || *v == '\n') goto bad;
        headers[count++] = (struct header){p, value};
        char **slot = NULL;
        if (!strcasecmp(p, "Host")) slot = &host;
        else if (!strcasecmp(p, "Proxy-Authorization")) slot = &auth;
        else if (!strcasecmp(p, "Connection")) slot = &connection;
        else if (!strcasecmp(p, "Content-Length")) slot = &length;
        else if (!strcasecmp(p, "Transfer-Encoding")) slot = &transfer;
        else if (!strcasecmp(p, "Upgrade")) { http_error(fd, 501, "Upgrade Not Supported"); return; }
        if (slot) {
            if (*slot) goto bad;
            *slot = value;
        }
        p = end + 2;
    }
    if (!basic_credentials(auth, ep)) { http_error(fd, 407, "Proxy Authentication Required"); return; }
    if ((length && transfer) || (transfer && strcasecmp(transfer, "chunked"))) goto bad;
    struct body body = {0};
    if (length && decimal(length, &body.left)) goto bad;
    body.chunked = transfer != NULL;
    body.done = !body.chunked && !body.left;
    if (connection_contains(connection, "Content-Length") || connection_contains(connection, "Transfer-Encoding") ||
        connection_contains(connection, "Host")) goto bad;
    struct address addr;
    bool connect_request = !strcmp(method, "CONNECT");
    const char *path = target;
    char query_path[8194];
    if (connect_request) {
        if (!body.done || authority(target, &addr, true)) goto bad;
    } else if (!strncasecmp(target, "http://", 7)) {
        char *start = target + 7, *end = strpbrk(start, "/?#");
        if (!end) {
            if (authority(start, &addr, false)) goto bad;
            path = "/";
        } else {
            char saved = *end;
            *end = '\0';
            if (authority(start, &addr, false)) goto bad;
            *end = saved;
            if (saved == '#') goto bad;
            if (saved == '?') {
                snprintf(query_path, sizeof(query_path), "/%s", end);
                path = query_path;
            } else path = end;
        }
        if (strchr(path, '#')) goto bad;
    } else {
        if (*target != '/' || strchr(target, '#') || !host || authority(host, &addr, false)) goto bad;
    }
    int remote = open_tunnel(&addr);
    if (remote < 0) { http_error(fd, errno == ETIMEDOUT ? 504 : 502, "Upstream Connection Failed"); return; }
    if (connect_request) {
        static const char response[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (!send_all(fd, response, sizeof(response) - 1, config.timeout_ms)) relay(fd, remote, NULL);
        close(remote);
        return;
    }
    char host_value[HOST_CAP + 16];
    snprintf(host_value, sizeof(host_value), strchr(addr.host, ':') ? "[%s]:%u" : "%s:%u", addr.host, addr.port);
    int n = snprintf(output, sizeof(output), "%s %s %s\r\nHost: %s\r\nConnection: close\r\n",
                     method, path, version, host_value);
    if (n < 0 || (size_t)n >= sizeof(output)) { close(remote); goto bad; }
    size_t used = (size_t)n;
    for (size_t i = 0; i < count; i++) {
        const char *name = headers[i].name;
        if (!strcasecmp(name, "Host") || !strcasecmp(name, "Connection") ||
            !strcasecmp(name, "Proxy-Connection") || !strcasecmp(name, "Proxy-Authorization") ||
            !strcasecmp(name, "Proxy-Authenticate") || !strcasecmp(name, "Keep-Alive") ||
            !strcasecmp(name, "TE") || connection_contains(connection, name)) continue;
        n = snprintf(output + used, sizeof(output) - used, "%s: %s\r\n", name, headers[i].value);
        if (n < 0 || (size_t)n >= sizeof(output) - used) { close(remote); goto bad; }
        used += (size_t)n;
    }
    if (used + 2 >= sizeof(output)) { close(remote); goto bad; }
    memcpy(output + used, "\r\n", 2);
    if (!send_all(remote, output, used + 2, config.timeout_ms)) relay(fd, remote, &body);
    close(remote);
    return;
bad:
    http_error(fd, 400, "Bad Request");
}
