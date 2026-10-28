#include "internal.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int normalize(const char *s, char out[256]) {
    if (!s || !*s || strlen(s) > 300) return -1;
    struct address addr;
    const char *host = s;
    if (!parse_address(s, &addr, true)) host = *addr.host ? addr.host : "0.0.0.0";
    if (sp_copy(out, 256, host)) return -1;
    size_t n = strlen(out);
    if (n > 1 && out[0] == '[' && out[n - 1] == ']') {
        memmove(out, out + 1, n - 2); out[n - 2] = 0;
    }
    char *zone = strchr(out, '%');
    if (zone) *zone = 0;
    n = strlen(out);
    while (n && out[n - 1] == '.') out[--n] = 0;
    for (size_t i = 0; i < n; i++) if (out[i] >= 'A' && out[i] <= 'Z') out[i] += 'a' - 'A';
    return n ? 0 : -1;
}

static int ip_bytes(const char *host, unsigned char ip[16]) {
    if (inet_pton(AF_INET, host, ip) == 1) return 4;
    if (inet_pton(AF_INET6, host, ip) != 1) return 0;
    static const unsigned char mapped[12] = {0,0,0,0,0,0,0,0,0,0,255,255};
    if (!memcmp(ip, mapped, 12)) { memmove(ip, ip + 12, 4); return 4; }
    return 16;
}

bool sp_match(const char *pattern, const char *target) {
    char p[256], t[256];
    if (!pattern || normalize(target, t) || sp_copy(p, sizeof(p), pattern)) return false;
    char *slash = strchr(p, '/');
    long bits = -1;
    if (slash) {
        *slash++ = 0;
        char *end;
        bits = strtol(slash, &end, 10);
        if (!*slash || *end || bits < 0 || bits > 128) return false;
    }
    unsigned char a[16], b[16];
    int size = ip_bytes(p, a), other = ip_bytes(t, b);
    if (size) {
        if (bits < 0) bits = size * 8;
        else if (strchr(p, ':') && size == 4 && bits >= 96) bits -= 96;
        if (bits > size * 8 || size != other) return false;
        unsigned full = (unsigned)bits / 8, partial = (unsigned)bits % 8;
        return !memcmp(a, b, full) && (!partial || !((a[full] ^ b[full]) & (0xff << (8 - partial))));
    }
    if (slash || other) return false;
    const char *domain = p;
    if (!strncmp(domain, "*.", 2)) domain += 2;
    while (*domain == '.') domain++;
    char norm[256];
    if (normalize(domain, norm) || !sp_valid_host(norm)) return false;
    size_t pn = strlen(norm), tn = strlen(t);
    return tn >= pn && !strcmp(t + tn - pn, norm) && (tn == pn || t[tn - pn - 1] == '.');
}

bool sp_private(const char *host) {
    char norm[256]; unsigned char ip[16];
    if (normalize(host, norm) || !ip_bytes(norm, ip)) return true;
    static const char *ranges[] = {
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/96", "::1/128",
        "100::/64", "2001::/32", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"
    };
    for (size_t i = 0; i < sizeof(ranges) / sizeof(ranges[0]); i++) if (sp_match(ranges[i], norm)) return true;
    /* Standard NAT64 embeds an IPv4 address; it must pass the IPv4 policy too. */
    if (sp_match("64:ff9b::/96", norm)) {
        char v4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ip + 12, v4, sizeof(v4));
        return sp_private(v4);
    }
    return false;
}

static cJSON *user_rule(struct agent *a, const char *id) {
    cJSON *users = cJSON_GetObjectItemCaseSensitive(a->state, "users"), *u;
    cJSON_ArrayForEach(u, users) {
        const char *uid = sp_string(u, "id");
        if (uid && !strcmp(uid, id)) return u;
    }
    return NULL;
}

bool sp_auth(struct agent *a, const char *id, const char *password) {
    if (!id || !password) return false;
    unsigned char got[32], want[32] = {0};
    if (!EVP_Digest(password, strlen(password), got, NULL, EVP_sha256(), NULL)) return false;
    pthread_mutex_lock(&a->lock);
    cJSON *u = user_rule(a, id);
    const char *hash = sp_string(u, "pass_sha256"), *access = sp_string(u, "access");
    bool known = hash && strlen(hash) == 64;
    if (known) {
        for (size_t i = 0; i < 32; i++) {
            unsigned v;
            if (sscanf(hash + 2 * i, "%2x", &v) != 1) { known = false; break; }
            want[i] = (unsigned char)v;
        }
    }
    bool allowed = known && access && !strcmp(access, "allow");
    bool match = CRYPTO_memcmp(got, want, sizeof(got)) == 0;
    pthread_mutex_unlock(&a->lock);
    return allowed && match;
}

uint64_t sp_rate(struct agent *a, const char *id) {
    pthread_mutex_lock(&a->lock);
    cJSON *u = user_rule(a, id);
    const char *access = sp_string(u, "access");
    uint64_t rate = 0;
    if (!access || strcmp(access, "allow")) rate = UINT64_MAX;
    else sp_integer(cJSON_GetObjectItemCaseSensitive(u, "rate_kbps"), 1000000000, &rate);
    pthread_mutex_unlock(&a->lock);
    return rate == UINT64_MAX ? rate : rate * 125;
}

static bool list_matches(const cJSON *list, const char *host) {
    const cJSON *p;
    cJSON_ArrayForEach(p, list) if (cJSON_IsString(p) && sp_match(p->valuestring, host)) return true;
    return false;
}

static bool denied_locked(struct agent *a, const char *user, const char *host) {
    cJSON *u = user_rule(a, user);
    const char *access = sp_string(u, "access");
    if (!access || strcmp(access, "allow")) return true;
    char normalized[256]; unsigned char ip[16];
    if (normalize(host, normalized)) return true;
    int size = ip_bytes(normalized, ip);
    if ((size && sp_private(normalized)) || (!size && (!sp_valid_host(normalized) || !strchr(normalized, '.') ||
        sp_match("localhost", normalized)))) return true;
    const cJSON *bl = cJSON_GetObjectItemCaseSensitive(a->state, "blacklist");
    const cJSON *by = cJSON_GetObjectItemCaseSensitive(bl, "users");
    return list_matches(cJSON_GetObjectItemCaseSensitive(bl, "global"), normalized) ||
           list_matches(cJSON_GetObjectItemCaseSensitive(by, user), normalized);
}

static struct addrinfo *checked_addresses(struct agent *a, const char *user, const struct address *target, int type) {
    pthread_mutex_lock(&a->lock);
    bool denied = !target->port || denied_locked(a, user, target->host);
    pthread_mutex_unlock(&a->lock);
    if (denied) { errno = EACCES; return NULL; }
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = type}, *list;
    char port[6]; snprintf(port, sizeof(port), "%u", target->port);
    if (getaddrinfo(target->host, port, &hints, &list)) { errno = EHOSTUNREACH; return NULL; }
    /* Judge every resolved address, then connect to that exact numeric address.
       Neither a second DNS lookup nor a cached positive verdict is involved. */
    for (struct addrinfo *p = list; p; p = p->ai_next) {
        struct address numeric;
        if (address_from_sockaddr(p->ai_addr, p->ai_addrlen, &numeric)) { denied = true; break; }
        pthread_mutex_lock(&a->lock);
        denied = denied_locked(a, user, numeric.host);
        pthread_mutex_unlock(&a->lock);
        if (denied) break;
    }
    if (denied) { freeaddrinfo(list); errno = EACCES; return NULL; }
    return list;
}

int sp_authorize_target(struct agent *a, const char *user, const struct address *target, int type) {
    struct addrinfo *list = checked_addresses(a, user, target, type);
    if (!list) return -1;
    int fd = -1, saved = EHOSTUNREACH;
    for (struct addrinfo *p = list; p && !stopping; p = p->ai_next) {
        struct address numeric;
        if (address_from_sockaddr(p->ai_addr, p->ai_addrlen, &numeric)) continue;
        fd = dial_socket(&numeric, type, config.connect_timeout_ms);
        if (fd >= 0) break;
        saved = errno;
    }
    freeaddrinfo(list);
    if (fd < 0) errno = saved;
    return fd;
}

bool sp_destination_allowed(struct agent *a, const char *user, const char *host, const char *numeric) {
    pthread_mutex_lock(&a->lock);
    bool allowed = !denied_locked(a, user, host) && !denied_locked(a, user, numeric);
    pthread_mutex_unlock(&a->lock);
    return allowed;
}

bool sp_denied(struct agent *a, const char *user, const char *host, const char *addr) {
    bool judged = false;
    const char *values[] = {host, addr};
    for (size_t i = 0; i < 2; i++) {
        if (!values[i] || !*values[i]) continue;
        struct address target = {.port = 1};
        if (normalize(values[i], target.host)) return true;
        struct addrinfo *list = checked_addresses(a, user, &target, SOCK_STREAM);
        if (!list) return true;
        freeaddrinfo(list); judged = true;
    }
    return !judged;
}
