#include "internal.h"
#include <arpa/inet.h>
#include <ctype.h>
#ifndef SPARTA_CLIENT_ONLY
#include <curl/curl.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

int sp_copy(char *out, size_t cap, const char *s) {
    if (!s || strlen(s) >= cap) return -1;
    memcpy(out, s, strlen(s) + 1);
    return 0;
}

char *sp_read_file(const char *path, size_t max) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *data = malloc(max + 1);
    if (!data) { fclose(f); return NULL; }
    size_t n = fread(data, 1, max, f);
    int extra = fgetc(f), error = ferror(f);
    fclose(f);
    if (error || extra != EOF || memchr(data, 0, n)) { free(data); return NULL; }
    data[n] = 0;
    return data;
}

static bool json_tree(const cJSON *v, unsigned depth) {
    if (depth > 32) return false;
    size_t count = 0;
    for (const cJSON *p = v->child; p; p = p->next) {
        if (++count > 16384 || !json_tree(p, depth + 1)) return false;
        if (cJSON_IsObject(v)) {
            if (!p->string) return false;
            for (const cJSON *q = p->next; q; q = q->next)
                if (q->string && !strcmp(p->string, q->string)) return false;
        }
    }
    return !cJSON_IsNumber(v) || isfinite(v->valuedouble);
}

cJSON *sp_json(const char *text) {
    if (!text || strlen(text) > SP_MAX_JSON) return NULL;
    size_t length = strlen(text);
    for (size_t i = 0; i < length; i++) {
        const unsigned char *p = (const void *)(text + i);
        if (*p < 128) continue;
        size_t n = *p >= 0xc2 && *p <= 0xdf ? 2 : *p >= 0xe0 && *p <= 0xef ? 3 : *p >= 0xf0 && *p <= 0xf4 ? 4 : 0;
        if (!n || n > length - i) return NULL;
        for (size_t j = 1; j < n; j++) if ((p[j] & 0xc0) != 0x80) return NULL;
        if ((*p == 0xe0 && p[1] < 0xa0) || (*p == 0xed && p[1] >= 0xa0) ||
            (*p == 0xf0 && p[1] < 0x90) || (*p == 0xf4 && p[1] >= 0x90)) return NULL;
        i += n - 1;
    }
    /* cJSON represents strings as C strings: explicitly refuse embedded NULs. */
    for (const char *p = text; *p; p++) {
        if (*p != '\\') continue;
        p++;
        if (!*p) return NULL;
        if (*p == 'u' && !strncmp(p + 1, "0000", 4)) return NULL;
    }
    static pthread_mutex_t parse_lock = PTHREAD_MUTEX_INITIALIZER;
    const char *end;
    pthread_mutex_lock(&parse_lock);
    cJSON *v = cJSON_ParseWithOpts(text, &end, 1);
    pthread_mutex_unlock(&parse_lock);
    if (v && !json_tree(v, 0)) { cJSON_Delete(v); return NULL; }
    return v;
}

const char *sp_string(const cJSON *obj, const char *key) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

bool sp_integer(const cJSON *v, uint64_t max, uint64_t *out) {
    if (!cJSON_IsNumber(v) || !isfinite(v->valuedouble) || v->valuedouble < 0 ||
        v->valuedouble > (double)max || floor(v->valuedouble) != v->valuedouble) return false;
    *out = (uint64_t)v->valuedouble;
    return true;
}

bool sp_valid_host(const char *host) {
    unsigned char ip[16];
    if (!host || !*host || strlen(host) > 253) return false;
    if (inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host, ip) == 1) return true;
    const char *label = host;
    for (const char *p = host;; p++) {
        if (!*p || *p == '.') {
            if (p == label || p - label > 63 || label[0] == '-' || p[-1] == '-') return false;
            if (!*p) return true;
            label = p + 1;
        } else if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                     (*p >= '0' && *p <= '9') || *p == '-')) return false;
    }
}

int sp_profile(const char *json, const char *password, const char *override, const char *ca, struct profile *out) {
    cJSON *v = sp_json(json);
    if (!cJSON_IsObject(v)) { cJSON_Delete(v); return -1; }
    uint64_t version, port = 443;
    const char *host = sp_string(v, "host"), *path = sp_string(v, "path"), *user = sp_string(v, "user");
    const char *name = sp_string(v, "name"), *fp = sp_string(v, "fingerprint");
    if (!password) password = sp_string(v, "password");
    int result = -1;
    memset(out, 0, sizeof(*out));
    if (!sp_integer(cJSON_GetObjectItemCaseSensitive(v, "v"), 1, &version) || version != 1 ||
        !name || !*name || !sp_valid_host(host) || !path || path[0] != '/' ||
        !user || !*user || !password || !*password) goto done;
    size_t runes = 0;
    for (const unsigned char *p = (const void *)name; *p; p++) {
        if (*p < 32 || *p == 127) goto done;
        if ((*p & 0xc0) != 0x80) runes++;
    }
    if (runes > 40) goto done;
    if (fp && strcmp(fp, "native") && strcmp(fp, "safari") && strcmp(fp, "ios") &&
        strcmp(fp, "chrome") && strcmp(fp, "firefox")) goto done;
    for (const unsigned char *p = (const void *)path; *p; p++)
        if (*p <= 32 || *p >= 127 || strchr("?#\\\"<>", *p)) goto done;
    const cJSON *pv = cJSON_GetObjectItemCaseSensitive(v, "port");
    if (pv && (!sp_integer(pv, 65535, &port) || !port)) goto done;
    if (sp_copy(out->host, sizeof(out->host), host) || sp_copy(out->path, sizeof(out->path), path) ||
        sp_copy(out->user, sizeof(out->user), user) || sp_copy(out->password, sizeof(out->password), password) ||
        (ca && sp_copy(out->ca, sizeof(out->ca), ca))) goto done;
    sp_copy(out->node.host, sizeof(out->node.host), host);
    out->node.port = (uint16_t)port;
    out->origin_port = (uint16_t)port;
    if (override && *override) {
        unsigned char ip[16];
        if (parse_address(override, &out->node, false) ||
            (inet_pton(AF_INET, out->node.host, ip) != 1 && inet_pton(AF_INET6, out->node.host, ip) != 1)) goto done;
    }
    result = 0;
done:
    cJSON_Delete(v);
    if (result) memset(out, 0, sizeof(*out));
    return result;
}

char *sp_decode_link(const char *link, const char *kind) {
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "sparta://%s/v1/", kind);
    if (strncmp(link, prefix, strlen(prefix))) return NULL;
    const char *input = link + strlen(prefix);
    size_t len = strlen(input);
    while (len && isspace((unsigned char)input[len - 1])) len--;
    while (len && input[len - 1] == '=') len--;
    if (!len || len > 65536 || len % 4 == 1) return NULL;
    char *encoded = calloc(len + 5, 1), *out = calloc(len + 5, 1);
    if (!encoded || !out) { free(encoded); free(out); return NULL; }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)input[i];
        if (!(isalnum(c) || c == '-' || c == '_')) { free(encoded); free(out); return NULL; }
        encoded[i] = c == '-' ? '+' : c == '_' ? '/' : (char)c;
    }
    size_t padded = len;
    while (padded % 4) encoded[padded++] = '=';
    int n = EVP_DecodeBlock((unsigned char *)out, (unsigned char *)encoded, (int)padded);
    free(encoded);
    if (n < 0) { free(out); return NULL; }
    size_t used = (size_t)n - (padded - len);
    if (memchr(out, 0, used)) { free(out); return NULL; }
    out[used] = 0;
    return out;
}

#ifndef SPARTA_CLIENT_ONLY
static size_t http_body(char *data, size_t size, size_t count, void *arg) {
    struct http_result *r = arg;
    if (size && count > SIZE_MAX / size) return 0;
    size_t n = size * count;
    if (n > SP_MAX_JSON - r->len) return 0;
    char *next = realloc(r->body, r->len + n + 1);
    if (!next) return 0;
    r->body = next;
    memcpy(next + r->len, data, n);
    r->len += n;
    next[r->len] = 0;
    return n;
}

static size_t http_header(char *data, size_t size, size_t count, void *arg) {
    struct http_result *r = arg;
    size_t n = size * count;
    if (n > 6 && !strncasecmp(data, "ETag:", 5)) {
        size_t start = 5, end = n;
        while (start < end && (data[start] == ' ' || data[start] == '\t')) start++;
        while (end > start && (data[end - 1] == '\r' || data[end - 1] == '\n' || data[end - 1] == ' ')) end--;
        if (end - start < sizeof(r->etag)) {
            memcpy(r->etag, data + start, end - start);
            r->etag[end - start] = 0;
        }
    }
    return n;
}

static bool safe_header(const char *s) {
    if (!s) return true;
    for (; *s; s++) if ((unsigned char)*s < 32 || (unsigned char)*s == 127) return false;
    return true;
}

int sp_http(const char *method, const char *url, const char *token, const char *etag,
             const char *body, const char *ca, struct http_result *out) {
    memset(out, 0, sizeof(*out));
    if (!safe_header(token) || !safe_header(etag)) return -1;
    CURLU *u = curl_url();
    char *scheme = NULL, *host = NULL, *extra = NULL;
    bool valid = u && curl_url_set(u, CURLUPART_URL, url, 0) == CURLUE_OK &&
                 curl_url_get(u, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
                 curl_url_get(u, CURLUPART_HOST, &host, 0) == CURLUE_OK;
    if (valid) {
        unsigned char v4[4];
        bool loopback4 = inet_pton(AF_INET, host, v4) == 1 && v4[0] == 127;
        valid = !strcmp(scheme, "https") || (!strcmp(scheme, "http") &&
                (!strcmp(host, "localhost") || !strcmp(host, "[::1]") || loopback4 ||
                 (!strchr(host, '.') && !strchr(host, ':') && !strchr(host, '['))));
        const CURLUPart parts[] = {CURLUPART_USER, CURLUPART_PASSWORD, CURLUPART_QUERY, CURLUPART_FRAGMENT};
        for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
            if (curl_url_get(u, parts[i], &extra, 0) == CURLUE_OK) valid = false;
            curl_free(extra); extra = NULL;
        }
    }
    curl_free(scheme); curl_free(host); curl_url_cleanup(u);
    if (!valid) return -1;
    CURL *c = curl_easy_init();
    if (!c) return -1;
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    char value[1400];
    if (token && *token) {
        int n = snprintf(value, sizeof(value), "Authorization: Bearer %s", token);
        if (n < 0 || (size_t)n >= sizeof(value)) { curl_slist_free_all(headers); curl_easy_cleanup(c); return -1; }
        headers = curl_slist_append(headers, value);
    }
    if (etag && *etag) {
        snprintf(value, sizeof(value), "If-None-Match: %.255s", etag);
        headers = curl_slist_append(headers, value);
    }
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, 15000L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    if (ca && *ca) curl_easy_setopt(c, CURLOPT_CAINFO, ca);
    if (body) curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, http_body);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, out);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, http_header);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, out);
    CURLcode result = curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &out->status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(c);
    if (result != CURLE_OK || (out->body && memchr(out->body, 0, out->len))) { sp_http_free(out); return -1; }
    if (!out->body) out->body = strdup("");
    return out->body ? 0 : -1;
}

void sp_http_free(struct http_result *out) { free(out->body); memset(out, 0, sizeof(*out)); }
#endif

int sp_save(struct agent *a, const char *name, const char *data) {
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/.%s-XXXXXX", a->dir, name);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    int result = fchmod(fd, 0600);
    size_t left = strlen(data);
    const char *p = data;
    while (!result && left) {
        ssize_t wrote = write(fd, p, left);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) { result = -1; break; }
        p += wrote; left -= (size_t)wrote;
    }
    if (!result) result = fsync(fd);
    if (close(fd)) result = -1;
    if (!result) result = renameat(AT_FDCWD, path, a->dirfd, name);
    if (!result) result = fsync(a->dirfd);
    if (result) unlink(path);
    return result;
}
