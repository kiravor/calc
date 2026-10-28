#include "internal.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

#define WS_LIMIT 65536
struct ws {
    int fd, pipe;
    SSL_CTX *ctx;
    SSL *ssl;
    bool client;
    bool filter_relay;
    unsigned char relay_header[4];
    size_t relay_header_used, relay_skip;
    char verify_host[256];
};
static pthread_mutex_t ws_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ws_done = PTHREAD_COND_INITIALIZER;
static unsigned ws_count;

#ifdef __APPLE__
static bool apple_add_cert(CFMutableArrayRef array, X509 *cert) {
    unsigned char *der = NULL;
    int len = i2d_X509(cert, &der);
    if (len <= 0) { OPENSSL_free(der); return false; }
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, der, len);
    OPENSSL_free(der);
    if (!data) return false;
    SecCertificateRef native = SecCertificateCreateWithData(kCFAllocatorDefault, data);
    CFRelease(data);
    if (!native) return false;
    CFArrayAppendValue(array, native); CFRelease(native);
    return true;
}

static int apple_verify(X509_STORE_CTX *store, void *arg) {
    CFMutableArrayRef certs = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFStringRef host = CFStringCreateWithCString(kCFAllocatorDefault, arg, kCFStringEncodingUTF8);
    SecPolicyRef policy = host ? SecPolicyCreateSSL(true, host) : NULL;
    SecTrustRef trust = NULL;
    X509 *leaf = X509_STORE_CTX_get0_cert(store);
    bool valid = certs && policy && leaf && apple_add_cert(certs, leaf);
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_untrusted(store);
    for (int i = 0; valid && chain && i < sk_X509_num(chain); i++) {
        X509 *cert = sk_X509_value(chain, i);
        if (cert != leaf) valid = apple_add_cert(certs, cert);
    }
    valid = valid && SecTrustCreateWithCertificates(certs, policy, &trust) == errSecSuccess && SecTrustEvaluateWithError(trust, NULL);
    if (trust) CFRelease(trust);
    if (policy) CFRelease(policy);
    if (host) CFRelease(host);
    if (certs) CFRelease(certs);
    X509_STORE_CTX_set_error(store, valid ? X509_V_OK : X509_V_ERR_CERT_REJECTED);
    return valid ? 1 : 0;
}
#endif

/* A socket BIO that never raises SIGPIPE in an embedding application. */
static BIO_METHOD *socket_method;
static pthread_once_t bio_once = PTHREAD_ONCE_INIT;
static int bio_write(BIO *b, const char *data, int n) {
    BIO_clear_retry_flags(b);
    int result = (int)send((int)(intptr_t)BIO_get_data(b), data, (size_t)n, MSG_NOSIGNAL);
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_write(b);
    return result;
}
static int bio_read(BIO *b, char *data, int n) {
    BIO_clear_retry_flags(b);
    int result = (int)recv((int)(intptr_t)BIO_get_data(b), data, (size_t)n, 0);
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_read(b);
    return result;
}
static long bio_ctrl(BIO *b, int cmd, long n, void *ptr) {
    (void)b; (void)n; (void)ptr;
    return cmd == BIO_CTRL_FLUSH || cmd == BIO_CTRL_DUP ? 1 : 0;
}
static int bio_create(BIO *b) { BIO_set_init(b, 1); return 1; }
static void bio_init(void) {
    socket_method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "sparta socket");
    if (socket_method) {
        BIO_meth_set_write(socket_method, bio_write); BIO_meth_set_read(socket_method, bio_read);
        BIO_meth_set_ctrl(socket_method, bio_ctrl); BIO_meth_set_create(socket_method, bio_create);
    }
}

static ssize_t io_read(struct ws *w, void *buf, size_t n, short *want) {
    *want = POLLIN;
    if (!w->ssl) return recv(w->fd, buf, n, 0);
    int result = SSL_read(w->ssl, buf, (int)n);
    if (result > 0) return result;
    int error = SSL_get_error(w->ssl, result);
    if (error == SSL_ERROR_ZERO_RETURN) return 0;
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        *want = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        errno = EAGAIN;
    } else errno = ECONNRESET;
    return -1;
}

static ssize_t io_write(struct ws *w, const void *buf, size_t n, short *want) {
    *want = POLLOUT;
    if (!w->ssl) return send(w->fd, buf, n, MSG_NOSIGNAL);
    int result = SSL_write(w->ssl, buf, (int)n);
    if (result > 0) return result;
    int error = SSL_get_error(w->ssl, result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        *want = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        errno = EAGAIN;
    } else errno = ECONNRESET;
    return -1;
}

static int io_all(struct ws *w, void *buf, size_t n, bool write_mode, int64_t deadline) {
    unsigned char *p = buf;
    while (n && !stopping) {
        short want;
        ssize_t got = write_mode ? io_write(w, p, n, &want) : io_read(w, p, n, &want);
        if (got > 0) { p += got; n -= (size_t)got; continue; }
        if (got == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return -1;
        if (wait_fd(w->fd, want, deadline)) return -1;
    }
    return n ? -1 : 0;
}

static int ws_headers(struct ws *w, char *buf, size_t cap, int64_t deadline) {
    size_t used = 0;
    while (used + 1 < cap) {
        if (io_all(w, buf + used, 1, false, deadline)) return -1;
        unsigned char c = (unsigned char)buf[used++];
        if (!c || (c < 32 && c != '\r' && c != '\n' && c != '\t') || c == 127) return -1;
        if (used >= 4 && !memcmp(buf + used - 4, "\r\n\r\n", 4)) { buf[used] = 0; return 0; }
    }
    return -1;
}

/* Return a unique field; duplicate critical fields invalidate the handshake. */
static int field(const char *headers, const char *name, char *out, size_t cap) {
    const char *p = strstr(headers, "\r\n");
    bool found = false;
    size_t want = strlen(name);
    if (!p) return -1;
    for (p += 2; *p && strncmp(p, "\r\n", 2);) {
        const char *end = strstr(p, "\r\n"), *colon = strchr(p, ':');
        if (!end || !colon || colon >= end || *p == ' ' || *p == '\t') return -1;
        if ((size_t)(colon - p) == want && !strncasecmp(p, name, want)) {
            if (found) return -1;
            const char *start = colon + 1;
            while (start < end && (*start == ' ' || *start == '\t')) start++;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
            if ((size_t)(end - start) >= cap) return -1;
            memcpy(out, start, (size_t)(end - start)); out[end - start] = 0;
            found = true;
        }
        p = strstr(p, "\r\n") + 2;
    }
    return found ? 0 : -1;
}

static bool has_token(const char *list, const char *token) {
    size_t n = strlen(token);
    while (*list) {
        while (*list == ',' || *list == ' ' || *list == '\t') list++;
        const char *start = list;
        while (*list && *list != ',') list++;
        const char *end = list;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
        if ((size_t)(end - start) == n && !strncasecmp(start, token, n)) return true;
    }
    return false;
}

static int accept_key(const char *key, char out[64]) {
    if (strlen(key) != 24 || key[22] != '=' || key[23] != '=') return -1;
    unsigned char decoded[32];
    if (EVP_DecodeBlock(decoded, (const unsigned char *)key, 24) != 18) return -1;
    char raw[128]; unsigned char hash[20];
    snprintf(raw, sizeof(raw), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    if (!EVP_Digest(raw, strlen(raw), hash, NULL, EVP_sha1(), NULL)) return -1;
    base64_encode(hash, 20, out);
    return 0;
}

static size_t frame(unsigned char *out, unsigned opcode, const unsigned char *data, size_t n, bool mask) {
    size_t pos = 0;
    out[pos++] = (unsigned char)(0x80 | opcode);
    out[pos++] = (unsigned char)((mask ? 0x80 : 0) | (n < 126 ? n : 126));
    if (n >= 126) { out[pos++] = (unsigned char)(n >> 8); out[pos++] = (unsigned char)n; }
    unsigned char key[4] = {0};
    if (mask) {
        if (RAND_bytes(key, 4) != 1) return 0;
        memcpy(out + pos, key, 4); pos += 4;
    }
    for (size_t i = 0; i < n; i++) out[pos + i] = data[i] ^ key[i % 4];
    return pos + n;
}

static void ws_free(struct ws *w) {
    if (w->ssl) SSL_free(w->ssl);
    if (w->ctx) SSL_CTX_free(w->ctx);
    if (w->fd >= 0) close(w->fd);
    if (w->pipe >= 0) close(w->pipe);
    free(w);
}

static void *bridge(void *arg) {
    struct ws *w = arg;
    unsigned char input[WS_LIMIT + 14], output[WS_LIMIT + 14], plain[WS_LIMIT];
    size_t received = 0, written = 0, outgoing = 0, start = 0, end = 0;
    bool fragmented = false;
    short read_want = POLLIN, write_want = POLLOUT;
    int64_t ping = now_ms(), pong = ping;
    while (!stopping) {
        /* Decode one complete frame only while the destination buffer is free. */
        if (start == end && received >= 2) {
            start = end = 0;
            unsigned opcode = input[0] & 15;
            bool fin = !!(input[0] & 0x80), masked = !!(input[1] & 0x80);
            if ((input[0] & 0x70) || masked == w->client || (opcode != 0 && opcode != 2 && opcode != 8 && opcode != 9 && opcode != 10)) break;
            uint64_t length = input[1] & 127;
            size_t header = 2;
            if (length == 126) {
                if (received < 4) goto polling;
                length = ((unsigned)input[2] << 8) | input[3]; header = 4;
                if (length < 126) break;
            } else if (length == 127) {
                if (received < 10) goto polling;
                length = 0;
                for (size_t i = 2; i < 10; i++) length = (length << 8) | input[i];
                header = 10;
                if (length < 65536) break;
            }
            if (length > WS_LIMIT || (opcode >= 8 && (!fin || length > 125))) break;
            size_t payload = header + (masked ? 4 : 0);
            if (received < payload + (size_t)length) goto polling;
            if ((opcode == 9 || opcode == 8) && outgoing != written) goto polling;
            unsigned char key[4] = {0};
            if (masked) memcpy(key, input + header, 4);
            for (size_t i = 0; i < (size_t)length; i++) plain[i] = input[payload + i] ^ key[i % 4];
            if (opcode == 8) break;
            if (opcode == 9) {
                outgoing = frame(output, 10, plain, (size_t)length, w->client); written = 0;
                if (!outgoing) break;
            } else if (opcode == 10) pong = now_ms();
            else {
                if ((opcode == 0 && !fragmented) || (opcode == 2 && fragmented)) break;
                fragmented = !fin;
                end = (size_t)length;
                if (w->filter_relay) {
                    size_t pos = 0;
                    while (pos < end && w->relay_header_used < 4) w->relay_header[w->relay_header_used++] = plain[pos++];
                    if (w->relay_header_used == 4) {
                        if (w->relay_header[0] != 1 || w->relay_header[1]) break;
                        if (!w->relay_skip) {
                            w->relay_skip = (((size_t)w->relay_header[2] << 8) | w->relay_header[3]) + 1;
                            if (w->relay_skip > 4097) break;
                        }
                        size_t n = end - pos;
                        if (n > w->relay_skip - 1) n = w->relay_skip - 1;
                        pos += n; w->relay_skip -= n;
                        if (w->relay_skip == 1) w->filter_relay = false;
                    }
                    memmove(plain, plain + pos, end - pos); end -= pos;
                }
            }
            size_t consumed = payload + (size_t)length;
            memmove(input, input + consumed, received - consumed); received -= consumed;
            /* Buffered frames need processing even if the network is now quiet. */
            if (!end && received >= 2) continue;
        }
polling:
        if (end > start) pong = now_ms(); /* Local backpressure is not a peer failure. */
        if (now_ms() - pong > 120000) break;
        if (outgoing == written && now_ms() - ping >= 60000) {
            outgoing = frame(output, 9, (const unsigned char *)"", 0, w->client); written = 0; ping = now_ms();
            if (!outgoing) break;
        }
        struct pollfd p[2] = {{.fd = w->fd}, {.fd = w->pipe}};
        if (received < sizeof(input) && start == end) p[0].events |= read_want;
        if (outgoing > written) p[0].events |= write_want;
        if (outgoing == written) p[1].events |= POLLIN;
        if (end > start) p[1].events |= POLLOUT;
        if (!p[0].events) p[0].fd = -1;
        if (!p[1].events) p[1].fd = -1;
        bool pending = w->ssl && SSL_pending(w->ssl) > 0 && received < sizeof(input) && start == end;
        int n = poll(p, 2, pending ? 0 : 100);
        if (n < 0) { if (errno == EINTR) continue; break; }
        /* A reset may accompany a final buffered relay refusal. Drain readable
           bytes and flush the current frame before observing EOF/error. */
        if ((p[0].revents | p[1].revents) & POLLNVAL) break;
        if (outgoing > written && (p[0].revents & (write_want | POLLHUP))) {
            ssize_t sent = io_write(w, output + written, outgoing - written, &write_want);
            if (sent > 0) written += (size_t)sent;
            else if (sent == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) break;
        }
        if (end > start && (p[1].revents & (POLLOUT | POLLHUP))) {
            ssize_t sent = send(w->pipe, plain + start, end - start, MSG_NOSIGNAL);
            if (sent > 0) start += (size_t)sent;
            else if (sent == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) break;
        }
        if (outgoing == written && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            unsigned char data[16384];
            ssize_t got = recv(w->pipe, data, sizeof(data), 0);
            if (!got) break;
            if (got > 0) {
                outgoing = frame(output, 2, data, (size_t)got, w->client); written = 0;
                if (!outgoing) break;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
        }
        if (received < sizeof(input) && start == end && (pending || (p[0].revents & (read_want | POLLHUP | POLLERR)))) {
            ssize_t got = io_read(w, input + received, sizeof(input) - received, &read_want);
            if (!got) break;
            if (got > 0) received += (size_t)got;
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
        }
    }
    ws_free(w);
    pthread_mutex_lock(&ws_lock);
    ws_count--; pthread_cond_broadcast(&ws_done);
    pthread_mutex_unlock(&ws_lock);
    return NULL;
}

static int launch(struct ws *w) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) { ws_free(w); return -1; }
    if (set_nonblocking(pair[0]) || set_nonblocking(pair[1])) {
        close(pair[0]); close(pair[1]); ws_free(w); return -1;
    }
    w->pipe = pair[1];
    pthread_mutex_lock(&ws_lock); ws_count++;
    pthread_t thread;
    int result = pthread_create(&thread, NULL, bridge, w);
    if (result) ws_count--;
    pthread_mutex_unlock(&ws_lock);
    if (result) { close(pair[0]); ws_free(w); return -1; }
    pthread_detach(thread);
    return pair[0];
}

static int ws_client(const struct profile *p, bool filter_relay) {
    struct ws *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    w->fd = -1; w->pipe = -1; w->client = true;
    w->filter_relay = filter_relay;
    int64_t deadline = now_ms() + sp_timeout();
    w->fd = dial_socket(&p->node, SOCK_STREAM, sp_timeout());
    if (w->fd < 0) goto fail;
    int yes = 1;
    setsockopt(w->fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
#ifdef TCP_KEEPIDLE
    int idle = 90;
    setsockopt(w->fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
    w->ctx = SSL_CTX_new(TLS_client_method());
    if (!w->ctx || !SSL_CTX_set_min_proto_version(w->ctx, TLS1_2_VERSION)) goto tls_fail;
    SSL_CTX_set_verify(w->ctx, SSL_VERIFY_PEER, NULL);
#ifdef __APPLE__
    if (!*p->ca) {
        sp_copy(w->verify_host, sizeof(w->verify_host), p->host);
        SSL_CTX_set_cert_verify_callback(w->ctx, apple_verify, w->verify_host);
    } else if (!SSL_CTX_load_verify_locations(w->ctx, p->ca, NULL)) goto tls_fail;
#else
    if (*p->ca ? !SSL_CTX_load_verify_locations(w->ctx, p->ca, NULL) : !SSL_CTX_set_default_verify_paths(w->ctx)) goto tls_fail;
#endif
    SSL_CTX_set_options(w->ctx, SSL_OP_NO_RENEGOTIATION);
    w->ssl = SSL_new(w->ctx);
    pthread_once(&bio_once, bio_init);
    BIO *bio = socket_method ? BIO_new(socket_method) : NULL;
    if (!w->ssl || !bio) { BIO_free(bio); goto tls_fail; }
    BIO_set_data(bio, (void *)(intptr_t)w->fd);
    SSL_set_bio(w->ssl, bio, bio);
    unsigned char ip[16];
    if (inet_pton(AF_INET, p->host, ip) == 1 || inet_pton(AF_INET6, p->host, ip) == 1) {
        if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(w->ssl), p->host)) goto tls_fail;
    } else if (!SSL_set1_host(w->ssl, p->host) || !SSL_set_tlsext_host_name(w->ssl, p->host)) goto tls_fail;
    static const unsigned char alpn[] = {8,'h','t','t','p','/','1','.','1'};
    if (SSL_set_alpn_protos(w->ssl, alpn, sizeof(alpn))) goto tls_fail;
    for (;;) {
        int n = SSL_connect(w->ssl);
        if (n == 1) break;
        int e = SSL_get_error(w->ssl, n);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) goto tls_fail;
        if (wait_fd(w->fd, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline)) goto fail;
    }
    unsigned char random[16]; char key[32], expected[64];
    if (RAND_bytes(random, sizeof(random)) != 1) goto fail;
    base64_encode(random, sizeof(random), key);
    if (accept_key(key, expected)) goto fail;
    char request[4096], answer[HEADER_CAP], upgrade[64], connection[256], accept[128];
    int n = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s%s%s:%u\r\n"
                     "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Key: %s\r\nUser-Agent: sparta-c/0.2\r\n\r\n", p->path,
                     strchr(p->host, ':') ? "[" : "", p->host, strchr(p->host, ':') ? "]" : "", p->origin_port, key);
    if (n < 0 || (size_t)n >= sizeof(request) || io_all(w, request, (size_t)n, true, deadline) ||
        ws_headers(w, answer, sizeof(answer), deadline)) goto fail;
    int code = 0;
    if (sscanf(answer, "HTTP/1.1 %d", &code) != 1 || code != 101) { errno = code == 404 || code == 401 || code == 403 ? EACCES : EPROTO; goto fail; }
    if (field(answer, "Upgrade", upgrade, sizeof(upgrade)) || strcasecmp(upgrade, "websocket") ||
        field(answer, "Connection", connection, sizeof(connection)) || !has_token(connection, "upgrade") ||
        field(answer, "Sec-WebSocket-Accept", accept, sizeof(accept)) || strcmp(accept, expected)) { errno = EPROTO; goto fail; }
    return launch(w);
tls_fail:
    errno = EILSEQ;
fail: {
        int saved = errno; ws_free(w); errno = saved; return -1;
    }
}

int sp_ws_client(const struct profile *p) { return ws_client(p, false); }
int sp_ws_client_filtered(const struct profile *p) { return ws_client(p, true); }

int sp_ws_server(int fd, const char *path) {
    struct ws *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    /* Keep the caller's fd in its worker registry until that worker finishes. */
    w->fd = dup(fd); w->pipe = -1;
    if (w->fd < 0 || set_nonblocking(w->fd)) { ws_free(w); return -1; }
    char input[HEADER_CAP], expected_line[2100], key[64], accept[64], upgrade[64], connection[256], version[16];
    if (ws_headers(w, input, sizeof(input), now_ms() + config.connect_timeout_ms)) goto fail;
    snprintf(expected_line, sizeof(expected_line), "GET %s HTTP/1.1\r\n", path);
    if (strncmp(input, expected_line, strlen(expected_line)) ||
        field(input, "Upgrade", upgrade, sizeof(upgrade)) || strcasecmp(upgrade, "websocket") ||
        field(input, "Connection", connection, sizeof(connection)) || !has_token(connection, "upgrade") ||
        field(input, "Sec-WebSocket-Version", version, sizeof(version)) || strcmp(version, "13") ||
        field(input, "Sec-WebSocket-Key", key, sizeof(key)) || accept_key(key, accept)) {
        char response[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        io_all(w, response, sizeof(response) - 1, true, now_ms() + 1000);
        goto fail;
    }
    char response[256];
    int n = snprintf(response, sizeof(response), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept);
    if (n < 0 || io_all(w, response, (size_t)n, true, now_ms() + config.connect_timeout_ms)) goto fail;
    return launch(w);
fail:
    ws_free(w);
    return -1;
}

void sp_ws_drain(void) {
    pthread_mutex_lock(&ws_lock);
    while (ws_count) pthread_cond_wait(&ws_done, &ws_lock);
    pthread_mutex_unlock(&ws_lock);
}
