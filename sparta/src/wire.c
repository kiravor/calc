#include "internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

_Thread_local int64_t sp_deadline;
int sp_timeout(void) {
    if (!sp_deadline) return config.connect_timeout_ms;
    int64_t left = sp_deadline - now_ms();
    if (left <= 0) return 0;
    return left < config.connect_timeout_ms ? (int)left : config.connect_timeout_ms;
}

int sp_relay_send(int fd, int cmd, int network, const struct address *addr, const struct profile *p) {
    unsigned char buf[1100] = {1, (unsigned char)cmd, 0, 0};
    size_t used = 4, u = strlen(p->user), pass = strlen(p->password);
    size_t auth = u + pass + 2;
    buf[used++] = 1; buf[used++] = (unsigned char)(auth >> 8); buf[used++] = (unsigned char)auth;
    buf[used++] = (unsigned char)u;
    memcpy(buf + used, p->user, u); used += u;
    buf[used++] = (unsigned char)pass;
    memcpy(buf + used, p->password, pass); used += pass;
    buf[used++] = 4; buf[used++] = 0; buf[used++] = 2;
    buf[used++] = 0; buf[used++] = (unsigned char)network;
    buf[used++] = 2;
    size_t length = used; used += 2;
    int n = socks_pack_address(addr, buf + used, sizeof(buf) - used);
    if (n < 0) return -1;
    buf[length] = (unsigned char)(n >> 8); buf[length + 1] = (unsigned char)n;
    used += (size_t)n;
    buf[2] = (unsigned char)((used - 4) >> 8); buf[3] = (unsigned char)(used - 4);
    return send_all(fd, buf, used, sp_timeout());
}

int sp_relay_read(int fd, struct relay_request *out) {
    unsigned char buf[4096], header[4];
    memset(out, 0, sizeof(*out));
    if (read_exact(fd, header, 4, config.connect_timeout_ms) || header[0] != 1 || (header[1] & 0x70)) return -1;
    size_t len = ((size_t)header[2] << 8) | header[3];
    if (len > sizeof(buf) || read_exact(fd, buf, len, config.connect_timeout_ms)) return -1;
    out->cmd = header[1] & 0x0f;
    out->network = !!(header[1] & 0x80);
    bool auth = false, addr = false, net = false;
    for (size_t pos = 0; pos < len;) {
        if (len - pos < 3) return -1;
        unsigned type = buf[pos++];
        size_t n = ((size_t)buf[pos] << 8) | buf[pos + 1]; pos += 2;
        if (n > len - pos) return -1;
        const unsigned char *data = buf + pos;
        if (type == 1) {
            if (auth || n < 2) return -1;
            size_t u = data[0];
            if (!u || u + 2 > n) return -1;
            size_t p = data[u + 1];
            if (!p || u + p + 2 != n || memchr(data + 1, 0, u) || memchr(data + u + 2, 0, p)) return -1;
            memcpy(out->user, data + 1, u);
            memcpy(out->password, data + u + 2, p);
            auth = true;
        } else if (type == 2) {
            size_t consumed;
            if (addr || socks_unpack_address(data, n, &out->addr, &consumed) || consumed != n) return -1;
            addr = true;
        } else if (type == 4) {
            if (net || n != 2 || data[0] || data[1] > 1 || ((header[1] & 0x80) && data[1] != 1)) return -1;
            out->network = data[1]; net = true;
        }
        pos += n;
    }
    return auth && addr ? 0 : -1;
}

int sp_relay_response(int fd, int status, const struct address *addr) {
    unsigned char buf[300] = {1, (unsigned char)status, 0, 0};
    size_t size = 4;
    if (addr) {
        buf[4] = 2;
        int n = socks_pack_address(addr, buf + 7, sizeof(buf) - 7);
        if (n < 0) return -1;
        buf[5] = (unsigned char)(n >> 8); buf[6] = (unsigned char)n;
        size += (size_t)n + 3;
        buf[2] = (unsigned char)((size - 4) >> 8); buf[3] = (unsigned char)(size - 4);
    }
    return send_all(fd, buf, size, config.connect_timeout_ms);
}

int sp_relay_verdict(int fd) {
    unsigned char header[4], buf[4096];
    if (read_exact(fd, header, 4, sp_timeout()) || header[0] != 1) return -1;
    size_t len = ((size_t)header[2] << 8) | header[3];
    if (len > sizeof(buf) || read_exact(fd, buf, len, sp_timeout())) return -1;
    if (header[1]) { errno = header[1] == 2 || header[1] == 3 ? EACCES : header[1] == 4 ? ETIMEDOUT : EHOSTUNREACH; return -1; }
    return 0;
}

/* GOST UDP-over-stream: payload length in RSV, FRAG=0xff, SOCKS address,
   payload. Return 1 for a complete frame, 0 for incomplete, -1 for invalid. */
int sp_read_datagram(const unsigned char *buf, size_t len, struct address *addr, size_t *header, size_t *payload) {
    if (len < 4) return 0;
    if (buf[2] != 255) return -1;
    size_t addr_len;
    if (buf[3] == 1) addr_len = 7;
    else if (buf[3] == 4) addr_len = 19;
    else if (buf[3] == 3) {
        if (len < 5) return 0;
        if (!buf[4]) return -1;
        addr_len = (size_t)buf[4] + 4;
    } else return -1;
    if (len < addr_len + 3) return 0;
    size_t consumed;
    if (socks_unpack_address(buf + 3, addr_len, addr, &consumed) || consumed != addr_len) return -1;
    *header = addr_len + 3;
    *payload = ((size_t)buf[0] << 8) | buf[1];
    return len >= *header + *payload ? 1 : 0;
}
