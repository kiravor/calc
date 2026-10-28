#include "internal.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char node_ws_path[2048];

static void node_tcp(int tunnel, int remote, const char *user) {
    struct direction { unsigned char buf[16384]; size_t start, end; bool eof, shut; int64_t wait; } d[2] = {0};
    int fds[] = {tunnel, remote};
    int64_t last = now_ms();
    while (!stopping && now_ms() - last < config.timeout_ms && sp_rate(&node_agent, user) != UINT64_MAX) {
        struct pollfd p[2] = {{.fd = tunnel}, {.fd = remote}};
        bool done = true;
        for (unsigned i = 0; i < 2; i++) {
            if (d[i].start == d[i].end) {
                d[i].start = d[i].end = 0;
                if (d[i].eof && !d[i].shut) { shutdown(fds[1-i], SHUT_WR); d[i].shut = true; }
            }
            if (!d[i].eof && d[i].end < sizeof(d[i].buf)) p[i].events |= POLLIN;
            if (d[i].end > d[i].start && now_ms() >= d[i].wait) p[1-i].events |= POLLOUT;
            if (!d[i].eof || d[i].start != d[i].end) done = false;
        }
        if (done) break;
        for (unsigned i = 0; i < 2; i++) if (!p[i].events) p[i].fd = -1;
        int n = poll(p, 2, 10);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if ((p[0].revents | p[1].revents) & (POLLERR | POLLNVAL)) break;
        for (unsigned i = 0; i < 2; i++) {
            if (d[i].end > d[i].start && (p[1-i].revents & (POLLOUT | POLLHUP))) {
                ssize_t sent = sp_limited_send(&node_agent, user, (int)i, fds[1-i], d[i].buf + d[i].start, d[i].end - d[i].start);
                if (sent > 0) { d[i].start += (size_t)sent; last = now_ms(); }
                else if (errno == ENOBUFS) d[i].wait = now_ms() + 10;
                else if (sent == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return;
            }
            if (!d[i].eof && d[i].end < sizeof(d[i].buf) && (p[i].revents & (POLLIN | POLLHUP))) {
                ssize_t got = recv(fds[i], d[i].buf + d[i].end, sizeof(d[i].buf) - d[i].end, 0);
                if (got > 0) { d[i].end += (size_t)got; last = now_ms(); }
                else if (!got) d[i].eof = true;
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return;
            }
        }
    }
}

struct node_flow { int fd; struct address target, numeric; int64_t last; };

static void node_udp(int tunnel, const char *user) {
    struct node_flow flows[MAX_FLOWS];
    for (size_t i = 0; i < MAX_FLOWS; i++) flows[i].fd = -1;
    struct address bound = {.host = "0.0.0.0"};
    if (sp_relay_response(tunnel, 0, &bound)) return;
    unsigned char rx[66000], tx[66000], payload[65536];
    size_t received = 0, outgoing = 0, written = 0;
    int64_t last = now_ms(), write_after = 0;
    while (!stopping && now_ms() - last < config.timeout_ms && sp_rate(&node_agent, user) != UINT64_MAX) {
        struct pollfd p[MAX_FLOWS + 1] = {{.fd = tunnel, .events = POLLIN}};
        if (outgoing > written && now_ms() >= write_after) p[0].events |= POLLOUT;
        for (size_t i = 0; i < MAX_FLOWS; i++) {
            if (flows[i].fd >= 0 && (now_ms() - flows[i].last >= config.timeout_ms ||
                !sp_destination_allowed(&node_agent, user, flows[i].target.host, flows[i].numeric.host))) {
                close(flows[i].fd); flows[i].fd = -1;
            }
            p[i + 1] = (struct pollfd){.fd = outgoing == written ? flows[i].fd : -1, .events = POLLIN};
        }
        int n = poll(p, MAX_FLOWS + 1, 10);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (p[0].revents & (POLLERR | POLLNVAL)) break;
        if (outgoing > written && (p[0].revents & (POLLOUT | POLLHUP))) {
            ssize_t sent = sp_limited_send(&node_agent, user, 1, tunnel, tx + written, outgoing - written);
            if (sent > 0) { written += (size_t)sent; last = now_ms(); }
            else if (errno == ENOBUFS) write_after = now_ms() + 10;
            else if (sent == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) break;
        }
        if (received < sizeof(rx) && (p[0].revents & (POLLIN | POLLHUP))) {
            ssize_t got = recv(tunnel, rx + received, sizeof(rx) - received, 0);
            if (!got) break;
            if (got > 0) received += (size_t)got;
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
        }
        while (received) {
            struct address target; size_t header, size;
            int ready = sp_read_datagram(rx, received, &target, &header, &size);
            if (ready < 0) goto done;
            if (!ready) break;
            if (target.port && target.port != 443) {
                size_t slot = MAX_FLOWS, empty = MAX_FLOWS;
                for (size_t i = 0; i < MAX_FLOWS; i++) {
                    if (flows[i].fd < 0) { if (empty == MAX_FLOWS) empty = i; continue; }
                    if (flows[i].target.port == target.port && !strcmp(flows[i].target.host, target.host)) { slot = i; break; }
                }
                if (slot == MAX_FLOWS && empty != MAX_FLOWS) {
                    int fd = sp_authorize_target(&node_agent, user, &target, SOCK_DGRAM);
                    if (fd >= 0) {
                        slot = empty; flows[slot] = (struct node_flow){.fd = fd, .target = target, .last = now_ms()};
                        if (socket_address(fd, true, &flows[slot].numeric)) { close(fd); flows[slot].fd = -1; slot = MAX_FLOWS; }
                        p[empty + 1].revents = 0;
                    }
                }
                if (slot != MAX_FLOWS && sp_limited_send(&node_agent, user, 2, flows[slot].fd, rx + header, size) >= 0)
                    last = flows[slot].last = now_ms();
            }
            size_t consumed = header + size;
            memmove(rx, rx + consumed, received - consumed); received -= consumed;
        }
        if (received == sizeof(rx)) break;
        for (size_t i = 0; i < MAX_FLOWS && outgoing == written; i++) {
            if (flows[i].fd < 0 || !p[i+1].revents) continue;
            if (p[i+1].revents & (POLLERR | POLLNVAL)) { close(flows[i].fd); flows[i].fd = -1; continue; }
            if (!(p[i+1].revents & POLLIN)) continue;
            ssize_t got = recv(flows[i].fd, payload, sizeof(payload), 0);
            if (got < 0) continue;
            int header = socks_pack_address(&flows[i].numeric, tx + 3, sizeof(tx) - 3);
            if (header < 0 || got > 65535) continue;
            tx[0] = (unsigned char)((size_t)got >> 8); tx[1] = (unsigned char)got; tx[2] = 255;
            memcpy(tx + 3 + header, payload, (size_t)got);
            outgoing = (size_t)got + (size_t)header + 3; written = 0;
            last = flows[i].last = now_ms();
        }
    }
done:
    for (size_t i = 0; i < MAX_FLOWS; i++) if (flows[i].fd >= 0) close(flows[i].fd);
}

void sp_node_client(int fd) {
    int tunnel = sp_ws_server(fd, node_ws_path);
    if (tunnel < 0) return;
    struct relay_request req;
    if (sp_relay_read(tunnel, &req)) { sp_relay_response(tunnel, 1, NULL); goto done; }
    bool authenticated = sp_auth(&node_agent, req.user, req.password);
    OPENSSL_cleanse(req.password, sizeof(req.password));
    if (!authenticated) { sp_relay_response(tunnel, 2, NULL); goto done; }
    if (req.cmd == 2 && req.network == 1) {
        if (req.addr.port || (strcmp(req.addr.host, "0.0.0.0") && strcmp(req.addr.host, "::"))) {
            sp_relay_response(tunnel, 3, NULL); goto done;
        }
        node_udp(tunnel, req.user); goto done;
    }
    if (req.cmd != 1 || req.network) { sp_relay_response(tunnel, 1, NULL); goto done; }
    int remote = sp_authorize_target(&node_agent, req.user, &req.addr, SOCK_STREAM);
    if (remote < 0) { sp_relay_response(tunnel, errno == EACCES ? 3 : errno == ETIMEDOUT ? 4 : 6, NULL); goto done; }
    if (!sp_relay_response(tunnel, 0, NULL)) node_tcp(tunnel, remote, req.user);
    close(remote);
done:
    close(tunnel);
}

int sp_serve_node(const cJSON *cfg) {
    const char *listen = sp_string(cfg, "listen"), *path = sp_string(cfg, "ws_path");
    if (!path || *path != '/' || sp_copy(node_ws_path, sizeof(node_ws_path), path)) return -1;
    for (const char *p = path; *p; p++) if ((unsigned char)*p <= 32 || (unsigned char)*p >= 127 || strchr("?#\\", *p)) return -1;
    config = (struct config){.service_count = 1, .timeout_ms = 180000, .connect_timeout_ms = 10000,
                             .max_clients = 96, .client_override = sp_node_client, .transport_drain = sp_ws_drain};
    config.services[0].fd = -1;
    config.services[0].endpoint.protocol = PROTO_TCP;
    if (parse_address(listen ? listen : "127.0.0.1:8080", &config.services[0].endpoint.addr, true)) return -1;
    if (sp_agent_init(&node_agent, cfg)) return -1;
    bool plugins = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(cfg, "plugins_enabled"));
    if (sp_agent_start(&node_agent, plugins)) { stopping = 1; sp_agent_close(&node_agent); return -1; }
    int result = run_server();
    stopping = 1; sp_save_counts(&node_agent); sp_agent_close(&node_agent);
    return result;
}
