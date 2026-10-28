#include "gost.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct flow {
    int fd;
    struct sockaddr_storage client;
    socklen_t client_len;
    struct address target;
    int64_t last;
};

static void run_udp(int fd, int control, const struct address *target,
                    const struct sockaddr_storage *tcp_peer, uint16_t requested_port) {
    struct flow flows[MAX_FLOWS];
    for (size_t i = 0; i < MAX_FLOWS; i++) flows[i].fd = -1;
    struct sockaddr_storage associated = {0};
    socklen_t associated_len = 0;
    int64_t last = now_ms();
    unsigned char packet[65536], response[65536];
    while (!stopping) {
        int64_t now = now_ms();
        if (control >= 0 && now - last >= config.timeout_ms) break;
        struct pollfd p[MAX_FLOWS + 2] = {{.fd = fd, .events = POLLIN}, {.fd = control, .events = POLLIN}};
        for (size_t i = 0; i < MAX_FLOWS; i++) {
            if (flows[i].fd >= 0 && now - flows[i].last >= config.timeout_ms) {
                close(flows[i].fd);
                flows[i].fd = -1;
            }
            p[i + 2] = (struct pollfd){.fd = flows[i].fd, .events = POLLIN};
        }
        int ready = poll(p, MAX_FLOWS + 2, 250);
        if (ready < 0) { if (errno == EINTR) continue; break; }
        if (control >= 0 && p[1].revents) break;
        if (p[0].revents & (POLLERR | POLLNVAL)) break;
        if (p[0].revents & POLLIN) {
            struct sockaddr_storage client = {0};
            socklen_t len = sizeof(client);
            ssize_t n = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&client, &len);
            if (n >= 0) {
                size_t skip = 0;
                struct address destination;
                if (control >= 0) {
                    if (!same_peer(&client, tcp_peer, false)) goto replies;
                    if (associated_len && !same_peer(&client, &associated, true)) goto replies;
                    struct address source;
                    if (address_from_sockaddr((struct sockaddr *)&client, len, &source)) goto replies;
                    if (requested_port && requested_port != source.port) goto replies;
                    if (n < 4 || packet[0] || packet[1] || packet[2]) goto replies; /* FRAG unsupported. */
                    if (socks_unpack_address(packet + 3, (size_t)n - 3, &destination, &skip) ||
                        !destination.port) goto replies;
                    skip += 3;
                    if (!associated_len) { associated = client; associated_len = len; }
                } else destination = *target;
                size_t slot = MAX_FLOWS, empty = MAX_FLOWS;
                for (size_t i = 0; i < MAX_FLOWS; i++) {
                    if (flows[i].fd < 0) { if (empty == MAX_FLOWS) empty = i; continue; }
                    bool match = control >= 0 ?
                        flows[i].target.port == destination.port && !strcmp(flows[i].target.host, destination.host) :
                        same_peer(&flows[i].client, &client, true);
                    if (match) { slot = i; break; }
                }
                if (slot == MAX_FLOWS) {
                    if (empty == MAX_FLOWS) goto replies;
                    int remote = dial_socket(&destination, SOCK_DGRAM, config.connect_timeout_ms);
                    if (remote < 0) goto replies;
                    slot = empty;
                    flows[slot] = (struct flow){.fd = remote, .client = client, .client_len = len,
                                               .target = destination, .last = now_ms()};
                    /* p[] describes the old descriptor, not this newly created socket. */
                    p[slot + 2].revents = 0;
                }
                if (send(flows[slot].fd, packet + skip, (size_t)n - skip, 0) >= 0)
                    last = flows[slot].last = now_ms();
            }
        }
replies:
        /* Invalid/new packets must not starve responses on established flows. */
        for (size_t i = 0; i < MAX_FLOWS; i++) {
            if (flows[i].fd < 0 || !p[i + 2].revents) continue;
            if (p[i + 2].revents & (POLLERR | POLLNVAL)) {
                close(flows[i].fd);
                flows[i].fd = -1;
                continue;
            }
            if (!(p[i + 2].revents & POLLIN)) continue;
            ssize_t n = recv(flows[i].fd, packet, sizeof(packet), 0);
            if (n < 0) continue;
            if (control >= 0) {
                struct address source;
                if (socket_address(flows[i].fd, true, &source)) continue;
                memset(response, 0, 3);
                int size = socks_pack_address(&source, response + 3, sizeof(response) - 3);
                if (size < 0 || (size_t)n > sizeof(response) - (size_t)size - 3) continue;
                size_t header = (size_t)size + 3;
                memcpy(response + header, packet, (size_t)n);
                sendto(fd, response, header + (size_t)n, 0, (struct sockaddr *)&associated, associated_len);
            } else {
                sendto(fd, packet, (size_t)n, 0, (struct sockaddr *)&flows[i].client, flows[i].client_len);
            }
            last = flows[i].last = now_ms();
        }
    }
    for (size_t i = 0; i < MAX_FLOWS; i++) if (flows[i].fd >= 0) close(flows[i].fd);
}

void *udp_forward(void *arg) {
    struct service *service = arg;
    run_udp(service->fd, -1, &service->endpoint.target, NULL, 0);
    return NULL;
}

void handle_socks_udp(int control, const struct address *requested) {
    struct address local, peer;
    struct sockaddr_storage tcp_peer;
    socklen_t peer_len = sizeof(tcp_peer);
    if (socket_address(control, false, &local) || socket_address(control, true, &peer) ||
        getpeername(control, (struct sockaddr *)&tcp_peer, &peer_len)) return;
    if (strcmp(requested->host, "0.0.0.0") && strcmp(requested->host, "::") && strcmp(requested->host, peer.host)) {
        static const unsigned char denied[] = {5, 2, 0, 1, 0, 0, 0, 0, 0, 0};
        send_all(control, denied, sizeof(denied), config.timeout_ms);
        return;
    }
    local.port = 0;
    int fd = bind_socket(&local, SOCK_DGRAM);
    if (fd < 0) {
        static const unsigned char failed[] = {5, 1, 0, 1, 0, 0, 0, 0, 0, 0};
        send_all(control, failed, sizeof(failed), config.timeout_ms);
        return;
    }
    unsigned char reply[260] = {5, 0, 0};
    if (!socket_address(fd, false, &local)) {
        int n = socks_pack_address(&local, reply + 3, sizeof(reply) - 3);
        if (n > 0 && !send_all(control, reply, (size_t)n + 3, config.timeout_ms))
            run_udp(fd, control, NULL, &tcp_peer, requested->port);
    }
    close(fd);
}
