#include "internal.h"
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

void sp_client_udp(int control, const struct address *requested) {
    struct address local, peer, any = {.host = "0.0.0.0", .port = 0};
    struct sockaddr_storage tcp_peer;
    socklen_t tcp_len = sizeof(tcp_peer);
    int udp = -1, tunnel = -1;
    if (socket_address(control, false, &local) || socket_address(control, true, &peer) ||
        getpeername(control, (struct sockaddr *)&tcp_peer, &tcp_len)) goto fail;
    if (strcmp(requested->host, "0.0.0.0") && strcmp(requested->host, "::") && strcmp(requested->host, peer.host)) goto fail;
    local.port = 0;
    udp = bind_socket(&local, SOCK_DGRAM);
    if (udp < 0) goto fail;
    tunnel = sp_ws_client(&client_profile);
    if (tunnel < 0 || sp_relay_send(tunnel, 0x82, 1, &any, &client_profile) || sp_relay_verdict(tunnel)) goto fail;
    unsigned char reply[300] = {5, 0, 0};
    if (socket_address(udp, false, &local)) goto fail;
    int packed = socks_pack_address(&local, reply + 3, sizeof(reply) - 3);
    if (packed < 0 || send_all(control, reply, (size_t)packed + 3, config.timeout_ms)) goto done;
    struct sockaddr_storage client = {0}; socklen_t client_len = 0;
    unsigned char tx[66000], rx[66000], packet[66000];
    size_t outgoing = 0, written = 0, received = 0;
    int64_t last = now_ms();
    while (!stopping && now_ms() - last < config.timeout_ms) {
        struct pollfd p[3] = {{.fd = control, .events = POLLIN}, {.fd = udp, .events = POLLIN},
                             {.fd = tunnel, .events = POLLIN | (outgoing > written ? POLLOUT : 0)}};
        int n = poll(p, 3, 100);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (p[0].revents || (p[1].revents & (POLLERR | POLLNVAL)) || (p[2].revents & (POLLERR | POLLNVAL))) break;
        if (outgoing > written && (p[2].revents & (POLLOUT | POLLHUP))) {
            ssize_t sent = send(tunnel, tx + written, outgoing - written, 0);
            if (sent > 0) written += (size_t)sent;
            else if (sent == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) break;
        }
        if (p[1].revents & POLLIN) {
            struct sockaddr_storage from = {0}; socklen_t len = sizeof(from);
            ssize_t got = recvfrom(udp, packet, sizeof(packet), 0, (struct sockaddr *)&from, &len);
            if (got >= 4 && outgoing == written && same_peer(&from, &tcp_peer, false) &&
                (!client_len || same_peer(&from, &client, true)) && !packet[0] && !packet[1] && !packet[2]) {
                struct address source, target; size_t header;
                if (!address_from_sockaddr((struct sockaddr *)&from, len, &source) &&
                    (!requested->port || requested->port == source.port) &&
                    !socks_unpack_address(packet + 3, (size_t)got - 3, &target, &header) && target.port && target.port != 443) {
                    size_t payload = (size_t)got - header - 3;
                    if (payload <= 65535) {
                        memcpy(tx, packet, (size_t)got);
                        tx[0] = (unsigned char)(payload >> 8); tx[1] = (unsigned char)payload; tx[2] = 255;
                        outgoing = (size_t)got; written = 0;
                        if (!client_len) { client = from; client_len = len; }
                        last = now_ms();
                    }
                }
            }
        }
        if (received < sizeof(rx) && (p[2].revents & (POLLIN | POLLHUP))) {
            ssize_t got = recv(tunnel, rx + received, sizeof(rx) - received, 0);
            if (!got) break;
            if (got > 0) received += (size_t)got;
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
        }
        while (received) {
            struct address source; size_t header, payload;
            int ready = sp_read_datagram(rx, received, &source, &header, &payload);
            if (ready < 0) goto done;
            if (!ready) break;
            if (client_len && source.port) {
                memcpy(packet, rx, header + payload); packet[0] = packet[1] = packet[2] = 0;
                sendto(udp, packet, header + payload, 0, (struct sockaddr *)&client, client_len);
            }
            size_t consumed = header + payload;
            memmove(rx, rx + consumed, received - consumed); received -= consumed;
            last = now_ms();
        }
        if (received == sizeof(rx)) break;
    }
    goto done;
fail: {
        static const unsigned char refused[] = {5, 1, 0, 1, 0, 0, 0, 0, 0, 0};
        send_all(control, refused, sizeof(refused), config.timeout_ms);
    }
done:
    if (tunnel >= 0) close(tunnel);
    if (udp >= 0) close(udp);
}
