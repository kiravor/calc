#include "gost.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct client { int fd; const struct endpoint *endpoint; struct client *next; };
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t drained = PTHREAD_COND_INITIALIZER;
static struct client *clients;
static unsigned active;

static void stop_signal(int signal_number) { (void)signal_number; stopping = 1; }

static void *worker(void *arg) {
    struct client *client = arg;
    handle_client(client->fd, client->endpoint);
    pthread_mutex_lock(&lock);
    struct client **p = &clients;
    while (*p && *p != client) p = &(*p)->next;
    if (*p) *p = client->next;
    /* Close while holding the list lock so shutdown cannot hit a reused fd. */
    close(client->fd);
    active--;
    pthread_cond_signal(&drained);
    pthread_mutex_unlock(&lock);
    free(client);
    return NULL;
}

int run_server(void) {
    struct sigaction action = {.sa_handler = stop_signal};
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
    pthread_t udp_threads[MAX_SERVICES];
    bool udp_started[MAX_SERVICES] = {0};
    struct pollfd p[MAX_SERVICES];
    int result = 0;
    /* Bind all sockets before accepting clients; fail the whole startup on errors. */
    for (size_t i = 0; i < config.service_count; i++) {
        struct service *service = &config.services[i];
        bool udp = service->endpoint.protocol == PROTO_UDP;
        service->fd = bind_socket(&service->endpoint.addr, udp ? SOCK_DGRAM : SOCK_STREAM);
        if (service->fd < 0) {
            fprintf(stderr, "Cannot bind listener %zu: %s\n", i + 1, strerror(errno));
            result = 1;
            goto done;
        }
        p[i] = (struct pollfd){.fd = udp ? -1 : service->fd, .events = POLLIN};
    }
    for (size_t i = 0; i < config.service_count; i++) {
        struct service *service = &config.services[i];
        if (service->endpoint.protocol == PROTO_UDP) {
            int rc = pthread_create(&udp_threads[i], NULL, udp_forward, service);
            if (rc) { fprintf(stderr, "Cannot start UDP worker: %s\n", strerror(rc)); result = 1; goto done; }
            udp_started[i] = true;
        }
        struct address bound;
        if (!socket_address(service->fd, false, &bound))
            fprintf(stderr, "Listening %s on [%s]:%u\n", protocol_name(service->endpoint.protocol), bound.host, bound.port);
    }
    while (!stopping) {
        int n = poll(p, config.service_count, 250);
        if (n < 0) { if (errno == EINTR) continue; result = 1; break; }
        for (size_t i = 0; i < config.service_count; i++) {
            if (p[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { result = 1; stopping = 1; break; }
            if (!(p[i].revents & POLLIN)) continue;
            int fd = accept(p[i].fd, NULL, NULL);
            if (fd < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                    fprintf(stderr, "Accept failed: %s\n", strerror(errno));
                continue;
            }
            if (set_nonblocking(fd)) { close(fd); continue; }
            pthread_mutex_lock(&lock);
            if (active >= config.max_clients) { pthread_mutex_unlock(&lock); close(fd); continue; }
            struct client *client = malloc(sizeof(*client));
            if (!client) { pthread_mutex_unlock(&lock); close(fd); continue; }
            *client = (struct client){.fd = fd, .endpoint = &config.services[i].endpoint, .next = clients};
            clients = client;
            active++;
            pthread_t thread;
            int rc = pthread_create(&thread, NULL, worker, client);
            if (rc) { clients = client->next; active--; close(fd); free(client); }
            else pthread_detach(thread);
            pthread_mutex_unlock(&lock);
        }
    }
done:
    stopping = 1;
    for (size_t i = 0; i < config.service_count; i++) if (udp_started[i]) pthread_join(udp_threads[i], NULL);
    for (size_t i = 0; i < config.service_count; i++) if (config.services[i].fd >= 0) close(config.services[i].fd);
    pthread_mutex_lock(&lock);
    for (struct client *client = clients; client; client = client->next) shutdown(client->fd, SHUT_RDWR);
    while (active) pthread_cond_wait(&drained, &lock);
    pthread_mutex_unlock(&lock);
    return result;
}
