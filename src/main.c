#include "gost.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out) {
    fputs("gost-c 0.1.0 — HTTP/SOCKS5 and TCP/UDP proxy (C17, POSIX)\n"
          "Usage: gost-c -L URL [-L URL ...] [-F URL ...] [options]\n"
          "  -L http://[user:pass@]host:port        HTTP and CONNECT\n"
          "  -L socks5://[user:pass@]host:port      SOCKS5 CONNECT / UDP ASSOCIATE\n"
          "  -L auto://[user:pass@]host:port        Detect HTTP or SOCKS5\n"
          "  -L tcp://host:port/target:port        TCP port forwarding\n"
          "  -L udp://host:port/target:port        UDP port forwarding\n"
          "  -F http://[user:pass@]host:port        TCP chain hop (CONNECT)\n"
          "  -F socks5://[user:pass@]host:port      TCP chain hop\n"
          "  --timeout SECONDS                    Idle/handshake timeout (default 60)\n"
          "  --connect-timeout SECONDS            Per-hop connect timeout (default 10)\n"
          "  --max-clients NUMBER                 Concurrent TCP clients (default 256)\n"
          "  -V, --version                        Print version\n"
          "  -h, --help                           Show help\n"
          "Use [IPv6]:port for IPv6; an empty listening host binds wildcard IPv4.\n"
          "UDP chaining, TLS listeners and GOST YAML/JSON config are unsupported.\n", out);
}

static int number(const char *s, unsigned max, unsigned *out) {
    char *end;
    if (!*s || *s == '-' || *s == '+') return -1;
    errno = 0;
    unsigned long n = strtoul(s, &end, 10);
    if (errno || *end || !n || n > max) return -1;
    *out = (unsigned)n;
    return 0;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) { usage(stdout); return 0; }
        if (!strcmp(arg, "-V") || !strcmp(arg, "--version")) { puts("gost-c 0.1.0"); return 0; }
        if (strcmp(arg, "-L") && strcmp(arg, "-F") && strcmp(arg, "--timeout") &&
            strcmp(arg, "--connect-timeout") && strcmp(arg, "--max-clients")) {
            fprintf(stderr, "Unsupported option: %s\n", arg);
            return 2;
        }
        if (++i == argc) { fprintf(stderr, "Missing option value\n"); return 2; }
        if (!strcmp(arg, "-L")) {
            if (config.service_count == MAX_SERVICES ||
                parse_endpoint(argv[i], &config.services[config.service_count].endpoint, false)) {
                fputs("Invalid -L URL or too many listeners; see --help\n", stderr);
                return 2;
            }
            config.services[config.service_count++].fd = -1;
        } else if (!strcmp(arg, "-F")) {
            if (config.hop_count == MAX_HOPS || parse_endpoint(argv[i], &config.hops[config.hop_count], true)) {
                fputs("Invalid -F URL or too many chain hops; see --help\n", stderr);
                return 2;
            }
            config.hop_count++;
        } else {
            unsigned n;
            if (number(argv[i], !strcmp(arg, "--max-clients") ? 4096 : 86400, &n)) {
                fprintf(stderr, "Invalid value for %s\n", arg);
                return 2;
            }
            if (!strcmp(arg, "--timeout")) config.timeout_ms = (int)n * 1000;
            else if (!strcmp(arg, "--connect-timeout")) config.connect_timeout_ms = (int)n * 1000;
            else config.max_clients = n;
        }
    }
    if (!config.service_count) { usage(stderr); return 2; }
    for (size_t i = 0; i < config.service_count; i++) {
        if (config.hop_count && config.services[i].endpoint.protocol == PROTO_UDP) {
            fputs("UDP forwarding through -F chains is not supported\n", stderr);
            return 2;
        }
    }
    return run_server();
}
