/* Test-only connector injection. Production binaries always use policy.c.
   Maps an approved public.example destination to a loopback test backend;
   no private-network override exists in the product configuration. */
#include "internal.h"
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

bool __real_sp_destination_allowed(struct agent *, const char *, const char *, const char *);
bool __wrap_sp_destination_allowed(struct agent *a, const char *user, const char *host, const char *numeric) {
    (void)numeric;
    return __real_sp_destination_allowed(a, user, host, "93.184.216.34");
}
int __wrap_sp_authorize_target(struct agent *a, const char *user, const struct address *target, int type) {
    if (strcmp(target->host, "public.example") || !__real_sp_destination_allowed(a, user, target->host, "93.184.216.34")) {
        errno = EACCES; return -1;
    }
    struct address local = {.host = "127.0.0.1", .port = target->port};
    return dial_socket(&local, type, config.connect_timeout_ms);
}
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc != 2) return 2;
    char *text = sp_read_file(argv[1], SP_MAX_JSON);
    cJSON *cfg = text ? sp_json(text) : NULL; free(text);
    if (!cfg) return 2;
    int result = sp_serve_node(cfg);
    cJSON_Delete(cfg);
    return result < 0 ? 2 : result;
}
