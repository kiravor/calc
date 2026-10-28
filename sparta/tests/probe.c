#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static int check_result;
static char check_error[256];
static void *checking(void *unused) {
    (void)unused;
    check_result = sparta_check("http://public.example/", 5000, check_error, sizeof(check_error));
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 3 && (!strcmp(argv[1], "check-timeout") || !strcmp(argv[1], "cancel-check"))) {
        char *json = sp_read_file(argv[2], 65536), error[256];
        if (!json || sparta_start(json, NULL, NULL, 0, "u", "p", NULL, error, sizeof(error))) { free(json); return 2; }
        int result;
        if (!strcmp(argv[1], "check-timeout")) {
            result = sparta_check("http://public.example/", 150, error, sizeof(error));
            result = result && !strncmp(error, "timeout:", 8) ? 0 : 3;
        } else {
            pthread_t thread;
            if (pthread_create(&thread, NULL, checking, NULL)) { free(json); sparta_stop(); return 4; }
            struct timespec wait = {.tv_nsec = 100000000}; nanosleep(&wait, NULL);
            sparta_stop(); pthread_join(thread, NULL);
            result = check_result ? 0 : 5;
        }
        sparta_stop(); free(json); return result;
    }
#ifndef SPARTA_CLIENT_ONLY
    if (argc == 3 && !strcmp(argv[1], "private")) { puts(sp_private(argv[2]) ? "yes" : "no"); return 0; }
    if (argc == 4 && !strcmp(argv[1], "match")) { puts(sp_match(argv[2], argv[3]) ? "yes" : "no"); return 0; }
#endif
    if (argc == 3 && !strcmp(argv[1], "lifecycle")) {
        char *json = sp_read_file(argv[2], 65536), error[256];
        if (!json) return 2;
        for (unsigned i = 0; i < 12; i++) {
            if (sparta_start(json, NULL, NULL, 0, "u", "p", NULL, error, sizeof(error))) { free(json); return 3; }
            if (!sparta_port()) { free(json); return 4; }
            if (!sparta_start(json, NULL, NULL, 0, "u", "p", NULL, error, sizeof(error))) { free(json); return 5; }
            sparta_stop(); sparta_stop();
            if (sparta_port()) { free(json); return 6; }
        }
        free(json); puts("OK"); return 0;
    }
    return 2;
}
