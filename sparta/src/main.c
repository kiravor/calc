#include "internal.h"
#include <curl/curl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void stop(int signal_number) { (void)signal_number; stopping = 1; }

static char *secret_file(const char *path) {
    if (!path) return NULL;
    char *value = sp_read_file(path, 1024);
    if (value) {
        size_t n = strlen(value);
        while (n && (value[n-1] == '\r' || value[n-1] == '\n')) value[--n] = 0;
    }
    return value;
}

static void usage(void) {
    puts("sparta-c 0.2.0\n"
         "  sparta client --profile FILE [--password-file FILE] [options]\n"
         "  sparta client --link sparta://import/v1/... [options]\n"
         "  sparta client --subscription sparta://sub/v1/... [--node NAME] [options]\n"
         "  sparta profile --profile FILE [--password-file FILE]\n"
         "  sparta node --config FILE\n"
         "  sparta agent --config FILE\n"
         "Client options: --socks-port PORT (1080; 0 allocates a free port),\n"
         "  --socks-user USER --socks-password-file FILE, --node-address IP:PORT,\n"
         "  --ca FILE, --check-url http://host/path, --check-only, --skip-check.\n"
         "TLS uses verified native OpenSSL; browser ClientHello emulation is absent.\n"
         "Node/agent secrets: SPARTA_PLUGIN_TOKEN, SPARTA_NODE_KEY (environment).");
}

int main(int argc, char **argv) {
    if (argc == 1 || !strcmp(argv[1], "--help")) { usage(); return 0; }
    if (!strcmp(argv[1], "--version")) { puts("sparta-c 0.2.0"); return 0; }
    const char *command = argv[1], *profile_path = NULL, *cfg_path = NULL, *password_path = NULL;
    const char *ca = "", *override = "", *socks_user = "", *socks_pass_path = NULL, *link = NULL, *sub = NULL, *want = NULL;
    const char *check_url = "http://cp.cloudflare.com/generate_204";
    unsigned port = 1080;
    bool check_only = false, skip_check = false;
    for (int i = 2; i < argc; i++) {
        const char *arg = argv[i];
        if (!strcmp(arg, "--check-only")) { check_only = true; continue; }
        if (!strcmp(arg, "--skip-check")) { skip_check = true; continue; }
        if (strcmp(arg, "--profile") && strcmp(arg, "--config") && strcmp(arg, "--password-file") && strcmp(arg, "--ca") &&
            strcmp(arg, "--node-address") && strcmp(arg, "--socks-port") && strcmp(arg, "--socks-user") &&
            strcmp(arg, "--socks-password-file") && strcmp(arg, "--link") && strcmp(arg, "--subscription") &&
            strcmp(arg, "--node") && strcmp(arg, "--check-url")) { fputs("Unsupported option\n", stderr); return 2; }
        if (++i == argc) { fputs("Missing option value\n", stderr); return 2; }
        if (!strcmp(arg, "--profile")) profile_path = argv[i];
        else if (!strcmp(arg, "--config")) cfg_path = argv[i];
        else if (!strcmp(arg, "--password-file")) password_path = argv[i];
        else if (!strcmp(arg, "--ca")) ca = argv[i];
        else if (!strcmp(arg, "--node-address")) override = argv[i];
        else if (!strcmp(arg, "--socks-user")) socks_user = argv[i];
        else if (!strcmp(arg, "--socks-password-file")) socks_pass_path = argv[i];
        else if (!strcmp(arg, "--link")) link = argv[i];
        else if (!strcmp(arg, "--subscription")) sub = argv[i];
        else if (!strcmp(arg, "--node")) want = argv[i];
        else if (!strcmp(arg, "--check-url")) check_url = argv[i];
        else {
            char *end; errno = 0;
            unsigned long value = strtoul(argv[i], &end, 10);
            if (errno || !*argv[i] || *end || value > 65535 || argv[i][0] == '-') { fputs("Invalid SOCKS port\n", stderr); return 2; }
            port = (unsigned)value;
        }
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT)) return 1;
    struct sigaction action = {.sa_handler = stop}; sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL); sigaction(SIGTERM, &action, NULL);
    action.sa_handler = SIG_IGN; sigaction(SIGPIPE, &action, NULL);
    int code = 2;
    if (!strcmp(command, "node") || !strcmp(command, "agent")) {
        char *text = cfg_path ? sp_read_file(cfg_path, SP_MAX_JSON) : NULL;
        cJSON *cfg = text ? sp_json(text) : NULL; free(text);
        if (!cJSON_IsObject(cfg)) { fputs("Invalid stack configuration\n", stderr); cJSON_Delete(cfg); goto done; }
        if (!strcmp(command, "node")) {
            code = sp_serve_node(cfg);
            if (code < 0) { code = 2; fputs("Node setup failed\n", stderr); }
        } else if (!sp_agent_init(&node_agent, cfg)) {
            if (sp_agent_start(&node_agent, true)) { stopping = 1; code = 2; fputs("Agent setup failed\n", stderr); }
            else {
                while (!stopping) { struct timespec wait = {.tv_nsec = 100000000}; nanosleep(&wait, NULL); }
                code = sp_save_counts(&node_agent) ? 1 : 0;
            }
            sp_agent_close(&node_agent);
        } else fputs("Invalid agent configuration or state store\n", stderr);
        cJSON_Delete(cfg); goto done;
    }
    if (strcmp(command, "client") && strcmp(command, "profile")) { usage(); goto done; }
    if ((!!profile_path + !!link + !!sub) != 1 || (want && !sub) || (check_only && skip_check)) {
        fputs("Choose exactly one profile, import link or subscription\n", stderr); goto done;
    }
    char *json = profile_path ? sp_read_file(profile_path, 65536) : link ? sp_decode_link(link, "import") : sp_subscription(sub, want, ca, &code);
    char *password = secret_file(password_path), *socks_pass = secret_file(socks_pass_path);
    if (!json || (password_path && !password) || (socks_pass_path && !socks_pass)) {
        fputs(sub && code == 3 ? "Подписка недоступна: блокировка, квота, отозванная ссылка или нет узлов\n" : "Cannot read profile or credentials\n", stderr);
        free(json); free(password); free(socks_pass); goto done;
    }
    struct profile parsed;
    if (sp_profile(json, password, override, ca, &parsed)) { fputs("Invalid profile\n", stderr); code = 2; }
    else if (!strcmp(command, "profile")) { puts("OK (native TLS)"); code = 0; }
    else {
        char error[256];
        fputs("TLS: verified native OpenSSL; browser fingerprints are not emulated\n", stderr);
        if (sparta_start(json, password, override, port, socks_user, socks_pass ? socks_pass : "", ca, error, sizeof(error))) {
            fprintf(stderr, "%s\n", error); code = 1;
        } else {
            if (!skip_check && sparta_check(check_url, 5000, error, sizeof(error))) { fprintf(stderr, "%s\n", error); code = 1; }
            else {
                puts("OK"); fflush(stdout); code = 0;
                while (!check_only && !stopping) { struct timespec wait = {.tv_nsec = 100000000}; nanosleep(&wait, NULL); }
            }
            sparta_stop();
        }
    }
    OPENSSL_cleanse(&parsed, sizeof(parsed));
    if (password) OPENSSL_cleanse(password, strlen(password));
    if (socks_pass) OPENSSL_cleanse(socks_pass, strlen(socks_pass));
    OPENSSL_cleanse(json, strlen(json));
    free(json); free(password); free(socks_pass);
done:
    curl_global_cleanup();
    return code;
}
