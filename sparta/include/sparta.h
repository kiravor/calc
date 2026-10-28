#ifndef SPARTA_PUBLIC_H
#define SPARTA_PUBLIC_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Process-wide single instance. Returns only after bind succeeds; port=0 is
   allocated atomically. node_addr may be NULL or a numeric IP:port override.
   Errors never contain passwords, paths or destination addresses. */
int sparta_start(const char *profile_json, const char *password, const char *node_addr,
                 unsigned port, const char *socks_user, const char *socks_pass,
                 const char *ca_file, char *error, size_t error_cap);
unsigned sparta_port(void);
int sparta_check(const char *url, unsigned timeout_ms, char *error, size_t cap);
void sparta_stop(void);
#ifdef __cplusplus
}
#endif
#endif
