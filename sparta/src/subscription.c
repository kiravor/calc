#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

char *sp_subscription(const char *link, const char *want, const char *ca, int *code) {
    *code = 2;
    char *decoded = sp_decode_link(link, "sub");
    cJSON *sub = decoded ? sp_json(decoded) : NULL; free(decoded);
    const char *hub = sp_string(sub, "hub"), *token = sp_string(sub, "token");
    uint64_t version;
    if (!hub || !token || !*token || !sp_integer(cJSON_GetObjectItemCaseSensitive(sub, "v"), 1, &version) || version != 1) {
        cJSON_Delete(sub); return NULL;
    }
    char url[4608];
    size_t len = strlen(hub); while (len && hub[len - 1] == '/') len--;
    int n = snprintf(url, sizeof(url), "%.*s/v1/provision", (int)len, hub);
    struct http_result result;
    *code = 1;
    if (n < 0 || (size_t)n >= sizeof(url) || sp_http("POST", url, token, NULL, "", ca, &result)) { cJSON_Delete(sub); return NULL; }
    cJSON_Delete(sub);
    if (result.status == 404) *code = 3;
    cJSON *provision = result.status == 200 ? sp_json(result.body) : NULL;
    sp_http_free(&result);
    const char *status = sp_string(provision, "status");
    char *out = NULL;
    if (!status || !sp_integer(cJSON_GetObjectItemCaseSensitive(provision, "v"), 1, &version) || version != 1) goto done;
    if (!strcmp(status, "blocked") || !strcmp(status, "over_quota")) { *code = 3; goto done; }
    if (strcmp(status, "active")) goto done;
    const cJSON *nodes = cJSON_GetObjectItemCaseSensitive(provision, "nodes");
    const cJSON *creds = cJSON_GetObjectItemCaseSensitive(provision, "credentials");
    const char *user = sp_string(creds, "username"), *password = sp_string(creds, "password");
    if (!user || !*user || !password || !*password || !cJSON_IsArray(nodes)) goto done;
    if (!cJSON_GetArraySize(nodes)) { *code = 3; goto done; }
    const cJSON *selected = NULL, *node;
    cJSON_ArrayForEach(node, nodes) {
        const char *id = sp_string(node, "id"), *name = sp_string(node, "name");
        if ((!want || !*want) || (id && !strcmp(want, id)) || (name && !strcasecmp(want, name))) { selected = node; break; }
    }
    if (!selected) { *code = 2; goto done; }
    cJSON *profile = cJSON_Duplicate(selected, 1);
    cJSON_DeleteItemFromObjectCaseSensitive(profile, "v");
    cJSON_DeleteItemFromObjectCaseSensitive(profile, "user");
    cJSON_DeleteItemFromObjectCaseSensitive(profile, "password");
    cJSON_AddNumberToObject(profile, "v", 1);
    cJSON_AddStringToObject(profile, "user", user);
    cJSON_AddStringToObject(profile, "password", password);
    out = cJSON_PrintUnformatted(profile); cJSON_Delete(profile);
    *code = out ? 0 : 1;
done:
    cJSON_Delete(provision);
    return out;
}
