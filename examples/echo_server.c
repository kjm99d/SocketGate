/*
 * SockGate echo server: authenticates clients and echoes every message back
 * as a reply to its request. Pure C, public API only.
 *
 *   sg_echo_server --cert server.crt --key server.key [--port 7443]
 *                  [--bind 127.0.0.1] [--registry registry.bin]
 *                  [--licenses licenses.bin] [--token-key token.key]
 *                  [--issue-token PRODUCT] [--license ID] [--allow-enroll]
 *
 * Listens on loopback unless --bind says otherwise (e.g. --bind 0.0.0.0).
 * Runs until Enter is pressed (or stdin closes).
 */
#include <sockgate/server.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* memset() of a buffer that is not read afterwards may be optimised away;
 * volatile stores are not. */
static void wipe(void* data, size_t size)
{
    volatile unsigned char* p = (volatile unsigned char*)data;
    while (size-- > 0) *p++ = 0;
}

static void SG_CALL on_log(void* user, uint32_t level, const char* message)
{
    (void)user;
    fprintf(stderr, "[sockgate:%u] %s\n", (unsigned)level, message);
}

static void SG_CALL on_opened(void* user, const SG_ServerSessionInfo* info)
{
    (void)user;
    /* License ids are customer data: not printed (see SECURITY.md, logging). */
    printf("session %llu opened from %s (policy %u, features 0x%llx%s)\n", (unsigned long long)info->session,
           info->peer_address, (unsigned)info->policy, (unsigned long long)info->granted_features,
           info->license_id[0] != '\0' ? ", licensed" : "");
    fflush(stdout);
}

static SG_Server* g_server = NULL;

static void SG_CALL on_message(void* user, SG_SessionHandle session, const void* data, size_t size,
                               const SG_MessageInfo* info)
{
    (void)user;
    /* Reply to the client's request id so it can match the answer. */
    const SG_Status st = SG_Server_SendEx(g_server, session, data, size, info->request_id);
    if (st != SG_OK) fprintf(stderr, "echo to session %llu failed: %s\n", (unsigned long long)session, SG_StatusString(st));
}

static void SG_CALL on_closed(void* user, SG_SessionHandle session, SG_Status reason)
{
    (void)user;
    printf("session %llu closed (%s)\n", (unsigned long long)session, SG_StatusString(reason));
    fflush(stdout);
}

/* Reads a whole small file (token key). Returns the size, 0 on error or if
 * the file does not fit (a truncated key would silently differ). */
static size_t read_file(const char* path, uint8_t* buffer, size_t capacity)
{
    FILE* f = NULL;
    size_t n;
    int extra;
#ifdef _MSC_VER
    if (fopen_s(&f, path, "rb") != 0) f = NULL;
#else
    f = fopen(path, "rb");
#endif
    if (f == NULL) return 0;
    setvbuf(f, NULL, _IONBF, 0); /* no stdio buffer holding a copy of the key */
    n = fread(buffer, 1, capacity, f);
    extra = fgetc(f);
    if (ferror(f) || extra != EOF) n = 0;
    fclose(f);
    if (n == 0) wipe(buffer, capacity);
    return n;
}

/* Strict decimal port: digits only, 0..65535 (0: any free port). */
static int parse_port(const char* text, uint16_t* out)
{
    unsigned long value = 0;
    size_t i;
    if (text[0] == '\0' || strlen(text) > 5) return 0;
    for (i = 0; text[i] != '\0'; ++i) {
        if (text[i] < '0' || text[i] > '9') return 0;
        value = value * 10 + (unsigned long)(text[i] - '0');
    }
    if (value > 65535) return 0;
    *out = (uint16_t)value;
    return 1;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: sg_echo_server --cert FILE --key FILE [--port N] [--bind ADDR]\n"
            "                      [--registry FILE] [--licenses FILE] [--token-key FILE]\n"
            "                      [--allow-enroll] [--issue-token PRODUCT [--license ID]]\n");
}

int main(int argc, char** argv)
{
    const char* cert = NULL;
    const char* key = NULL;
    const char* bind = "127.0.0.1";
    const char* registry = NULL;
    const char* licenses = NULL;
    const char* token_key_file = NULL;
    const char* issue_product = NULL;
    const char* issue_license = NULL;
    int allow_enroll = 0;
    uint16_t port = 7443;
    uint8_t token_key[256];
    size_t token_key_size = 0;
    SG_ServerOptions options;
    SG_ServerCallbacks callbacks;
    SG_Status st;
    uint16_t bound_port = 0;
    int i;

    for (i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        const char* value = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(arg, "--allow-enroll") == 0) {
            allow_enroll = 1;
            continue;
        }
        if (value == NULL) {
            usage();
            return 2;
        }
        ++i;
        if (strcmp(arg, "--cert") == 0) cert = value;
        else if (strcmp(arg, "--key") == 0) key = value;
        else if (strcmp(arg, "--port") == 0) {
            if (!parse_port(value, &port)) {
                usage();
                return 2;
            }
        } else if (strcmp(arg, "--bind") == 0) bind = value;
        else if (strcmp(arg, "--registry") == 0) registry = value;
        else if (strcmp(arg, "--licenses") == 0) licenses = value;
        else if (strcmp(arg, "--token-key") == 0) token_key_file = value;
        else if (strcmp(arg, "--issue-token") == 0) issue_product = value;
        else if (strcmp(arg, "--license") == 0) issue_license = value;
        else {
            usage();
            return 2;
        }
    }
    if (cert == NULL || key == NULL || (issue_license != NULL && issue_product == NULL)) {
        usage();
        return 2;
    }

    SG_ServerCallbacks_Init(&callbacks);
    callbacks.on_session_opened = on_opened;
    callbacks.on_message = on_message;
    callbacks.on_session_closed = on_closed;

    SG_ServerOptions_Init(&options);
    options.bind_address = bind;
    options.port = port;
    options.tls_cert_chain_file = cert;
    options.tls_private_key_file = key;
    options.registry_path = registry;   /* NULL: in memory */
    options.license_path = licenses;    /* NULL: in memory */
    options.callbacks = &callbacks;
    options.log_callback = on_log;
    options.log_level = SG_LOG_INFO;
    if (allow_enroll || issue_product != NULL) options.flags |= SG_SERVER_OPT_ALLOW_ENROLLMENT;
    if (token_key_file != NULL) {
        /* A persistent token key keeps issued enrollment tokens valid across restarts. */
        token_key_size = read_file(token_key_file, token_key, sizeof(token_key));
        if (token_key_size < 32) {
            fprintf(stderr, "token key file must hold 32..%u random bytes (see sg_admin token-key)\n",
                    (unsigned)sizeof(token_key));
            wipe(token_key, sizeof(token_key));
            return 1;
        }
        options.token_key = token_key;
        options.token_key_size = token_key_size;
    }

    st = SG_Server_Create(&options, &g_server);
    wipe(token_key, sizeof(token_key)); /* SG_Server_Create keeps its own copy */
    if (st != SG_OK) {
        fprintf(stderr, "SG_Server_Create: %s\n", SG_StatusString(st));
        return 1;
    }
    st = SG_Server_Start(g_server);
    if (st != SG_OK) {
        fprintf(stderr, "SG_Server_Start: %s\n", SG_StatusString(st));
        SG_Server_Destroy(g_server);
        return 1;
    }
    SG_Server_GetPort(g_server, &bound_port);
    printf("listening on %s:%u\n", bind, (unsigned)bound_port);

    if (issue_product != NULL) {
        SG_EnrollmentTokenRequest request;
        char token[1024];
        size_t written = 0;
        SG_EnrollmentTokenRequest_Init(&request);
        request.product_id = issue_product;
        request.license_id = issue_license;
        st = SG_Server_IssueEnrollmentToken(g_server, &request, token, sizeof(token), &written);
        if (st == SG_OK) {
            printf("enrollment token (single use):\n%s\n", token);
        } else {
            fprintf(stderr, "SG_Server_IssueEnrollmentToken: %s\n", SG_StatusString(st));
        }
        wipe(token, sizeof(token));
    }

    printf("press Enter to stop\n");
    fflush(stdout);
    (void)getchar();
    SG_Server_Destroy(g_server);  /* stops the server, closes sessions */
    return 0;
}
