/*
 * SockGate echo client: authenticates (or enrolls) with an installation key
 * and sends each line typed on stdin, printing the server's reply.
 * Pure C, public API only.
 *
 *   sg_echo_client --host gate.example.com --port 7443 --ca ca.crt
 *                  [--pin <sha256 hex of the server SPKI>] [--identity NAME]
 *                  [--key-dir DIR] [--product ID] [--enroll-file FILE]
 *
 * Without --enroll-file the installation must already be known to the
 * server: the client prints its public key for out-of-band registration.
 * The enrollment token is read from a file, not the command line, so it
 * does not show up in process listings or shell history.
 */
#include <sockgate/client.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_hex(const char* label, const uint8_t* data, size_t size)
{
    size_t i;
    printf("%s", label);
    for (i = 0; i < size; ++i) printf("%02x", data[i]);
    printf("\n");
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex32(const char* text, SG_Sha256* out)
{
    size_t i;
    if (strlen(text) != 64) return 0;
    for (i = 0; i < 32; ++i) {
        const int hi = hex_digit(text[2 * i]);
        const int lo = hex_digit(text[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out->bytes[i] = (uint8_t)(hi * 16 + lo);
    }
    return 1;
}

/* Strict decimal port: digits only, 1..65535. */
static int parse_port(const char* text, uint16_t* out)
{
    unsigned long value = 0;
    size_t i;
    if (text[0] == '\0' || strlen(text) > 5) return 0;
    for (i = 0; text[i] != '\0'; ++i) {
        if (text[i] < '0' || text[i] > '9') return 0;
        value = value * 10 + (unsigned long)(text[i] - '0');
    }
    if (value == 0 || value > 65535) return 0;
    *out = (uint16_t)value;
    return 1;
}

/* Reads the enrollment token (one line, trailing whitespace stripped).
 * Returns 0 on error or if it does not fit. */
static int read_token(const char* path, char* buffer, size_t capacity)
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
    setvbuf(f, NULL, _IONBF, 0); /* no stdio buffer holding a copy of the token */
    n = fread(buffer, 1, capacity - 1, f);
    extra = fgetc(f);
    if (ferror(f) || extra != EOF) {
        memset(buffer, 0, capacity);
        n = 0;
    }
    fclose(f);
    while (n > 0 && (buffer[n - 1] == '\n' || buffer[n - 1] == '\r' || buffer[n - 1] == ' ' ||
                     buffer[n - 1] == '\t')) {
        --n;
    }
    buffer[n] = '\0';
    return n > 0;
}

/* The reply is untrusted data: printable ASCII as is, everything else
 * escaped, so it cannot drive the terminal. */
static void print_safe(const char* data, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        const unsigned char c = (unsigned char)data[i];
        if (c >= 0x20 && c < 0x7F && c != '\\') putchar(c);
        else printf("\\x%02x", c);
    }
}

static void usage(void)
{
    fprintf(stderr,
            "usage: sg_echo_client --host HOST --port N --ca FILE [--pin HEX] [--identity NAME]\n"
            "                      [--key-dir DIR] [--product ID] [--enroll-file FILE]\n");
}

int main(int argc, char** argv)
{
    const char* host = NULL;
    const char* ca = NULL;
    const char* pin_hex = NULL;
    const char* identity = "com.example.sockgate-echo";
    const char* key_dir = NULL;
    const char* product = "sockgate-echo";
    const char* enroll_file = NULL;
    const char* enroll_token = NULL;
    char token[1024];
    uint16_t port = 7443;
    SG_ClientConfig config;
    SG_ServerConfig server;
    SG_IdentityInfo id;
    SG_ClientSessionInfo session;
    SG_Client* client = NULL;
    SG_Sha256 pin;
    SG_Status st;
    char line[4096];
    char reply[65536];
    int i;

    for (i = 1; i + 1 < argc; i += 2) {
        const char* arg = argv[i];
        const char* value = argv[i + 1];
        if (strcmp(arg, "--host") == 0) host = value;
        else if (strcmp(arg, "--port") == 0) {
            if (!parse_port(value, &port)) {
                usage();
                return 2;
            }
        }
        else if (strcmp(arg, "--ca") == 0) ca = value;
        else if (strcmp(arg, "--pin") == 0) pin_hex = value;
        else if (strcmp(arg, "--identity") == 0) identity = value;
        else if (strcmp(arg, "--key-dir") == 0) key_dir = value;
        else if (strcmp(arg, "--product") == 0) product = value;
        else if (strcmp(arg, "--enroll-file") == 0) enroll_file = value;
        else {
            usage();
            return 2;
        }
    }
    if (i != argc || host == NULL || ca == NULL) {
        usage();
        return 2;
    }

    SG_ClientConfig_Init(&config);
    config.identity_name = identity;
    /* A persistent key: the strongest store available (TPM first), or the
     * protected FILE store in --key-dir. */
    config.key_store_type = key_dir != NULL ? SG_KEYSTORE_FILE : SG_KEYSTORE_AUTO;
    config.key_store_path = key_dir;
    config.product_id = product;
    config.flags = SG_CLIENT_FLAG_APP_ENCRYPTION | SG_CLIENT_FLAG_AUTO_REFRESH;
    st = SG_Client_Create(&config, &client);
    if (st != SG_OK) {
        fprintf(stderr, "SG_Client_Create: %s\n", SG_StatusString(st));
        return 1;
    }

    SG_IdentityInfo_Init(&id);
    st = SG_Client_EnsureIdentity(client, &id);
    if (st != SG_OK) {
        fprintf(stderr, "SG_Client_EnsureIdentity: %s\n", SG_StatusString(st));
        SG_Client_Destroy(client);
        return 1;
    }
    print_hex("installation id: ", id.installation_id.bytes, sizeof(id.installation_id.bytes));
    print_hex("public key:      ", id.public_key.bytes, sizeof(id.public_key.bytes));
    printf("key store:       %s\n", id.hardware_backed ? "hardware (TPM)" : "software");

    SG_ServerConfig_Init(&server);
    server.host = host;
    server.port = port;
    server.ca_file = ca;
    if (pin_hex != NULL) {
        if (!parse_hex32(pin_hex, &pin)) {
            fprintf(stderr, "--pin must be 64 hex digits (see sg_admin pin)\n");
            SG_Client_Destroy(client);
            return 2;
        }
        server.spki_pins = &pin;
        server.spki_pin_count = 1;
    }

    if (enroll_file != NULL) {
        /* Read only now, so that one place wipes it on every path. */
        if (!read_token(enroll_file, token, sizeof(token))) {
            fprintf(stderr, "cannot read an enrollment token from %s\n", enroll_file);
            SG_Client_Destroy(client);
            return 2;
        }
        enroll_token = token;
    }
    st = SG_Client_Connect(client, &server);
    if (st == SG_OK) st = enroll_token != NULL ? SG_Client_Enroll(client, enroll_token) : SG_Client_Authenticate(client);
    memset(token, 0, sizeof(token)); /* single use: not needed any more */
    if (st != SG_OK) {
        fprintf(stderr, "connect/authenticate: %s\n", SG_StatusString(st));
        if (st == SG_SERVER_REJECTED && enroll_token == NULL) {
            fprintf(stderr, "register the public key above with the server (sg_admin client register) "
                            "or enroll with --enroll-file FILE\n");
        }
        SG_Client_Destroy(client);
        return 1;
    }
    SG_ClientSessionInfo_Init(&session);
    SG_Client_GetSessionInfo(client, &session);
    printf("authenticated: %s %s, policy %u, features 0x%llx\n", session.tls_protocol, session.tls_cipher,
           (unsigned)session.policy, (unsigned long long)session.granted_features);
    printf("type lines to send, EOF to quit\n");
    fflush(stdout);

    while (fgets(line, sizeof(line), stdin) != NULL) {
        size_t length = strlen(line);
        size_t received = 0;
        uint64_t request_id = 0;
        SG_MessageInfo info;
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) line[--length] = '\0';
        st = SG_Client_SendEx(client, line, length, 0, &request_id);
        if (st != SG_OK) {
            fprintf(stderr, "send: %s\n", SG_StatusString(st));
            break;
        }
        SG_MessageInfo_Init(&info);
        st = SG_Client_ReceiveEx(client, reply, sizeof(reply), &received, &info, SG_WAIT_DEFAULT);
        if (st != SG_OK) {
            fprintf(stderr, "receive: %s\n", SG_StatusString(st));
            break;
        }
        if (!(info.flags & SG_MESSAGE_FLAG_RESPONSE) || info.request_id != request_id) {
            fprintf(stderr, "unexpected message (not the reply to request %llu)\n", (unsigned long long)request_id);
            break;
        }
        printf("echo[%llu]: ", (unsigned long long)info.request_id);
        print_safe(reply, received);
        printf("\n");
        fflush(stdout);
    }

    SG_Client_Disconnect(client);
    SG_Client_Destroy(client);
    return 0;
}
