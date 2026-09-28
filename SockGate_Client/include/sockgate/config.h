/*
 * SockGate client - configuration structures.
 *
 * Every structure starts with { size, version } and must be initialised with
 * its *_Init() function, which sets the defaults below. The library only
 * reads fields that lie within `size`, so binaries built against an older
 * header keep working when fields are appended.
 */
#ifndef SOCKGATE_CONFIG_H
#define SOCKGATE_CONFIG_H

#include "sockgate/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Key store selection (SG_ClientConfig.key_store_type) ---------------- */
#define SG_KEYSTORE_AUTO         0u /* strongest available: TPM -> OS store -> protected file */
#define SG_KEYSTORE_MEMORY       1u /* process memory, not persistent (tests, ephemeral) */
#define SG_KEYSTORE_FILE         2u /* PKCS#8 file (0600 on Linux, DPAPI-wrapped on Windows) */
#define SG_KEYSTORE_CNG_SOFTWARE 3u /* Windows: Microsoft Software KSP, non-exportable */
#define SG_KEYSTORE_CNG_TPM      4u /* Windows: Microsoft Platform Crypto Provider (TPM) */
#define SG_KEYSTORE_TPM2         5u /* Linux: TPM2 via tpm2-tss (optional build) */

/* ---- Client flags (SG_ClientConfig.flags) --------------------------------- */
#define SG_CLIENT_FLAG_APP_ENCRYPTION   (1u << 0) /* AEAD-encrypt DATA payloads inside TLS */
#define SG_CLIENT_FLAG_ALLOW_TLS12      (1u << 1) /* permit TLS 1.2 (with EMS) in addition to 1.3 */
#define SG_CLIENT_FLAG_AUTO_IDENTITY    (1u << 2) /* create the installation key on demand */
#define SG_CLIENT_FLAG_INTEGRITY_REPORT (1u << 3) /* send integrity observations to the server */
#define SG_CLIENT_FLAG_AUTO_REFRESH     (1u << 4) /* re-authenticate at 80% of the session lifetime */

/* ---- Proxy (SG_ProxyConfig) ------------------------------------------------ */
#define SG_PROXY_MODE_DIRECT   0u /* default: connect directly, ignore system settings */
#define SG_PROXY_MODE_SYSTEM   1u /* use the OS / environment proxy configuration */
#define SG_PROXY_MODE_EXPLICIT 2u /* use the proxy described in SG_ProxyConfig */

#define SG_PROXY_TYPE_HTTP_CONNECT 1u
#define SG_PROXY_TYPE_SOCKS4A      2u
#define SG_PROXY_TYPE_SOCKS5       3u

#define SG_PROXY_CONFIG_VERSION 1u
typedef struct SG_ProxyConfig {
    uint32_t size;
    uint32_t version;
    uint32_t mode;         /* SG_PROXY_MODE_* */
    uint32_t type;         /* SG_PROXY_TYPE_* (explicit mode) */
    const char* host;      /* explicit mode */
    uint16_t port;
    uint16_t reserved;
    const char* username;  /* optional: HTTP Basic / SOCKS5 user-password / SOCKS4a user id */
    const char* password;  /* optional */
} SG_ProxyConfig;

#define SG_CLIENT_CONFIG_VERSION 1u
typedef struct SG_ClientConfig {
    uint32_t size;
    uint32_t version;

    /* Installation identity */
    const char* identity_name;   /* required, [A-Za-z0-9._-]{1,128} */
    uint32_t key_store_type;     /* SG_KEYSTORE_* (default AUTO) */
    uint32_t flags;              /* SG_CLIENT_FLAG_* */
    const char* key_store_path;  /* FILE store directory; NULL = per-user default */

    /* Product / license claims (the server decides what they are worth) */
    const char* product_id;      /* optional, <= 64 bytes UTF-8 */
    const char* product_version; /* optional, <= 32 bytes */
    const char* license_id;      /* optional, <= 128 bytes */
    uint64_t requested_features;
    uint16_t client_version_major;
    uint16_t client_version_minor;
    uint16_t client_version_patch;
    uint16_t reserved0;

    /* Limits and timeouts */
    uint32_t connect_timeout_ms; /* default 10000; covers TCP, proxy and TLS handshake */
    uint32_t io_timeout_ms;      /* default 30000; 0 = no timeout */
    uint32_t max_payload_size;   /* default 1 MiB, max 16 MiB */
    uint32_t reserved1;

    const SG_ProxyConfig* proxy; /* NULL = direct */

    /* Diagnostics */
    SG_LogCallback log_callback; /* NULL = silent */
    void* log_user;
    uint32_t log_level;          /* SG_LOG_* (default SG_LOG_WARN) */
    uint32_t reserved2;
} SG_ClientConfig;

/* ---- Target server (SG_ServerConfig) --------------------------------------- */
#define SG_TRUST_SYSTEM_STORE           (1u << 0) /* also trust the OS root store */
#define SG_SERVER_FLAG_ALLOW_NO_PINNING (1u << 1) /* explicit opt-out, see below */

/*
 * Describes the server the client connects to (not the server library's
 * own configuration, which is SG_ServerOptions in sockgate/server.h).
 *
 * Trust: at least one of ca_file, ca_pem or SG_TRUST_SYSTEM_STORE.
 * When the OS store is trusted, at least one SPKI pin or server proof key is
 * required unless SG_SERVER_FLAG_ALLOW_NO_PINNING is set, because a
 * user-installed CA could otherwise impersonate the server.
 */
#define SG_SERVER_CONFIG_VERSION 1u
typedef struct SG_ServerConfig {
    uint32_t size;
    uint32_t version;
    const char* host;            /* DNS name or IP literal */
    uint16_t port;
    uint16_t reserved0;
    const char* server_name;     /* name to verify / send as SNI; NULL = host */
    const char* ca_file;         /* PEM bundle path */
    const char* ca_pem;          /* PEM bundle in memory */
    size_t ca_pem_size;          /* 0 = NUL-terminated */
    uint32_t flags;              /* SG_TRUST_SYSTEM_STORE | SG_SERVER_FLAG_* */
    uint32_t spki_pin_count;     /* <= SG_MAX_PINS */
    const SG_Sha256* spki_pins;  /* SHA-256 of DER SubjectPublicKeyInfo */
    uint32_t proof_key_count;    /* <= SG_MAX_PROOF_KEYS */
    uint32_t reserved1;
    const SG_PublicKey* proof_keys; /* server proof keys; when set the server MUST sign */
} SG_ServerConfig;

#ifdef __cplusplus
}
#endif

#endif /* SOCKGATE_CONFIG_H */
