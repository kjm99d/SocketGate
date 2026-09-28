#ifndef SOCKGATE_CONFIG_H
#define SOCKGATE_CONFIG_H
/**
 * @file
 * @brief SockGate client - configuration structures.
 * @ingroup sg_client
 *
 * Every structure starts with { size, version } and must be initialised with
 * its *_Init() function, which sets the defaults below. The library only
 * reads fields that lie within `size`, so binaries built against an older
 * header keep working when fields are appended. Appended fields that the
 * library does not know must be zero (otherwise SG_NOT_SUPPORTED), so a
 * setting is never silently ignored.
 */

#include "sockgate/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup sg_client
 * @{
 */

/* ---- Key store selection (SG_ClientConfig.key_store_type) ---------------- */
#define SG_KEYSTORE_AUTO         0u /**< strongest available. Windows: CNG TPM -> CNG Software;
                                       Linux: TPM2 (if built) -> protected file */
#define SG_KEYSTORE_MEMORY       1u /**< process memory, not persistent (tests, ephemeral) */
#define SG_KEYSTORE_FILE         2u /**< PKCS#8 file (0600 on Linux, DPAPI-wrapped on Windows) */
#define SG_KEYSTORE_CNG_SOFTWARE 3u /**< Windows: Microsoft Software KSP, non-exportable */
#define SG_KEYSTORE_CNG_TPM      4u /**< Windows: Microsoft Platform Crypto Provider (TPM) */
#define SG_KEYSTORE_TPM2         5u /**< Linux: TPM2 via tpm2-tss (optional build) */

/* ---- Client flags (SG_ClientConfig.flags) --------------------------------- */
#define SG_CLIENT_FLAG_APP_ENCRYPTION   (1u << 0) /**< AEAD-encrypt DATA payloads inside TLS */
#define SG_CLIENT_FLAG_ALLOW_TLS12      (1u << 1) /**< permit TLS 1.2 (with EMS) in addition to 1.3 */
/** create the installation key on demand (SG_Client_Authenticate calls SG_Client_EnsureIdentity) */
#define SG_CLIENT_FLAG_AUTO_IDENTITY    (1u << 2)
/** send integrity observations to the server (SG_INTEGRITY_*); SG_Client_Create hashes the executable */
#define SG_CLIENT_FLAG_INTEGRITY_REPORT (1u << 3)
/** re-authenticate at 80% of the session lifetime; checked when SG_Client_Send or SG_Client_Receive is
 *  called (no background thread) */
#define SG_CLIENT_FLAG_AUTO_REFRESH     (1u << 4)

/* ---- Proxy (SG_ProxyConfig) ------------------------------------------------ */
#define SG_PROXY_MODE_DIRECT   0u /**< default: connect directly, ignore system settings */
#define SG_PROXY_MODE_SYSTEM   1u /**< use the OS / environment proxy configuration */
#define SG_PROXY_MODE_EXPLICIT 2u /**< use the proxy described in SG_ProxyConfig */

#define SG_PROXY_TYPE_HTTP_CONNECT 1u /**< HTTP proxy using CONNECT. */
#define SG_PROXY_TYPE_SOCKS4A      2u /**< SOCKS4a proxy. */
#define SG_PROXY_TYPE_SOCKS5       3u /**< SOCKS5 proxy. */

#define SG_PROXY_CONFIG_VERSION 1u /**< Current version of SG_ProxyConfig. */
/**
 * @brief Proxy settings, referenced by SG_ClientConfig.proxy.
 *
 * Initialise with SG_ProxyConfig_Init() (mode SG_PROXY_MODE_DIRECT). SG_Client_Create() validates and
 * copies it; invalid settings fail with SG_INVALID_ARGUMENT.
 */
typedef struct SG_ProxyConfig {
    uint32_t size;         /**< Size of this structure in bytes (set by SG_ProxyConfig_Init). */
    uint32_t version;      /**< SG_PROXY_CONFIG_VERSION (set by SG_ProxyConfig_Init). */
    uint32_t mode;         /**< SG_PROXY_MODE_* */
    uint32_t type;         /**< SG_PROXY_TYPE_* (explicit mode) */
    const char* host;      /**< explicit mode; required there, <= 253 bytes */
    uint16_t port;         /**< Proxy port; explicit mode, required there (non-zero). */
    uint16_t reserved;     /**< Reserved. */
    /** optional: HTTP Basic / SOCKS5 user-password / SOCKS4a user id; <= 255 bytes */
    const char* username;
    /** optional; <= 255 bytes.
     *  @warning Secret: SG_Client_Create() copies it, so the caller may wipe its own copy afterwards. */
    const char* password;
} SG_ProxyConfig;

#define SG_CLIENT_CONFIG_VERSION 1u /**< Current version of SG_ClientConfig. */
/**
 * @brief Client configuration for SG_Client_Create().
 *
 * Initialise with SG_ClientConfig_Init(), which sets the defaults noted below. SG_Client_Create() copies
 * the strings and the proxy settings, so they may be freed once it returns; log_callback and log_user are
 * kept and must stay valid until SG_Client_Destroy().
 */
typedef struct SG_ClientConfig {
    uint32_t size;               /**< Size of this structure in bytes (set by SG_ClientConfig_Init). */
    uint32_t version;            /**< SG_CLIENT_CONFIG_VERSION (set by SG_ClientConfig_Init). */

    /* Installation identity */
    /**
     * required, `[A-Za-z0-9._-]{1,128}`; must not start with '.' or be a Windows device name (CON, NUL,
     * COM1, ...). Names are shared by all applications of a user: use a reverse-DNS style name
     * ("com.example.app").
     */
    const char* identity_name;
    /** SG_KEYSTORE_* (default AUTO). A store this platform or build does not provide: SG_NOT_SUPPORTED. */
    uint32_t key_store_type;
    uint32_t flags;              /**< SG_CLIENT_FLAG_*; unknown flags: SG_NOT_SUPPORTED */
    /** FILE store directory; NULL = per-user default. Also used by the TPM2 store (key blobs) and, on Linux,
     *  by AUTO. <= 4096 bytes. */
    const char* key_store_path;

    /* Product / license claims (the server decides what they are worth) */
    const char* product_id;      /**< optional, <= 64 bytes UTF-8 */
    const char* product_version; /**< optional, <= 32 bytes */
    const char* license_id;      /**< optional, <= 128 bytes */
    uint64_t requested_features; /**< 0 = everything the license entitles */
    uint16_t client_version_major; /**< Application version reported to the server (claim): major. */
    uint16_t client_version_minor; /**< Application version (claim): minor. */
    uint16_t client_version_patch; /**< Application version (claim): patch. */
    uint16_t reserved0;          /**< Reserved. */

    /* Limits and timeouts */
    /** default 10000 (also used for 0); one budget for the system proxy lookup,
     *  name resolution, TCP, the proxy and the TLS handshake. A single resolver or system proxy lookup call
     *  is not interrupted, and writes are limited by io_timeout_ms instead. */
    uint32_t connect_timeout_ms;
    /** default 30000; 0 = no timeout. Deadline of SG_Client_Authenticate / SG_Client_Enroll /
     *  SG_Client_Refresh, the timeout of SG_Client_Receive and of each write to the connection. */
    uint32_t io_timeout_ms;
    /** default 1 MiB (also used for 0), max 16 MiB. Largest message payload sent or accepted. */
    uint32_t max_payload_size;
    uint32_t reserved1;          /**< Reserved. */

    const SG_ProxyConfig* proxy; /**< NULL = direct */

    /* Diagnostics */
    SG_LogCallback log_callback; /**< NULL = silent */
    void* log_user;              /**< Passed to log_callback. */
    uint32_t log_level;          /**< SG_LOG_* (default SG_LOG_WARN) */
    uint32_t reserved2;          /**< Reserved. */
} SG_ClientConfig;

/* ---- Target server (SG_ServerConfig) --------------------------------------- */
#define SG_TRUST_SYSTEM_STORE           (1u << 0) /**< also trust the OS root store */
#define SG_SERVER_FLAG_ALLOW_NO_PINNING (1u << 1) /**< explicit opt-out, see SG_ServerConfig */

#define SG_SERVER_CONFIG_VERSION 1u /**< Current version of SG_ServerConfig. */
/**
 * @brief Describes the server the client connects to (not the server library's
 * own configuration, which is SG_ServerOptions in sockgate/server.h).
 *
 * Initialise with SG_ServerConfig_Init(). SG_Client_Connect() validates and copies it.
 *
 * Trust: at least one of ca_file, ca_pem or SG_TRUST_SYSTEM_STORE.
 * When the OS store is trusted, at least one SPKI pin or server proof key is
 * required unless SG_SERVER_FLAG_ALLOW_NO_PINNING is set, because a
 * user-installed CA could otherwise impersonate the server.
 * @warning SG_SERVER_FLAG_ALLOW_NO_PINNING removes that protection.
 */
typedef struct SG_ServerConfig {
    uint32_t size;               /**< Size of this structure in bytes (set by SG_ServerConfig_Init). */
    uint32_t version;            /**< SG_SERVER_CONFIG_VERSION (set by SG_ServerConfig_Init). */
    const char* host;            /**< DNS name or IP literal; required, <= 253 bytes */
    uint16_t port;               /**< Server port; required (non-zero). */
    uint16_t reserved0;          /**< Reserved. */
    const char* server_name;     /**< name to verify / send as SNI; NULL = host */
    const char* ca_file;         /**< PEM bundle path */
    const char* ca_pem;          /**< PEM bundle in memory */
    size_t ca_pem_size;          /**< 0 = NUL-terminated */
    uint32_t flags;              /**< SG_TRUST_SYSTEM_STORE | SG_SERVER_FLAG_*; others: SG_NOT_SUPPORTED */
    uint32_t spki_pin_count;     /**< <= SG_MAX_PINS */
    const SG_Sha256* spki_pins;  /**< SHA-256 of DER SubjectPublicKeyInfo (see SG_Client_ComputeSpkiPin) */
    uint32_t proof_key_count;    /**< <= SG_MAX_PROOF_KEYS */
    uint32_t reserved1;          /**< Reserved. */
    const SG_PublicKey* proof_keys; /**< server proof keys; when set the server MUST sign */
} SG_ServerConfig;

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* SOCKGATE_CONFIG_H */
