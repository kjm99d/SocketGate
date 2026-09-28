#ifndef SOCKGATE_TYPES_H
#define SOCKGATE_TYPES_H
/**
 * @file
 * @brief SockGate - common public types shared by the client and server APIs.
 * @ingroup sg_common
 *
 * ABI rules:
 *  - Enumerations are transported as uint32_t fields plus \#define constants.
 *  - Versioned structures start with { uint32_t size; uint32_t version; }.
 */

#include <stddef.h>
#include <stdint.h>

#include "sockgate/error.h"
#include "sockgate/export.h"
#include "sockgate/version.h"

/**
 * @addtogroup sg_common
 * @{
 */

#define SG_INSTALLATION_ID_SIZE 16 /**< Size of an installation id in bytes. */
#define SG_SESSION_ID_SIZE      16 /**< Size of a session id in bytes. */
#define SG_SHA256_SIZE          32 /**< Size of a SHA-256 digest in bytes. */
#define SG_PUBLIC_KEY_SIZE      65 /**< SEC1 uncompressed P-256 point: 0x04 || X || Y */
#define SG_MAX_PINS              8 /**< Maximum number of SPKI pins (SG_ServerConfig.spki_pin_count). */
#define SG_MAX_PROOF_KEYS        4 /**< Maximum number of server proof keys (SG_ServerConfig.proof_key_count). */

/** @brief Installation id: identifies an installation key pair and is derived from its public key. */
typedef struct SG_InstallationId { uint8_t bytes[SG_INSTALLATION_ID_SIZE]; } SG_InstallationId;
/** @brief Session id assigned by the server to an authenticated session. */
typedef struct SG_SessionId      { uint8_t bytes[SG_SESSION_ID_SIZE]; } SG_SessionId;
/** @brief SHA-256 digest, e.g. an SPKI pin or an executable hash. */
typedef struct SG_Sha256         { uint8_t bytes[SG_SHA256_SIZE]; } SG_Sha256;
/** @brief ECDSA P-256 public key in SEC1 uncompressed form (see SG_PUBLIC_KEY_SIZE). */
typedef struct SG_PublicKey      { uint8_t bytes[SG_PUBLIC_KEY_SIZE]; } SG_PublicKey;
/** @var SG_InstallationId::bytes
 *  @brief The id bytes. */
/** @var SG_SessionId::bytes
 *  @brief The id bytes. */
/** @var SG_Sha256::bytes
 *  @brief The digest bytes. */
/** @var SG_PublicKey::bytes
 *  @brief The encoded point: 0x04 || X || Y. */

/** @brief Server-side session reference. Never reused during the lifetime of an SG_Server. */
typedef uint64_t SG_SessionHandle;
#define SG_INVALID_SESSION_HANDLE ((SG_SessionHandle)0) /**< Handle value that never refers to a session. */

/* ---- Logging ------------------------------------------------------------ */
#define SG_LOG_NONE  0u /**< Log level: logging disabled. */
#define SG_LOG_ERROR 1u /**< Log level: errors. */
#define SG_LOG_WARN  2u /**< Log level: warnings and more severe. */
#define SG_LOG_INFO  3u /**< Log level: informational events and more severe. */
#define SG_LOG_DEBUG 4u /**< Log level: debug; compiled out of release builds unless SOCKGATE_ENABLE_DEBUG_LOG */
#define SG_LOG_TRACE 5u /**< Log level: trace; compiled out of release builds unless SOCKGATE_ENABLE_DEBUG_LOG */

/**
 * @brief Log callback of the client and server libraries.
 *
 * Log messages never contain key material, tokens, signatures or payload bytes.
 * The callback receives messages whose level is at most the configured log level.
 *
 * @param[in] user    The `log_user` pointer of the configuration.
 * @param[in] level   SG_LOG_* level of the message.
 * @param[in] message NUL-terminated message text, valid only during the call.
 * @note The server may call it while internal locks are held: it must only record the message and never
 *       call a SockGate function (see @ref sg_server).
 */
typedef void (SG_CALL *SG_LogCallback)(void* user, uint32_t level, const char* message);

/* ---- Client session state (SG_Client_GetState) -------------------------- */
#define SG_CLIENT_STATE_DISCONNECTED    0u /**< Not connected yet (initial state). */
#define SG_CLIENT_STATE_CONNECTING      1u /**< SG_Client_Connect: opening the TCP / proxy connection. */
#define SG_CLIENT_STATE_TLS_HANDSHAKE   2u /**< SG_Client_Connect: TLS handshake in progress. */
#define SG_CLIENT_STATE_TLS_ESTABLISHED 3u /**< TLS established; ready for SG_Client_Authenticate / Enroll. */
#define SG_CLIENT_STATE_AUTHENTICATING  4u /**< SockGate authentication in progress. */
#define SG_CLIENT_STATE_AUTHENTICATED   5u /**< Authentication succeeded (transient, followed by ACTIVE). */
#define SG_CLIENT_STATE_ACTIVE          6u /**< Session established: messages can be sent and received. */
#define SG_CLIENT_STATE_REFRESHING      7u /**< Re-authentication in progress; the session stays usable. */
#define SG_CLIENT_STATE_EXPIRED         8u /**< The session expired; connect again. */
#define SG_CLIENT_STATE_CLOSED          9u /**< The connection was closed or failed; connect again. */

/* ---- Session policy decided by the server ------------------------------- */
#define SG_SESSION_POLICY_NONE       0u /**< No policy (no authenticated session). */
#define SG_SESSION_POLICY_NORMAL     1u /**< Normal session. */
#define SG_SESSION_POLICY_RESTRICTED 2u /**< Restricted session; the application decides what it restricts. */

/* ---- Client integrity observations (reported, never trusted to raise trust) */
#define SG_INTEGRITY_DEBUGGER_PRESENT     (1u << 0) /**< A debugger or tracer is attached to the process. */
/** Library preloading is configured (Linux: LD_PRELOAD, LD_AUDIT or /etc/ld.so.preload). */
#define SG_INTEGRITY_PRELOAD_PRESENT      (1u << 1)
/** The executable has no valid embedded Authenticode signature (Windows only). */
#define SG_INTEGRITY_UNSIGNED_EXECUTABLE  (1u << 2)
#define SG_INTEGRITY_ASLR_DISABLED        (1u << 3) /**< ASLR is disabled for the executable or the system. */
#define SG_INTEGRITY_DEP_DISABLED         (1u << 4) /**< DEP is disabled for the process (Windows). */
#define SG_INTEGRITY_CFG_DISABLED         (1u << 5) /**< Control Flow Guard is disabled (Windows). */
#define SG_INTEGRITY_EXECUTABLE_WRITABLE  (1u << 6) /**< The executable is group- or world-writable (Linux). */
/** The executable or a loaded module comes from a temporary or other unexpected location
 *  (Linux also: the module scan failed). */
#define SG_INTEGRITY_UNEXPECTED_MODULES   (1u << 7)
#define SG_INTEGRITY_HASH_UNAVAILABLE     (1u << 8) /**< An executable or module hash could not be computed. */
#define SG_INTEGRITY_KNOWN_FLAGS          0x000001FFu /**< All SG_INTEGRITY_* observation bits defined here. */

#define SG_INTEGRITY_PLATFORM_WINDOWS 1u /**< Integrity report platform: Windows. */
#define SG_INTEGRITY_PLATFORM_LINUX   2u /**< Integrity report platform: Linux. */
#define SG_INTEGRITY_PLATFORM_MACOS   3u /**< Integrity report platform: macOS. */

/* ---- Per-message metadata ----------------------------------------------- */
#define SG_MESSAGE_FLAG_ENCRYPTED (1u << 0) /**< payload used application-layer AEAD */
#define SG_MESSAGE_FLAG_RESPONSE  (1u << 1) /**< request_id refers to the receiver's own request */

#define SG_MESSAGE_INFO_VERSION 1u /**< Current version of SG_MessageInfo. */
/**
 * @brief Metadata of one received message.
 *
 * Filled by SG_Client_ReceiveEx() and passed to the server's on_message callback.
 * Initialise with SG_MessageInfo_Init() before passing it to the client.
 */
typedef struct SG_MessageInfo {
    uint32_t size;       /**< Size of this structure in bytes (set by SG_MessageInfo_Init). */
    uint32_t version;    /**< SG_MESSAGE_INFO_VERSION (set by SG_MessageInfo_Init). */
    uint64_t request_id; /**< Request id of the message; 0 = none */
    uint32_t flags;      /**< SG_MESSAGE_FLAG_* */
    uint32_t reserved;   /**< Reserved. */
} SG_MessageInfo;

/** @} */

#endif /* SOCKGATE_TYPES_H */
