/*
 * SockGate - common public types shared by the client and server APIs.
 *
 * ABI rules:
 *  - Enumerations are transported as uint32_t fields plus #define constants.
 *  - Versioned structures start with { uint32_t size; uint32_t version; }.
 */
#ifndef SOCKGATE_TYPES_H
#define SOCKGATE_TYPES_H

#include <stddef.h>
#include <stdint.h>

#include "sockgate/error.h"
#include "sockgate/export.h"
#include "sockgate/version.h"

#define SG_INSTALLATION_ID_SIZE 16
#define SG_SESSION_ID_SIZE      16
#define SG_SHA256_SIZE          32
#define SG_PUBLIC_KEY_SIZE      65 /* SEC1 uncompressed P-256 point: 0x04 || X || Y */
#define SG_MAX_PINS              8
#define SG_MAX_PROOF_KEYS        4

typedef struct SG_InstallationId { uint8_t bytes[SG_INSTALLATION_ID_SIZE]; } SG_InstallationId;
typedef struct SG_SessionId      { uint8_t bytes[SG_SESSION_ID_SIZE]; } SG_SessionId;
typedef struct SG_Sha256         { uint8_t bytes[SG_SHA256_SIZE]; } SG_Sha256;
typedef struct SG_PublicKey      { uint8_t bytes[SG_PUBLIC_KEY_SIZE]; } SG_PublicKey;

/* Server-side session reference. Never reused during the lifetime of an SG_Server. */
typedef uint64_t SG_SessionHandle;
#define SG_INVALID_SESSION_HANDLE ((SG_SessionHandle)0)

/* ---- Logging ------------------------------------------------------------ */
#define SG_LOG_NONE  0u
#define SG_LOG_ERROR 1u
#define SG_LOG_WARN  2u
#define SG_LOG_INFO  3u
#define SG_LOG_DEBUG 4u /* compiled out of release builds unless SOCKGATE_ENABLE_DEBUG_LOG */
#define SG_LOG_TRACE 5u /* compiled out of release builds unless SOCKGATE_ENABLE_DEBUG_LOG */

/* Log messages never contain key material, tokens, signatures or payload bytes. */
typedef void (SG_CALL *SG_LogCallback)(void* user, uint32_t level, const char* message);

/* ---- Client session state (SG_Client_GetState) -------------------------- */
#define SG_CLIENT_STATE_DISCONNECTED    0u
#define SG_CLIENT_STATE_CONNECTING      1u
#define SG_CLIENT_STATE_TLS_HANDSHAKE   2u
#define SG_CLIENT_STATE_TLS_ESTABLISHED 3u
#define SG_CLIENT_STATE_AUTHENTICATING  4u
#define SG_CLIENT_STATE_AUTHENTICATED   5u
#define SG_CLIENT_STATE_ACTIVE          6u
#define SG_CLIENT_STATE_REFRESHING      7u
#define SG_CLIENT_STATE_EXPIRED         8u
#define SG_CLIENT_STATE_CLOSED          9u

/* ---- Session policy decided by the server ------------------------------- */
#define SG_SESSION_POLICY_NONE       0u
#define SG_SESSION_POLICY_NORMAL     1u
#define SG_SESSION_POLICY_RESTRICTED 2u

/* ---- Client integrity observations (reported, never trusted to raise trust) */
#define SG_INTEGRITY_DEBUGGER_PRESENT     (1u << 0)
#define SG_INTEGRITY_PRELOAD_PRESENT      (1u << 1)
#define SG_INTEGRITY_UNSIGNED_EXECUTABLE  (1u << 2)
#define SG_INTEGRITY_ASLR_DISABLED        (1u << 3)
#define SG_INTEGRITY_DEP_DISABLED         (1u << 4)
#define SG_INTEGRITY_CFG_DISABLED         (1u << 5)
#define SG_INTEGRITY_EXECUTABLE_WRITABLE  (1u << 6)
#define SG_INTEGRITY_UNEXPECTED_MODULES   (1u << 7)
#define SG_INTEGRITY_HASH_UNAVAILABLE     (1u << 8)
#define SG_INTEGRITY_KNOWN_FLAGS          0x000001FFu

/* ---- Per-message metadata ----------------------------------------------- */
#define SG_MESSAGE_FLAG_ENCRYPTED (1u << 0) /* payload used application-layer AEAD */
#define SG_MESSAGE_FLAG_RESPONSE  (1u << 1) /* request_id refers to the receiver's own request */

#define SG_MESSAGE_INFO_VERSION 1u
typedef struct SG_MessageInfo {
    uint32_t size;
    uint32_t version;
    uint64_t request_id; /* 0 = none */
    uint32_t flags;      /* SG_MESSAGE_FLAG_* */
    uint32_t reserved;
} SG_MessageInfo;

#endif /* SOCKGATE_TYPES_H */
