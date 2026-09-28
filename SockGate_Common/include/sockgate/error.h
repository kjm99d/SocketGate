#ifndef SOCKGATE_ERROR_H
#define SOCKGATE_ERROR_H
/**
 * @file
 * @brief SockGate - status codes.
 * @ingroup sg_common
 *
 * Numeric values are part of the ABI: never renumber, only append.
 * Local applications receive specific codes; the wire protocol only ever
 * carries generalised results so remote peers cannot probe internal state.
 */

#include <stdint.h>

/**
 * @defgroup sg_common Common types and status codes
 * @brief Status codes, identifiers, constants and ABI macros shared by the client and server libraries.
 *
 * Declared in sockgate/error.h, sockgate/types.h, sockgate/export.h and sockgate/version.h.
 *
 * ABI conventions used by both libraries:
 * - Enumerations are transported as uint32_t fields plus \#define constants.
 * - Versioned structures start with { uint32_t size; uint32_t version; } and are initialised with their
 *   *_Init() function. The libraries read only the fields that lie within `size`.
 * - No C++ exception crosses the API: internal failures are reported as SG_OUT_OF_MEMORY or
 *   SG_INTERNAL_ERROR. The codes listed per function are the notable ones, not all possible ones: treat any
 *   other code as an error.
 * @{
 */

/** @brief Result of a SockGate function: one of the ::SG_StatusCode values. */
typedef int32_t SG_Status;

/**
 * @brief SockGate status codes (values of ::SG_Status).
 *
 * The numeric values are part of the ABI.
 */
enum SG_StatusCode {
    SG_OK                   = 0,  /**< Success. */
    /** Invalid argument or configuration: NULL pointer, size, structure size / version, string length, or a
     *  message that cannot be encoded. */
    SG_INVALID_ARGUMENT     = 1,
    SG_OUT_OF_MEMORY        = 2,  /**< Memory allocation failed. */
    SG_NETWORK_ERROR        = 3,  /**< Socket, connection or address resolution error. */
    SG_TLS_ERROR            = 4,  /**< TLS negotiation or record error, including TLS 1.2 without EMS. */
    /** Certificate chain, host name or validity check failed, or a certificate / CA could not be loaded. */
    SG_CERTIFICATE_ERROR    = 5,
    SG_PINNING_ERROR        = 6,  /**< The validated chain matches none of the configured SPKI pins. */
    SG_AUTH_FAILED          = 7,  /**< Authentication failed (local reason). */
    /** Signature verification failed (client: a required server proof is missing or invalid). */
    SG_INVALID_SIGNATURE    = 8,
    SG_CHALLENGE_EXPIRED    = 9,  /**< An authentication challenge expired. */
    SG_REPLAY_DETECTED      = 10, /**< A frame with an old sequence number or a duplicate request id arrived. */
    /** Protocol violation: malformed frame, frame not allowed in the current phase, skipped sequence number
     *  or failed tag check. */
    SG_PROTOCOL_ERROR       = 11,
    /** The server rejected the authentication or re-authentication, or closed the session with an
     *  authentication failure. */
    SG_SERVER_REJECTED      = 12,
    SG_SESSION_EXPIRED      = 13, /**< The session expired. */
    /** Integrity category code. Not returned by the current implementation: a denial by the server's
     *  integrity policy reaches the client as SG_SERVER_REJECTED. */
    SG_INTEGRITY_FAILED     = 14,
    SG_TIMEOUT              = 15, /**< The operation timed out. */
    SG_INVALID_STATE        = 16, /**< The call is not allowed in the current state. */
    SG_BUFFER_TOO_SMALL     = 17, /**< The caller's buffer is too small. */
    /** Feature or platform not supported, or a non-zero structure field (flag, mask bit or appended field)
     *  that this build does not know. */
    SG_NOT_SUPPORTED        = 18,
    SG_CLOSED               = 19, /**< The connection is closed (close_notify, EOF or CLOSE). */
    SG_KEYSTORE_ERROR       = 20, /**< Key store error. */
    SG_NOT_FOUND            = 21, /**< The requested object does not exist. */
    SG_ALREADY_EXISTS       = 22, /**< The object already exists. */
    SG_LIMIT_EXCEEDED       = 23, /**< A resource limit was exceeded. */
    SG_PROXY_ERROR          = 24, /**< Proxy negotiation failed. */
    SG_VERSION_MISMATCH     = 25, /**< Wire layout version mismatch or failed protocol version negotiation. */
    SG_CRYPTO_ERROR         = 26, /**< A cryptographic operation failed. */
    /** Internal error, including an exception caught at the API boundary or an internal code outside the
     *  public range. */
    SG_INTERNAL_ERROR       = 27,
    SG_STORAGE_ERROR        = 28, /**< Server storage (registry or license file) could not be read or written. */
    SG_IDENTITY_LOST        = 29  /**< The key store that held the identity no longer has its key. */
};

/**
 * @brief Returns a static, human readable name for a status code.
 *
 * @param[in] status Status code; any value is accepted.
 * @return The code's name (e.g. "SG_OK"), or "SG_UNKNOWN_STATUS" for an unknown value. Never NULL.
 * @note Thread-safe. Defined static inline so that the client and server libraries do not both export it.
 */
static inline const char* SG_StatusString(SG_Status status)
{
    switch (status) {
    case SG_OK:                return "SG_OK";
    case SG_INVALID_ARGUMENT:  return "SG_INVALID_ARGUMENT";
    case SG_OUT_OF_MEMORY:     return "SG_OUT_OF_MEMORY";
    case SG_NETWORK_ERROR:     return "SG_NETWORK_ERROR";
    case SG_TLS_ERROR:         return "SG_TLS_ERROR";
    case SG_CERTIFICATE_ERROR: return "SG_CERTIFICATE_ERROR";
    case SG_PINNING_ERROR:     return "SG_PINNING_ERROR";
    case SG_AUTH_FAILED:       return "SG_AUTH_FAILED";
    case SG_INVALID_SIGNATURE: return "SG_INVALID_SIGNATURE";
    case SG_CHALLENGE_EXPIRED: return "SG_CHALLENGE_EXPIRED";
    case SG_REPLAY_DETECTED:   return "SG_REPLAY_DETECTED";
    case SG_PROTOCOL_ERROR:    return "SG_PROTOCOL_ERROR";
    case SG_SERVER_REJECTED:   return "SG_SERVER_REJECTED";
    case SG_SESSION_EXPIRED:   return "SG_SESSION_EXPIRED";
    case SG_INTEGRITY_FAILED:  return "SG_INTEGRITY_FAILED";
    case SG_TIMEOUT:           return "SG_TIMEOUT";
    case SG_INVALID_STATE:     return "SG_INVALID_STATE";
    case SG_BUFFER_TOO_SMALL:  return "SG_BUFFER_TOO_SMALL";
    case SG_NOT_SUPPORTED:     return "SG_NOT_SUPPORTED";
    case SG_CLOSED:            return "SG_CLOSED";
    case SG_KEYSTORE_ERROR:    return "SG_KEYSTORE_ERROR";
    case SG_NOT_FOUND:         return "SG_NOT_FOUND";
    case SG_ALREADY_EXISTS:    return "SG_ALREADY_EXISTS";
    case SG_LIMIT_EXCEEDED:    return "SG_LIMIT_EXCEEDED";
    case SG_PROXY_ERROR:       return "SG_PROXY_ERROR";
    case SG_VERSION_MISMATCH:  return "SG_VERSION_MISMATCH";
    case SG_CRYPTO_ERROR:      return "SG_CRYPTO_ERROR";
    case SG_INTERNAL_ERROR:    return "SG_INTERNAL_ERROR";
    case SG_STORAGE_ERROR:     return "SG_STORAGE_ERROR";
    case SG_IDENTITY_LOST:     return "SG_IDENTITY_LOST";
    default:                   return "SG_UNKNOWN_STATUS";
    }
}

/** @} */

#endif /* SOCKGATE_ERROR_H */
