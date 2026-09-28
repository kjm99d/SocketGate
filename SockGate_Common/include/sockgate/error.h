/*
 * SockGate - status codes.
 *
 * Numeric values are part of the ABI: never renumber, only append.
 * Local applications receive specific codes; the wire protocol only ever
 * carries generalised results so remote peers cannot probe internal state.
 */
#ifndef SOCKGATE_ERROR_H
#define SOCKGATE_ERROR_H

#include <stdint.h>

typedef int32_t SG_Status;

enum SG_StatusCode {
    SG_OK                   = 0,
    SG_INVALID_ARGUMENT     = 1,
    SG_OUT_OF_MEMORY        = 2,
    SG_NETWORK_ERROR        = 3,
    SG_TLS_ERROR            = 4,
    SG_CERTIFICATE_ERROR    = 5,
    SG_PINNING_ERROR        = 6,
    SG_AUTH_FAILED          = 7,
    SG_INVALID_SIGNATURE    = 8,
    SG_CHALLENGE_EXPIRED    = 9,
    SG_REPLAY_DETECTED      = 10,
    SG_PROTOCOL_ERROR       = 11,
    SG_SERVER_REJECTED      = 12,
    SG_SESSION_EXPIRED      = 13,
    SG_INTEGRITY_FAILED     = 14,
    SG_TIMEOUT              = 15,
    SG_INVALID_STATE        = 16,
    SG_BUFFER_TOO_SMALL     = 17,
    SG_NOT_SUPPORTED        = 18,
    SG_CLOSED               = 19,
    SG_KEYSTORE_ERROR       = 20,
    SG_NOT_FOUND            = 21,
    SG_ALREADY_EXISTS       = 22,
    SG_LIMIT_EXCEEDED       = 23,
    SG_PROXY_ERROR          = 24,
    SG_VERSION_MISMATCH     = 25,
    SG_CRYPTO_ERROR         = 26,
    SG_INTERNAL_ERROR       = 27,
    SG_STORAGE_ERROR        = 28
};

/* Returns a static, human readable name for a status code. Never NULL. */
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
    default:                   return "SG_UNKNOWN_STATUS";
    }
}

#endif /* SOCKGATE_ERROR_H */
