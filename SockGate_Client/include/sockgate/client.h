/*
 * SockGate client - public C API.
 *
 * Threading: SG_Client_Send and SG_Client_Receive may be called concurrently
 * from different threads; calls in the same direction are serialised.
 * SG_Client_Disconnect may be called from any thread and wakes blocked calls.
 * SG_Client_Destroy must not race any other call on the same handle.
 *
 * Typical use:
 *   SG_Client_Create -> SG_Client_EnsureIdentity -> SG_Client_Connect
 *   -> SG_Client_Authenticate -> SG_Client_Send / SG_Client_Receive
 *   -> SG_Client_Disconnect -> SG_Client_Destroy
 */
#ifndef SOCKGATE_CLIENT_H
#define SOCKGATE_CLIENT_H

#include "sockgate/config.h"
#include "sockgate/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SG_Client SG_Client;

/* Timeout values for SG_Client_ReceiveEx. */
#define SG_WAIT_INFINITE 0xFFFFFFFFu /* block until a message arrives */
#define SG_WAIT_DEFAULT  0xFFFFFFFEu /* use SG_ClientConfig.io_timeout_ms */

#define SG_IDENTITY_INFO_VERSION 1u
typedef struct SG_IdentityInfo {
    uint32_t size;
    uint32_t version;
    SG_InstallationId installation_id; /* derived from the public key */
    SG_PublicKey public_key;           /* register this with the server out of band, or enroll */
    uint8_t reserved[3];
    uint32_t key_store_type;           /* SG_KEYSTORE_* actually in use */
    uint32_t hardware_backed;          /* 1 if the private key cannot leave a TPM */
} SG_IdentityInfo;

#define SG_CLIENT_SESSION_INFO_VERSION 1u
typedef struct SG_ClientSessionInfo {
    uint32_t size;
    uint32_t version;
    uint32_t state;                   /* SG_CLIENT_STATE_* */
    uint32_t policy;                  /* SG_SESSION_POLICY_* granted by the server */
    SG_SessionId session_id;
    uint64_t granted_features;        /* decided by the server */
    uint64_t license_expires_at_ms;   /* Unix ms, 0 = not license bound */
    uint32_t expires_in_ms;           /* remaining session lifetime */
    uint32_t epoch;                   /* key epoch (increments on refresh) */
    char tls_protocol[16];
    char tls_cipher[64];
} SG_ClientSessionInfo;

SG_CLIENT_API void SG_CALL SG_ClientConfig_Init(SG_ClientConfig* config);
SG_CLIENT_API void SG_CALL SG_ServerConfig_Init(SG_ServerConfig* server);
SG_CLIENT_API void SG_CALL SG_ProxyConfig_Init(SG_ProxyConfig* proxy);
SG_CLIENT_API void SG_CALL SG_IdentityInfo_Init(SG_IdentityInfo* info);
SG_CLIENT_API void SG_CALL SG_ClientSessionInfo_Init(SG_ClientSessionInfo* info);
SG_CLIENT_API void SG_CALL SG_MessageInfo_Init(SG_MessageInfo* info);

SG_CLIENT_API SG_Status SG_CALL SG_Client_Create(const SG_ClientConfig* config, SG_Client** client);
SG_CLIENT_API SG_Status SG_CALL SG_Client_Destroy(SG_Client* client);

/* Installation identity (key pair in the configured key store). */
SG_CLIENT_API SG_Status SG_CALL SG_Client_EnsureIdentity(SG_Client* client, SG_IdentityInfo* info /* nullable */);
SG_CLIENT_API SG_Status SG_CALL SG_Client_GetIdentity(SG_Client* client, SG_IdentityInfo* info);
SG_CLIENT_API SG_Status SG_CALL SG_Client_DeleteIdentity(SG_Client* client);

/* Connection and authentication. */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Connect(SG_Client* client, const SG_ServerConfig* server);
SG_CLIENT_API SG_Status SG_CALL SG_Client_Authenticate(SG_Client* client);
SG_CLIENT_API SG_Status SG_CALL SG_Client_Enroll(SG_Client* client, const char* enrollment_token);
SG_CLIENT_API SG_Status SG_CALL SG_Client_Refresh(SG_Client* client);
SG_CLIENT_API SG_Status SG_CALL SG_Client_Disconnect(SG_Client* client);

/* Data. One call = one message. */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Send(SG_Client* client, const void* data, size_t size);
SG_CLIENT_API SG_Status SG_CALL SG_Client_SendEx(SG_Client* client, const void* data, size_t size,
                                                 uint64_t reply_to_request_id, uint64_t* out_request_id);
/* On SG_BUFFER_TOO_SMALL, *received holds the required size and the message
 * stays queued for the next call. */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Receive(SG_Client* client, void* buffer, size_t capacity,
                                                  size_t* received);
SG_CLIENT_API SG_Status SG_CALL SG_Client_ReceiveEx(SG_Client* client, void* buffer, size_t capacity,
                                                    size_t* received, SG_MessageInfo* info /* nullable */,
                                                    uint32_t timeout_ms);
SG_CLIENT_API SG_Status SG_CALL SG_Client_Ping(SG_Client* client);

/* Introspection. */
SG_CLIENT_API SG_Status SG_CALL SG_Client_GetState(SG_Client* client, uint32_t* state);
SG_CLIENT_API SG_Status SG_CALL SG_Client_GetSessionInfo(SG_Client* client, SG_ClientSessionInfo* info);
SG_CLIENT_API uint32_t SG_CALL SG_Client_GetApiVersion(void);

/* Utility: SHA-256 SPKI pin of the first certificate in a PEM blob. */
SG_CLIENT_API SG_Status SG_CALL SG_Client_ComputeSpkiPin(const char* certificate_pem, size_t pem_size,
                                                         SG_Sha256* pin);

#ifdef __cplusplus
}
#endif

#endif /* SOCKGATE_CLIENT_H */
