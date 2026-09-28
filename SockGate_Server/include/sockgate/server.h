/*
 * SockGate server - public C API.
 *
 * The server is the final authority: clients are authenticated with their
 * installation keys and every permission (policy, features, lifetime) is
 * decided here, optionally refined by the on_authorize callback.
 *
 * Threading: callbacks run without any SockGate lock held, usually on I/O
 * worker threads, but also on the thread whose call closed a session
 * (SG_Server_CloseSession, SG_Server_RevokeClient, SG_Server_Stop, a failing
 * SG_Server_Send) and on the internal timer thread (expiry, idle timeout).
 * Callbacks for one session are serialised and ordered; callbacks for
 * different sessions may run concurrently. Every API function except
 * SG_Server_Stop and SG_Server_Destroy may be called from a callback,
 * including for the session being processed. A slow on_message callback
 * applies backpressure: reading from that session pauses until it returns.
 */
#ifndef SOCKGATE_SERVER_H
#define SOCKGATE_SERVER_H

#include "sockgate/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SG_Server SG_Server;

/* ---- SG_ServerOptions.flags ------------------------------------------------ */
#define SG_SERVER_OPT_ALLOW_TLS12            (1u << 0)
#define SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION (1u << 1) /* reject DATA without application-layer AEAD */
#define SG_SERVER_OPT_ALLOW_ENROLLMENT       (1u << 2) /* accept ENROLL handshakes */
#define SG_SERVER_OPT_REQUIRE_LICENSE        (1u << 3) /* deny sessions without a valid license (reserved) */

#define SG_AUTH_MODE_AUTHENTICATE 1u
#define SG_AUTH_MODE_ENROLL       2u

/* Everything below that came from the client is a claim, not a fact. */
#define SG_AUTH_REQUEST_VERSION 1u
typedef struct SG_AuthRequest {
    uint32_t size;
    uint32_t version;
    SG_SessionHandle session;
    SG_InstallationId installation_id; /* verified: the client proved possession of this key */
    uint8_t reserved0[4];
    uint32_t auth_mode;                 /* SG_AUTH_MODE_* */
    uint32_t reauthentication;          /* 1 during SG_Client_Refresh */
    const char* product_id;             /* claim ("" if absent) */
    const char* product_version;        /* claim */
    const char* license_id;             /* claim */
    uint64_t requested_features;        /* claim */
    uint16_t client_version_major;      /* claim */
    uint16_t client_version_minor;
    uint16_t client_version_patch;
    uint16_t integrity_present;         /* 1 if the client sent an integrity report */
    uint32_t integrity_flags;           /* SG_INTEGRITY_* observations (claim) */
    uint32_t integrity_platform;
    const uint8_t* executable_sha256;   /* 32 bytes or NULL (claim) */
    const char* peer_address;
    const char* registered_product_id;  /* from the server's registry ("" if none) */
    const char* registered_license_id;
} SG_AuthRequest;

/* Pre-filled with the built-in decision; the callback may change it. */
#define SG_AUTH_DECISION_VERSION 1u
typedef struct SG_AuthDecision {
    uint32_t size;
    uint32_t version;
    uint32_t allow;                   /* 0 = reject (the client sees a generic rejection) */
    uint32_t policy;                  /* SG_SESSION_POLICY_NORMAL / _RESTRICTED */
    uint64_t granted_features;
    uint32_t session_lifetime_ms;     /* 0 = server default */
    uint32_t reserved;
    uint64_t license_expires_at_ms;   /* Unix ms, 0 = none; caps the session lifetime */
} SG_AuthDecision;

#define SG_ENROLL_REQUEST_VERSION 1u
typedef struct SG_EnrollRequest {
    uint32_t size;
    uint32_t version;
    SG_InstallationId installation_id;
    SG_PublicKey public_key;
    uint8_t reserved[3];
    const uint8_t* token_pub;          /* public part of the enrollment token */
    size_t token_pub_size;
    const char* product_id;            /* claims from the handshake */
    const char* license_id;
    const char* peer_address;
} SG_EnrollRequest;

#define SG_SERVER_SESSION_INFO_VERSION 1u
typedef struct SG_ServerSessionInfo {
    uint32_t size;
    uint32_t version;
    SG_SessionHandle session;
    SG_SessionId session_id;
    SG_InstallationId installation_id;
    uint32_t policy;
    uint32_t epoch;
    uint64_t granted_features;
    uint64_t license_expires_at_ms;
    uint32_t expires_in_ms;
    uint32_t enrolled;
    char peer_address[64];
    char product_id[65];
    char license_id[129];
    char reserved[6];
} SG_ServerSessionInfo;

#define SG_SERVER_CALLBACKS_VERSION 1u
typedef struct SG_ServerCallbacks {
    uint32_t size;
    uint32_t version;
    void* user;
    /* Called after cryptographic authentication, before the session opens. */
    SG_Status (SG_CALL *on_authorize)(void* user, const SG_AuthRequest* request, SG_AuthDecision* decision);
    /* ENROLL validation for externally issued tokens. Must return SG_OK and
     * the token's 32-byte key K_tok, or an error to reject. NULL = built-in
     * tokens from SG_Server_IssueEnrollmentToken. */
    SG_Status (SG_CALL *on_enroll)(void* user, const SG_EnrollRequest* request, uint8_t token_key_out[32]);
    void (SG_CALL *on_session_opened)(void* user, const SG_ServerSessionInfo* info);
    void (SG_CALL *on_message)(void* user, SG_SessionHandle session, const void* data, size_t size,
                               const SG_MessageInfo* info);
    void (SG_CALL *on_session_closed)(void* user, SG_SessionHandle session, SG_Status reason);
} SG_ServerCallbacks;

#define SG_SERVER_OPTIONS_VERSION 1u
typedef struct SG_ServerOptions {
    uint32_t size;
    uint32_t version;

    const char* bind_address;          /* default "0.0.0.0" */
    uint16_t port;                     /* 0 = ephemeral (see SG_Server_GetPort) */
    uint16_t reserved0;

    /* TLS identity: file paths or in-memory PEM (unencrypted keys). */
    const char* tls_cert_chain_file;
    const char* tls_private_key_file;
    const char* tls_cert_chain_pem;
    size_t tls_cert_chain_pem_size;    /* 0 = NUL-terminated */
    const char* tls_private_key_pem;
    size_t tls_private_key_pem_size;

    /* Optional server proof key (ECDSA P-256, PEM). */
    const char* proof_key_file;
    const char* proof_key_pem;
    size_t proof_key_pem_size;

    /* Enrollment token secret (>= 32 bytes). NULL = random per server start. */
    const uint8_t* token_key;
    size_t token_key_size;

    const char* registry_path;         /* NULL = in-memory registry */

    uint32_t worker_threads;           /* 0 = hardware concurrency */
    uint32_t max_connections;          /* default 10000 */
    uint32_t handshake_timeout_ms;     /* default 15000 */
    uint32_t challenge_ttl_ms;         /* default 30000 */
    uint32_t session_lifetime_ms;      /* default 3600000, max 7 days */
    uint32_t idle_timeout_ms;          /* default 300000, 0 = disabled */
    uint32_t max_payload_size;         /* default 1 MiB, max 16 MiB */
    uint32_t min_reauth_interval_ms;   /* default 10000 */
    uint32_t flags;                    /* SG_SERVER_OPT_* */
    uint32_t reserved1;

    const SG_ServerCallbacks* callbacks; /* copied at creation; nullable */

    SG_LogCallback log_callback;
    void* log_user;
    uint32_t log_level;                /* default SG_LOG_WARN */
    uint32_t reserved2;
} SG_ServerOptions;

#define SG_CLIENT_RECORD_VERSION 1u
typedef struct SG_ClientRecord {
    uint32_t size;
    uint32_t version;
    SG_PublicKey public_key;           /* installation id is derived from it */
    uint8_t reserved[7];
    const char* product_id;            /* optional binding */
    const char* license_id;            /* optional binding */
} SG_ClientRecord;

#define SG_ENROLLMENT_TOKEN_REQUEST_VERSION 1u
typedef struct SG_EnrollmentTokenRequest {
    uint32_t size;
    uint32_t version;
    const char* product_id;            /* required */
    const char* license_id;            /* optional */
    uint32_t ttl_ms;                   /* default 24 h */
    uint32_t reserved;
} SG_EnrollmentTokenRequest;

#define SG_SERVER_STATS_VERSION 1u
typedef struct SG_ServerStats {
    uint32_t size;
    uint32_t version;
    uint64_t active_connections;
    uint64_t active_sessions;
    uint64_t total_connections;
    uint64_t auth_succeeded;
    uint64_t auth_failed;
    uint64_t protocol_errors;
    uint64_t messages_received;
    uint64_t messages_sent;
} SG_ServerStats;

SG_SERVER_API void SG_CALL SG_ServerOptions_Init(SG_ServerOptions* options);
SG_SERVER_API void SG_CALL SG_ServerCallbacks_Init(SG_ServerCallbacks* callbacks);
SG_SERVER_API void SG_CALL SG_ClientRecord_Init(SG_ClientRecord* record);
SG_SERVER_API void SG_CALL SG_EnrollmentTokenRequest_Init(SG_EnrollmentTokenRequest* request);
SG_SERVER_API void SG_CALL SG_ServerSessionInfo_Init(SG_ServerSessionInfo* info);
SG_SERVER_API void SG_CALL SG_ServerStats_Init(SG_ServerStats* stats);

SG_SERVER_API SG_Status SG_CALL SG_Server_Create(const SG_ServerOptions* options, SG_Server** server);
SG_SERVER_API SG_Status SG_CALL SG_Server_Start(SG_Server* server);
SG_SERVER_API SG_Status SG_CALL SG_Server_Stop(SG_Server* server);
SG_SERVER_API SG_Status SG_CALL SG_Server_Destroy(SG_Server* server);
SG_SERVER_API SG_Status SG_CALL SG_Server_GetPort(SG_Server* server, uint16_t* port);

SG_SERVER_API SG_Status SG_CALL SG_Server_Send(SG_Server* server, SG_SessionHandle session, const void* data,
                                               size_t size);
SG_SERVER_API SG_Status SG_CALL SG_Server_SendEx(SG_Server* server, SG_SessionHandle session, const void* data,
                                                 size_t size, uint64_t reply_to_request_id);
SG_SERVER_API SG_Status SG_CALL SG_Server_CloseSession(SG_Server* server, SG_SessionHandle session);
SG_SERVER_API SG_Status SG_CALL SG_Server_GetSessionInfo(SG_Server* server, SG_SessionHandle session,
                                                         SG_ServerSessionInfo* info);

/* Registry. Revocation closes the installation's live sessions immediately. */
SG_SERVER_API SG_Status SG_CALL SG_Server_RegisterClient(SG_Server* server, const SG_ClientRecord* record);
SG_SERVER_API SG_Status SG_CALL SG_Server_RevokeClient(SG_Server* server, const SG_InstallationId* installation_id);
SG_SERVER_API SG_Status SG_CALL SG_Server_IssueEnrollmentToken(SG_Server* server,
                                                               const SG_EnrollmentTokenRequest* request, char* token,
                                                               size_t capacity, size_t* written);

SG_SERVER_API SG_Status SG_CALL SG_Server_GetStats(SG_Server* server, SG_ServerStats* stats);
SG_SERVER_API uint32_t SG_CALL SG_Server_GetApiVersion(void);

#ifdef __cplusplus
}
#endif

#endif /* SOCKGATE_SERVER_H */
