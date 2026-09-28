/*
 * SockGate server - public C API.
 *
 * The server is the final authority: clients are authenticated with their
 * installation keys and every permission (policy, features, lifetime) is
 * decided here, optionally refined by the on_authorize callback.
 *
 * Built-in authorization (before on_authorize):
 *  - the installation must be registered and active; its registered product /
 *    license bindings win, and a client claim contradicting them is denied;
 *  - the effective license is the registered one (SG_ClientRecord, or the
 *    enrollment token's). A license id claimed by an installation without a
 *    binding is an unverified claim (SG_LICENSE_STATUS_UNKNOWN), unless
 *    SG_SERVER_OPT_LICENSE_ACTIVATION is set: then a claimed license from
 *    the store activates and is bound to the installation permanently;
 *  - a license from the store must be active, for the same product and
 *    unexpired. Then
 *        granted_features = requested_features & license.features
 *    (all license features when the client requested none) and the license
 *    expiry caps the session lifetime. Licenses unknown to the store grant
 *    nothing;
 *  - with SG_SERVER_OPT_REQUIRE_LICENSE every session without a verified
 *    license is denied;
 *  - integrity policy: the client's SG_INTEGRITY_* observations plus the
 *    server-side conditions below are matched against
 *    SG_ServerOptions.integrity_reject_mask (deny) and
 *    integrity_restrict_mask (SG_SESSION_POLICY_RESTRICTED). Reports can only
 *    lower trust: they are claims of a machine the attacker may control;
 *  - after on_authorize allowed the session it takes a seat of the license
 *    (up to max_installations; no free seat = denial). A seat is an
 *    activation, kept until SG_Server_ReleaseLicenseSeat or
 *    SG_Server_RevokeClient, not only while connected.
 *
 * Threading: callbacks run without any SockGate lock held (except the ones
 * SG_Server_Stop / SG_Server_Destroy deliver, under their lifecycle lock),
 * usually on I/O worker threads, but also on the thread whose call closed a
 * session (SG_Server_CloseSession, SG_Server_RevokeClient,
 * SG_Server_RevokeLicense, SG_Server_ReleaseLicenseSeat, SG_Server_Stop, a
 * failing SG_Server_Send) and on the internal timer thread (expiry, idle
 * timeout). The log callback is the exception: it may run while internal
 * locks are held, so it must only record the message and never call a
 * SockGate function. Callbacks for one session are serialised and ordered;
 * callbacks for different sessions may run concurrently. Every API function
 * except SG_Server_Start, SG_Server_Stop and SG_Server_Destroy may be called
 * from a callback, including for the session being processed. A slow on_message callback
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
#define SG_SERVER_OPT_REQUIRE_LICENSE        (1u << 3) /* deny sessions without a license from the license store */
/* Let installations without a license binding activate a license by claiming
 * its id. License ids then act as bearer secrets: make them unguessable. */
#define SG_SERVER_OPT_LICENSE_ACTIVATION     (1u << 4)

#define SG_AUTH_MODE_AUTHENTICATE 1u
#define SG_AUTH_MODE_ENROLL       2u

/* Integrity conditions evaluated by the server (in addition to the client's
 * SG_INTEGRITY_* observations) for the integrity masks and SG_AuthRequest. */
#define SG_INTEGRITY_REPORT_MISSING      (1u << 30) /* the client sent no integrity report */
#define SG_INTEGRITY_UNKNOWN_EXECUTABLE  (1u << 31) /* allowlist configured, executable hash not in it */

/* SG_AuthRequest.license_status: result of the built-in license check. */
#define SG_LICENSE_STATUS_NONE    0u /* no license registered or claimed */
#define SG_LICENSE_STATUS_VALID   1u /* verified against the license store */
#define SG_LICENSE_STATUS_UNKNOWN 2u /* registered but not in the license store, or an unverified claim */

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
    uint32_t license_status;            /* SG_LICENSE_STATUS_* (server-verified) */
    uint32_t reserved1;
    uint64_t license_features;          /* entitlement of a VALID license, else 0 */
    uint32_t integrity_conditions;      /* reported flags + server conditions (see masks) */
    uint32_t reserved2;
} SG_AuthRequest;

/* Pre-filled with the built-in decision; the callback may change it (the
 * application is trusted: it may also grant features beyond the license). */
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
    char product_id[65];               /* registered product; the client's claim if none is registered */
    char license_id[129];              /* registered or verified license, never a raw claim */
    char reserved[6];
    uint32_t license_status;           /* SG_LICENSE_STATUS_* of license_id */
    uint32_t reserved2;
} SG_ServerSessionInfo;

#define SG_SERVER_CALLBACKS_VERSION 1u
typedef struct SG_ServerCallbacks {
    uint32_t size;
    uint32_t version;
    void* user;
    /* Called after cryptographic authentication, before the session opens. */
    SG_Status (SG_CALL *on_authorize)(void* user, const SG_AuthRequest* request, SG_AuthDecision* decision);
    /* ENROLL validation for externally issued tokens. Must return SG_OK and
     * the token's 32-byte key K_tok, or an error to reject. NULL = only
     * built-in tokens from SG_Server_IssueEnrollmentToken are accepted; when
     * set, built-in tokens are rejected (set it only if all tokens come from
     * your issuer).
     * This is a key lookup, called BEFORE anything is verified: the request
     * (token_pub included) is unauthenticated and may come from anyone who saw
     * the token's public part. SockGate enforces single use per registry: the
     * token is marked used (permanently) and the installation registered only
     * after the channel-bound token proof, the key and the signature were
     * verified - and before on_authorize, so an enrollment that on_authorize
     * denies has still used its token. Servers with separate registries do
     * not share that record: to keep a token single-use across them, consume
     * it here, atomically, in a shared store. Anyone who saw token_pub can
     * then burn the token (a denial of service, never an enrollment), so keep
     * such tokens short-lived. On success the installation is registered with
     * the claimed product; a claimed license is NOT bound (it is treated like
     * any license claim, see above). */
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

    /* Enrollment token secret (>= 32 bytes). NULL = random per SG_Server_Create:
     * tokens issued by one server object are not valid for another. */
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
    /* Connections still in the TLS / authentication phase; more are closed at
     * accept, so a flood of unauthenticated connections cannot take the
     * places of established sessions. 0 = max_connections / 2 (at least 1);
     * must not exceed max_connections. */
    uint32_t max_unauthenticated;

    const SG_ServerCallbacks* callbacks; /* copied at creation; nullable */

    SG_LogCallback log_callback;
    void* log_user;
    uint32_t log_level;                /* default SG_LOG_WARN */
    uint32_t reserved2;

    const char* license_path;          /* NULL = in-memory license store; must differ from registry_path */

    /* Integrity policy (see the header comment). 0 = ignore reports. */
    uint32_t integrity_restrict_mask;
    uint32_t integrity_reject_mask;
    const SG_Sha256* allowed_executables;  /* optional allowlist of executable SHA-256 values */
    size_t allowed_executable_count;       /* <= 4096 */
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

#define SG_LICENSE_RECORD_VERSION 1u
typedef struct SG_LicenseRecord {
    uint32_t size;
    uint32_t version;
    const char* license_id;            /* required, 1..128 bytes */
    const char* product_id;            /* required, 1..64 bytes */
    uint64_t features;                 /* feature bits the license entitles */
    uint64_t expires_at_ms;            /* Unix ms, 0 = perpetual */
    uint32_t max_installations;        /* 0 = unlimited */
    uint32_t reserved;
} SG_LicenseRecord;

#define SG_LICENSE_INFO_VERSION 1u
typedef struct SG_LicenseInfo {
    uint32_t size;
    uint32_t version;
    char product_id[65];
    uint8_t reserved0[7];
    uint64_t features;
    uint64_t expires_at_ms;
    uint32_t max_installations;
    uint32_t installations;            /* seats in use */
    uint32_t revoked;                  /* 1 once revoked */
    uint32_t reserved1;
} SG_LicenseInfo;

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
SG_SERVER_API void SG_CALL SG_LicenseRecord_Init(SG_LicenseRecord* record);
SG_SERVER_API void SG_CALL SG_LicenseInfo_Init(SG_LicenseInfo* info);
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

/* Registry. Revocation closes the installation's live sessions immediately.
 * Revocations (of installations and licenses) that cannot be persisted still
 * take effect in this process and return SG_STORAGE_ERROR; calling the revoke
 * function again retries the write (as does any later successful change of
 * that store) until it returns SG_OK.
 * A license binding in a record or token must name an active license for
 * the same product when the license store knows it (SG_INVALID_STATE /
 * SG_INVALID_ARGUMENT), and must exist with SG_SERVER_OPT_REQUIRE_LICENSE
 * (SG_NOT_FOUND). */
SG_SERVER_API SG_Status SG_CALL SG_Server_RegisterClient(SG_Server* server, const SG_ClientRecord* record);
SG_SERVER_API SG_Status SG_CALL SG_Server_RevokeClient(SG_Server* server, const SG_InstallationId* installation_id);
SG_SERVER_API SG_Status SG_CALL SG_Server_IssueEnrollmentToken(SG_Server* server,
                                                               const SG_EnrollmentTokenRequest* request, char* token,
                                                               size_t capacity, size_t* written);

/* Licenses. AddLicense inserts a license or updates its terms; changed terms
 * apply to new sessions and at each session's next refresh. Revocation is
 * permanent and closes the sessions authorised under the license
 * immediately. ReleaseLicenseSeat frees an installation's seat (closing its
 * sessions under that license); the installation takes a seat again on its
 * next successful authorization if one is free. */
SG_SERVER_API SG_Status SG_CALL SG_Server_AddLicense(SG_Server* server, const SG_LicenseRecord* license);
SG_SERVER_API SG_Status SG_CALL SG_Server_RevokeLicense(SG_Server* server, const char* license_id);
SG_SERVER_API SG_Status SG_CALL SG_Server_ReleaseLicenseSeat(SG_Server* server, const char* license_id,
                                                             const SG_InstallationId* installation_id);
SG_SERVER_API SG_Status SG_CALL SG_Server_GetLicense(SG_Server* server, const char* license_id,
                                                     SG_LicenseInfo* info);

SG_SERVER_API SG_Status SG_CALL SG_Server_GetStats(SG_Server* server, SG_ServerStats* stats);
SG_SERVER_API uint32_t SG_CALL SG_Server_GetApiVersion(void);

#ifdef __cplusplus
}
#endif

#endif /* SOCKGATE_SERVER_H */
