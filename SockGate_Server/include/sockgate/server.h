#ifndef SOCKGATE_SERVER_H
#define SOCKGATE_SERVER_H
/**
 * @file
 * @brief SockGate server - public C API.
 * @ingroup sg_server
 *
 * The authorization model and the threading rules are described in @ref sg_server.
 */

#include "sockgate/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup sg_server Server API
 * @brief Accepts SockGate clients, authenticates and authorises them, and exchanges messages.
 *
 * The server is the final authority: clients are authenticated with their
 * installation keys and every permission (policy, features, lifetime) is
 * decided here, optionally refined by the on_authorize callback.
 *
 * @par Built-in authorization (before on_authorize)
 * - the installation must be registered and active; its registered product /
 *   license bindings win, and a client claim contradicting them is denied;
 * - the effective license is the registered one (SG_ClientRecord, or the
 *   enrollment token's). A license id claimed by an installation without a
 *   binding is an unverified claim (SG_LICENSE_STATUS_UNKNOWN), unless
 *   SG_SERVER_OPT_LICENSE_ACTIVATION is set: then a claimed license from
 *   the store activates and is bound to the installation permanently;
 * - a license from the store must be active, for the same product and
 *   unexpired. Then
 *   `granted_features = requested_features & license.features`
 *   (all license features when the client requested none) and the license
 *   expiry caps the session lifetime. Licenses unknown to the store grant
 *   nothing;
 * - with SG_SERVER_OPT_REQUIRE_LICENSE every session without a verified
 *   license is denied;
 * - integrity policy: the client's SG_INTEGRITY_* observations plus the
 *   server-side conditions (SG_INTEGRITY_REPORT_MISSING, SG_INTEGRITY_UNKNOWN_EXECUTABLE) are matched against
 *   SG_ServerOptions.integrity_reject_mask (deny) and
 *   integrity_restrict_mask (SG_SESSION_POLICY_RESTRICTED). Reports can only
 *   lower trust: they are claims of a machine the attacker may control;
 * - after on_authorize allowed the session it takes a seat of the license
 *   (up to max_installations; no free seat = denial). A seat is an
 *   activation, kept until SG_Server_ReleaseLicenseSeat or
 *   SG_Server_RevokeClient, not only while connected.
 *
 * @par Threading
 * Callbacks run without any SockGate lock held (except the ones
 * SG_Server_Stop / SG_Server_Destroy deliver, under their lifecycle lock),
 * usually on I/O worker threads, but also on the thread whose call closed a
 * session (SG_Server_CloseSession, SG_Server_RevokeClient,
 * SG_Server_RevokeLicense, SG_Server_ReleaseLicenseSeat, SG_Server_Stop, a
 * failing SG_Server_Send) and on the internal timer thread (expiry, idle
 * timeout). The log callback is the exception: it may run while internal
 * locks are held, so it must only record the message and never call a
 * SockGate function. Callbacks for one session are serialised and ordered,
 * with one exception: on_authorize for a re-authentication (the client's
 * SG_Client_Refresh) runs on an I/O thread outside that order and may overlap
 * the same session's on_message and on_session_closed, so per-session data it
 * uses must be synchronised and must not be freed while it runs. Callbacks for
 * different sessions may run concurrently. Every API function except
 * SG_Server_Start, SG_Server_Stop and SG_Server_Destroy may be called from a
 * callback, including for the session being processed. A slow on_message
 * callback applies backpressure: once more than 8 MiB of that session's
 * messages wait for delivery, reading from it pauses until the application has
 * caught up (and more than 64 MiB close the session with SG_LIMIT_EXCEEDED).
 * @{
 */

/** @brief Opaque server handle, created by SG_Server_Create() and released by SG_Server_Destroy(). */
typedef struct SG_Server SG_Server;

/* ---- SG_ServerOptions.flags ------------------------------------------------ */
#define SG_SERVER_OPT_ALLOW_TLS12            (1u << 0) /**< accept TLS 1.2 in addition to TLS 1.3 */
#define SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION (1u << 1) /**< reject DATA without application-layer AEAD */
#define SG_SERVER_OPT_ALLOW_ENROLLMENT       (1u << 2) /**< accept ENROLL handshakes */
#define SG_SERVER_OPT_REQUIRE_LICENSE        (1u << 3) /**< deny sessions without a license from the license store */
/** Let installations without a license binding activate a license by claiming
 *  its id.
 *  @warning License ids then act as bearer secrets: make them unguessable. */
#define SG_SERVER_OPT_LICENSE_ACTIVATION     (1u << 4)

#define SG_AUTH_MODE_AUTHENTICATE 1u /**< Handshake mode: authentication of a registered installation. */
#define SG_AUTH_MODE_ENROLL       2u /**< Handshake mode: enrollment with an enrollment token. */

/** Integrity condition evaluated by the server (in addition to the client's SG_INTEGRITY_* observations) for
 *  the integrity masks and SG_AuthRequest: the client sent no integrity report. */
#define SG_INTEGRITY_REPORT_MISSING      (1u << 30)
/** Integrity condition evaluated by the server: allowlist configured, executable hash not in it (also set
 *  when no integrity report was sent). */
#define SG_INTEGRITY_UNKNOWN_EXECUTABLE  (1u << 31)

#define SG_LICENSE_STATUS_NONE    0u /**< no license registered or claimed */
#define SG_LICENSE_STATUS_VALID   1u /**< verified against the license store */
#define SG_LICENSE_STATUS_UNKNOWN 2u /**< registered but not in the license store, or an unverified claim */

#define SG_AUTH_REQUEST_VERSION 1u /**< Current version of SG_AuthRequest. */
/**
 * @brief Authorization request passed to the on_authorize callback.
 *
 * Everything below that came from the client is a claim, not a fact.
 * Pointers and strings are valid only during the callback.
 */
typedef struct SG_AuthRequest {
    uint32_t size;                      /**< Size of this structure in bytes. */
    uint32_t version;                   /**< SG_AUTH_REQUEST_VERSION. */
    SG_SessionHandle session;           /**< Session being authorised. */
    SG_InstallationId installation_id; /**< verified: the client proved possession of this key */
    uint8_t reserved0[4];               /**< Reserved. */
    uint32_t auth_mode;                 /**< SG_AUTH_MODE_* */
    uint32_t reauthentication;          /**< 1 during SG_Client_Refresh */
    const char* product_id;             /**< claim ("" if absent) */
    const char* product_version;        /**< claim */
    const char* license_id;             /**< claim */
    uint64_t requested_features;        /**< claim; 0 if the client requested none */
    uint16_t client_version_major;      /**< claim */
    uint16_t client_version_minor;      /**< Client version, minor (claim). */
    uint16_t client_version_patch;      /**< Client version, patch (claim). */
    uint16_t integrity_present;         /**< 1 if the client sent an integrity report */
    uint32_t integrity_flags;           /**< SG_INTEGRITY_* observations (claim) */
    uint32_t integrity_platform;        /**< SG_INTEGRITY_PLATFORM_* (claim); 0 without a report. */
    const uint8_t* executable_sha256;   /**< 32 bytes or NULL (claim) */
    const char* peer_address;           /**< Remote address of the connection. */
    const char* registered_product_id;  /**< from the server's registry ("" if none) */
    const char* registered_license_id;  /**< License bound in the server's registry ("" if none). */
    /** SG_LICENSE_STATUS_* (server-verified): result of the built-in license check. */
    uint32_t license_status;
    uint32_t reserved1;                 /**< Reserved. */
    uint64_t license_features;          /**< entitlement of a VALID license, else 0 */
    uint32_t integrity_conditions;      /**< reported flags + server conditions (see masks) */
    uint32_t reserved2;                 /**< Reserved. */
} SG_AuthRequest;

#define SG_AUTH_DECISION_VERSION 1u /**< Current version of SG_AuthDecision. */
/**
 * @brief Authorization decision of the on_authorize callback.
 *
 * Pre-filled with the built-in decision; the callback may change it (the
 * application is trusted: it may also grant features beyond the license).
 */
typedef struct SG_AuthDecision {
    uint32_t size;                    /**< Size of this structure in bytes. */
    uint32_t version;                 /**< SG_AUTH_DECISION_VERSION. */
    uint32_t allow;                   /**< 0 = reject (the client sees a generic rejection) */
    /** SG_SESSION_POLICY_NORMAL / _RESTRICTED; any other value denies the session. A session restricted by
     *  the integrity policy stays restricted. */
    uint32_t policy;
    uint64_t granted_features;        /**< Feature bits granted to the session. */
    uint32_t session_lifetime_ms;     /**< 0 = server default; capped at 7 days */
    uint32_t reserved;                /**< Reserved. */
    /** Unix ms, 0 = none; caps the session lifetime. An expiry that has passed denies the session. */
    uint64_t license_expires_at_ms;
} SG_AuthDecision;

#define SG_ENROLL_REQUEST_VERSION 1u /**< Current version of SG_EnrollRequest. */
/**
 * @brief Enrollment request passed to the on_enroll callback.
 *
 * Unauthenticated when on_enroll runs (see SG_ServerCallbacks.on_enroll). Pointers and strings are valid
 * only during the callback.
 */
typedef struct SG_EnrollRequest {
    uint32_t size;                     /**< Size of this structure in bytes. */
    uint32_t version;                  /**< SG_ENROLL_REQUEST_VERSION. */
    SG_InstallationId installation_id; /**< Installation id the client presents (not yet verified). */
    SG_PublicKey public_key;           /**< Installation public key the client presents (not yet verified). */
    uint8_t reserved[3];               /**< Reserved. */
    const uint8_t* token_pub;          /**< public part of the enrollment token */
    size_t token_pub_size;             /**< Size of token_pub in bytes. */
    const char* product_id;            /**< claims from the handshake */
    const char* license_id;            /**< License id claimed in the handshake. */
    const char* peer_address;          /**< Remote address of the connection. */
} SG_EnrollRequest;

#define SG_SERVER_SESSION_INFO_VERSION 1u /**< Current version of SG_ServerSessionInfo. */
/**
 * @brief Information about an open session.
 *
 * Passed to on_session_opened and filled by SG_Server_GetSessionInfo() (initialise it with
 * SG_ServerSessionInfo_Init()).
 */
typedef struct SG_ServerSessionInfo {
    uint32_t size;                     /**< Size of this structure in bytes (set by SG_ServerSessionInfo_Init). */
    uint32_t version;                  /**< SG_SERVER_SESSION_INFO_VERSION. */
    SG_SessionHandle session;          /**< Session handle. */
    SG_SessionId session_id;           /**< Session id sent to the client. */
    SG_InstallationId installation_id; /**< Authenticated installation. */
    uint32_t policy;                   /**< SG_SESSION_POLICY_* */
    uint32_t epoch;                    /**< Key epoch; increments with every re-authentication. */
    uint64_t granted_features;         /**< Feature bits granted to the session. */
    uint64_t license_expires_at_ms;    /**< Unix ms, 0 = none. */
    uint32_t expires_in_ms;            /**< Remaining session lifetime. */
    uint32_t enrolled;                 /**< 1 if this session's ENROLL handshake registered the installation. */
    char peer_address[64];             /**< Remote address (NUL-terminated, truncated to fit). */
    /** registered product; the client's claim if none is registered.
     *  @warning Without a registered product this is not verified: do not base permissions on it alone. */
    char product_id[65];
    char license_id[129];              /**< registered or verified license, never a raw claim */
    char reserved[6];                  /**< Reserved. */
    uint32_t license_status;           /**< SG_LICENSE_STATUS_* of license_id */
    uint32_t reserved2;                /**< Reserved. */
} SG_ServerSessionInfo;

#define SG_SERVER_CALLBACKS_VERSION 1u /**< Current version of SG_ServerCallbacks. */
/**
 * @brief Application callbacks of a server.
 *
 * Initialise with SG_ServerCallbacks_Init(); every callback is optional (NULL). SG_Server_Create() copies
 * the structure. The threading rules are described in @ref sg_server.
 */
typedef struct SG_ServerCallbacks {
    uint32_t size;                     /**< Size of this structure in bytes (set by SG_ServerCallbacks_Init). */
    uint32_t version;                  /**< SG_SERVER_CALLBACKS_VERSION (set by SG_ServerCallbacks_Init). */
    void* user;                        /**< First argument of every callback; must outlive the server. */
    /**
     * @brief Called after cryptographic authentication, before the session opens.
     *
     * Runs only when the built-in authorization allowed the session (decision->allow is 1 on entry), for
     * the first authentication and for every re-authentication (request->reauthentication = 1).
     * @param[in]     user     SG_ServerCallbacks.user.
     * @param[in]     request  The request; valid only during the call.
     * @param[in,out] decision Pre-filled with the built-in decision; the callback may change it.
     * @return SG_OK to apply *decision; any other value denies the session.
     */
    SG_Status (SG_CALL *on_authorize)(void* user, const SG_AuthRequest* request, SG_AuthDecision* decision);
    /**
     * @brief ENROLL validation for externally issued tokens.
     *
     * Must return SG_OK and
     * the token's 32-byte key K_tok, or an error to reject. NULL = only
     * built-in tokens from SG_Server_IssueEnrollmentToken are accepted; when
     * set, built-in tokens are rejected (set it only if all tokens come from
     * your issuer).
     *
     * This is a key lookup, called BEFORE anything is verified: the request
     * (token_pub included) is unauthenticated and may come from anyone who saw
     * the token's public part. SockGate enforces single use per registry: the
     * token is marked used (permanently, as long as the registry lasts: without
     * registry_path it lives in memory only, so with a persistent token_key an
     * unexpired token can be redeemed again after a restart) and the installation
     * registered only after the channel-bound token proof, the key and the
     * signature were verified - and before on_authorize (and the built-in
     * authorization), so an enrollment that on_authorize denies has still used
     * its token, and the installation stays registered and active. Authorization
     * runs again at every authentication, so a policy that denied it keeps
     * denying; SG_Server_RevokeClient removes it. Servers with separate registries do
     * not share that record: to keep a token single-use across them, consume
     * it here, atomically, in a shared store. Anyone who saw token_pub can
     * then burn the token (a denial of service, never an enrollment), so keep
     * such tokens short-lived. On success the installation is registered with
     * the claimed product; a claimed license is NOT bound (it is treated like
     * any license claim, see @ref sg_server).
     * @param[in]  user          SG_ServerCallbacks.user.
     * @param[in]  request       The unauthenticated request; valid only during the call.
     * @param[out] token_key_out Receives K_tok (32 bytes). SockGate wipes its copy after use.
     * @return SG_OK with token_key_out filled; any other value rejects the enrollment.
     */
    SG_Status (SG_CALL *on_enroll)(void* user, const SG_EnrollRequest* request, uint8_t token_key_out[32]);
    /**
     * @brief Called when a session has opened (authentication and authorization succeeded).
     * @param[in] user SG_ServerCallbacks.user.
     * @param[in] info The session; valid only during the call.
     */
    void (SG_CALL *on_session_opened)(void* user, const SG_ServerSessionInfo* info);
    /**
     * @brief Called for every message received on a session.
     * @param[in] user    SG_ServerCallbacks.user.
     * @param[in] session Session the message arrived on.
     * @param[in] data    Payload; valid only during the call.
     * @param[in] size    Payload size in bytes.
     * @param[in] info    request_id and flags of the message; valid only during the call. Answer a request
     *                    with SG_Server_SendEx(server, session, ..., info->request_id).
     */
    void (SG_CALL *on_message)(void* user, SG_SessionHandle session, const void* data, size_t size,
                               const SG_MessageInfo* info);
    /**
     * @brief Called once when an opened session closes; the handle is no longer valid afterwards.
     * @param[in] user    SG_ServerCallbacks.user.
     * @param[in] session The closed session.
     * @param[in] reason  Why it closed, e.g. SG_CLOSED (closed by either side, SG_Server_CloseSession(),
     *                    SG_Server_Stop()), SG_SESSION_EXPIRED, SG_TIMEOUT (idle), SG_AUTH_FAILED (revocation,
     *                    released seat or failed re-authentication).
     */
    void (SG_CALL *on_session_closed)(void* user, SG_SessionHandle session, SG_Status reason);
} SG_ServerCallbacks;

#define SG_SERVER_OPTIONS_VERSION 1u /**< Current version of SG_ServerOptions. */
/**
 * @brief Server configuration for SG_Server_Create().
 *
 * Initialise with SG_ServerOptions_Init(), which sets the defaults noted below; for the numeric limits and
 * timeouts except idle_timeout_ms, 0 also selects the default. SG_Server_Create() copies or loads everything
 * it needs, so strings, PEM data, token_key, the callbacks structure and the allowlist may be freed once it
 * returns; log_callback, log_user and callbacks->user must stay valid while the server exists. Appended
 * fields this library does not know must be zero (otherwise SG_NOT_SUPPORTED).
 */
typedef struct SG_ServerOptions {
    uint32_t size;                     /**< Size of this structure in bytes (set by SG_ServerOptions_Init). */
    uint32_t version;                  /**< SG_SERVER_OPTIONS_VERSION (set by SG_ServerOptions_Init). */

    const char* bind_address;          /**< default "0.0.0.0" */
    uint16_t port;                     /**< 0 = ephemeral (see SG_Server_GetPort) */
    uint16_t reserved0;                /**< Reserved. */

    /* TLS identity: file paths or in-memory PEM (unencrypted keys). */
    const char* tls_cert_chain_file;   /**< Certificate chain PEM file; takes precedence over the PEM field. */
    const char* tls_private_key_file;  /**< Private key PEM file; takes precedence over the PEM field. */
    const char* tls_cert_chain_pem;    /**< Certificate chain PEM, leaf certificate first. */
    size_t tls_cert_chain_pem_size;    /**< 0 = NUL-terminated */
    /** Private key PEM (unencrypted).
     *  @warning Secret: SG_Server_Create() copies it and wipes its copy once loaded; wipe the caller's copy. */
    const char* tls_private_key_pem;
    size_t tls_private_key_pem_size;   /**< 0 = NUL-terminated. */

    /* Optional server proof key (ECDSA P-256, PEM). */
    const char* proof_key_file;        /**< Proof key PEM file; takes precedence over proof_key_pem. */
    const char* proof_key_pem;         /**< Proof key PEM in memory. */
    size_t proof_key_pem_size;         /**< 0 = NUL-terminated. */

    /** Enrollment token secret (>= 32 bytes, <= 1024 bytes; copied). NULL = random per SG_Server_Create:
     *  tokens issued by one server object are not valid for another.
     *  @warning Secret: anyone holding it can issue enrollment tokens for this server. When it is persistent,
     *           also set registry_path: an in-memory registry forgets used tokens at a restart, so an
     *           unexpired token could be redeemed again. */
    const uint8_t* token_key;
    size_t token_key_size;             /**< Size of token_key in bytes; 0 = as NULL. */

    /** NULL = in-memory registry. The file is locked while the server exists: another open store of it
     *  fails with SG_INVALID_STATE. */
    const char* registry_path;

    uint32_t worker_threads;           /**< 0 = hardware concurrency */
    uint32_t max_connections;          /**< default 10000 */
    /** default 15000; a connection that has not completed TLS and authentication in time is closed */
    uint32_t handshake_timeout_ms;
    uint32_t challenge_ttl_ms;         /**< default 30000; validity of an authentication challenge */
    uint32_t session_lifetime_ms;      /**< default 3600000, max 7 days */
    /** default 300000, 0 = disabled; a session that received nothing for this long is closed */
    uint32_t idle_timeout_ms;
    uint32_t max_payload_size;         /**< default 1 MiB, max 16 MiB */
    /** default 10000; a re-authentication sooner than this after the session opened or the previous
     *  re-authentication is a protocol error and closes the session */
    uint32_t min_reauth_interval_ms;
    uint32_t flags;                    /**< SG_SERVER_OPT_*; unknown flags: SG_NOT_SUPPORTED */
    /** Connections still in the TLS / authentication phase; more are closed at
     *  accept, so a flood of unauthenticated connections cannot take the
     *  places of established sessions. 0 = max_connections / 2 (at least 1);
     *  must not exceed max_connections. */
    uint32_t max_unauthenticated;

    const SG_ServerCallbacks* callbacks; /**< copied at creation; nullable */

    SG_LogCallback log_callback;       /**< Log callback; NULL = silent. */
    void* log_user;                    /**< Passed to log_callback. */
    uint32_t log_level;                /**< default SG_LOG_WARN */
    uint32_t reserved2;                /**< Reserved. */

    /** NULL = in-memory license store; must differ from registry_path. The file is locked like the
     *  registry. */
    const char* license_path;

    /* Integrity policy (see the header comment). 0 = ignore reports. */
    /** SG_INTEGRITY_* and server conditions that make a session SG_SESSION_POLICY_RESTRICTED. Unknown
     *  bits: SG_NOT_SUPPORTED. */
    uint32_t integrity_restrict_mask;
    /** Conditions that deny the session; checked first, so they win over the restrict mask. Unknown bits:
     *  SG_NOT_SUPPORTED. */
    uint32_t integrity_reject_mask;
    /** optional allowlist of executable SHA-256 values; copied. All-zero entries are refused. It has an
     *  effect only with SG_INTEGRITY_UNKNOWN_EXECUTABLE in a mask. */
    const SG_Sha256* allowed_executables;
    size_t allowed_executable_count;       /**< <= 4096 */
} SG_ServerOptions;

#define SG_CLIENT_RECORD_VERSION 1u /**< Current version of SG_ClientRecord. */
/**
 * @brief Installation registered out of band with SG_Server_RegisterClient().
 *
 * Initialise with SG_ClientRecord_Init(). Copied by SG_Server_RegisterClient().
 */
typedef struct SG_ClientRecord {
    uint32_t size;                     /**< Size of this structure in bytes (set by SG_ClientRecord_Init). */
    uint32_t version;                  /**< SG_CLIENT_RECORD_VERSION (set by SG_ClientRecord_Init). */
    SG_PublicKey public_key;           /**< installation id is derived from it */
    uint8_t reserved[7];               /**< Reserved. */
    const char* product_id;            /**< optional binding; <= 64 bytes */
    const char* license_id;            /**< optional binding; <= 128 bytes */
} SG_ClientRecord;

#define SG_ENROLLMENT_TOKEN_REQUEST_VERSION 1u /**< Current version of SG_EnrollmentTokenRequest. */
/**
 * @brief Parameters of SG_Server_IssueEnrollmentToken().
 *
 * Initialise with SG_EnrollmentTokenRequest_Init().
 */
typedef struct SG_EnrollmentTokenRequest {
    uint32_t size;                     /**< Size of this structure (set by SG_EnrollmentTokenRequest_Init). */
    uint32_t version;                  /**< SG_ENROLLMENT_TOKEN_REQUEST_VERSION. */
    const char* product_id;            /**< required; <= 64 bytes */
    const char* license_id;            /**< optional; <= 128 bytes */
    uint32_t ttl_ms;                   /**< default 24 h (also used for 0); max 30 days */
    uint32_t reserved;                 /**< Reserved. */
} SG_EnrollmentTokenRequest;

#define SG_LICENSE_RECORD_VERSION 1u /**< Current version of SG_LicenseRecord. */
/**
 * @brief License terms for SG_Server_AddLicense().
 *
 * Initialise with SG_LicenseRecord_Init(). Copied by SG_Server_AddLicense().
 */
typedef struct SG_LicenseRecord {
    uint32_t size;                     /**< Size of this structure in bytes (set by SG_LicenseRecord_Init). */
    uint32_t version;                  /**< SG_LICENSE_RECORD_VERSION (set by SG_LicenseRecord_Init). */
    const char* license_id;            /**< required, 1..128 bytes */
    const char* product_id;            /**< required, 1..64 bytes */
    uint64_t features;                 /**< feature bits the license entitles */
    uint64_t expires_at_ms;            /**< Unix ms, 0 = perpetual */
    uint32_t max_installations;        /**< 0 = unlimited */
    uint32_t reserved;                 /**< Reserved. */
} SG_LicenseRecord;

#define SG_LICENSE_INFO_VERSION 1u /**< Current version of SG_LicenseInfo. */
/**
 * @brief License state, filled by SG_Server_GetLicense().
 *
 * Initialise with SG_LicenseInfo_Init().
 */
typedef struct SG_LicenseInfo {
    uint32_t size;                     /**< Size of this structure in bytes (set by SG_LicenseInfo_Init). */
    uint32_t version;                  /**< SG_LICENSE_INFO_VERSION (set by SG_LicenseInfo_Init). */
    char product_id[65];               /**< Product the license is for (NUL-terminated). */
    uint8_t reserved0[7];              /**< Reserved. */
    uint64_t features;                 /**< Feature bits the license entitles. */
    uint64_t expires_at_ms;            /**< Unix ms, 0 = perpetual. */
    uint32_t max_installations;        /**< Seat limit, 0 = unlimited. */
    uint32_t installations;            /**< seats in use */
    uint32_t revoked;                  /**< 1 once revoked */
    uint32_t reserved1;                /**< Reserved. */
} SG_LicenseInfo;

#define SG_SERVER_STATS_VERSION 1u /**< Current version of SG_ServerStats. */
/**
 * @brief Server counters, filled by SG_Server_GetStats().
 *
 * Initialise with SG_ServerStats_Init(). The totals count since SG_Server_Create().
 */
typedef struct SG_ServerStats {
    uint32_t size;                     /**< Size of this structure in bytes (set by SG_ServerStats_Init). */
    uint32_t version;                  /**< SG_SERVER_STATS_VERSION (set by SG_ServerStats_Init). */
    uint64_t active_connections;       /**< Open connections, including those still authenticating. */
    uint64_t active_sessions;          /**< Open authenticated sessions. */
    uint64_t total_connections;        /**< Accepted connections (refused ones are not counted). */
    uint64_t auth_succeeded;           /**< Authentications that opened a session. */
    uint64_t auth_failed;              /**< Rejected authentications and re-authentications. */
    uint64_t protocol_errors;          /**< Connections closed on an error while processing received data. */
    uint64_t messages_received;        /**< DATA messages received from clients. */
    uint64_t messages_sent;            /**< DATA messages sent to clients. */
} SG_ServerStats;

/**
 * @brief Initialises server options: zeroes them, sets size and version and the defaults
 *        (max_connections 10000, handshake_timeout_ms 15000, challenge_ttl_ms 30000,
 *        session_lifetime_ms 3600000, idle_timeout_ms 300000, max_payload_size 1 MiB,
 *        min_reauth_interval_ms 10000, log_level SG_LOG_WARN).
 * @param[out] options Structure to initialise; NULL is ignored.
 */
SG_SERVER_API void SG_CALL SG_ServerOptions_Init(SG_ServerOptions* options);
/**
 * @brief Initialises a callbacks structure: zeroes it (no callbacks) and sets size and version.
 * @param[out] callbacks Structure to initialise; NULL is ignored.
 */
SG_SERVER_API void SG_CALL SG_ServerCallbacks_Init(SG_ServerCallbacks* callbacks);
/**
 * @brief Initialises a client record: zeroes it and sets size and version.
 * @param[out] record Structure to initialise; NULL is ignored.
 */
SG_SERVER_API void SG_CALL SG_ClientRecord_Init(SG_ClientRecord* record);
/**
 * @brief Initialises an enrollment token request: zeroes it and sets size and version.
 * @param[out] request Structure to initialise; NULL is ignored.
 */
SG_SERVER_API void SG_CALL SG_EnrollmentTokenRequest_Init(SG_EnrollmentTokenRequest* request);
/**
 * @brief Initialises a license record: zeroes it and sets size and version.
 * @param[out] record Structure to initialise; NULL is ignored.
 */
SG_SERVER_API void SG_CALL SG_LicenseRecord_Init(SG_LicenseRecord* record);
/**
 * @brief Initialises a license information output structure: zeroes it and sets size and version.
 * @param[out] info Structure to initialise; NULL is ignored.
 */
SG_SERVER_API void SG_CALL SG_LicenseInfo_Init(SG_LicenseInfo* info);
/**
 * @brief Initialises a session information output structure: zeroes it and sets size and version.
 * @param[out] info Structure to initialise; NULL is ignored.
 */
SG_SERVER_API void SG_CALL SG_ServerSessionInfo_Init(SG_ServerSessionInfo* info);
/**
 * @brief Initialises a statistics output structure: zeroes it and sets size and version.
 * @param[out] stats Structure to initialise; NULL is ignored.
 */
SG_SERVER_API void SG_CALL SG_ServerStats_Init(SG_ServerStats* stats);

/**
 * @brief Creates a server; it does not accept connections before SG_Server_Start().
 *
 * Loads the TLS identity and the proof key, opens (and locks) the registry and license files and copies
 * the callbacks.
 * @param[in]  options Options initialised with SG_ServerOptions_Init(); see SG_ServerOptions for what must
 *                     stay valid.
 * @param[out] server  Receives the new handle; set to NULL on failure.
 * @retval SG_OK                *server holds the handle; release it with SG_Server_Destroy().
 * @retval SG_INVALID_ARGUMENT  NULL argument, bad size or version, missing TLS certificate or key, an
 *                              unusable key, a value out of range, or registry_path and license_path naming
 *                              the same file.
 * @retval SG_NOT_SUPPORTED     Unknown flag or integrity mask bit, or a non-zero unknown field.
 * @retval SG_CERTIFICATE_ERROR The certificate chain could not be loaded.
 * @retval SG_NOT_FOUND         proof_key_file does not exist.
 * @retval SG_INVALID_STATE     The registry or license file is already open in another store (another
 *                              server object or process).
 * @retval SG_STORAGE_ERROR     A registry or license file could not be read or is corrupt, or the proof key
 *                              file could not be read (an unparsable proof key is SG_INVALID_ARGUMENT).
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_Create(const SG_ServerOptions* options, SG_Server** server);
/**
 * @brief Starts listening and the I/O worker threads.
 * @param[in] server Server handle.
 * @retval SG_OK               The server accepts connections (see SG_Server_GetPort()).
 * @retval SG_INVALID_ARGUMENT NULL server.
 * @retval SG_INVALID_STATE    Already running, or called from a callback.
 * @retval SG_NETWORK_ERROR    The listening socket could not be opened.
 * @note Must not be called from a callback.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_Start(SG_Server* server);
/**
 * @brief Stops the server: closes every connection (authenticated clients are told that the server shuts
 *        down) and stops the worker threads.
 *
 * The on_session_closed callbacks it delivers (reason SG_CLOSED) run under its lifecycle lock.
 * @param[in] server Server handle.
 * @retval SG_OK               The server is stopped (also if it was not running).
 * @retval SG_INVALID_ARGUMENT NULL server.
 * @retval SG_INVALID_STATE    Called from a callback.
 * @note Must not be called from a callback.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_Stop(SG_Server* server);
/**
 * @brief Stops the server (as SG_Server_Stop()) and frees it.
 * @param[in] server Handle to destroy; NULL is accepted. The handle is invalid afterwards.
 * @retval SG_OK            The server was destroyed (or server was NULL).
 * @retval SG_INVALID_STATE Called from a callback; nothing was done.
 * @note Must not be called from a callback, nor while another call on the same server is running.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_Destroy(SG_Server* server);
/**
 * @brief Returns the port the server listens on (useful with SG_ServerOptions.port 0).
 * @param[in]  server Server handle.
 * @param[out] port   Receives the port.
 * @retval SG_OK               *port holds the port.
 * @retval SG_INVALID_ARGUMENT NULL argument.
 * @retval SG_INVALID_STATE    The server has not been started.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_GetPort(SG_Server* server, uint16_t* port);

/**
 * @brief Sends one message to a session; same as SG_Server_SendEx(server, session, data, size, 0).
 * @param[in] server  Server handle.
 * @param[in] session Target session.
 * @param[in] data    Payload; may be NULL when size is 0. Not used after the call returns.
 * @param[in] size    Payload size in bytes, <= SG_ServerOptions.max_payload_size.
 * @retval SG_OK The message was accepted for sending.
 * @return Otherwise the same codes as SG_Server_SendEx().
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_Send(SG_Server* server, SG_SessionHandle session, const void* data,
                                               size_t size);
/**
 * @brief Sends one message to a session, optionally as the response to a request from the client.
 *
 * The payload uses application-layer AEAD when SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION is set or once the
 * client has sent an application-encrypted message; messages sent before that are protected by TLS and the
 * frame's authentication tag only. A failed write closes the session.
 * @param[in] server              Server handle.
 * @param[in] session             Target session.
 * @param[in] data                Payload; may be NULL when size is 0. Not used after the call returns.
 * @param[in] size                Payload size in bytes, <= SG_ServerOptions.max_payload_size.
 * @param[in] reply_to_request_id 0 to send a request (a new request id is assigned); otherwise the
 *                                request_id of a message received on this session that this message answers
 *                                (sent with SG_MESSAGE_FLAG_RESPONSE).
 * @retval SG_OK               The message was accepted for sending.
 * @retval SG_INVALID_ARGUMENT NULL server, NULL data with a non-zero size, size above max_payload_size, or a
 *                             reply_to_request_id higher than any request received on the session.
 * @retval SG_NOT_FOUND        Unknown session handle (or the session is gone).
 * @retval SG_LIMIT_EXCEEDED   Too much data is waiting to be written to this client; the session stays open.
 * @retval SG_CLOSED           The connection has not completed authentication, the session is closing, or
 *                             the write failed and closed it.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_SendEx(SG_Server* server, SG_SessionHandle session, const void* data,
                                                 size_t size, uint64_t reply_to_request_id);
/**
 * @brief Closes a session (or a connection that is still authenticating).
 *
 * An authenticated client is sent a CLOSE. on_session_closed (reason SG_CLOSED) may run on the calling
 * thread.
 * @param[in] server  Server handle.
 * @param[in] session Session to close.
 * @retval SG_OK               The session is closed.
 * @retval SG_INVALID_ARGUMENT NULL server.
 * @retval SG_NOT_FOUND        Unknown session handle.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_CloseSession(SG_Server* server, SG_SessionHandle session);
/**
 * @brief Returns information about an open session.
 * @param[in]  server  Server handle.
 * @param[in]  session Session handle.
 * @param[out] info    Receives the information; initialise it with SG_ServerSessionInfo_Init().
 * @retval SG_OK               *info holds the information.
 * @retval SG_INVALID_ARGUMENT NULL argument, or info->size too small.
 * @retval SG_NOT_FOUND        Unknown handle, or the session is not open (not yet authenticated or closed).
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_GetSessionInfo(SG_Server* server, SG_SessionHandle session,
                                                         SG_ServerSessionInfo* info);

/* Registry. */
/**
 * @brief Registers an installation out of band: its public key and optional product / license bindings.
 *
 * A license binding in a record or token must name an active license for
 * the same product when the license store knows it (SG_INVALID_STATE /
 * SG_INVALID_ARGUMENT), and must exist with SG_SERVER_OPT_REQUIRE_LICENSE
 * (SG_NOT_FOUND).
 * @param[in] server Server handle.
 * @param[in] record Record initialised with SG_ClientRecord_Init(). Copied.
 * @retval SG_OK               Registered (and written to registry_path, if set).
 * @retval SG_INVALID_ARGUMENT NULL argument, bad size or version, invalid public key or string, or a bound
 *                             license for another product.
 * @retval SG_NOT_SUPPORTED    Non-zero unknown field.
 * @retval SG_ALREADY_EXISTS   The installation is already registered (also if revoked).
 * @retval SG_INVALID_STATE    The bound license is revoked.
 * @retval SG_NOT_FOUND        SG_SERVER_OPT_REQUIRE_LICENSE is set and the bound license is not in the store.
 * @retval SG_LIMIT_EXCEEDED   The registry file would grow beyond its size limit; nothing was registered.
 * @retval SG_STORAGE_ERROR    The registry could not be written; nothing was registered.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_RegisterClient(SG_Server* server, const SG_ClientRecord* record);
/**
 * @brief Revokes an installation.
 *
 * Revocation closes the installation's live sessions immediately (the clients see SG_SERVER_REJECTED) and
 * frees its license seat (best effort: a failure to free the seat is not reported).
 * Revocations (of installations and licenses) that cannot be persisted still
 * take effect in this process and return SG_STORAGE_ERROR; calling the revoke
 * function again retries the write (as does any later successful change of
 * that store) until it returns SG_OK.
 * @param[in] server          Server handle.
 * @param[in] installation_id Installation to revoke.
 * @retval SG_OK               Revoked and persisted (also if it was already revoked).
 * @retval SG_INVALID_ARGUMENT NULL argument.
 * @retval SG_NOT_FOUND        Unknown installation.
 * @retval SG_STORAGE_ERROR    Revoked in this process, but not persisted.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_RevokeClient(SG_Server* server, const SG_InstallationId* installation_id);
/**
 * @brief Issues a single-use enrollment token for SG_Client_Enroll().
 *
 * A license binding in the token follows the rules of SG_Server_RegisterClient(). Every call issues a new
 * token. Tokens are rejected while an on_enroll callback is set, and with a random token_key they are valid
 * only for this server object. Enrollment also requires SG_SERVER_OPT_ALLOW_ENROLLMENT. The token is used up
 * and the installation registered before authorization, so an enrollment that is then denied leaves the
 * installation registered and active (see SG_ServerCallbacks.on_enroll).
 * @param[in]  server   Server handle.
 * @param[in]  request  Request initialised with SG_EnrollmentTokenRequest_Init().
 * @param[out] token    Receives the NUL-terminated token; may be NULL when capacity is 0.
 * @param[in]  capacity Size of token in bytes.
 * @param[out] written  Receives the token size including the terminating NUL; required.
 * @retval SG_OK               *token holds the token.
 * @retval SG_BUFFER_TOO_SMALL *written holds the required size; the token issued by this call is discarded.
 * @retval SG_INVALID_ARGUMENT NULL argument, bad size or version, missing or too long product_id, too long
 *                             license_id, ttl_ms above 30 days, or a bound license for another product.
 * @retval SG_NOT_SUPPORTED    Non-zero unknown field.
 * @retval SG_INVALID_STATE    The bound license is revoked.
 * @retval SG_NOT_FOUND        SG_SERVER_OPT_REQUIRE_LICENSE is set and the bound license is not in the store.
 * @warning The token contains the secret enrollment key: treat it as a credential until it is used. The
 *          library wipes its own copy.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_IssueEnrollmentToken(SG_Server* server,
                                                               const SG_EnrollmentTokenRequest* request, char* token,
                                                               size_t capacity, size_t* written);

/* Licenses. */
/**
 * @brief Adds a license to the license store or updates its terms.
 *
 * AddLicense inserts a license or updates its terms; changed terms
 * apply to new sessions and at each session's next refresh. Existing seats are kept, also when
 * max_installations is lowered. A refresh updates the session's features, policy and license expiry on the
 * server (SG_Server_GetSessionInfo); the client learns only the new lifetime (see SG_ClientSessionInfo).
 * @param[in] server  Server handle.
 * @param[in] license Terms initialised with SG_LicenseRecord_Init(). Copied.
 * @retval SG_OK               Stored (and written to license_path, if set).
 * @retval SG_INVALID_ARGUMENT NULL argument, bad size or version, or a missing, too long or invalid id.
 * @retval SG_NOT_SUPPORTED    Non-zero unknown field.
 * @retval SG_INVALID_STATE    The license is revoked (revocation is permanent).
 * @retval SG_LIMIT_EXCEEDED   The store already holds the maximum number of licenses, or its file would grow
 *                             beyond its size limit.
 * @retval SG_STORAGE_ERROR    The store could not be written; the change was not applied.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_AddLicense(SG_Server* server, const SG_LicenseRecord* license);
/**
 * @brief Revokes a license.
 *
 * Revocation is permanent and closes the sessions authorised under the license
 * immediately. A revocation that cannot be persisted still takes effect in this process and returns
 * SG_STORAGE_ERROR; calling this function again retries the write (as does any later successful change of
 * the license store) until it returns SG_OK.
 * @param[in] server     Server handle.
 * @param[in] license_id NUL-terminated license id, 1..128 bytes.
 * @retval SG_OK               Revoked and persisted (also if it was already revoked).
 * @retval SG_INVALID_ARGUMENT NULL argument, or an empty or too long id.
 * @retval SG_NOT_FOUND        Unknown license.
 * @retval SG_STORAGE_ERROR    Revoked in this process, but not persisted.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_RevokeLicense(SG_Server* server, const char* license_id);
/**
 * @brief Frees an installation's license seat.
 *
 * ReleaseLicenseSeat frees an installation's seat (closing its sessions under that
 * license); the installation takes a seat again on its next successful authorization if one is free.
 * @param[in] server          Server handle.
 * @param[in] license_id      NUL-terminated license id, 1..128 bytes.
 * @param[in] installation_id Installation holding the seat.
 * @retval SG_OK               The seat was freed.
 * @retval SG_INVALID_ARGUMENT NULL argument, or an empty or too long id.
 * @retval SG_NOT_FOUND        Unknown license, or the installation holds no seat of it.
 * @retval SG_STORAGE_ERROR    The store could not be written; the seat is kept.
 * @see SG_Server_RevokeClient() to keep an installation out for good.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_ReleaseLicenseSeat(SG_Server* server, const char* license_id,
                                                             const SG_InstallationId* installation_id);
/**
 * @brief Returns the terms and seat usage of a license.
 * @param[in]  server     Server handle.
 * @param[in]  license_id NUL-terminated license id, 1..128 bytes.
 * @param[out] info       Receives the license state; initialise it with SG_LicenseInfo_Init().
 * @retval SG_OK               *info holds the license state.
 * @retval SG_INVALID_ARGUMENT NULL argument, an empty or too long id, or info->size too small.
 * @retval SG_NOT_FOUND        Unknown license.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_GetLicense(SG_Server* server, const char* license_id,
                                                     SG_LicenseInfo* info);

/**
 * @brief Returns the server counters.
 * @param[in]  server Server handle.
 * @param[out] stats  Receives the counters; initialise it with SG_ServerStats_Init().
 * @retval SG_OK               *stats holds the counters.
 * @retval SG_INVALID_ARGUMENT NULL argument, or stats->size too small.
 */
SG_SERVER_API SG_Status SG_CALL SG_Server_GetStats(SG_Server* server, SG_ServerStats* stats);
/**
 * @brief Returns the C ABI version of the library.
 * @return SOCKGATE_API_VERSION the library was built with; compare it with the header's
 *         SOCKGATE_API_VERSION.
 */
SG_SERVER_API uint32_t SG_CALL SG_Server_GetApiVersion(void);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* SOCKGATE_SERVER_H */
