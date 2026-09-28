#ifndef SOCKGATE_CLIENT_H
#define SOCKGATE_CLIENT_H
/**
 * @file
 * @brief SockGate client - public C API.
 * @ingroup sg_client
 *
 * Threading rules, the typical call sequence and the identity rules are described in @ref sg_client.
 */

#include "sockgate/config.h"
#include "sockgate/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup sg_client Client API
 * @brief Connects to a SockGate server, authenticates the installation and exchanges messages.
 *
 * Configuration structures are declared in sockgate/config.h, functions in sockgate/client.h;
 * sockgate/sockgate.h includes both together with the common headers.
 *
 * @par Threading
 * SG_Client_Send and SG_Client_Receive may be called concurrently
 * from different threads; calls in the same direction are serialised.
 * SG_Client_Disconnect may be called from any thread and wakes blocked calls.
 * SG_Client_Destroy must not race any other call on the same handle.
 * SG_Client_Connect, SG_Client_Authenticate, SG_Client_Enroll, SG_Client_Refresh and the identity delete
 * functions are serialised with one another. The SG_*_Init functions only write the structure they are given.
 *
 * @par Typical use
 * SG_Client_Create -> SG_Client_EnsureIdentity -> SG_Client_Connect
 * -> SG_Client_Authenticate -> SG_Client_Send / SG_Client_Receive
 * -> SG_Client_Disconnect -> SG_Client_Destroy
 *
 * @par Identities in SG_KEYSTORE_AUTO
 * SG_KEYSTORE_AUTO remembers which store holds an identity. If that store is
 * unavailable (e.g. the TPM provider cannot be opened) identity calls fail
 * with SG_KEYSTORE_ERROR, and if the store no longer has the key with
 * SG_IDENTITY_LOST - never by silently creating a new identity. A key the
 * store still has but can no longer use (e.g. a Linux TPM2 key after the TPM
 * was cleared) fails signing with SG_KEYSTORE_ERROR; if that persists after
 * a TPM clear or reset, delete the identity with SG_IDENTITY_DELETE_FORCE.
 * Deleting an identity whose store is unavailable is refused unless forced;
 * a forced delete may leave the key behind in that store. A new identity
 * must be registered / enrolled again.
 * @{
 */

/** @brief Opaque client handle, created by SG_Client_Create() and released by SG_Client_Destroy(). */
typedef struct SG_Client SG_Client;

#define SG_WAIT_INFINITE 0xFFFFFFFFu /**< SG_Client_ReceiveEx timeout: block until a message arrives */
#define SG_WAIT_DEFAULT  0xFFFFFFFEu /**< SG_Client_ReceiveEx timeout: use SG_ClientConfig.io_timeout_ms */

#define SG_IDENTITY_INFO_VERSION 1u /**< Current version of SG_IdentityInfo. */
/**
 * @brief Installation identity, filled by SG_Client_EnsureIdentity() and SG_Client_GetIdentity().
 *
 * Initialise with SG_IdentityInfo_Init() before use.
 */
typedef struct SG_IdentityInfo {
    uint32_t size;                     /**< Size of this structure in bytes (set by SG_IdentityInfo_Init). */
    uint32_t version;                  /**< SG_IDENTITY_INFO_VERSION (set by SG_IdentityInfo_Init). */
    SG_InstallationId installation_id; /**< derived from the public key */
    SG_PublicKey public_key;           /**< register this with the server out of band, or enroll */
    uint8_t reserved[3];               /**< Reserved. */
    uint32_t key_store_type;           /**< SG_KEYSTORE_* actually in use */
    uint32_t hardware_backed;          /**< 1 if the private key cannot leave a TPM */
} SG_IdentityInfo;

#define SG_CLIENT_SESSION_INFO_VERSION 1u /**< Current version of SG_ClientSessionInfo. */
/**
 * @brief Snapshot of the client's connection and session, filled by SG_Client_GetSessionInfo().
 *
 * Initialise with SG_ClientSessionInfo_Init() before use. A refresh tells the client only the new epoch and
 * lifetime: epoch and expires_in_ms change, while policy, granted_features and license_expires_at_ms keep
 * the values of the authentication even when the server changed them at the refresh (the server's current
 * values are in its SG_ServerSessionInfo).
 */
typedef struct SG_ClientSessionInfo {
    uint32_t size;                    /**< Size of this structure in bytes (set by SG_ClientSessionInfo_Init). */
    uint32_t version;                 /**< SG_CLIENT_SESSION_INFO_VERSION (set by SG_ClientSessionInfo_Init). */
    uint32_t state;                   /**< SG_CLIENT_STATE_* */
    uint32_t policy;                  /**< SG_SESSION_POLICY_* granted by the server */
    SG_SessionId session_id;          /**< Session id; all zero before authentication. */
    uint64_t granted_features;        /**< decided by the server */
    uint64_t license_expires_at_ms;   /**< Unix ms, 0 = not license bound */
    uint32_t expires_in_ms;           /**< remaining session lifetime */
    uint32_t epoch;                   /**< key epoch (increments on refresh) */
    char tls_protocol[16];            /**< Negotiated TLS protocol (NUL-terminated); empty without TLS. */
    char tls_cipher[64];              /**< Negotiated TLS cipher suite (NUL-terminated); empty without TLS. */
} SG_ClientSessionInfo;

/**
 * @brief Initialises a client configuration: zeroes it, sets size and version and the defaults
 *        (key_store_type SG_KEYSTORE_AUTO, connect_timeout_ms 10000, io_timeout_ms 30000,
 *        max_payload_size 1 MiB, log_level SG_LOG_WARN).
 * @param[out] config Structure to initialise; NULL is ignored.
 */
SG_CLIENT_API void SG_CALL SG_ClientConfig_Init(SG_ClientConfig* config);
/**
 * @brief Initialises a target server description: zeroes it and sets size and version.
 * @param[out] server Structure to initialise; NULL is ignored.
 */
SG_CLIENT_API void SG_CALL SG_ServerConfig_Init(SG_ServerConfig* server);
/**
 * @brief Initialises proxy settings: zeroes them, sets size and version and mode SG_PROXY_MODE_DIRECT.
 * @param[out] proxy Structure to initialise; NULL is ignored.
 */
SG_CLIENT_API void SG_CALL SG_ProxyConfig_Init(SG_ProxyConfig* proxy);
/**
 * @brief Initialises an identity output structure: zeroes it and sets size and version.
 * @param[out] info Structure to initialise; NULL is ignored.
 */
SG_CLIENT_API void SG_CALL SG_IdentityInfo_Init(SG_IdentityInfo* info);
/**
 * @brief Initialises a session information output structure: zeroes it and sets size and version.
 * @param[out] info Structure to initialise; NULL is ignored.
 */
SG_CLIENT_API void SG_CALL SG_ClientSessionInfo_Init(SG_ClientSessionInfo* info);
/**
 * @brief Initialises a message metadata structure: zeroes it and sets size and version.
 * @param[out] info Structure to initialise; NULL is ignored.
 */
SG_CLIENT_API void SG_CALL SG_MessageInfo_Init(SG_MessageInfo* info);

/**
 * @brief Creates a client.
 *
 * Validates and copies the configuration and opens the configured key store; no network access. With
 * SG_CLIENT_FLAG_INTEGRITY_REPORT the executable is hashed here.
 * @param[in]  config Configuration initialised with SG_ClientConfig_Init(). Copied (see SG_ClientConfig for
 *                    the pointers that must stay valid).
 * @param[out] client Receives the new handle; set to NULL on failure.
 * @retval SG_OK               *client holds the handle; release it with SG_Client_Destroy().
 * @retval SG_INVALID_ARGUMENT NULL argument, bad size or version, invalid identity_name, a string that is too
 *                             long, max_payload_size above 16 MiB, invalid proxy settings or an unknown
 *                             key_store_type.
 * @retval SG_NOT_SUPPORTED    Unknown flag, non-zero unknown field, or a key store this platform or build
 *                             does not provide.
 * @retval SG_KEYSTORE_ERROR   The key store could not be opened.
 * @retval SG_NOT_FOUND        Windows: the key directory could not be created.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Create(const SG_ClientConfig* config, SG_Client** client);
/**
 * @brief Disconnects (as SG_Client_Disconnect()) and frees the client.
 * @param[in] client Handle to destroy; NULL is accepted. The handle is invalid afterwards.
 * @retval SG_OK The client was destroyed (or client was NULL).
 * @note Must not race any other call on the same handle.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Destroy(SG_Client* client);

/* Installation identity (key pair in the configured key store). */
/**
 * @brief Loads the installation identity (key pair in the configured key store), creating it if absent.
 *
 * A concurrent creator of the same identity is tolerated: the key is created once. Callable in any
 * connection state.
 * @param[in]  client Client handle.
 * @param[out] info   Receives the identity; may be NULL. Initialise it with SG_IdentityInfo_Init().
 * @retval SG_OK               The identity exists (created now or earlier).
 * @retval SG_INVALID_ARGUMENT NULL client, or info->size too small.
 * @retval SG_KEYSTORE_ERROR   Key store failure, e.g. the store recorded by SG_KEYSTORE_AUTO is unavailable.
 * @retval SG_IDENTITY_LOST    SG_KEYSTORE_AUTO: the store that held the identity no longer has its key.
 * @retval SG_NOT_SUPPORTED    No available store can create the key.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_EnsureIdentity(SG_Client* client, SG_IdentityInfo* info /* nullable */);
/**
 * @brief Returns the existing installation identity without creating one.
 * @param[in]  client Client handle.
 * @param[out] info   Receives the identity; initialise it with SG_IdentityInfo_Init().
 * @retval SG_OK               *info holds the identity.
 * @retval SG_INVALID_ARGUMENT NULL argument, or info->size too small.
 * @retval SG_NOT_FOUND        No identity exists.
 * @retval SG_KEYSTORE_ERROR   Key store failure, e.g. the store recorded by SG_KEYSTORE_AUTO is unavailable.
 * @retval SG_IDENTITY_LOST    SG_KEYSTORE_AUTO: the store that held the identity no longer has its key.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_GetIdentity(SG_Client* client, SG_IdentityInfo* info);
/**
 * @brief Deletes the installation identity; same as SG_Client_DeleteIdentityEx(client, 0).
 * @param[in] client Client handle.
 * @retval SG_OK               The key was deleted.
 * @retval SG_INVALID_ARGUMENT NULL client.
 * @retval SG_INVALID_STATE    A connection is open or being opened (disconnect first).
 * @retval SG_NOT_FOUND        No identity exists.
 * @retval SG_KEYSTORE_ERROR   Key store failure, e.g. the store recorded by SG_KEYSTORE_AUTO is unavailable.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_DeleteIdentity(SG_Client* client);

/** Delete flag: also forget an identity whose SG_KEYSTORE_AUTO store is unavailable; the key may be left
 *  behind in that store. */
#define SG_IDENTITY_DELETE_FORCE (1u << 0)
/**
 * @brief Deletes the installation identity, optionally forced.
 *
 * Deleting an identity whose store is unavailable is refused unless SG_IDENTITY_DELETE_FORCE is set; a
 * forced delete may leave the key behind in that store. A new identity must be registered / enrolled again.
 * @param[in] client Client handle.
 * @param[in] flags  0 or SG_IDENTITY_DELETE_FORCE.
 * @retval SG_OK               The identity was deleted (a forced delete may only have forgotten it).
 * @retval SG_INVALID_ARGUMENT NULL client or unknown flag.
 * @retval SG_INVALID_STATE    A connection is open or being opened (disconnect first).
 * @retval SG_NOT_FOUND        No identity exists.
 * @retval SG_KEYSTORE_ERROR   Key store failure, e.g. the store recorded by SG_KEYSTORE_AUTO is unavailable
 *                             and the delete was not forced.
 * @see @ref sg_client "Identities in SG_KEYSTORE_AUTO"
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_DeleteIdentityEx(SG_Client* client, uint32_t flags);

/* Connection and authentication. */
/**
 * @brief Connects to the server: TCP (through the configured proxy) and the TLS handshake with server
 *        verification.
 *
 * Requires SG_CLIENT_STATE_DISCONNECTED, _CLOSED or _EXPIRED. On success the state is
 * SG_CLIENT_STATE_TLS_ESTABLISHED; continue with SG_Client_Authenticate() or SG_Client_Enroll(). Invalid
 * arguments or trust settings and TLS setup errors (e.g. a CA that fails to load) leave the state unchanged;
 * a failure once the connection attempt has started leaves SG_CLIENT_STATE_CLOSED. Either way the call may
 * be repeated. SG_Client_Disconnect() from another thread aborts an attempt in progress: the call then
 * returns SG_CLOSED (argument, TLS setup, certificate and pinning errors found first are still reported as
 * such) and the state is the one SG_Client_Disconnect() left.
 * Resolution, TCP, the proxy and the TLS handshake share the SG_ClientConfig.connect_timeout_ms budget, but
 * a single name resolution or system proxy lookup call cannot be interrupted, and writes during the proxy
 * and TLS handshakes are limited by io_timeout_ms instead.
 * @param[in] client Client handle.
 * @param[in] server Target server, initialised with SG_ServerConfig_Init(). Copied.
 * @retval SG_OK                TLS is established and the server certificate verified. Server proof keys
 *                              (SG_ServerConfig.proof_keys) are checked only by SG_Client_Authenticate() /
 *                              SG_Client_Enroll().
 * @retval SG_INVALID_ARGUMENT  NULL argument or invalid SG_ServerConfig (including its trust rules).
 * @retval SG_NOT_SUPPORTED     Unknown flag or non-zero unknown field in SG_ServerConfig, or the system proxy
 *                              configuration names a proxy of an unsupported kind (e.g. https://).
 * @retval SG_INVALID_STATE     Already connecting or connected.
 * @retval SG_NETWORK_ERROR     Name resolution or the TCP connection failed.
 * @retval SG_PROXY_ERROR       Proxy negotiation failed.
 * @retval SG_TIMEOUT           connect_timeout_ms elapsed.
 * @retval SG_TLS_ERROR         The TLS handshake failed.
 * @retval SG_CERTIFICATE_ERROR The server certificate did not validate, or ca_file / ca_pem could not be
 *                              loaded.
 * @retval SG_PINNING_ERROR     The chain validated against a trusted CA but matches no SPKI pin (possible
 *                              TLS interception).
 * @retval SG_CLOSED            SG_Client_Disconnect() aborted the call.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Connect(SG_Client* client, const SG_ServerConfig* server);
/**
 * @brief Authenticates the installation with its key (AUTHENTICATE handshake) and opens the session.
 *
 * Requires SG_CLIENT_STATE_TLS_ESTABLISHED. Uses the existing identity, or creates it when
 * SG_CLIENT_FLAG_AUTO_IDENTITY is set. Bounded by SG_ClientConfig.io_timeout_ms. On success the state is
 * SG_CLIENT_STATE_ACTIVE; a failure during the exchange with the server closes the connection.
 * @param[in] client Client handle.
 * @retval SG_OK                The session is active; SG_Client_GetSessionInfo() shows what was granted.
 * @retval SG_INVALID_ARGUMENT  NULL client.
 * @retval SG_INVALID_STATE     Not in SG_CLIENT_STATE_TLS_ESTABLISHED.
 * @retval SG_NOT_FOUND         No identity, and SG_CLIENT_FLAG_AUTO_IDENTITY is not set.
 * @retval SG_KEYSTORE_ERROR    Key store or signing failure.
 * @retval SG_IDENTITY_LOST     SG_KEYSTORE_AUTO: the store that held the identity no longer has its key.
 * @retval SG_SERVER_REJECTED   The server rejected the session (generic; the reason is in the server log).
 * @retval SG_VERSION_MISMATCH  No common protocol version.
 * @retval SG_INVALID_SIGNATURE The server proof is missing or matches none of SG_ServerConfig.proof_keys.
 * @retval SG_TIMEOUT           io_timeout_ms elapsed.
 * @retval SG_CLOSED            The connection was closed, e.g. by SG_Client_Disconnect().
 * @retval SG_PROTOCOL_ERROR    The server violated the protocol.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Authenticate(SG_Client* client);
/**
 * @brief Enrolls the installation with an enrollment token (ENROLL handshake) and opens the session.
 *
 * Like SG_Client_Authenticate(), but always creates the identity if needed and proves possession of the
 * token; the server registers the installation. The server must accept enrollment
 * (SG_SERVER_OPT_ALLOW_ENROLLMENT).
 * @param[in] client           Client handle.
 * @param[in] enrollment_token NUL-terminated token from the server operator, <= 1024 bytes. Copied; the
 *                             library wipes its copy.
 * @retval SG_OK               The installation is registered and the session is active.
 * @retval SG_INVALID_ARGUMENT NULL argument, or an empty, too long or malformed token.
 * @retval SG_INVALID_STATE    Not in SG_CLIENT_STATE_TLS_ESTABLISHED.
 * @retval SG_SERVER_REJECTED  The server rejected the enrollment.
 * @return Otherwise the same codes as SG_Client_Authenticate().
 * @warning The token is a credential until it is used: wipe the caller's copy after the call.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Enroll(SG_Client* client, const char* enrollment_token);
/**
 * @brief Re-authenticates the active session: proves possession of the key again, rotates the session keys
 *        (the epoch increments) and renews the session lifetime.
 *
 * Requires SG_CLIENT_STATE_ACTIVE; meanwhile the state is SG_CLIENT_STATE_REFRESHING and messages can still
 * be sent. The server applies changed license terms at this point. Waits until an SG_Client_Receive() running
 * in another thread returns. Bounded by SG_ClientConfig.io_timeout_ms. A failure during the exchange closes
 * the connection.
 * @param[in] client Client handle.
 * @retval SG_OK               The session was renewed.
 * @retval SG_INVALID_ARGUMENT NULL client.
 * @retval SG_INVALID_STATE    No active session.
 * @retval SG_SESSION_EXPIRED  The session has expired.
 * @retval SG_SERVER_REJECTED  The server refused the re-authentication.
 * @retval SG_KEYSTORE_ERROR   Signing with the installation key failed.
 * @retval SG_IDENTITY_LOST    SG_KEYSTORE_AUTO: the store that held the identity no longer has its key.
 * @retval SG_PROTOCOL_ERROR   The server violated the protocol.
 * @retval SG_TIMEOUT          io_timeout_ms elapsed.
 * @retval SG_CLOSED           The connection was closed.
 * @see SG_CLIENT_FLAG_AUTO_REFRESH
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Refresh(SG_Client* client);
/**
 * @brief Closes the connection and wakes blocked calls.
 *
 * Sends a CLOSE to the server when a session is active (best effort with a short time limit; it can still
 * wait up to io_timeout_ms - indefinitely when that is 0 - while a concurrent SG_Client_Receive() is writing
 * TLS data to a peer that does not read) and aborts an SG_Client_Connect() in progress. Idempotent.
 * Afterwards the state is
 * SG_CLIENT_STATE_CLOSED (a client that never connected or whose session expired keeps its state) and
 * SG_Client_Connect() may be called again.
 * @param[in] client Client handle.
 * @retval SG_OK               The connection is closed.
 * @retval SG_INVALID_ARGUMENT NULL client.
 * @note May be called from any thread.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Disconnect(SG_Client* client);

/* Data. One call = one message. */
/**
 * @brief Sends one message; same as SG_Client_SendEx(client, data, size, 0, NULL).
 * @param[in] client Client handle.
 * @param[in] data   Payload; may be NULL when size is 0. Not used after the call returns.
 * @param[in] size   Payload size in bytes, <= SG_ClientConfig.max_payload_size.
 * @retval SG_OK The message was written to the connection.
 * @return Otherwise the same codes as SG_Client_SendEx().
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Send(SG_Client* client, const void* data, size_t size);
/**
 * @brief Sends one message, optionally as the response to a request received from the server.
 *
 * Requires SG_CLIENT_STATE_ACTIVE or _REFRESHING. The payload is AEAD-encrypted inside TLS when
 * SG_CLIENT_FLAG_APP_ENCRYPTION is set. With SG_CLIENT_FLAG_AUTO_REFRESH the call may refresh the session
 * first (up to io_timeout_ms; a failed refresh closes the connection and returns its error). A failed write
 * closes the connection and returns the write error (e.g. SG_TIMEOUT, SG_NETWORK_ERROR).
 * @param[in]  client              Client handle.
 * @param[in]  data                Payload; may be NULL when size is 0. Not used after the call returns.
 * @param[in]  size                Payload size in bytes, <= SG_ClientConfig.max_payload_size.
 * @param[in]  reply_to_request_id 0 to send a request (a new request id is assigned); otherwise the
 *                                 request_id of a received message that this message answers (it is then
 *                                 sent with SG_MESSAGE_FLAG_RESPONSE).
 * @param[out] out_request_id      Receives the request id assigned to this message, 0 for a response; may
 *                                 be NULL.
 * @retval SG_OK               The message was written to the connection.
 * @retval SG_INVALID_ARGUMENT NULL client, NULL data with a non-zero size, size above max_payload_size, or a
 *                             reply_to_request_id higher than any request received from the server.
 * @retval SG_INVALID_STATE    No active session.
 * @retval SG_SESSION_EXPIRED  The session has expired.
 * @retval SG_CLOSED           The connection is closed.
 * @note May run concurrently with SG_Client_Receive(); concurrent sends are serialised.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_SendEx(SG_Client* client, const void* data, size_t size,
                                                 uint64_t reply_to_request_id, uint64_t* out_request_id);
/**
 * @brief Receives the next message, waiting up to SG_ClientConfig.io_timeout_ms; same as
 *        SG_Client_ReceiveEx(client, buffer, capacity, received, NULL, SG_WAIT_DEFAULT).
 *
 * On SG_BUFFER_TOO_SMALL, *received holds the required size and the message
 * stays queued for the next call.
 * @param[in]  client   Client handle.
 * @param[out] buffer   Destination; may be NULL when capacity is 0.
 * @param[in]  capacity Size of buffer in bytes.
 * @param[out] received Receives the message size; required.
 * @retval SG_OK               *received bytes were copied to buffer.
 * @retval SG_BUFFER_TOO_SMALL *received holds the required size; the message stays queued.
 * @retval SG_TIMEOUT          No message arrived in time; the session stays usable unless an automatic
 *                             refresh timed out (see SG_Client_ReceiveEx()).
 * @return Otherwise the same codes as SG_Client_ReceiveEx().
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Receive(SG_Client* client, void* buffer, size_t capacity,
                                                  size_t* received);
/**
 * @brief Receives the next message with its metadata, using a per-call timeout.
 *
 * Returns a queued message, or reads from the connection until one arrives. Pings from the server are
 * answered and PONG / CLOSE frames are handled internally. With SG_CLIENT_FLAG_AUTO_REFRESH the call may
 * refresh the session first; that can take up to io_timeout_ms whatever timeout_ms is (also for a 0 ms poll),
 * and a failed refresh, including one that times out, closes the connection. A connection or protocol error
 * closes the connection; a receive timeout and SG_BUFFER_TOO_SMALL do not.
 * @param[in]  client     Client handle.
 * @param[out] buffer     Destination; may be NULL when capacity is 0.
 * @param[in]  capacity   Size of buffer in bytes.
 * @param[out] received   Receives the message size (the required size on SG_BUFFER_TOO_SMALL); required.
 * @param[out] info       Receives request_id and flags of the message; may be NULL. Initialise it with
 *                        SG_MessageInfo_Init().
 * @param[in]  timeout_ms Milliseconds to wait (0 polls), SG_WAIT_INFINITE or SG_WAIT_DEFAULT.
 * @retval SG_OK               *received bytes were copied to buffer.
 * @retval SG_BUFFER_TOO_SMALL *received holds the required size; the message stays queued.
 * @retval SG_TIMEOUT          No message arrived in time; the session stays usable (an automatic refresh
 *                             that timed out has closed it instead).
 * @retval SG_INVALID_ARGUMENT NULL client or received, NULL buffer with a non-zero capacity, or info->size
 *                             too small.
 * @retval SG_INVALID_STATE    No active session.
 * @retval SG_SESSION_EXPIRED  The session expired (locally, or the server closed it for expiry).
 * @retval SG_SERVER_REJECTED  The server closed the session with an authentication failure, e.g. after
 *                             revoking the installation or its license.
 * @retval SG_CLOSED           The connection was closed (by the server, SG_Client_Disconnect() or an error).
 * @retval SG_LIMIT_EXCEEDED   Too much unread data was queued.
 * @retval SG_PROTOCOL_ERROR   The server violated the protocol, e.g. a frame failed its integrity check.
 * @retval SG_REPLAY_DETECTED  A frame with an old sequence number or a duplicate request id arrived.
 * @note May run concurrently with SG_Client_Send(); concurrent receives are serialised.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_ReceiveEx(SG_Client* client, void* buffer, size_t capacity,
                                                    size_t* received, SG_MessageInfo* info /* nullable */,
                                                    uint32_t timeout_ms);
/**
 * @brief Sends a keep-alive ping to the server; this also resets the server's idle timer.
 *
 * Does not wait for the reply: the PONG is consumed by a later SG_Client_Receive(). A failed write closes the
 * connection.
 * @param[in] client Client handle.
 * @retval SG_OK               The ping was sent.
 * @retval SG_INVALID_ARGUMENT NULL client.
 * @retval SG_INVALID_STATE    No active session.
 * @retval SG_SESSION_EXPIRED  The session has expired.
 * @retval SG_CLOSED           The connection is closed.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_Ping(SG_Client* client);

/* Introspection. */
/**
 * @brief Returns the current connection state.
 * @param[in]  client Client handle.
 * @param[out] state  Receives an SG_CLIENT_STATE_* value.
 * @retval SG_OK               *state holds the state.
 * @retval SG_INVALID_ARGUMENT NULL argument.
 * @note May be called from any thread; the state can change right after the call.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_GetState(SG_Client* client, uint32_t* state);
/**
 * @brief Returns a snapshot of the connection and session.
 * @param[in]  client Client handle.
 * @param[out] info   Receives the snapshot; initialise it with SG_ClientSessionInfo_Init().
 * @retval SG_OK               *info holds the snapshot.
 * @retval SG_INVALID_ARGUMENT NULL argument, or info->size too small.
 * @note May be called from any thread.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_GetSessionInfo(SG_Client* client, SG_ClientSessionInfo* info);
/**
 * @brief Returns the C ABI version of the library.
 * @return SOCKGATE_API_VERSION the library was built with; compare it with the header's
 *         SOCKGATE_API_VERSION.
 */
SG_CLIENT_API uint32_t SG_CALL SG_Client_GetApiVersion(void);

/**
 * @brief Utility: SHA-256 SPKI pin of the first certificate in a PEM blob.
 *
 * The result can be used in SG_ServerConfig.spki_pins. Needs no client handle.
 * @param[in]  certificate_pem PEM text containing at least one certificate.
 * @param[in]  pem_size        Size of certificate_pem in bytes; 0 = NUL-terminated.
 * @param[out] pin             Receives the SHA-256 of the certificate's DER SubjectPublicKeyInfo.
 * @retval SG_OK                *pin holds the pin.
 * @retval SG_INVALID_ARGUMENT  NULL argument or empty input.
 * @retval SG_CERTIFICATE_ERROR No certificate could be read from the PEM text.
 */
SG_CLIENT_API SG_Status SG_CALL SG_Client_ComputeSpkiPin(const char* certificate_pem, size_t pem_size,
                                                         SG_Sha256* pin);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* SOCKGATE_CLIENT_H */
