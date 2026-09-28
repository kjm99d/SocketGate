#pragma once
/**
 * @file
 * @brief Client session: the state machine behind the public client API.
 *
 * Locking (always acquired in this order when more than one is needed):
 * @verbatim
   control_mutex_  Connect / Authenticate / Refresh / DeleteIdentity (one control operation at a time)
   recv_mutex_     decoder, receive side of the channel, message queue, phase
   send_mutex_     send side of the channel + TLS writes (sequence order == wire order)
   link_mutex_     the current connection generation (short critical sections only)
   info_mutex_     session information snapshot
   @endverbatim
 *
 * A connection "generation" (Link) bundles the TLS channel with the protected channel created for it. Every
 * operation captures the link it works on; a failure only tears down that same generation, so a stale operation can
 * never damage a newer connection after a reconnect.
 *
 * Disconnect() takes no long-held lock first: it shuts the transport down to wake blocked operations, then waits
 * for them via recv/send locks.
 */

#include "auth/client_handshake.h"
#include "crypto/key_store.h"
#include "tls/tls_channel.h"

#include "sockgate_common/core/clock.h"
#include "sockgate_common/core/log.h"
#include "sockgate_common/protocol/channel.h"
#include "sockgate_common/protocol/frame.h"

#include <sockgate/client.h>

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace sg::client {

/**
 * @brief Server to connect to and how to authenticate it (from SG_ServerConfig).
 *
 * ClientSession::Connect() requires: host of 1..253 characters, port != 0, at least one trust source (ca_file,
 * ca_pem or trust_system_store), at most SG_MAX_PINS pins and SG_MAX_PROOF_KEYS proof keys (valid P-256 points),
 * and trust_system_store without pins or proof keys only together with allow_no_pinning.
 */
struct ServerTarget {
    std::string host;          ///< DNS name or IP literal; resolved locally when direct, by the proxy otherwise.
    uint16_t port = 0;         ///< TCP port.
    std::string server_name;   ///< Name verified against the certificate (DNS names also sent as SNI); empty = host.
    std::string ca_file;       ///< PEM file with trust anchors; "" = none.
    std::string ca_pem;        ///< In-memory PEM trust anchors; "" = none.
    bool trust_system_store = false;  ///< Also trust the operating system's CA store.
    /**
     * @brief Explicit opt-out that permits trust_system_store without pins or proof keys.
     * @warning Trusting the OS store without pins or proof keys lets any user-installed CA impersonate the server.
     */
    bool allow_no_pinning = false;
    /** @brief SHA-256 of DER SubjectPublicKeyInfo; when non-empty a certificate of the verified chain must match. */
    std::vector<crypto::Sha256Digest> spki_pins;
    /** @brief Server proof keys (SEC1 uncompressed); see ClientHandshakeConfig::server_proof_keys. */
    std::vector<crypto::P256PublicKey> proof_keys;
};

/**
 * @brief Proxy policy used by Connect() (from SG_ProxyConfig).
 * @note The proxy only sees TLS ciphertext; see transport/proxy.h.
 */
struct ProxySettings {
    uint32_t mode = SG_PROXY_MODE_DIRECT;  ///< SG_PROXY_MODE_DIRECT, SG_PROXY_MODE_SYSTEM or SG_PROXY_MODE_EXPLICIT.
    uint32_t type = 0;       ///< SG_PROXY_TYPE_* (EXPLICIT only).
    std::string host;        ///< Proxy host (EXPLICIT only).
    uint16_t port = 0;       ///< Proxy port (EXPLICIT only).
    std::string username;    ///< User name (SOCKS4a: user id); "" = no credentials.
    SecureBytes password;    ///< Password for HTTP Basic / SOCKS5 (unused by SOCKS4a); wiped on release.
};

/** @brief Configuration of one client (from SG_ClientConfig); owned by its ClientSession. */
struct ClientSettings {
    std::string identity_name;               ///< Installation key name in key_store (see ValidateKeyName()).
    std::unique_ptr<IKeyStore> key_store;    ///< Store holding the installation key (owned).
    uint32_t flags = 0;                      ///< SG_CLIENT_FLAG_* bits.
    /**
     * @brief Product / license / features / version claims.
     *
     * server_proof_keys is replaced by ServerTarget::proof_keys, and with SG_CLIENT_FLAG_INTEGRITY_REPORT the
     * integrity report is collected for each authentication.
     */
    ClientHandshakeConfig handshake;
    /**
     * @brief One budget (ms) for the system proxy lookup, name resolution, TCP connect, proxy negotiation and the TLS
     *        handshake of Connect(); 0 = no limit.
     */
    uint32_t connect_timeout_ms = 10'000;
    uint32_t io_timeout_ms = 30'000;  /**< Transport I/O timeout and deadline of each Authenticate() / Refresh()
                                           exchange (ms); 0 = no timeout. */
    uint32_t max_payload = 1u << 20;         ///< Largest DATA payload (bytes) sent or accepted.
    ProxySettings proxy;                     ///< Proxy policy.
    Logger logger;                           ///< Log sink.
};

/**
 * @brief Client connection state machine behind one SG_Client handle.
 *
 * States (SG_CLIENT_STATE_*): Connect() goes DISCONNECTED -> CONNECTING -> TLS_HANDSHAKE -> TLS_ESTABLISHED,
 * Authenticate() -> AUTHENTICATING -> AUTHENTICATED -> ACTIVE, Refresh() ACTIVE -> REFRESHING -> ACTIVE. Failures
 * end in CLOSED, expiry in EXPIRED; Connect() is allowed again from DISCONNECTED, CLOSED and EXPIRED.
 *
 * @note Thread safety: Send() and Receive() may run concurrently on different threads; calls in the same direction
 *       are serialised (Ping() shares the send side). Connect(), Authenticate(), Refresh() and DeleteIdentity() run
 *       one at a time (control_mutex_). Disconnect(), state() and GetSessionInfo() may be called from any thread.
 *       EnsureIdentity() and GetIdentity() take no session lock. The destructor must not run concurrently with any
 *       other call.
 */
class ClientSession {
public:
    /**
     * @brief Creates a disconnected session.
     * @param[in] settings Configuration (taken over).
     */
    explicit ClientSession(ClientSettings settings);
    /** @brief Disconnect()s, then wipes the stored channel binding and transcript hash. */
    ~ClientSession();

    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    /**
     * @brief Loads the installation identity, creating it when absent (sg::client::EnsureIdentity()).
     *
     * Logs event=identity_created when a key was generated. Takes no session lock.
     *
     * @param[out] out Receives the identity; may be nullptr.
     * @return As sg::client::EnsureIdentity().
     */
    Status EnsureIdentity(IdentityInfo* out);
    /**
     * @brief Loads the installation identity without creating it (sg::client::GetIdentity()). Takes no session lock.
     * @param[out] out Receives the identity; must not be nullptr.
     * @return As sg::client::GetIdentity(), e.g. SG_NOT_FOUND when there is no identity.
     */
    Status GetIdentity(IdentityInfo* out);
    /**
     * @brief Deletes the installation key: IKeyStore::DeleteKey(), or IKeyStore::ForceDeleteKey() when @p force.
     *
     * Takes control_mutex_.
     *
     * @param[in] force Also forget an identity whose store is unavailable (AUTO); its key may survive.
     * @retval SG_INVALID_STATE Not in DISCONNECTED, CLOSED or EXPIRED.
     * @return Otherwise the key store's status.
     */
    Status DeleteIdentity(bool force);

    /**
     * @brief Opens the transport (direct or through a proxy) and runs the TLS handshake with @p target.
     *
     * Validates @p target and creates the TLS context first; the state is unchanged if that fails. Then one
     * connect_timeout_ms budget covers the proxy lookup, name resolution, TCP connect, proxy negotiation and the TLS
     * handshake: the handshake gets only what the transport left, and is not tried when nothing is left. The budget
     * is checked between steps: a single resolver call or system proxy lookup cannot be interrupted, and proxy
     * requests and TLS records are written with the io_timeout_ms of the transport. States: CONNECTING,
     * TLS_HANDSHAKE, then TLS_ESTABLISHED, or CLOSED on failure. Takes control_mutex_.
     *
     * A Disconnect() from another thread at any point after the state check makes this call return SG_CLOSED,
     * unless target validation or TLS context creation fails first (that error is returned) or a certificate or
     * pinning failure was already detected (reported as such). An abort before the transport is set up leaves the
     * state as Disconnect() set it. A torn-down connection is never resurrected. Other transport and TLS errors are
     * passed through.
     *
     * @param[in] target Server and trust settings; kept for Authenticate() once TLS is established.
     * @retval SG_OK                TLS established.
     * @retval SG_INVALID_STATE     Not in DISCONNECTED, CLOSED or EXPIRED.
     * @retval SG_INVALID_ARGUMENT  @p target fails validation (see ServerTarget).
     * @retval SG_CLOSED            Disconnect() was called meanwhile.
     * @retval SG_TIMEOUT           The budget ran out.
     * @retval SG_PROXY_ERROR       The proxy could not be used.
     * @retval SG_CERTIFICATE_ERROR Certificate chain or host name verification failed.
     * @retval SG_PINNING_ERROR     The chain validated against a trusted CA but matched no pin (logged as a
     *                              possible TLS interception).
     * @retval SG_TLS_ERROR         Other TLS failure.
     */
    Status Connect(const ServerTarget& target);
    /**
     * @brief Runs the SockGate handshake over the established TLS connection.
     *
     * Requires TLS_ESTABLISHED. The identity is created when missing only with SG_CLIENT_FLAG_AUTO_IDENTITY or in
     * ENROLL mode; otherwise a missing identity fails with SG_NOT_FOUND. With SG_CLIENT_FLAG_INTEGRITY_REPORT a fresh
     * integrity report is collected. The client signs a transcript bound to this TLS connection's channel binding;
     * the target's proof keys make the server proof mandatory. On success the session keys come from the TLS
     * exporter with TH1 as context, the local lifetime starts, and the state becomes ACTIVE. Waiting for the server
     * is bounded by one io_timeout_ms deadline for the whole exchange. Takes control_mutex_ and recv_mutex_.
     *
     * Identity lookup and token parsing errors leave the state TLS_ESTABLISHED; every later error closes the
     * connection (CLOSED). Identity, key store and token errors are passed through.
     *
     * @param[in] enrollment_token enrollment_token == nullptr: AUTHENTICATE, otherwise ENROLL. K_tok derived from it
     *                             is wiped on every return path; the string itself is the caller's to wipe.
     * @retval SG_OK                Authenticated; state ACTIVE.
     * @retval SG_INVALID_STATE     Not in TLS_ESTABLISHED.
     * @retval SG_CLOSED            The connection was torn down meanwhile (e.g. Disconnect()).
     * @retval SG_SERVER_REJECTED   The server rejected the client or asked it to retry later.
     * @retval SG_VERSION_MISMATCH  No common protocol version.
     * @retval SG_INVALID_SIGNATURE The required server proof is missing or invalid.
     * @retval SG_PROTOCOL_ERROR    Malformed or unexpected server message.
     * @retval SG_TIMEOUT           The deadline passed.
     */
    Status Authenticate(const std::string* enrollment_token);
    /**
     * @brief Re-authenticates the active session (REAUTH exchange) and switches to the next key epoch.
     *
     * Requires ACTIVE. Takes control_mutex_, then waits for recv_mutex_, so it blocks while another thread is in
     * Receive(). The state is REFRESHING meanwhile: DATA that arrives is queued for Receive(), and Send() keeps
     * working. The client signs a fresh transcript bound to the previous one and to the channel binding; on success
     * both directions switch to keys of epoch + 1 (no frame is sealed with a mixed epoch), a TLS 1.3 KeyUpdate is
     * requested and the local lifetime restarts. Waiting for the server is bounded by io_timeout_ms.
     *
     * @retval SG_OK              ACTIVE again with the new epoch.
     * @retval SG_SESSION_EXPIRED The session expired (state EXPIRED).
     * @retval SG_INVALID_STATE   Not ACTIVE.
     * @retval SG_CLOSED          The connection was closed or replaced meanwhile.
     * @retval SG_SERVER_REJECTED The server refused the re-authentication.
     * @retval SG_PROTOCOL_ERROR  Unexpected frame or epoch.
     * @retval SG_TIMEOUT         The deadline passed.
     * @warning Every failure once the exchange started is terminal: the connection is closed (EXPIRED for
     *          SG_SESSION_EXPIRED, CLOSED otherwise).
     */
    Status Refresh();
    /**
     * @brief Closes the connection and cancels every operation in progress. Idempotent; never throws.
     *
     * Detaches the current link and starts a new generation, so running operations become stale and cannot
     * resurrect the connection; the state becomes CLOSED (DISCONNECTED and EXPIRED are kept). Shuts down a transport
     * that is still connecting (one a stale Connect() creates later is shut down at once). If the session was ACTIVE or
     * REFRESHING, sends a CLOSE frame, best effort: skipped if another thread is mid-send, and bounded (200 ms) so a
     * peer that stopped reading cannot block it. Then close_notify (bounded, 200 ms) and transport shutdown, which
     * wake blocked operations. Finally waits for recv_mutex_ and send_mutex_, i.e. until woken Receive(), Send(),
     * Authenticate() or Refresh() exchanges have left, and discards queued messages.
     *
     * @note Callable from any thread; does not take control_mutex_. Woken calls fail, usually with SG_CLOSED.
     */
    void Disconnect() noexcept;

    /**
     * @brief Sends one DATA message: a new request, or a response to a received request.
     *
     * Runs an automatic refresh first when one is due (SG_CLIENT_FLAG_AUTO_REFRESH). Allowed in ACTIVE and
     * REFRESHING. With SG_CLIENT_FLAG_APP_ENCRYPTION the payload is also encrypted at the application layer inside
     * TLS. Takes send_mutex_, so sequence order equals wire order. Errors of the automatic refresh are returned.
     *
     * @param[in]  data                Payload, at most max_payload bytes.
     * @param[in]  reply_to_request_id 0: a new request with a fresh request id; otherwise the id of the received
     *                                 request this message answers.
     * @param[out] out_request_id      Optional: receives the new request id, or 0 for a response.
     * @retval SG_OK               Sent.
     * @retval SG_INVALID_ARGUMENT @p data exceeds max_payload, or the reply refers to a request never received; the
     *                             connection stays usable.
     * @retval SG_SESSION_EXPIRED  The session expired (state EXPIRED).
     * @retval SG_CLOSED           The connection is closed.
     * @retval SG_INVALID_STATE    Not ACTIVE or REFRESHING.
     * @warning Any other failure (sealing, a failed or partial TLS write) closes the connection and is returned.
     */
    Status Send(ByteView data, uint64_t reply_to_request_id, uint64_t* out_request_id);
    /**
     * @brief Receives the next DATA message.
     *
     * Runs an automatic refresh first when one is due. Messages already queued for the current connection are
     * delivered first, also after the connection failed (until Disconnect() or a new Connect()). Otherwise frames
     * are read under recv_mutex_ (one receiver at a time): PING is answered with PONG, PONG is dropped, a CLOSE from
     * the server ends the session, and reauth frames are accepted only while Refresh() waits for them. Read and
     * frame errors close the connection; SG_TIMEOUT does not.
     *
     * @param[out] buffer     Destination; may be nullptr only when @p capacity is 0.
     * @param[in]  capacity   Size of @p buffer in bytes.
     * @param[out] received   Receives the payload size; on SG_BUFFER_TOO_SMALL the size required.
     * @param[out] info       Optional: receives the request id and SG_MESSAGE_FLAG_* bits.
     * @param[in]  timeout_ms Deadline (ms); net::kNoTimeout (0) waits indefinitely.
     * @retval SG_OK               One message delivered.
     * @retval SG_BUFFER_TOO_SMALL The message does not fit; it stays queued.
     * @retval SG_TIMEOUT          Nothing arrived in time (not fatal).
     * @retval SG_INVALID_ARGUMENT @p received is nullptr, or @p buffer is nullptr with a non-zero @p capacity.
     * @retval SG_SESSION_EXPIRED  Expired locally or closed by the server as expired (state EXPIRED).
     * @retval SG_SERVER_REJECTED  The server closed the session because authentication failed.
     * @retval SG_CLOSED           Closed by the server or by Disconnect(), or reconnected meanwhile.
     * @retval SG_LIMIT_EXCEEDED   More than 64 MiB of undelivered messages.
     * @retval SG_INVALID_STATE    No authenticated session.
     */
    Status Receive(uint8_t* buffer, size_t capacity, size_t* received, SG_MessageInfo* info, uint32_t timeout_ms);
    /**
     * @brief Sends a PING frame; the PONG is consumed by a later Receive() and not reported.
     * @return As the state checks of Send() (SG_SESSION_EXPIRED, SG_CLOSED, SG_INVALID_STATE); a failed write closes
     *         the connection and is returned.
     */
    Status Ping();

    /**
     * @brief Current state; callable from any thread (atomic read).
     * @return SG_CLIENT_STATE_* value.
     */
    uint32_t state() const noexcept { return state_.load(); }
    /**
     * @brief Snapshot of the session: state, policy, session id, granted features, license expiry, remaining
     *        lifetime, epoch, TLS protocol and cipher.
     * @param[out] info Receives the snapshot; expires_in_ms is 0 once expired and clamped to UINT32_MAX; the TLS
     *                  strings are empty without a connection.
     * @retval SG_OK               Filled.
     * @retval SG_INVALID_ARGUMENT @p info is nullptr.
     */
    Status GetSessionInfo(SG_ClientSessionInfo* info);
    /**
     * @brief Configured I/O timeout.
     * @return ClientSettings::io_timeout_ms (ms; 0 = none).
     */
    uint32_t io_timeout_ms() const noexcept { return settings_.io_timeout_ms; }

private:
    /** @brief A received DATA message waiting for Receive(). */
    struct QueuedMessage {
        SecureBytes data;         ///< Payload; wiped on release.
        uint64_t request_id = 0;  ///< Request id from the frame header.
        uint32_t flags = 0;       ///< SG_MESSAGE_FLAG_ENCRYPTED / SG_MESSAGE_FLAG_RESPONSE.
    };

    /** @brief One connection generation: the TLS channel and the protected channel created for it. */
    struct Link {
        std::shared_ptr<TlsChannel> tls;                    ///< TLS channel; nullptr once torn down.
        std::shared_ptr<proto::ProtectedChannel> channel;  ///< Protected channel; set once authenticated.
        uint64_t generation = 0;                            ///< Generation number (see next_generation_).
    };

    /**
     * @brief Copy of the current link (takes link_mutex_).
     * @return The current Link; its tls is nullptr when there is no connection.
     */
    Link CurrentLink();
    /**
     * @brief Checks whether @p generation is the live connection (takes link_mutex_).
     * @param[in] generation Generation to check.
     * @return True if @p generation is current and not torn down.
     */
    bool IsCurrent(uint64_t generation);
    /**
     * @brief Stores `state` only if `generation` is still the current connection (takes link_mutex_).
     * @param[in] generation Generation the caller works on.
     * @param[in] state      SG_CLIENT_STATE_* value to store.
     * @return False for a stale or torn-down generation.
     */
    bool SetStateIfCurrent(uint64_t generation, uint32_t state);
    /**
     * @brief Checks @p target against the rules listed at ServerTarget; proof key validation errors are passed
     *        through.
     * @param[in] target Target to check.
     * @retval SG_OK               Valid.
     * @retval SG_INVALID_ARGUMENT A rule is violated.
     */
    Status ValidateTarget(const ServerTarget& target) const;
    /**
     * @brief Creates the connected transport for @p target (direct or through a proxy).
     *
     * The transport is published in connecting_transport_ before any blocking connect so Disconnect() can shut it
     * down; if Disconnect() already moved past @p attempt, the transport is shut down at once.
     *
     * @param[in]  target  Server target.
     * @param[in]  attempt Generation current when Connect() started.
     * @param[out] out     Receives the transport.
     * @return As CreateConnectedTransport().
     */
    Status OpenTransport(const ServerTarget& target, uint64_t attempt, std::shared_ptr<net::ITransport>* out);
    /**
     * @brief Resets the receive state for @p generation: new decoder with the pre-authentication buffer limit, phase
     *        kClosed, empty queue, no pending reauth frame. Caller holds recv_mutex_.
     * @param[in] generation Generation the receive state belongs to from now on.
     */
    void ResetReceiveStateLocked(uint64_t generation);
    /**
     * @brief Checks that @p link can carry session traffic: state ACTIVE or REFRESHING, TLS and protected channel
     *        present, local lifetime not over.
     * @param[in] link Link to check.
     * @retval SG_OK              Usable.
     * @retval SG_SESSION_EXPIRED State EXPIRED, or the lifetime is over (the connection is then torn down).
     * @retval SG_CLOSED          State CLOSED, or the link has no channel.
     * @retval SG_INVALID_STATE   Any other state.
     */
    Status CheckUsable(const Link& link);
    /**
     * @brief With SG_CLIENT_FLAG_AUTO_REFRESH, refreshes once 80% of the session lifetime has passed.
     *
     * Called on entry to Send() and Receive(), without a separate thread. Never waits for a Receive() blocked in
     * another thread; the refresh is then retried on a later call.
     *
     * @return SG_OK when nothing was due or the refresh was skipped; otherwise the refresh result.
     */
    Status MaybeAutoRefresh();
    /**
     * @brief Implementation of Refresh().
     * @param[in] opportunistic True for the automatic refresh: re-checks under control_mutex_ that a refresh is due,
     *                          returns SG_OK instead of an error when not ACTIVE, and returns SG_OK instead of waiting
     *                          when recv_mutex_ is busy.
     * @return As Refresh().
     */
    Status RefreshImpl(bool opportunistic);

    // recv_mutex_ held:
    /**
     * @brief Reads until one frame is complete, then checks its header against the current phase (the phase may have
     *        changed since the header arrived). The read buffer is wiped.
     *
     * Decoder, header check and TLS errors are passed through.
     *
     * @param[in]  tls      TLS channel of the current link.
     * @param[out] out      Receives the frame.
     * @param[in]  deadline Deadline for the whole read.
     * @retval SG_OK      A frame is ready.
     * @retval SG_TIMEOUT @p deadline passed.
     */
    Status ReadFrameLocked(TlsChannel& tls, proto::DecodedFrame* out, const Deadline& deadline);
    /**
     * @brief Opens one session frame (sequence, request id, key phase and tag checks; decryption when encrypted) and
     *        acts on it.
     *
     * DATA is queued (SG_LIMIT_EXCEEDED beyond 64 MiB queued), PING is answered with PONG, PONG is checked and
     * dropped, CLOSE maps to SG_SESSION_EXPIRED / SG_SERVER_REJECTED / SG_CLOSED, and the reauth frame Refresh()
     * waits for is stored (any other reauth frame: SG_PROTOCOL_ERROR). Open failures are logged and returned.
     *
     * @param[in]     link  Link the frame arrived on.
     * @param[in,out] frame Frame to handle; moved from when stored as the reauth frame.
     * @return SG_OK when the frame was handled; otherwise the error, which ends the connection.
     */
    Status HandleSessionFrameLocked(const Link& link, proto::DecodedFrame& frame);
    /**
     * @brief Handles session frames (DATA is queued meanwhile) until the reauth frame of @p type arrives.
     * @param[in]  link            Link to read from.
     * @param[in]  type            REAUTH_CHALLENGE or REAUTH_RESULT.
     * @param[in]  deadline        Deadline for the wait.
     * @param[out] out             Receives the frame.
     * @param[out] plaintext_frame Receives its plaintext view (transcript input).
     * @return SG_OK, or the first read or frame error.
     */
    Status WaitForReauthFrameLocked(const Link& link, proto::MessageType type, const Deadline& deadline,
                                    proto::DecodedFrame* out, Bytes* plaintext_frame);
    /**
     * @brief Copies the oldest queued message to @p buffer and removes it; the queue must not be empty.
     * @param[out] buffer   Destination.
     * @param[in]  capacity Size of @p buffer.
     * @param[out] received Receives the message size.
     * @param[out] info     Optional: receives the request id and flags.
     * @retval SG_OK               Delivered.
     * @retval SG_BUFFER_TOO_SMALL The message is kept; *received is its size.
     */
    Status DeliverLocked(uint8_t* buffer, size_t capacity, size_t* received, SG_MessageInfo* info);

    /**
     * @brief Seals and writes one frame (takes send_mutex_).
     *
     * Does not tear the connection down on failure; callers do. Sealing and TLS errors are passed through.
     *
     * @param[in]  link      Link to send on.
     * @param[in]  type      Message type.
     * @param[in]  payload   Frame payload.
     * @param[in]  options   Sealing options (encryption, request id).
     * @param[out] frame_out Optional: receives the sealed wire frame.
     * @retval SG_OK            Sent.
     * @retval SG_INVALID_STATE @p link has no protected channel.
     */
    Status SendFrame(const Link& link, proto::MessageType type, ByteView payload, const proto::SealOptions& options,
                     Bytes* frame_out = nullptr);
    /**
     * @brief Terminal failure of `generation`: records the state and tears that connection down. A stale generation
     *        is left alone.
     *
     * Tearing down aborts the TLS channel without sending anything.
     *
     * @param[in] generation Generation that failed.
     * @param[in] status     Status to return.
     * @param[in] new_state  State to record.
     * @return @p status, unchanged.
     */
    Status Fail(uint64_t generation, Status status, uint32_t new_state = SG_CLIENT_STATE_CLOSED);

    ClientSettings settings_;                              ///< Configuration; not modified after construction.
    std::atomic<uint32_t> state_{SG_CLIENT_STATE_DISCONNECTED};  ///< SG_CLIENT_STATE_*; read without locks.

    std::mutex control_mutex_;  ///< Lock order 1: one control operation at a time.
    std::mutex recv_mutex_;     ///< Lock order 2: receive side.
    std::mutex send_mutex_;     ///< Lock order 3: send side and TLS writes.
    std::mutex link_mutex_;     ///< Lock order 4: current generation (short sections only).
    std::mutex info_mutex_;     ///< Lock order 5: session information.

    // link_mutex_:
    Link link_;                                             ///< Current connection generation.
    uint64_t next_generation_ = 1;                          ///< Next generation number to hand out.
    std::shared_ptr<net::ITransport> connecting_transport_;  ///< Transport of a Connect() in progress.

    // control_mutex_:
    ServerTarget target_;  ///< Target of the current connection (proof keys for Authenticate()).

    // recv_mutex_:
    uint64_t recv_generation_ = 0;  ///< Generation the receive state below belongs to.
    std::unique_ptr<proto::FrameDecoder> decoder_;  ///< Frame decoder of that generation.
    proto::Phase phase_ = proto::Phase::kClosed;    ///< Protocol phase used for header checks.
    proto::FrameLimits limits_;                     ///< Frame limits (max DATA payload = max_payload).
    std::deque<QueuedMessage> queue_;               ///< DATA messages not yet delivered.
    size_t queued_bytes_ = 0;                       ///< Payload bytes in queue_ (at most 64 MiB).
    proto::MessageType reauth_expected_ = proto::MessageType::kClose;  ///< Reauth frame type Refresh() waits for.
    bool reauth_waiting_ = false;                   ///< Refresh() is waiting for a reauth frame.
    bool reauth_arrived_ = false;                   ///< The awaited reauth frame is stored.
    proto::DecodedFrame reauth_frame_;              ///< The stored reauth frame.
    Bytes reauth_plaintext_;                        ///< Its plaintext view.

    // info_mutex_:
    proto::SessionId session_id_{};            ///< Session id of the authenticated session.
    crypto::Sha256Digest channel_binding_{};   ///< Channel binding of that connection; wiped on destruction.
    crypto::Sha256Digest last_transcript_{};   ///< TH1 or the last reauth transcript hash; wiped on destruction.
    uint32_t epoch_ = 0;                       ///< Current key epoch (0 after authentication).
    uint32_t policy_ = SG_SESSION_POLICY_NONE;  ///< SG_SESSION_POLICY_* granted by the server.
    uint64_t granted_features_ = 0;            ///< Feature bits granted by the server.
    uint64_t license_expires_at_ms_ = 0;       ///< License expiry reported by the server (Unix epoch ms).
    uint64_t authenticated_at_ = 0;            ///< MonotonicMs() of the last authentication or refresh.
    uint64_t lifetime_ms_ = 0;                 ///< Session lifetime granted by the server (ms).
    uint64_t expires_at_ = 0;                  ///< MonotonicMs() of local expiry; 0 = not checked (no session).
};

}  // namespace sg::client
