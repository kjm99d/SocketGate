#pragma once
/**
 * @file
 * @brief One accepted connection: TLS (memory BIO) + SockGate framing + handshake + protected session +
 *        reauthentication.
 *
 * All state is guarded by mutex_; application callbacks are queued as events and delivered outside the lock,
 * serially and in order, by whichever thread finds the queue non-empty.
 */

#include "auth/server_handshake.h"
#include "core/server_engine.h"
#include "transport/io_service.h"

#include "sockgate_common/protocol/channel.h"
#include "sockgate_common/protocol/frame.h"

#include <memory>
#include <mutex>
#include <vector>

namespace sg::server {

/**
 * @brief One accepted connection and, once authenticated, its session.
 *
 * Lifecycle: TLS handshake, CLIENT_HELLO / CLIENT_PROOF, then the protected session (DATA, PING/PONG, CLOSE,
 * reauthentication) until it closes. Closing is one-way: once closed, a connection never reopens and queues a
 * final remove event that hands it back to ServerEngine::OnConnectionClosed().
 *
 * @note Thread safety: every public method may be called from any thread. All state is guarded by mutex_,
 *       except the handshake object while OnClientProof() runs (only the read-processing thread touches it,
 *       with mutex_ released) and the lock-free unauthenticated flag. Lock order: mutex_ is never held while
 *       engine mutexes are acquired or session and authorization callbacks run; it may be held while the
 *       registry, the license store and the stream take their internal locks.
 * @warning The application's log callback (EngineConfig::logger) is invoked while mutex_ is held; calling back
 *          into this connection from it (e.g. Send or CloseSession for this session) would deadlock.
 * @note Only one read is outstanding at a time: the next read is issued after the previous data was processed,
 *       and reading pauses while more than 8 MiB of undelivered message bytes are queued.
 */
class Connection : public std::enable_shared_from_this<Connection> {
public:
    /**
     * @brief Creates a connection for an accepted stream (not yet reading; see Start()).
     * @param[in] engine Owning engine (not owned).
     * @param[in] stream Accepted stream.
     * @param[in] tls    Server TLS engine for this connection.
     * @param[in] handle Session handle assigned at accept.
     * @param[in] now_ms Monotonic accept time in ms (start of the handshake timeout).
     */
    Connection(ServerEngine* engine, std::shared_ptr<AsyncStream> stream, std::unique_ptr<tls::ITlsEngine> tls,
               SG_SessionHandle handle, uint64_t now_ms);
    /** @brief Wipes the channel binding, the last transcript hash and the reauthentication challenge. */
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    /** @brief Issues the first read. If it cannot be issued, the connection closes. */
    void Start();
    /**
     * @brief Sends a DATA message on the open session.
     *
     * The message is encrypted when require_app_encryption is set or the peer sent encrypted DATA.
     *
     * @param[in] data                Payload; at most max_payload bytes.
     * @param[in] reply_to_request_id Request id to answer (marks a response), or 0 for a new request id.
     * @retval SG_OK               Queued for transmission.
     * @retval SG_CLOSED           Closed, not yet authenticated, or sending failed (the connection is then
     *                             closed).
     * @retval SG_INVALID_ARGUMENT Payload too large, or a reply to an unknown request id.
     * @retval SG_LIMIT_EXCEEDED   More than 32 MiB of output is pending (slow reader).
     */
    Status Send(ByteView data, uint64_t reply_to_request_id);
    /**
     * @brief Graceful close; authenticated peers receive CLOSE(reason).
     *
     * Idempotent. Sends TLS close_notify (once TLS is up), destroys the session keys and lets the stream flush
     * before it closes.
     * An opened session reports @p status to the session-closed callback. Pending events are delivered on the
     * calling thread unless another thread is delivering.
     *
     * @param[in] reason Close reason sent to an authenticated peer.
     * @param[in] status Status reported to the application (converted to its public code).
     */
    void Close(proto::CloseReason reason, Status status);
    /**
     * @brief Immediate close of the socket (graceful-close timeout, shutdown).
     *
     * Only closes the stream: it takes no connection lock, sends nothing and does not change the connection's
     * own state.
     */
    void ForceClose() noexcept;
    /**
     * @brief Enforces timeouts; called by the engine's sweeper.
     *
     * Closes the connection when the handshake timeout passed before authentication (abortively, SG_TIMEOUT),
     * when the session lifetime ended (CLOSE(SESSION_EXPIRED), SG_SESSION_EXPIRED), after idle_timeout_ms
     * without a received frame (CLOSE(IDLE_TIMEOUT), SG_TIMEOUT), or when a reauthentication challenge expired
     * unanswered (CLOSE(AUTH_FAILED), SG_CHALLENGE_EXPIRED).
     */
    void Tick();

    /** @brief Session handle. @return The handle assigned at accept. */
    SG_SessionHandle handle() const noexcept { return handle_; }
    /** @brief Underlying stream. @return The accepted stream. */
    const std::shared_ptr<AsyncStream>& stream() const noexcept { return stream_; }
    /**
     * @brief Takes a snapshot of the open session.
     * @param[out] out Receives the snapshot.
     * @return False if the session is not (or no longer) open.
     */
    bool Snapshot(SessionSnapshot* out);
    /**
     * @brief Tells whether this is an open session of an installation.
     * @param[in] id Installation id.
     * @return True if the session is open and authenticated as @p id.
     */
    bool IsInstallation(const proto::InstallationId& id);
    /**
     * @brief Open session authorised under `license_id` (and, if given, for `installation`).
     * @param[in] license_id   License id (AuthorizationDecision::license_id of the session).
     * @param[in] installation Installation to match, or null for any.
     * @return True if the session is open and matches.
     */
    bool UsesLicense(const std::string& license_id, const proto::InstallationId* installation);
    /**
     * @brief Tells whether the session is open (authenticated and not closed).
     * @return True if open.
     */
    bool IsAuthenticated();
    /**
     * @brief Marks the connection as holding a place in the engine's unauthenticated count (at accept).
     *
     * Accounting for ServerEngine's unauthenticated-connection limit: set at
     * accept, left exactly once. LeaveUnauthenticated releases the place (on
     * authentication); TakeUnauthenticated hands it to the caller (the engine,
     * which keeps it while the stream closes).
     */
    void MarkUnauthenticated() noexcept { unauthenticated_.store(true); }
    /** @brief Releases the place on authentication (lock-free; no-op if already left). */
    void LeaveUnauthenticated() noexcept;
    /**
     * @brief Hands the place to the caller.
     * @return True if the connection still held it (the caller now owns the place).
     */
    bool TakeUnauthenticated() noexcept { return unauthenticated_.exchange(false); }

private:
    /** @brief A queued application event. */
    struct Event {
        /**
         * @brief Event kind: kOpened (session_opened with #snapshot), kMessage (message with #data, #request_id
         *        and #flags), kClosed (session_closed with #reason; opened sessions only), kRemove (hands the
         *        connection back through ServerEngine::OnConnectionClosed()).
         */
        enum class Kind { kOpened, kMessage, kClosed, kRemove } kind = Kind::kMessage;  ///< Kind of this event.
        SessionSnapshot snapshot;  ///< kOpened: the session at opening.
        SecureBytes data;          ///< kMessage: payload (wiped when freed).
        uint64_t request_id = 0;   ///< kMessage: request id.
        uint32_t flags = 0;        ///< kMessage: SG_MESSAGE_FLAG_* bits.
        SG_Status reason = SG_OK;  ///< kClosed: public status of the close reason.
    };

    /** @brief Issues the next read; if the stream refuses it, closes the connection (abortively). */
    void IssueRead();
    /**
     * @brief Read completion: processes the data under mutex_, closes on errors, delivers events and issues the
     *        next read unless closed or paused.
     *
     * Also closes a connection with more than 32 MiB of output pending because the peer does not read
     * (SG_LIMIT_EXCEEDED), and pauses reading above the event watermark.
     *
     * @param[in] status Read status (SG_CLOSED on orderly shutdown).
     * @param[in] data   Received bytes (valid during the call).
     * @param[in] size   Number of bytes.
     */
    void OnRead(Status status, const uint8_t* data, size_t size);

    /**
     * @brief Lock on mutex_ passed to the frame handlers.
     *
     * `lock` holds mutex_; handlers that call application code (authorisation,
     * enrollment validation) release it around the call and re-check state.
     */
    using Lock = std::unique_lock<std::mutex>;
    /**
     * @brief Feeds TLS ciphertext, completes the TLS handshake and dispatches every complete frame.
     *
     * Each frame header is re-validated against the current phase before it is handled.
     *
     * @param[in,out] lock       Holds mutex_ (may be released and re-acquired).
     * @param[in]     ciphertext Bytes received from the stream.
     * @retval SG_OK     Processed (the connection may have been closed meanwhile).
     * @retval SG_CLOSED The peer sent TLS close_notify.
     * @retval other     TLS, framing or protocol error: the caller closes the connection.
     */
    Status ProcessLocked(Lock& lock, ByteView ciphertext);
    /**
     * @brief Dispatches a frame by phase.
     * @param[in,out] lock  Holds mutex_.
     * @param[in,out] frame Decoded frame.
     * @retval SG_OK             Handled.
     * @retval SG_PROTOCOL_ERROR Frame in a phase that accepts none.
     * @retval other             Error of the phase handler.
     */
    Status HandleFrameLocked(Lock& lock, proto::DecodedFrame& frame);
    /**
     * @brief Handles CLIENT_HELLO (or an early CLOSE): writes SERVER_HELLO, or AUTH_RESULT(UNSUPPORTED_VERSION)
     *        and closes.
     * @param[in] frame Decoded frame.
     * @retval SG_OK Handled (possibly closed).
     * @retval other Protocol violation or write failure.
     */
    Status HandleClientHelloLocked(const proto::DecodedFrame& frame);
    /**
     * @brief Handles CLIENT_PROOF and opens the session.
     *
     * The handshake calls application code (on_authorize / on_enroll), which may call back into the server API
     * for this very session: mutex_ is released around it. A session authorised concurrently with a
     * revocation is re-checked (ServerEngine::IsStillAuthorized()); if it no longer holds, the seat it took is
     * given back and it is rejected. A rejection writes AUTH_RESULT(REJECTED) (the precise reason goes to the
     * server log only) and closes. On success the session keys are exported from TLS bound to TH1, the
     * connection leaves the unauthenticated count and the session-opened event is queued.
     *
     * @param[in,out] lock  Holds mutex_ (released during the handshake).
     * @param[in]     frame Decoded frame.
     * @retval SG_OK Handled (session opened, or rejected and closed, or closed meanwhile).
     * @retval other Protocol violation or internal failure.
     */
    Status HandleClientProofLocked(Lock& lock, const proto::DecodedFrame& frame);
    /**
     * @brief Handles a frame of the authenticated session.
     *
     * Opens the frame through the protected channel (verification and, if encrypted, decryption), then: DATA
     * is queued for the application (unencrypted DATA is a protocol error with require_app_encryption; more
     * than 64 MiB undelivered is SG_LIMIT_EXCEEDED); PING is answered with PONG; CLOSE closes gracefully;
     * REAUTH_REQUEST and REAUTH_PROOF drive reauthentication.
     *
     * @param[in,out] lock  Holds mutex_.
     * @param[in,out] frame Decoded frame.
     * @retval SG_OK Handled.
     * @retval other Frame rejected by the protected channel, protocol violation or limit: the caller closes.
     */
    Status HandleSessionFrameLocked(Lock& lock, proto::DecodedFrame& frame);
    /**
     * @brief Handles REAUTH_REQUEST: issues a single-use REAUTH_CHALLENGE and enters phase kRefreshing.
     *
     * One switch at a time, and a per-session rate limit on signature checks (min_reauth_interval_ms).
     *
     * @param[in] frame     Decoded frame.
     * @param[in] plaintext F(REAUTH_REQUEST): header || plaintext payload (transcript input).
     * @retval SG_OK             Challenge sent.
     * @retval SG_PROTOCOL_ERROR A key switch is still pending, or the request came too early.
     * @retval other             Malformed request or internal failure.
     */
    Status HandleReauthRequestLocked(const proto::DecodedFrame& frame, const Bytes& plaintext);
    /**
     * @brief Handles REAUTH_PROOF: verifies the signature, re-runs authorization and switches the key epoch.
     *
     * The challenge is wiped on arrival (single use). The signature is verified against the registry key
     * (against the dummy key if the installation is no longer active, so the timing is the same); an inactive
     * installation, a bad signature or an expired challenge rejects. Authorization is re-evaluated with mutex_
     * released: revoked licenses or changed policies apply now; a denial or an expired license rejects. If the
     * connection closed meanwhile, nothing more happens. On success REAUTH_RESULT(OK) is sent under the old key,
     * the send key switches, the new receive key is staged and a TLS KeyUpdate is requested. Any rejection
     * closes the session (RejectReauthLocked()).
     *
     * @param[in,out] lock  Holds mutex_ (released during authorization).
     * @param[in]     frame Decoded frame.
     * @retval SG_OK Handled (refreshed, or rejected and closed, or closed meanwhile).
     * @retval other Malformed proof or internal failure.
     */
    Status HandleReauthProofLocked(Lock& lock, const proto::DecodedFrame& frame);
    /**
     * @brief Sends REAUTH_RESULT(REJECTED), counts and logs the failure, and closes with SG_AUTH_FAILED.
     * @param[in] reason Log-only reason.
     * @retval SG_OK Always.
     */
    Status RejectReauthLocked(const std::string& reason);

    /**
     * @brief Writes a frame through TLS and flushes the ciphertext to the stream.
     * @param[in] frame Encoded frame.
     * @retval SG_OK Written.
     * @retval other TLS write failure.
     */
    Status WriteRawLocked(ByteView frame);
    /**
     * @brief Seals a message with the protected channel and writes it.
     * @param[in]  type       Message type.
     * @param[in]  payload    Plaintext payload.
     * @param[in]  options    Seal options (encryption, request id, response flag).
     * @param[out] sealed_out Optional; receives the sealed frame.
     * @retval SG_OK            Written.
     * @retval SG_INVALID_STATE No protected channel (not authenticated or closed).
     * @retval other            Seal or write failure.
     */
    Status SealAndWriteLocked(proto::MessageType type, ByteView payload, const proto::SealOptions& options,
                              Bytes* sealed_out = nullptr);
    /** @brief Moves pending TLS output to the stream (write errors are ignored here). */
    void FlushLocked();
    /**
     * @brief Closes the connection once (idempotent).
     *
     * Sends CLOSE(reason) if @p notify_peer and the session is authenticated, TLS close_notify, destroys the
     * session keys, closes the stream, updates the active-session count and queues the closed event (opened
     * sessions only) and the remove event.
     *
     * @param[in] reason      Close reason for the peer.
     * @param[in] status      Status reported to the application.
     * @param[in] notify_peer Send CLOSE to an authenticated peer.
     * @param[in] graceful    Let the stream flush first (CloseAfterWrites) instead of closing immediately.
     */
    void CloseLocked(proto::CloseReason reason, Status status, bool notify_peer, bool graceful);
    /**
     * @brief Fills a snapshot of the session.
     *
     * The license id is the registered or verified one only, never a raw client claim.
     *
     * @param[out] out Receives the snapshot.
     * @param[in]  now Monotonic time in ms (for expires_in_ms).
     */
    void SnapshotLocked(SessionSnapshot* out, uint64_t now) const;
    /**
     * @brief Effective session lifetime for a decision: its lifetime (or the default), capped by the maximum and
     *        by the remaining license validity; at least 1 ms.
     * @param[in]  decision Authorization decision.
     * @param[out] expired  Set to true if the license already expired (the result is then 0).
     * @return Lifetime in ms.
     */
    uint32_t ComputeLifetimeLocked(const AuthorizationDecision& decision, bool* expired) const;

    /**
     * @brief Delivers queued events to the application outside mutex_, serially and in order.
     *
     * Returns at once if another thread is delivering (that thread picks up new events). Resumes reading once
     * the undelivered backlog dropped to the watermark. Exceptions from callbacks are swallowed.
     */
    void DeliverEvents();

    ServerEngine* const engine_;                  ///< Owning engine (not owned).
    const std::shared_ptr<AsyncStream> stream_;   ///< The accepted stream.
    const SG_SessionHandle handle_;               ///< Session handle.

    std::mutex mutex_;                            ///< Guards the state below.
    std::unique_ptr<tls::ITlsEngine> tls_;        ///< TLS engine (memory BIO).
    proto::FrameDecoder decoder_;                 ///< Frame decoder (headers checked against the phase).
    proto::FrameLimits limits_;                   ///< Frame limits (max DATA payload).
    ServerHandshake handshake_;                   ///< Authentication handshake.
    std::unique_ptr<proto::ProtectedChannel> channel_;  ///< Session keys; set once authenticated, reset on close.
    proto::Phase phase_ = proto::Phase::kAwaitClientHello;  ///< Connection phase.
    bool tls_ready_ = false;       ///< TLS handshake complete (channel binding available).
    bool closed_ = false;          ///< CloseLocked() ran.
    bool opened_ = false;          ///< The session opened (a closed event will follow).
    bool peer_encrypts_ = false;   ///< The peer sent encrypted DATA: replies are encrypted too.
    uint64_t accepted_at_;         ///< Monotonic ms of accept (handshake timeout).
    uint64_t closing_since_ = 0;   ///< Monotonic ms at which the close began.
    uint64_t expires_at_ = 0;      ///< Monotonic ms at which the session expires.
    uint64_t last_activity_ = 0;   ///< Monotonic ms of the last authenticated frame received (idle timeout).
    uint64_t last_reauth_at_ = 0;  ///< Monotonic ms of session open or the last REAUTH_REQUEST (rate limit).

    crypto::Sha256Digest channel_binding_{};  ///< TLS channel binding (wiped on destruction).
    crypto::Sha256Digest last_transcript_{};  ///< Transcript hash of the last (re)authentication.
    uint32_t epoch_ = 0;                      ///< Current key epoch.
    HandshakeOutcome outcome_;                ///< Handshake result; decision and lifetime updated on refresh.

    // Reauthentication sub-state.
    proto::Challenge reauth_challenge_{};  ///< Pending reauthentication challenge (wiped when used).
    uint64_t reauth_issued_at_ = 0;        ///< Monotonic ms at which the challenge was issued.
    Bytes reauth_request_f_;               ///< F(REAUTH_REQUEST) for the reauthentication transcript.
    Bytes reauth_challenge_f_;             ///< F(REAUTH_CHALLENGE) for the reauthentication transcript.

    // Event queue (mutex_). Reading pauses while undelivered message bytes
    // exceed a watermark and resumes once the application caught up.
    std::vector<Event> pending_events_;   ///< Events not yet handed to a deliverer.
    size_t pending_event_bytes_ = 0;      ///< Message bytes in pending_events_.
    size_t delivering_bytes_ = 0;         ///< Message bytes of the batch being delivered.
    bool delivering_ = false;             ///< A thread is delivering events.
    bool read_paused_ = false;            ///< Reading paused for backpressure.
    bool counted_active_ = false;         ///< Counted in EngineStats::active_sessions.
    std::atomic<bool> unauthenticated_{false};  ///< Holds a place in the engine's unauthenticated count.
};

}  // namespace sg::server
