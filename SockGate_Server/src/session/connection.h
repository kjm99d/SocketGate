// One accepted connection: TLS (memory BIO) + SockGate framing + handshake +
// protected session + reauthentication. All state is guarded by mutex_;
// application callbacks are queued as events and delivered outside the lock,
// serially and in order, by whichever thread finds the queue non-empty.
#pragma once

#include "auth/server_handshake.h"
#include "core/server_engine.h"
#include "transport/io_service.h"

#include "sockgate_common/protocol/channel.h"
#include "sockgate_common/protocol/frame.h"

#include <memory>
#include <mutex>
#include <vector>

namespace sg::server {

class Connection : public std::enable_shared_from_this<Connection> {
public:
    Connection(ServerEngine* engine, std::shared_ptr<AsyncStream> stream, std::unique_ptr<tls::ITlsEngine> tls,
               SG_SessionHandle handle, uint64_t now_ms);
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    void Start();
    Status Send(ByteView data, uint64_t reply_to_request_id);
    // Graceful close; authenticated peers receive CLOSE(reason).
    void Close(proto::CloseReason reason, Status status);
    // Immediate close of the socket (graceful-close timeout, shutdown).
    void ForceClose() noexcept;
    void Tick();

    SG_SessionHandle handle() const noexcept { return handle_; }
    const std::shared_ptr<AsyncStream>& stream() const noexcept { return stream_; }
    bool Snapshot(SessionSnapshot* out);
    bool IsInstallation(const proto::InstallationId& id);
    // Open session authorised under `license_id` (and, if given, for `installation`).
    bool UsesLicense(const std::string& license_id, const proto::InstallationId* installation);
    bool IsAuthenticated();

private:
    struct Event {
        enum class Kind { kOpened, kMessage, kClosed, kRemove } kind = Kind::kMessage;
        SessionSnapshot snapshot;
        SecureBytes data;
        uint64_t request_id = 0;
        uint32_t flags = 0;
        SG_Status reason = SG_OK;
    };

    void IssueRead();
    void OnRead(Status status, const uint8_t* data, size_t size);

    // `lock` holds mutex_; handlers that call application code (authorisation,
    // enrollment validation) release it around the call and re-check state.
    using Lock = std::unique_lock<std::mutex>;
    Status ProcessLocked(Lock& lock, ByteView ciphertext);
    Status HandleFrameLocked(Lock& lock, proto::DecodedFrame& frame);
    Status HandleClientHelloLocked(const proto::DecodedFrame& frame);
    Status HandleClientProofLocked(Lock& lock, const proto::DecodedFrame& frame);
    Status HandleSessionFrameLocked(Lock& lock, proto::DecodedFrame& frame);
    Status HandleReauthRequestLocked(const proto::DecodedFrame& frame, const Bytes& plaintext);
    Status HandleReauthProofLocked(Lock& lock, const proto::DecodedFrame& frame);
    Status RejectReauthLocked(const std::string& reason);

    Status WriteRawLocked(ByteView frame);
    Status SealAndWriteLocked(proto::MessageType type, ByteView payload, const proto::SealOptions& options,
                              Bytes* sealed_out = nullptr);
    void FlushLocked();
    void CloseLocked(proto::CloseReason reason, Status status, bool notify_peer, bool graceful);
    void SnapshotLocked(SessionSnapshot* out, uint64_t now) const;
    uint32_t ComputeLifetimeLocked(const AuthorizationDecision& decision, bool* expired) const;

    void DeliverEvents();

    ServerEngine* const engine_;
    const std::shared_ptr<AsyncStream> stream_;
    const SG_SessionHandle handle_;

    std::mutex mutex_;
    std::unique_ptr<tls::ITlsEngine> tls_;
    proto::FrameDecoder decoder_;
    proto::FrameLimits limits_;
    ServerHandshake handshake_;
    std::unique_ptr<proto::ProtectedChannel> channel_;
    proto::Phase phase_ = proto::Phase::kAwaitClientHello;
    bool tls_ready_ = false;
    bool closed_ = false;
    bool opened_ = false;
    bool peer_encrypts_ = false;
    uint64_t accepted_at_;
    uint64_t closing_since_ = 0;
    uint64_t expires_at_ = 0;
    uint64_t last_activity_ = 0;
    uint64_t last_reauth_at_ = 0;

    crypto::Sha256Digest channel_binding_{};
    crypto::Sha256Digest last_transcript_{};
    uint32_t epoch_ = 0;
    HandshakeOutcome outcome_;

    // Reauthentication sub-state.
    proto::Challenge reauth_challenge_{};
    uint64_t reauth_issued_at_ = 0;
    Bytes reauth_request_f_;
    Bytes reauth_challenge_f_;

    // Event queue (mutex_). Reading pauses while undelivered message bytes
    // exceed a watermark and resumes once the application caught up.
    std::vector<Event> pending_events_;
    size_t pending_event_bytes_ = 0;
    size_t delivering_bytes_ = 0;
    bool delivering_ = false;
    bool read_paused_ = false;
    bool counted_active_ = false;
};

}  // namespace sg::server
