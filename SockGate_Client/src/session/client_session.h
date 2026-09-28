// Client session: the state machine behind the public client API.
//
// Locking (always acquired in this order when more than one is needed):
//   control_mutex_  Connect / Authenticate / Refresh (one control operation at a time)
//   recv_mutex_     decoder, receive side of the channel, message queue, phase
//   send_mutex_     send side of the channel + TLS writes (sequence order == wire order)
//   link_mutex_     the current connection generation (short critical sections only)
//   info_mutex_     session information snapshot
//
// A connection "generation" (Link) bundles the TLS channel with the
// protected channel created for it. Every operation captures the link it
// works on; a failure only tears down that same generation, so a stale
// operation can never damage a newer connection after a reconnect.
//
// Disconnect() takes no long-held lock first: it shuts the transport down
// to wake blocked operations, then waits for them via recv/send locks.
#pragma once

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

struct ServerTarget {
    std::string host;
    uint16_t port = 0;
    std::string server_name;  // empty = host
    std::string ca_file;
    std::string ca_pem;
    bool trust_system_store = false;
    bool allow_no_pinning = false;
    std::vector<crypto::Sha256Digest> spki_pins;
    std::vector<crypto::P256PublicKey> proof_keys;
};

struct ProxySettings {
    uint32_t mode = SG_PROXY_MODE_DIRECT;
    uint32_t type = 0;
    std::string host;
    uint16_t port = 0;
    std::string username;
    SecureBytes password;
};

struct ClientSettings {
    std::string identity_name;
    std::unique_ptr<IKeyStore> key_store;
    uint32_t flags = 0;
    ClientHandshakeConfig handshake;  // product / license / features / version claims
    uint32_t connect_timeout_ms = 10'000;
    uint32_t io_timeout_ms = 30'000;  // 0 = no timeout
    uint32_t max_payload = 1u << 20;
    ProxySettings proxy;
    Logger logger;
};

class ClientSession {
public:
    explicit ClientSession(ClientSettings settings);
    ~ClientSession();

    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    Status EnsureIdentity(IdentityInfo* out);
    Status GetIdentity(IdentityInfo* out);
    Status DeleteIdentity(bool force);

    Status Connect(const ServerTarget& target);
    // enrollment_token == nullptr: AUTHENTICATE, otherwise ENROLL.
    Status Authenticate(const std::string* enrollment_token);
    Status Refresh();
    void Disconnect() noexcept;

    Status Send(ByteView data, uint64_t reply_to_request_id, uint64_t* out_request_id);
    // timeout_ms: net::kNoTimeout (0) waits indefinitely.
    Status Receive(uint8_t* buffer, size_t capacity, size_t* received, SG_MessageInfo* info, uint32_t timeout_ms);
    Status Ping();

    uint32_t state() const noexcept { return state_.load(); }
    Status GetSessionInfo(SG_ClientSessionInfo* info);
    uint32_t io_timeout_ms() const noexcept { return settings_.io_timeout_ms; }

private:
    struct QueuedMessage {
        SecureBytes data;
        uint64_t request_id = 0;
        uint32_t flags = 0;
    };

    struct Link {
        std::shared_ptr<TlsChannel> tls;
        std::shared_ptr<proto::ProtectedChannel> channel;  // set once authenticated
        uint64_t generation = 0;
    };

    Link CurrentLink();
    bool IsCurrent(uint64_t generation);
    // Stores `state` only if `generation` is still the current connection.
    bool SetStateIfCurrent(uint64_t generation, uint32_t state);
    Status ValidateTarget(const ServerTarget& target) const;
    Status OpenTransport(const ServerTarget& target, uint64_t attempt, std::shared_ptr<net::ITransport>* out);
    void ResetReceiveStateLocked(uint64_t generation);
    Status CheckUsable(const Link& link);
    Status MaybeAutoRefresh();
    Status RefreshImpl(bool opportunistic);

    // recv_mutex_ held:
    Status ReadFrameLocked(TlsChannel& tls, proto::DecodedFrame* out, const Deadline& deadline);
    Status HandleSessionFrameLocked(const Link& link, proto::DecodedFrame& frame);
    Status WaitForReauthFrameLocked(const Link& link, proto::MessageType type, const Deadline& deadline,
                                    proto::DecodedFrame* out, Bytes* plaintext_frame);
    Status DeliverLocked(uint8_t* buffer, size_t capacity, size_t* received, SG_MessageInfo* info);

    // Seals and writes one frame (takes send_mutex_).
    Status SendFrame(const Link& link, proto::MessageType type, ByteView payload, const proto::SealOptions& options,
                     Bytes* frame_out = nullptr);
    // Terminal failure of `generation`: records the state and tears that
    // connection down. A stale generation is left alone.
    Status Fail(uint64_t generation, Status status, uint32_t new_state = SG_CLIENT_STATE_CLOSED);

    ClientSettings settings_;
    std::atomic<uint32_t> state_{SG_CLIENT_STATE_DISCONNECTED};

    std::mutex control_mutex_;
    std::mutex recv_mutex_;
    std::mutex send_mutex_;
    std::mutex link_mutex_;
    std::mutex info_mutex_;

    // link_mutex_:
    Link link_;
    uint64_t next_generation_ = 1;
    std::shared_ptr<net::ITransport> connecting_transport_;

    // control_mutex_:
    ServerTarget target_;

    // recv_mutex_:
    uint64_t recv_generation_ = 0;  // generation the receive state below belongs to
    std::unique_ptr<proto::FrameDecoder> decoder_;
    proto::Phase phase_ = proto::Phase::kClosed;
    proto::FrameLimits limits_;
    std::deque<QueuedMessage> queue_;
    size_t queued_bytes_ = 0;
    proto::MessageType reauth_expected_ = proto::MessageType::kClose;
    bool reauth_waiting_ = false;
    bool reauth_arrived_ = false;
    proto::DecodedFrame reauth_frame_;
    Bytes reauth_plaintext_;

    // info_mutex_:
    proto::SessionId session_id_{};
    crypto::Sha256Digest channel_binding_{};
    crypto::Sha256Digest last_transcript_{};
    uint32_t epoch_ = 0;
    uint32_t policy_ = SG_SESSION_POLICY_NONE;
    uint64_t granted_features_ = 0;
    uint64_t license_expires_at_ms_ = 0;
    uint64_t authenticated_at_ = 0;
    uint64_t lifetime_ms_ = 0;
    uint64_t expires_at_ = 0;
};

}  // namespace sg::client
