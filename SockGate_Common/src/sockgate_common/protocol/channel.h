// Authenticated frame protection for established sessions
// (docs/design/04-protocol-specification.md §7-§9).
//
// Every post-authentication frame carries:
//   - a per-direction sequence number that must be exactly previous + 1
//     (replay, duplication, reordering and deletion are all detected),
//   - a 16-byte AES-256-GCM tag keyed per direction and epoch, with the
//     48-byte header as AAD (payload too when not encrypted),
//   - KEY_PHASE = epoch & 1, selecting the receive key during a key switch.
// Request ids of requests are strictly increasing per direction; responses
// must refer to a request id the receiver actually issued.
//
// Thread-safety: Seal() calls (send side) and Open() calls (receive side)
// may run concurrently with each other, each side serialised by its owner.
// They touch disjoint state except the poison flag and the request-id
// high-water mark, which are atomic. SwitchSendKey needs the send lock,
// SwitchReceiveKey/StageReceiveKey the receive lock; Initialize both.
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/frame.h"
#include "sockgate_common/protocol/rules.h"

#include <atomic>

namespace sg::proto {

// First sequence number after the two handshake frames of each direction.
constexpr uint64_t kFirstSessionSequence = 3;

struct SealOptions {
    bool encrypt = false;          // application-layer AEAD over the payload
    uint64_t request_id = 0;       // DATA only; 0 = none
    bool response = false;         // request_id refers to the peer's request
};

class ProtectedChannel {
public:
    explicit ProtectedChannel(Role local_role) noexcept : role_(local_role) {}
    ~ProtectedChannel();

    ProtectedChannel(const ProtectedChannel&) = delete;
    ProtectedChannel& operator=(const ProtectedChannel&) = delete;

    // Installs epoch-0 keys derived from the TLS exporter output `km`.
    Status Initialize(ByteView km, const SessionId& session_id);

    // ---- sending (under the owner's send lock) ------------------------------
    // Responses must refer to a request id the peer actually sent
    // (SG_INVALID_ARGUMENT otherwise): the peer would reject them and drop
    // the session.
    Status Seal(MessageType type, ByteView payload, const SealOptions& options, Bytes* frame_out);
    // Allocates the next request id (strictly increasing, never 0).
    uint64_t NextRequestId() noexcept;

    // ---- receiving (under the owner's receive lock) -------------------------
    // Verifies sequence, request id rules, KEY_PHASE and tag; decrypts the
    // payload in place when ENCRYPTED. On any failure the channel is poisoned.
    // `plaintext_header_out` (optional) receives F(x) = header || plaintext
    // payload, as used by the reauthentication transcript.
    Status Open(DecodedFrame* frame, Bytes* plaintext_frame_out = nullptr);

    // ---- key switching (04 §7.3) ---------------------------------------------
    // Derives epoch `epoch` keys from `km` and switches the local send key.
    Status SwitchSendKey(ByteView km, uint32_t epoch);
    // Client: the peer switched right after REAUTH_RESULT; switch receive now.
    Status SwitchReceiveKey(ByteView km, uint32_t epoch);
    // Server: keep the current receive key until the first frame of the new
    // phase arrives, then drop it for good.
    Status StageReceiveKey(ByteView km, uint32_t epoch);
    bool HasStagedReceiveKey() const noexcept { return has_staged_; }

    uint32_t send_epoch() const noexcept { return send_epoch_; }
    uint32_t receive_epoch() const noexcept { return recv_epoch_; }
    uint64_t next_send_sequence() const noexcept { return next_send_seq_; }
    uint64_t next_receive_sequence() const noexcept { return next_recv_seq_; }
    bool initialized() const noexcept { return initialized_; }
    const SessionId& session_id() const noexcept { return session_id_; }

private:
    Status DeriveForRole(ByteView km, uint32_t epoch, crypto::AeadKey* send, crypto::AeadKey* recv) const;
    Status Poison(Status s) noexcept;

    const Role role_;
    bool initialized_ = false;
    std::atomic<bool> poisoned_{false};
    SessionId session_id_{};

    crypto::AeadKey send_key_{};
    uint32_t send_epoch_ = 0;
    uint64_t next_send_seq_ = kFirstSessionSequence;
    std::atomic<uint64_t> last_request_id_{0};  // ids issued by us

    crypto::AeadKey recv_key_{};
    uint32_t recv_epoch_ = 0;
    uint64_t next_recv_seq_ = kFirstSessionSequence;
    std::atomic<uint64_t> last_peer_request_id_{0};  // read by Seal() for response validation

    bool has_staged_ = false;
    crypto::AeadKey staged_key_{};
    uint32_t staged_epoch_ = 0;
};

// KEY_PHASE flag value for an epoch.
constexpr uint16_t KeyPhaseFlag(uint32_t epoch) noexcept { return (epoch & 1u) != 0 ? kFlagKeyPhase : 0; }

}  // namespace sg::proto
