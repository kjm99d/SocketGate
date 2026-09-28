#include "sockgate_common/protocol/channel.h"

#include "sockgate_common/protocol/transcript.h"
#include "sockgate_common/serialization/byte_order.h"

#include <cstring>
#include <limits>

namespace sg::proto {
namespace {

crypto::AeadNonce NonceFor(uint64_t sequence)
{
    crypto::AeadNonce nonce{};  // u32(0) || u64(sequence)
    ser::StoreBE64(nonce.data() + 4, sequence);
    return nonce;
}

}  // namespace

ProtectedChannel::~ProtectedChannel()
{
    SecureZero(send_key_.data(), send_key_.size());
    SecureZero(recv_key_.data(), recv_key_.size());
    SecureZero(staged_key_.data(), staged_key_.size());
}

// Called on the receive side only: it destroys receive-side keys and makes
// every later Seal()/Open() fail. The send key is left to the destructor
// because a concurrent Seal() on the send thread may still be reading it.
Status ProtectedChannel::Poison(Status s) noexcept
{
    poisoned_.store(true);
    SecureZero(recv_key_.data(), recv_key_.size());
    SecureZero(staged_key_.data(), staged_key_.size());
    has_staged_ = false;
    return s;
}

Status ProtectedChannel::DeriveForRole(ByteView km, uint32_t epoch, crypto::AeadKey* send, crypto::AeadKey* recv) const
{
    crypto::AeadKey c2s, s2c;
    SG_TRY(DeriveChannelKeys(km, session_id_, epoch, &c2s, &s2c));
    if (role_ == Role::kClient) {
        *send = c2s;
        *recv = s2c;
    } else {
        *send = s2c;
        *recv = c2s;
    }
    SecureZero(c2s.data(), c2s.size());
    SecureZero(s2c.data(), s2c.size());
    return OkStatus();
}

Status ProtectedChannel::Initialize(ByteView km, const SessionId& session_id)
{
    if (initialized_) return SG_INVALID_STATE;
    session_id_ = session_id;
    SG_TRY(DeriveForRole(km, 0, &send_key_, &recv_key_));
    initialized_ = true;
    return OkStatus();
}

uint64_t ProtectedChannel::NextRequestId() noexcept { return last_request_id_.fetch_add(1) + 1; }

Status ProtectedChannel::Seal(MessageType type, ByteView payload, const SealOptions& options, Bytes* frame_out)
{
    if (frame_out == nullptr) return SG_INVALID_ARGUMENT;
    if (!initialized_ || poisoned_) return SG_INVALID_STATE;
    if (payload.size() > kAbsoluteMaxPayload) return SG_INVALID_ARGUMENT;
    if (type != MessageType::kData && (options.request_id != 0 || options.response)) return SG_INVALID_ARGUMENT;
    if (options.response && (options.request_id == 0 || options.request_id > last_peer_request_id_.load())) {
        return SG_INVALID_ARGUMENT;
    }
    if (next_send_seq_ == std::numeric_limits<uint64_t>::max()) {
        poisoned_.store(true);
        return SG_SESSION_EXPIRED;
    }

    FrameHeader h;
    h.type = type;
    h.flags = static_cast<uint16_t>((options.encrypt ? kFlagEncrypted : 0) | (options.response ? kFlagResponse : 0) |
                                    KeyPhaseFlag(send_epoch_));
    h.session_id = session_id_;
    h.sequence = next_send_seq_;
    h.request_id = options.request_id;
    h.payload_length = static_cast<uint32_t>(payload.size());
    h.auth_length = static_cast<uint16_t>(kAuthTagSize);

    const size_t start = frame_out->size();
    frame_out->resize(start + kHeaderSize + payload.size() + kAuthTagSize);
    uint8_t* header = frame_out->data() + start;
    uint8_t* body = header + kHeaderSize;
    EncodeHeader(h, header);

    const crypto::AeadNonce nonce = NonceFor(h.sequence);
    crypto::AeadTag tag;
    Status st;
    if (options.encrypt) {
        st = crypto::AesGcmSeal(send_key_, nonce, ByteView(header, kHeaderSize), payload, body, &tag);
    } else {
        if (!payload.empty()) std::memcpy(body, payload.data(), payload.size());
        st = crypto::AesGcmSeal(send_key_, nonce, ByteView(header, kHeaderSize + payload.size()), ByteView(), nullptr,
                                &tag);
    }
    if (!st.ok()) {
        frame_out->resize(start);
        return st;
    }
    std::memcpy(body + payload.size(), tag.data(), tag.size());
    ++next_send_seq_;
    if (options.request_id != 0 && !options.response) {
        // Keep the high-water mark of requests we issued (response validation).
        uint64_t prev = last_request_id_.load();
        while (options.request_id > prev && !last_request_id_.compare_exchange_weak(prev, options.request_id)) {
        }
    }
    return OkStatus();
}

Status ProtectedChannel::Open(DecodedFrame* frame, Bytes* plaintext_frame_out)
{
    if (frame == nullptr) return SG_INVALID_ARGUMENT;
    if (!initialized_ || poisoned_) return SG_INVALID_STATE;
    const FrameHeader& h = frame->header();

    if (h.auth_length != kAuthTagSize) return Poison(SG_PROTOCOL_ERROR);
    if (h.session_id != session_id_) return Poison(SG_PROTOCOL_ERROR);

    // Sequence first (cheap): anything but exactly the next number is fatal.
    if (h.sequence != next_recv_seq_) {
        return Poison(h.sequence < next_recv_seq_ ? SG_REPLAY_DETECTED : SG_PROTOCOL_ERROR);
    }
    if (h.sequence == std::numeric_limits<uint64_t>::max()) return Poison(SG_SESSION_EXPIRED);

    // Key selection by phase.
    const uint16_t phase = static_cast<uint16_t>(h.flags & kFlagKeyPhase);
    const crypto::AeadKey* key = nullptr;
    bool promote_staged = false;
    if (phase == KeyPhaseFlag(recv_epoch_)) {
        key = &recv_key_;
    } else if (has_staged_ && phase == KeyPhaseFlag(staged_epoch_)) {
        key = &staged_key_;
        promote_staged = true;
    } else {
        return Poison(SG_PROTOCOL_ERROR);
    }

    const crypto::AeadNonce nonce = NonceFor(h.sequence);
    crypto::AeadTag tag;
    const ByteView tag_bytes = frame->auth_tag();
    std::memcpy(tag.data(), tag_bytes.data(), tag.size());
    const ByteView header_bytes = frame->header_bytes();
    const ByteView payload = frame->payload();

    Status st;
    if ((h.flags & kFlagEncrypted) != 0) {
        st = crypto::AesGcmOpen(*key, nonce, header_bytes, payload, tag, frame->mutable_payload());
    } else {
        st = crypto::AesGcmOpen(*key, nonce, ByteView(header_bytes.data(), kHeaderSize + payload.size()), ByteView(), tag,
                                nullptr);
    }
    if (!st.ok()) return Poison(SG_PROTOCOL_ERROR);  // forged or modified frame

    // Request id rules (after authenticity is established).
    if (h.request_id != 0) {
        if ((h.flags & kFlagResponse) != 0) {
            if (h.request_id > last_request_id_.load()) return Poison(SG_PROTOCOL_ERROR);
        } else {
            if (h.request_id <= last_peer_request_id_.load()) return Poison(SG_REPLAY_DETECTED);  // duplicate request
            last_peer_request_id_.store(h.request_id);
        }
    }

    if (promote_staged) {
        // First frame under the new epoch: the old key is gone for good.
        recv_key_ = staged_key_;
        recv_epoch_ = staged_epoch_;
        SecureZero(staged_key_.data(), staged_key_.size());
        has_staged_ = false;
    }
    ++next_recv_seq_;

    if (plaintext_frame_out != nullptr) {
        plaintext_frame_out->assign(header_bytes.begin(), header_bytes.end());
        const ByteView plain = frame->payload();
        plaintext_frame_out->insert(plaintext_frame_out->end(), plain.begin(), plain.end());
    }
    return OkStatus();
}

Status ProtectedChannel::SwitchSendKey(ByteView km, uint32_t epoch)
{
    if (!initialized_ || poisoned_) return SG_INVALID_STATE;
    if (epoch != send_epoch_ + 1) return SG_INVALID_ARGUMENT;
    crypto::AeadKey send, recv;
    SG_TRY(DeriveForRole(km, epoch, &send, &recv));
    send_key_ = send;
    send_epoch_ = epoch;
    SecureZero(send.data(), send.size());
    SecureZero(recv.data(), recv.size());
    return OkStatus();
}

Status ProtectedChannel::SwitchReceiveKey(ByteView km, uint32_t epoch)
{
    if (!initialized_ || poisoned_) return SG_INVALID_STATE;
    if (epoch != recv_epoch_ + 1 || has_staged_) return SG_INVALID_ARGUMENT;
    crypto::AeadKey send, recv;
    SG_TRY(DeriveForRole(km, epoch, &send, &recv));
    recv_key_ = recv;
    recv_epoch_ = epoch;
    SecureZero(send.data(), send.size());
    SecureZero(recv.data(), recv.size());
    return OkStatus();
}

Status ProtectedChannel::StageReceiveKey(ByteView km, uint32_t epoch)
{
    if (!initialized_ || poisoned_) return SG_INVALID_STATE;
    if (epoch != recv_epoch_ + 1 || has_staged_) return SG_INVALID_ARGUMENT;
    crypto::AeadKey send, recv;
    SG_TRY(DeriveForRole(km, epoch, &send, &recv));
    staged_key_ = recv;
    staged_epoch_ = epoch;
    has_staged_ = true;
    SecureZero(send.data(), send.size());
    SecureZero(recv.data(), recv.size());
    return OkStatus();
}

}  // namespace sg::proto
