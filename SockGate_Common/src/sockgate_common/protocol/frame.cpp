#include "sockgate_common/protocol/frame.h"

#include "sockgate_common/serialization/byte_order.h"

#include <cstring>

namespace sg::proto {
namespace {

// Upper bound for buffered-but-unparsed input: one maximal frame plus slack
// for a partially received following frame.
constexpr size_t kMaxBuffered = kHeaderSize + kAbsoluteMaxPayload + kAuthTagSize + 256 * 1024;

}  // namespace

bool IsKnownMessageType(uint8_t value) noexcept
{
    switch (static_cast<MessageType>(value)) {
    case MessageType::kClientHello:
    case MessageType::kServerHello:
    case MessageType::kClientProof:
    case MessageType::kAuthResult:
    case MessageType::kData:
    case MessageType::kPing:
    case MessageType::kPong:
    case MessageType::kReauthRequest:
    case MessageType::kReauthChallenge:
    case MessageType::kReauthProof:
    case MessageType::kReauthResult:
    case MessageType::kClose:
        return true;
    }
    return false;
}

const char* MessageTypeName(MessageType type) noexcept
{
    switch (type) {
    case MessageType::kClientHello: return "CLIENT_HELLO";
    case MessageType::kServerHello: return "SERVER_HELLO";
    case MessageType::kClientProof: return "CLIENT_PROOF";
    case MessageType::kAuthResult: return "AUTH_RESULT";
    case MessageType::kData: return "DATA";
    case MessageType::kPing: return "PING";
    case MessageType::kPong: return "PONG";
    case MessageType::kReauthRequest: return "REAUTH_REQUEST";
    case MessageType::kReauthChallenge: return "REAUTH_CHALLENGE";
    case MessageType::kReauthProof: return "REAUTH_PROOF";
    case MessageType::kReauthResult: return "REAUTH_RESULT";
    case MessageType::kClose: return "CLOSE";
    }
    return "UNKNOWN";
}

void EncodeHeader(const FrameHeader& h, uint8_t out[kHeaderSize]) noexcept
{
    ser::StoreBE32(out + 0, kMagic);
    out[4] = h.version;
    out[5] = static_cast<uint8_t>(h.type);
    ser::StoreBE16(out + 6, h.flags);
    std::memcpy(out + 8, h.session_id.data(), kSessionIdSize);
    ser::StoreBE64(out + 24, h.sequence);
    ser::StoreBE64(out + 32, h.request_id);
    ser::StoreBE32(out + 40, h.payload_length);
    ser::StoreBE16(out + 44, h.auth_length);
    ser::StoreBE16(out + 46, 0);  // reserved
}

Status DecodeHeader(ByteView in, FrameHeader* out)
{
    if (out == nullptr || in.size() < kHeaderSize) return SG_PROTOCOL_ERROR;
    const uint8_t* p = in.data();
    if (ser::LoadBE32(p) != kMagic) return SG_PROTOCOL_ERROR;
    if (p[4] != kWireVersion) return SG_VERSION_MISMATCH;
    if (!IsKnownMessageType(p[5])) return SG_PROTOCOL_ERROR;
    const uint16_t flags = ser::LoadBE16(p + 6);
    if ((flags & ~kKnownFlags) != 0) return SG_PROTOCOL_ERROR;
    const uint16_t auth_length = ser::LoadBE16(p + 44);
    if (auth_length != 0 && auth_length != kAuthTagSize) return SG_PROTOCOL_ERROR;
    if (ser::LoadBE16(p + 46) != 0) return SG_PROTOCOL_ERROR;
    const uint32_t payload_length = ser::LoadBE32(p + 40);
    if (payload_length > kAbsoluteMaxPayload) return SG_PROTOCOL_ERROR;

    out->version = p[4];
    out->type = static_cast<MessageType>(p[5]);
    out->flags = flags;
    std::memcpy(out->session_id.data(), p + 8, kSessionIdSize);
    out->sequence = ser::LoadBE64(p + 24);
    out->request_id = ser::LoadBE64(p + 32);
    out->payload_length = payload_length;
    out->auth_length = auth_length;
    return OkStatus();
}

FrameDecoder::FrameDecoder(HeaderCheck check) : check_(std::move(check)) {}

Status FrameDecoder::Fail(Status s)
{
    failure_ = s;
    // Drop buffered (possibly sensitive) data immediately.
    SecureZero(buffer_.data(), buffer_.size());
    buffer_.clear();
    consumed_ = 0;
    return s;
}

Status FrameDecoder::Append(ByteView data)
{
    if (!failure_.ok()) return failure_;
    if (data.empty()) return OkStatus();
    // Compact before growing so a long-lived connection does not accumulate
    // already-parsed bytes.
    if (consumed_ > 0 && consumed_ == buffer_.size()) {
        buffer_.clear();
        consumed_ = 0;
    } else if (consumed_ > 64 * 1024) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(consumed_));
        consumed_ = 0;
    }
    if (data.size() > kMaxBuffered || Buffered() > kMaxBuffered - data.size()) return Fail(SG_PROTOCOL_ERROR);
    buffer_.insert(buffer_.end(), data.begin(), data.end());
    return OkStatus();
}

Status FrameDecoder::Next(DecodedFrame* out, bool* ready)
{
    if (out == nullptr || ready == nullptr) return SG_INVALID_ARGUMENT;
    *ready = false;
    if (!failure_.ok()) return failure_;

    const size_t available = Buffered();
    if (!have_header_) {
        if (available < kHeaderSize) return OkStatus();  // truncated: wait for more
        const ByteView header_bytes(buffer_.data() + consumed_, kHeaderSize);
        Status st = DecodeHeader(header_bytes, &pending_);
        if (!st.ok()) return Fail(st);
        // State-dependent validation happens before any body byte is buffered
        // on behalf of this frame.
        if (check_) {
            st = check_(pending_);
            if (!st.ok()) return Fail(st);
        }
        have_header_ = true;
    }

    // payload_length <= kAbsoluteMaxPayload was enforced, so this sum cannot overflow.
    const size_t total = kHeaderSize + static_cast<size_t>(pending_.payload_length) + pending_.auth_length;
    if (available < total) return OkStatus();

    out->header_ = pending_;
    out->wire_.assign(buffer_.begin() + static_cast<std::ptrdiff_t>(consumed_),
                      buffer_.begin() + static_cast<std::ptrdiff_t>(consumed_ + total));
    consumed_ += total;
    have_header_ = false;
    *ready = true;
    return OkStatus();
}

Status EncodeFrame(FrameHeader header, ByteView payload, ByteView auth_tag, Bytes* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    if (payload.size() > kAbsoluteMaxPayload) return SG_INVALID_ARGUMENT;
    if (auth_tag.size() != 0 && auth_tag.size() != kAuthTagSize) return SG_INVALID_ARGUMENT;
    header.payload_length = static_cast<uint32_t>(payload.size());
    header.auth_length = static_cast<uint16_t>(auth_tag.size());
    const size_t start = out->size();
    out->resize(start + kHeaderSize);
    EncodeHeader(header, out->data() + start);
    out->insert(out->end(), payload.begin(), payload.end());
    out->insert(out->end(), auth_tag.begin(), auth_tag.end());
    return OkStatus();
}

}  // namespace sg::proto
