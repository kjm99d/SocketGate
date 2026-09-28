// Frame header codec and streaming frame decoder.
//
// The decoder never buffers a frame body before the header has been fully
// validated by both the structural checks (magic, version, type, flags,
// reserved, auth length) and the caller's state-dependent check (allowed
// type for the current state, payload limit). Oversized frames are therefore
// rejected after at most 48 bytes.
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/protocol/constants.h"

#include <functional>

namespace sg::proto {

struct FrameHeader {
    uint8_t version = kWireVersion;
    MessageType type = MessageType::kClose;
    uint16_t flags = 0;
    SessionId session_id{};
    uint64_t sequence = 0;
    uint64_t request_id = 0;
    uint32_t payload_length = 0;
    uint16_t auth_length = 0;
};

void EncodeHeader(const FrameHeader& header, uint8_t out[kHeaderSize]) noexcept;

// Structural validation only (no state). Returns SG_PROTOCOL_ERROR or
// SG_VERSION_MISMATCH. `in` must hold at least kHeaderSize bytes.
Status DecodeHeader(ByteView in, FrameHeader* out);

// Upper bound for buffered-but-unparsed input (one maximal frame plus slack).
constexpr size_t kMaxDecoderBuffer = kHeaderSize + kAbsoluteMaxPayload + kAuthTagSize + 256 * 1024;
// Buffer bound before authentication: a well-behaved peer sends a single
// handshake frame and waits, so a few KiB of slack is plenty.
constexpr size_t kPreAuthDecoderBuffer = 16 * 1024;

// A complete frame as received: the exact wire bytes plus views into them.
// The storage is wiped on destruction (it may hold decrypted plaintext).
class DecodedFrame {
public:
    const FrameHeader& header() const noexcept { return header_; }
    ByteView wire() const noexcept { return ByteView(wire_); }
    ByteView header_bytes() const noexcept { return ByteView(wire_).Sub(0, kHeaderSize); }
    ByteView payload() const noexcept { return ByteView(wire_).Sub(kHeaderSize, header_.payload_length); }
    ByteView auth_tag() const noexcept
    {
        return ByteView(wire_).Sub(kHeaderSize + header_.payload_length, header_.auth_length);
    }

    // Replaces the payload in place (after decryption); size must match.
    uint8_t* mutable_payload() noexcept { return wire_.data() + kHeaderSize; }

private:
    friend class FrameDecoder;
    FrameHeader header_;
    SecureBytes wire_;
};

class FrameDecoder {
public:
    // Invoked for every header before its body is buffered. Must return OK to
    // continue; any other status is terminal for the decoder. A decoder
    // without a check fails closed (every call returns SG_INVALID_ARGUMENT).
    using HeaderCheck = std::function<Status(const FrameHeader&)>;

    explicit FrameDecoder(HeaderCheck check);

    // Caps the amount of buffered, unparsed input (clamped to
    // kMaxDecoderBuffer). Sessions lower it before authentication.
    void SetMaxBuffered(size_t max_bytes) noexcept;

    // Appends received bytes. Fails if the decoder already failed or the
    // amount of buffered, unparsed data exceeds the absolute bound.
    Status Append(ByteView data);

    // Extracts the next complete frame. OK with *ready = false means "need
    // more data". Any error is terminal: the connection must be closed.
    Status Next(DecodedFrame* out, bool* ready);

    size_t Buffered() const noexcept { return buffer_.size() - consumed_; }
    bool failed() const noexcept { return !failure_.ok(); }

private:
    Status Fail(Status s);

    HeaderCheck check_;
    SecureBytes buffer_;
    size_t consumed_ = 0;
    size_t max_buffered_ = kMaxDecoderBuffer;
    bool have_header_ = false;
    FrameHeader pending_;
    Status failure_ = OkStatus();
};

// Serialises a frame: header (with payload/auth lengths filled in) + payload + tag.
Status EncodeFrame(FrameHeader header, ByteView payload, ByteView auth_tag, Bytes* out);

}  // namespace sg::proto
