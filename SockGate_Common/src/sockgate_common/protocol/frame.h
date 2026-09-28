#pragma once
/**
 * @file
 * @brief Frame header codec and streaming frame decoder.
 *
 * Wire layout of the 48-byte header (big endian): magic(4) | version(1) | type(1) | flags(2) |
 * session_id(16) | sequence(8) | request_id(8) | payload_length(4) | auth_length(2) | reserved(2),
 * followed by `payload[payload_length]` and `auth_data[auth_length]`.
 *
 * The decoder never buffers a frame body before the header has been fully
 * validated by both the structural checks (magic, version, type, flags,
 * reserved, auth length) and the caller's state-dependent check (allowed
 * type for the current state, payload limit). Oversized frames are therefore
 * rejected after at most 48 bytes.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/protocol/constants.h"

#include <functional>

namespace sg::proto {

/** @brief Decoded (or to-be-encoded) 48-byte frame header. */
struct FrameHeader {
    uint8_t version = kWireVersion;      ///< Wire layout version; must be kWireVersion.
    MessageType type = MessageType::kClose;  ///< Message type.
    uint16_t flags = 0;                  ///< kFlagEncrypted / kFlagResponse / kFlagKeyPhase; other bits reserved.
    SessionId session_id{};              ///< Session id; all zero before the server assigns one.
    uint64_t sequence = 0;               ///< Per-direction frame number: first frame 1, then exactly +1.
    uint64_t request_id = 0;             ///< 0 = none; DATA only after authentication.
    uint32_t payload_length = 0;         ///< Payload size in bytes (<= kAbsoluteMaxPayload).
    uint16_t auth_length = 0;            ///< Authentication tag size in bytes: 0 or kAuthTagSize.
};

/**
 * @brief Serialises @p header into its 48-byte wire form.
 *
 * Writes kMagic and a zero reserved field; performs no validation (see EncodeFrame()).
 *
 * @param[in]  header Header fields to encode.
 * @param[out] out    Destination of exactly kHeaderSize bytes.
 */
void EncodeHeader(const FrameHeader& header, uint8_t out[kHeaderSize]) noexcept;

/**
 * @brief Parses and structurally validates a frame header.
 *
 * Structural validation only (no state): magic, version, known type, reserved flag bits, auth_length in
 * {0, kAuthTagSize}, reserved field == 0, payload_length <= kAbsoluteMaxPayload.
 *
 * @param[in]  in  Input; must hold at least kHeaderSize bytes (only the first kHeaderSize are read).
 * @param[out] out Receives the decoded header on success.
 * @retval OK                  Header is structurally valid.
 * @retval SG_VERSION_MISMATCH `version` is not kWireVersion.
 * @retval SG_PROTOCOL_ERROR   Any other violation, fewer than kHeaderSize bytes, or @p out is nullptr.
 */
Status DecodeHeader(ByteView in, FrameHeader* out);

/** @brief Upper bound in bytes for buffered-but-unparsed input (one maximal frame plus 256 KiB slack). */
constexpr size_t kMaxDecoderBuffer = kHeaderSize + kAbsoluteMaxPayload + kAuthTagSize + 256 * 1024;
/**
 * @brief Buffer bound in bytes (16 KiB) before authentication.
 *
 * A well-behaved peer sends a single handshake frame and waits, so a few KiB of slack is plenty.
 */
constexpr size_t kPreAuthDecoderBuffer = 16 * 1024;

/**
 * @brief A complete frame as received: the exact wire bytes plus views into them.
 *
 * The storage is wiped on destruction (it may hold decrypted plaintext). The views returned by the accessors
 * are valid while this object is alive and not overwritten by FrameDecoder::Next().
 */
class DecodedFrame {
public:
    /** @brief Decoded header. @return Header validated by DecodeHeader() and the decoder's header check. */
    const FrameHeader& header() const noexcept { return header_; }
    /** @brief Whole frame. @return View of the header, payload and tag. */
    ByteView wire() const noexcept { return ByteView(wire_); }
    /** @brief Header bytes. @return View of the 48 header bytes as received. */
    ByteView header_bytes() const noexcept { return ByteView(wire_).Sub(0, kHeaderSize); }
    /** @brief Payload bytes. @return View of the payload (plaintext after an in-place decryption). */
    ByteView payload() const noexcept { return ByteView(wire_).Sub(kHeaderSize, header_.payload_length); }
    /** @brief Authentication tag bytes. @return View of the tag (empty when auth_length is 0). */
    ByteView auth_tag() const noexcept
    {
        return ByteView(wire_).Sub(kHeaderSize + header_.payload_length, header_.auth_length);
    }

    /**
     * @brief Writable pointer to the payload, used to replace it in place (after decryption).
     *
     * The size must match: exactly `header().payload_length` bytes may be written.
     * @return Pointer to the first payload byte.
     */
    uint8_t* mutable_payload() noexcept { return wire_.data() + kHeaderSize; }

private:
    friend class FrameDecoder;  ///< Fills header_ and wire_.
    FrameHeader header_;  ///< Decoded header.
    SecureBytes wire_;    ///< Exact wire bytes; wiped on deallocation.
};

/**
 * @brief Streaming frame decoder: splits a byte stream into validated frames.
 *
 * Every header passes DecodeHeader() and then the caller's HeaderCheck as soon as its 48 bytes are
 * available, before the decoder waits for the body; unparsed input is capped by SetMaxBuffered(). Any error
 * is terminal: the decoder latches it, wipes its buffer and returns the same status from every later
 * Append() / Next().
 *
 * @note Not thread-safe; the owner serialises all calls.
 */
class FrameDecoder {
public:
    /**
     * @brief State-dependent header check, invoked for every header before its body is buffered.
     *
     * Must return OK to continue; any other status is terminal for the decoder. A decoder
     * without a check fails closed (every call returns SG_INVALID_ARGUMENT).
     */
    using HeaderCheck = std::function<Status(const FrameHeader&)>;

    /**
     * @brief Creates a decoder with the given header check.
     * @param[in] check State-dependent check (typically wrapping CheckHeaderForState()); moved in.
     *                  An empty check puts the decoder into the failed state (SG_INVALID_ARGUMENT).
     */
    explicit FrameDecoder(HeaderCheck check);

    /**
     * @brief Caps the amount of buffered, unparsed input.
     *
     * Clamped to kMaxDecoderBuffer. Sessions lower it before authentication (kPreAuthDecoderBuffer).
     *
     * @param[in] max_bytes New bound in bytes.
     */
    void SetMaxBuffered(size_t max_bytes) noexcept;

    /**
     * @brief Appends received bytes.
     *
     * Fails if the decoder already failed or the amount of buffered, unparsed data would exceed the bound
     * set by SetMaxBuffered() (at most kMaxDecoderBuffer, the absolute bound).
     *
     * @param[in] data Received bytes (copied).
     * @retval OK                Bytes buffered (or @p data was empty).
     * @retval SG_PROTOCOL_ERROR Buffer bound exceeded; the decoder is now failed.
     * @return The latched failure status if the decoder had already failed.
     */
    Status Append(ByteView data);

    /**
     * @brief Extracts the next complete frame.
     *
     * OK with *ready = false means "need more data". Any error is terminal: the connection must be closed.
     *
     * @param[out] out   Receives the frame when *ready is set to true (previous contents are replaced).
     * @param[out] ready Set to true when a frame was extracted, false otherwise.
     * @retval OK                  A frame was extracted, or more data is needed (*ready false).
     * @retval SG_INVALID_ARGUMENT @p out or @p ready is nullptr (not latched), or the decoder has no header check.
     * @retval SG_PROTOCOL_ERROR   Structural header error (DecodeHeader()).
     * @retval SG_VERSION_MISMATCH Unsupported wire version (DecodeHeader()).
     * @return Any other status returned by the header check, or the latched failure status.
     */
    Status Next(DecodedFrame* out, bool* ready);

    /** @brief Unparsed input size. @return Buffered bytes not yet returned as part of a frame. */
    size_t Buffered() const noexcept { return buffer_.size() - consumed_; }
    /** @brief Failure state. @return True once the decoder has latched a terminal error. */
    bool failed() const noexcept { return !failure_.ok(); }

private:
    /**
     * @brief Latches @p s, wipes and drops the buffer, and returns @p s.
     * @param[in] s Terminal error.
     * @return @p s.
     */
    Status Fail(Status s);

    HeaderCheck check_;                        ///< State-dependent header check.
    SecureBytes buffer_;                       ///< Received bytes; the first consumed_ are already parsed.
    size_t consumed_ = 0;                      ///< Bytes of buffer_ already returned in frames.
    size_t max_buffered_ = kMaxDecoderBuffer;  ///< Current bound on unparsed bytes.
    bool have_header_ = false;                 ///< pending_ holds a validated header whose body is incomplete.
    FrameHeader pending_;                      ///< Header of the frame being assembled.
    Status failure_ = OkStatus();              ///< Latched terminal error (OK while healthy).
};

/**
 * @brief Serialises a frame: header (with payload/auth lengths filled in) + payload + tag.
 *
 * The header's payload_length and auth_length are overwritten from @p payload and @p auth_tag. The encoded
 * header is re-checked with DecodeHeader(), so a header our own decoder would reject is never emitted.
 *
 * @param[in]     header   Header fields (taken by value).
 * @param[in]     payload  Payload bytes; at most kAbsoluteMaxPayload.
 * @param[in]     auth_tag Tag bytes; empty or exactly kAuthTagSize.
 * @param[in,out] out      The frame is appended; left unchanged on failure.
 * @retval OK                  Frame appended.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, a size is out of range, or the header fails DecodeHeader().
 */
Status EncodeFrame(FrameHeader header, ByteView payload, ByteView auth_tag, Bytes* out);

}  // namespace sg::proto
