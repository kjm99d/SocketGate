#pragma once
/**
 * @file
 * @brief Bounds-checked reader for untrusted input.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace sg::ser {

/**
 * @brief Bounds-checked, big-endian reader for untrusted input.
 *
 * Every accessor verifies the remaining length *before* touching memory and before doing any arithmetic that
 * could overflow. A failed read latches the reader into an error state so that a sequence of reads followed by a
 * single status check cannot silently continue past a truncation.
 *
 * Invariant: the read position never exceeds the input size. Once failed, every accessor returns
 * SG_PROTOCOL_ERROR without reading, Remaining() returns 0 and AtEnd() returns false. Output parameters are only
 * written on success and must not be null.
 *
 * @note The reader does not own the input: the input must outlive the reader and every view it returns. Not
 *       synchronised: use one instance from one thread at a time.
 */
class Reader {
public:
    /** @brief Starts reading at the beginning of @p data. @param[in] data Input (not copied). */
    explicit Reader(ByteView data) noexcept : data_(data) {}

    /**
     * @brief Reads one byte.
     * @param[out] out Value.
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR Truncated input, or the reader has already failed.
     */
    Status U8(uint8_t* out);
    /**
     * @brief Reads a big-endian u16.
     * @param[out] out Value.
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR Truncated input, or the reader has already failed.
     */
    Status U16(uint16_t* out);
    /**
     * @brief Reads a big-endian u32.
     * @param[out] out Value.
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR Truncated input, or the reader has already failed.
     */
    Status U32(uint32_t* out);
    /**
     * @brief Reads a big-endian u64.
     * @param[out] out Value.
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR Truncated input, or the reader has already failed.
     */
    Status U64(uint64_t* out);

    /**
     * @brief Copies exactly `size` bytes.
     * @param[out] out  Destination with room for @p size bytes.
     * @param[in]  size Number of bytes.
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR Fewer than @p size bytes remain, or the reader has already failed.
     */
    Status Fixed(uint8_t* out, size_t size);
    /**
     * @brief Copies exactly N bytes into a fixed-size array.
     * @tparam N Array size.
     * @param[out] out Destination.
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR Fewer than N bytes remain, or the reader has already failed.
     */
    template <size_t N>
    Status Fixed(std::array<uint8_t, N>* out)
    {
        return Fixed(out->data(), N);
    }

    /**
     * @brief Returns a view of the next `size` bytes (valid while the input is alive).
     * @param[in]  size Number of bytes.
     * @param[out] out  View into the input (not a copy).
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR Fewer than @p size bytes remain, or the reader has already failed.
     */
    Status View(size_t size, ByteView* out);

    /**
     * @brief u16 length prefix, then that many bytes; length must be in [min, max].
     * @param[in]  min Minimum accepted length.
     * @param[in]  max Maximum accepted length.
     * @param[out] out View of the bytes after the prefix (valid while the input is alive).
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR Truncated input, length outside [@p min, @p max] (the reader is then failed too),
     *                           or the reader has already failed.
     */
    Status Vec16(size_t min, size_t max, ByteView* out);

    /** @brief Returns the number of unread bytes. @return Unread bytes; 0 once the reader has failed. */
    size_t Remaining() const noexcept { return failed_ ? 0 : data_.size() - pos_; }
    /** @brief Returns the read position. @return Number of bytes consumed so far. */
    size_t Position() const noexcept { return pos_; }
    /**
     * @brief Returns whether all input was read.
     * @return true when every byte has been read and the reader has not failed.
     */
    bool AtEnd() const noexcept { return !failed_ && pos_ == data_.size(); }

    /**
     * @brief Fails (SG_PROTOCOL_ERROR) when unread bytes remain: trailing data is an error.
     * @retval SG_OK             All input has been consumed.
     * @retval SG_PROTOCOL_ERROR Unread bytes remain (the reader is then failed), or the reader has already failed.
     */
    Status ExpectEnd();

    /**
     * @brief Returns the latched state.
     * @retval SG_OK             No read has failed.
     * @retval SG_PROTOCOL_ERROR A read has failed.
     */
    Status status() const noexcept { return failed_ ? Status(SG_PROTOCOL_ERROR) : OkStatus(); }

private:
    /**
     * @brief Consumes @p size bytes after checking that they remain.
     * @param[in]  size Number of bytes.
     * @param[out] out  Pointer to the first consumed byte.
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR Fewer than @p size bytes remain (the reader is then failed), or the reader has
     *                           already failed.
     */
    Status Take(size_t size, const uint8_t** out);

    ByteView data_;        ///< Input; not owned.
    size_t pos_ = 0;       ///< Read position; never exceeds data_.size().
    bool failed_ = false;  ///< Latched error state.
};

/**
 * @brief Strict UTF-8 validation for protocol strings.
 *
 * Rejects overlong encodings, surrogates, code points above U+10FFFF and all C0/C1 control characters (and DEL).
 * It also rejects noncharacters and invisible, formatting and bidirectional-override characters, which enable
 * spoofing in logs and admin interfaces: U+00AD, U+061C, U+180E, U+200B..U+200F, U+2028..U+202E,
 * U+2060..U+206F, U+FEFF, U+FFF9..U+FFFB, U+FDD0..U+FDEF and every code point ending in FFFE or FFFF.
 *
 * @param[in] bytes Candidate string (no terminator; an empty string is valid).
 * @return true when @p bytes is an acceptable protocol string.
 */
bool IsValidProtocolString(ByteView bytes) noexcept;

}  // namespace sg::ser
