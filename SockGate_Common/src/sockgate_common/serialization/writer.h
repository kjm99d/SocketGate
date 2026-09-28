#pragma once
/**
 * @file
 * @brief Serializer used by every SockGate encoder (big-endian, append-only).
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <array>
#include <cstdint>
#include <string>

namespace sg::ser {

/**
 * @brief Big-endian, append-only serializer into a caller-owned byte vector.
 *
 * @note The output is an ordinary Bytes (not wiped on release). The vector must outlive the writer. Not
 *       synchronised: use one instance from one thread at a time.
 */
class Writer {
public:
    /** @brief Appends to @p out. @param[in,out] out Output vector (not owned, not cleared). */
    explicit Writer(Bytes* out) noexcept : out_(out) {}

    /** @brief Appends one byte. @param[in] v Value. */
    void U8(uint8_t v);
    /** @brief Appends a big-endian u16. @param[in] v Value. */
    void U16(uint16_t v);
    /** @brief Appends a big-endian u32. @param[in] v Value. */
    void U32(uint32_t v);
    /** @brief Appends a big-endian u64. @param[in] v Value. */
    void U64(uint64_t v);
    /** @brief Appends bytes without a length prefix. @param[in] bytes Bytes to append. */
    void Raw(ByteView bytes);
    /** @brief Appends a fixed-size array without a length prefix. @tparam N Array size. @param[in] a Array. */
    template <size_t N>
    void Raw(const std::array<uint8_t, N>& a)
    {
        Raw(ByteView(a.data(), N));
    }

    /**
     * @brief u16 length prefix + bytes. Fails if the length does not fit or exceeds max.
     * @param[in] bytes Bytes to append.
     * @param[in] max   Maximum accepted length (default 0xFFFF).
     * @retval SG_OK               Success.
     * @retval SG_INVALID_ARGUMENT @p bytes is longer than 0xFFFF or @p max; nothing is appended.
     */
    Status Vec16(ByteView bytes, size_t max = 0xFFFF);

    /**
     * @brief Returns the output size.
     * @return Size of the output vector, including bytes it held before this writer.
     */
    size_t Size() const noexcept { return out_->size(); }

private:
    Bytes* out_;  ///< Output vector; not owned.
};

/**
 * @brief Builds a TLV extension section: u16 total_length, then {u16 type, u16 len, value}*.
 *
 * Entries are written in the order added. Size errors are recorded and reported by Finish().
 *
 * @note Unlike TlvSection::Parse(), the builder does not check for duplicate types or the #kMaxTlvCount limit.
 */
class TlvWriter {
public:
    /**
     * @brief Adds an entry. A value longer than 0xFFFF bytes is dropped and makes Finish() fail.
     * @param[in] type  Entry type.
     * @param[in] value Entry value (copied).
     */
    void Add(uint16_t type, ByteView value);
    /**
     * @brief Adds an entry whose value is @p value as 8 big-endian bytes.
     * @param[in] type  Entry type.
     * @param[in] value Value.
     */
    void AddU64(uint16_t type, uint64_t value);
    /**
     * @brief Adds an entry whose value is the bytes of @p value (no terminator).
     * @param[in] type  Entry type.
     * @param[in] value String (copied).
     */
    void AddString(uint16_t type, const std::string& value);
    /**
     * @brief Appends the section (with its total length) to `out`.
     * @param[in,out] out Writer to append to.
     * @retval SG_OK               Success.
     * @retval SG_INVALID_ARGUMENT An added value was longer than 0xFFFF bytes or the section body exceeds
     *                             0xFFFF bytes; nothing is appended.
     */
    Status Finish(Writer& out) const;

private:
    Bytes body_;             ///< Encoded entries.
    size_t count_ = 0;       ///< Number of entries added.
    bool overflow_ = false;  ///< Set when a value was too long; makes Finish() fail.
};

/**
 * @brief Views the bytes of a string (no terminator).
 * @param[in] s String; must outlive the view and stay unmodified.
 * @return View of `s.data()`, `s.size()`.
 */
ByteView AsBytes(const std::string& s) noexcept;
/**
 * @brief Views a NUL-terminated literal (no temporary std::string involved).
 * @param[in] s NUL-terminated string, or null.
 * @return View of the characters before the NUL (terminator excluded); an empty view for null.
 */
ByteView AsBytes(const char* s) noexcept;

}  // namespace sg::ser
