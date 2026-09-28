// Bounds-checked reader for untrusted input.
//
// Every accessor verifies the remaining length *before* touching memory and
// before doing any arithmetic that could overflow. A failed read latches the
// reader into an error state so that a sequence of reads followed by a
// single status check cannot silently continue past a truncation.
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace sg::ser {

class Reader {
public:
    explicit Reader(ByteView data) noexcept : data_(data) {}

    Status U8(uint8_t* out);
    Status U16(uint16_t* out);
    Status U32(uint32_t* out);
    Status U64(uint64_t* out);

    // Copies exactly `size` bytes.
    Status Fixed(uint8_t* out, size_t size);
    template <size_t N>
    Status Fixed(std::array<uint8_t, N>* out)
    {
        return Fixed(out->data(), N);
    }

    // Returns a view of the next `size` bytes (valid while the input is alive).
    Status View(size_t size, ByteView* out);

    // u16 length prefix, then that many bytes; length must be in [min, max].
    Status Vec16(size_t min, size_t max, ByteView* out);

    size_t Remaining() const noexcept { return failed_ ? 0 : data_.size() - pos_; }
    size_t Position() const noexcept { return pos_; }
    bool AtEnd() const noexcept { return !failed_ && pos_ == data_.size(); }

    // Fails (SG_PROTOCOL_ERROR) when unread bytes remain: trailing data is an error.
    Status ExpectEnd();

    Status status() const noexcept { return failed_ ? Status(SG_PROTOCOL_ERROR) : OkStatus(); }

private:
    Status Take(size_t size, const uint8_t** out);

    ByteView data_;
    size_t pos_ = 0;
    bool failed_ = false;
};

// Strict UTF-8 validation for protocol strings: rejects overlong encodings,
// surrogates, code points above U+10FFFF and all C0/C1 control characters.
bool IsValidProtocolString(ByteView bytes) noexcept;

}  // namespace sg::ser
