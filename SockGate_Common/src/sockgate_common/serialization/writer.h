// Serializer used by every SockGate encoder (big-endian, append-only).
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <array>
#include <cstdint>
#include <string>

namespace sg::ser {

class Writer {
public:
    explicit Writer(Bytes* out) noexcept : out_(out) {}

    void U8(uint8_t v);
    void U16(uint16_t v);
    void U32(uint32_t v);
    void U64(uint64_t v);
    void Raw(ByteView bytes);
    template <size_t N>
    void Raw(const std::array<uint8_t, N>& a)
    {
        Raw(ByteView(a.data(), N));
    }

    // u16 length prefix + bytes. Fails if the length does not fit or exceeds max.
    Status Vec16(ByteView bytes, size_t max = 0xFFFF);

    size_t Size() const noexcept { return out_->size(); }

private:
    Bytes* out_;
};

// Builds a TLV extension section: u16 total_length, then {u16 type, u16 len, value}*.
class TlvWriter {
public:
    void Add(uint16_t type, ByteView value);
    void AddU64(uint16_t type, uint64_t value);
    void AddString(uint16_t type, const std::string& value);
    // Appends the section (with its total length) to `out`.
    Status Finish(Writer& out) const;

private:
    Bytes body_;
    size_t count_ = 0;
    bool overflow_ = false;
};

ByteView AsBytes(const std::string& s) noexcept;

}  // namespace sg::ser
