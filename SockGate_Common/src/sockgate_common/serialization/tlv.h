// Strict parser for TLV extension sections (see PROTOCOL.md §4):
//   u16 total_length, then {u16 type, u16 length, value} repeated.
// Rules: total_length must match exactly, at most kMaxTlvCount entries,
// no duplicate types. Unknown types are retained (callers ignore them) but
// still length-validated.
#pragma once

#include "sockgate_common/serialization/reader.h"

#include <vector>

namespace sg::ser {

constexpr size_t kMaxTlvCount = 16;

struct TlvEntry {
    uint16_t type = 0;
    ByteView value;
};

class TlvSection {
public:
    // Reads the section from `reader` (u16 total length + entries).
    Status Parse(Reader& reader);

    const TlvEntry* Find(uint16_t type) const noexcept;
    const std::vector<TlvEntry>& entries() const noexcept { return entries_; }

private:
    std::vector<TlvEntry> entries_;
};

}  // namespace sg::ser
