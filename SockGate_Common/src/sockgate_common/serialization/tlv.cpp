#include "sockgate_common/serialization/tlv.h"

namespace sg::ser {

Status TlvSection::Parse(Reader& reader)
{
    entries_.clear();
    uint16_t total = 0;
    SG_TRY(reader.U16(&total));
    ByteView body;
    SG_TRY(reader.View(total, &body));

    Reader r(body);
    while (!r.AtEnd()) {
        if (entries_.size() >= kMaxTlvCount) return SG_PROTOCOL_ERROR;
        TlvEntry e;
        SG_TRY(r.U16(&e.type));
        SG_TRY(r.Vec16(0, 0xFFFF, &e.value));
        for (const auto& existing : entries_) {
            if (existing.type == e.type) return SG_PROTOCOL_ERROR;  // duplicate
        }
        entries_.push_back(e);
    }
    return r.status();
}

const TlvEntry* TlvSection::Find(uint16_t type) const noexcept
{
    for (const auto& e : entries_) {
        if (e.type == type) return &e;
    }
    return nullptr;
}

}  // namespace sg::ser
