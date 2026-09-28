#include "sockgate_common/serialization/writer.h"

#include "sockgate_common/serialization/byte_order.h"

namespace sg::ser {

void Writer::U8(uint8_t v) { out_->push_back(v); }

void Writer::U16(uint16_t v)
{
    uint8_t b[2];
    StoreBE16(b, v);
    out_->insert(out_->end(), b, b + 2);
}

void Writer::U32(uint32_t v)
{
    uint8_t b[4];
    StoreBE32(b, v);
    out_->insert(out_->end(), b, b + 4);
}

void Writer::U64(uint64_t v)
{
    uint8_t b[8];
    StoreBE64(b, v);
    out_->insert(out_->end(), b, b + 8);
}

void Writer::Raw(ByteView bytes) { out_->insert(out_->end(), bytes.begin(), bytes.end()); }

Status Writer::Vec16(ByteView bytes, size_t max)
{
    if (bytes.size() > 0xFFFF || bytes.size() > max) return SG_INVALID_ARGUMENT;
    U16(static_cast<uint16_t>(bytes.size()));
    Raw(bytes);
    return OkStatus();
}

void TlvWriter::Add(uint16_t type, ByteView value)
{
    if (value.size() > 0xFFFF) {
        overflow_ = true;
        return;
    }
    Writer w(&body_);
    w.U16(type);
    w.U16(static_cast<uint16_t>(value.size()));
    w.Raw(value);
    ++count_;
}

void TlvWriter::AddU64(uint16_t type, uint64_t value)
{
    Bytes v;
    Writer(&v).U64(value);
    Add(type, v);
}

void TlvWriter::AddString(uint16_t type, const std::string& value) { Add(type, AsBytes(value)); }

Status TlvWriter::Finish(Writer& out) const
{
    if (overflow_ || body_.size() > 0xFFFF) return SG_INVALID_ARGUMENT;
    out.U16(static_cast<uint16_t>(body_.size()));
    out.Raw(body_);
    return OkStatus();
}

ByteView AsBytes(const std::string& s) noexcept
{
    return ByteView(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

}  // namespace sg::ser
