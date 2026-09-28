#include "sockgate_common/serialization/reader.h"

#include "sockgate_common/serialization/byte_order.h"

#include <cstring>

namespace sg::ser {

Status Reader::Take(size_t size, const uint8_t** out)
{
    if (failed_) return SG_PROTOCOL_ERROR;
    // pos_ <= data_.size() is an invariant, so the subtraction cannot underflow
    // and the comparison cannot overflow.
    if (size > data_.size() - pos_) {
        failed_ = true;
        return SG_PROTOCOL_ERROR;
    }
    *out = data_.data() + pos_;
    pos_ += size;
    return OkStatus();
}

Status Reader::U8(uint8_t* out)
{
    const uint8_t* p = nullptr;
    SG_TRY(Take(1, &p));
    *out = p[0];
    return OkStatus();
}

Status Reader::U16(uint16_t* out)
{
    const uint8_t* p = nullptr;
    SG_TRY(Take(2, &p));
    *out = LoadBE16(p);
    return OkStatus();
}

Status Reader::U32(uint32_t* out)
{
    const uint8_t* p = nullptr;
    SG_TRY(Take(4, &p));
    *out = LoadBE32(p);
    return OkStatus();
}

Status Reader::U64(uint64_t* out)
{
    const uint8_t* p = nullptr;
    SG_TRY(Take(8, &p));
    *out = LoadBE64(p);
    return OkStatus();
}

Status Reader::Fixed(uint8_t* out, size_t size)
{
    const uint8_t* p = nullptr;
    SG_TRY(Take(size, &p));
    if (size != 0) std::memcpy(out, p, size);
    return OkStatus();
}

Status Reader::View(size_t size, ByteView* out)
{
    const uint8_t* p = nullptr;
    SG_TRY(Take(size, &p));
    *out = ByteView(p, size);
    return OkStatus();
}

Status Reader::Vec16(size_t min, size_t max, ByteView* out)
{
    uint16_t len = 0;
    SG_TRY(U16(&len));
    if (len < min || len > max) {
        failed_ = true;
        return SG_PROTOCOL_ERROR;
    }
    return View(len, out);
}

Status Reader::ExpectEnd()
{
    if (failed_ || pos_ != data_.size()) {
        failed_ = true;
        return SG_PROTOCOL_ERROR;
    }
    return OkStatus();
}

bool IsValidProtocolString(ByteView bytes) noexcept
{
    size_t i = 0;
    const size_t n = bytes.size();
    while (i < n) {
        const uint8_t c = bytes[i];
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7F) return false;  // C0 controls, DEL
            ++i;
            continue;
        }
        uint32_t cp;
        size_t len;
        if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1Fu;
            len = 2;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0Fu;
            len = 3;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07u;
            len = 4;
        } else {
            return false;  // continuation byte or invalid lead byte
        }
        if (len > n - i) return false;
        for (size_t k = 1; k < len; ++k) {
            const uint8_t cc = bytes[i + k];
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return false;  // overlong
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        if (cp >= 0x80 && cp <= 0x9F) return false;  // C1 controls
        // Invisible, formatting and bidirectional-override characters enable
        // spoofing in logs and admin interfaces; noncharacters are never valid.
        if (cp == 0x00AD || cp == 0x061C || cp == 0x180E || cp == 0xFEFF) return false;
        if ((cp >= 0x200B && cp <= 0x200F) || (cp >= 0x2028 && cp <= 0x202E) || (cp >= 0x2060 && cp <= 0x206F)) {
            return false;
        }
        if ((cp >= 0xFFF9 && cp <= 0xFFFB) || (cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFE) == 0xFFFE) return false;
        i += len;
    }
    return true;
}

}  // namespace sg::ser
