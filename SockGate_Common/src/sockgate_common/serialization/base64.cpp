#include "sockgate_common/serialization/base64.h"

namespace sg::ser {
namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int DecodeChar(char c) noexcept
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

}  // namespace

std::string Base64UrlEncode(ByteView data)
{
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8) | data[i + 2];
        out.push_back(kAlphabet[(v >> 18) & 63]);
        out.push_back(kAlphabet[(v >> 12) & 63]);
        out.push_back(kAlphabet[(v >> 6) & 63]);
        out.push_back(kAlphabet[v & 63]);
    }
    const size_t rest = data.size() - i;
    if (rest == 1) {
        const uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(kAlphabet[(v >> 18) & 63]);
        out.push_back(kAlphabet[(v >> 12) & 63]);
    } else if (rest == 2) {
        const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(kAlphabet[(v >> 18) & 63]);
        out.push_back(kAlphabet[(v >> 12) & 63]);
        out.push_back(kAlphabet[(v >> 6) & 63]);
    }
    return out;
}

Status Base64UrlDecode(const std::string& text, SecureBytes* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    if (text.size() % 4 == 1) return SG_INVALID_ARGUMENT;  // impossible length
    uint32_t acc = 0;
    struct Wipe {
        uint32_t* p;
        ~Wipe() { SecureZero(p, sizeof(*p)); }
    } wipe{&acc};
    int bits = 0;
    for (char c : text) {
        const int v = DecodeChar(c);
        if (v < 0) return SG_INVALID_ARGUMENT;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out->push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    // Leftover bits must be zero (canonical encoding).
    if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) return SG_INVALID_ARGUMENT;
    return OkStatus();
}

}  // namespace sg::ser
