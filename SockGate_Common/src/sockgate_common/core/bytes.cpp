#include "sockgate_common/core/bytes.h"

#include <openssl/crypto.h>

namespace sg {

void SecureZero(void* data, size_t size) noexcept
{
    if (data != nullptr && size != 0) OPENSSL_cleanse(data, size);
}

bool ConstantTimeEqual(const void* a, size_t a_size, const void* b, size_t b_size) noexcept
{
    if (a_size != b_size) return false;
    if (a_size == 0) return true;
    return CRYPTO_memcmp(a, b, a_size) == 0;
}

std::string ToHex(ByteView bytes)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

std::string ShortId(ByteView bytes)
{
    return ToHex(bytes.Sub(0, bytes.size() < 8 ? bytes.size() : 8));
}

}  // namespace sg
