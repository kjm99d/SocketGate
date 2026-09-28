#include "sockgate_common/protocol/enrollment_token.h"

#include "sockgate_common/serialization/base64.h"
#include "sockgate_common/serialization/reader.h"
#include "sockgate_common/serialization/writer.h"

namespace sg::proto {
namespace {

constexpr uint8_t kClaimsVersion = 1;
constexpr size_t kMaxTokenStringLength = 1024;

}  // namespace

Status EncodeTokenPublic(const EnrollmentClaims& claims, Bytes* token_pub)
{
    if (token_pub == nullptr || claims.product_id.empty() || claims.product_id.size() > kMaxProductIdLength ||
        claims.license_id.size() > kMaxLicenseIdLength || claims.expires_at_ms <= claims.issued_at_ms) {
        return SG_INVALID_ARGUMENT;
    }
    if (!ser::IsValidProtocolString(ser::AsBytes(claims.product_id)) ||
        !ser::IsValidProtocolString(ser::AsBytes(claims.license_id))) {
        return SG_INVALID_ARGUMENT;
    }
    ser::Writer w(token_pub);
    w.Raw(claims.token_id);
    w.U8(kClaimsVersion);
    SG_TRY(w.Vec16(ser::AsBytes(claims.product_id), kMaxProductIdLength));
    SG_TRY(w.Vec16(ser::AsBytes(claims.license_id), kMaxLicenseIdLength));
    w.U64(claims.issued_at_ms);
    w.U64(claims.expires_at_ms);
    return OkStatus();
}

Status DecodeTokenPublic(ByteView token_pub, EnrollmentClaims* claims)
{
    if (claims == nullptr || token_pub.size() > kMaxEnrollmentTokenIdLength) return SG_PROTOCOL_ERROR;
    ser::Reader r(token_pub);
    SG_TRY(r.Fixed(&claims->token_id));
    uint8_t version = 0;
    SG_TRY(r.U8(&version));
    if (version != kClaimsVersion) return SG_PROTOCOL_ERROR;
    ByteView product;
    ByteView license;
    SG_TRY(r.Vec16(1, kMaxProductIdLength, &product));
    SG_TRY(r.Vec16(0, kMaxLicenseIdLength, &license));
    SG_TRY(r.U64(&claims->issued_at_ms));
    SG_TRY(r.U64(&claims->expires_at_ms));
    SG_TRY(r.ExpectEnd());
    if (!ser::IsValidProtocolString(product) || !ser::IsValidProtocolString(license)) return SG_PROTOCOL_ERROR;
    if (claims->expires_at_ms <= claims->issued_at_ms) return SG_PROTOCOL_ERROR;
    claims->product_id.assign(reinterpret_cast<const char*>(product.data()), product.size());
    claims->license_id.assign(reinterpret_cast<const char*>(license.data()), license.size());
    return OkStatus();
}

Status DeriveEnrollmentKey(ByteView server_token_key, ByteView token_pub, crypto::Sha256Digest* k_tok)
{
    if (server_token_key.size() < 32 || k_tok == nullptr) return SG_INVALID_ARGUMENT;
    static const uint8_t kZero = 0;
    return crypto::HmacSha256(server_token_key,
                              {ser::AsBytes(kEnrollKeyContext), ByteView(&kZero, 1), token_pub}, k_tok);
}

Status BuildEnrollmentToken(ByteView server_token_key, const EnrollmentClaims& claims, std::string* token)
{
    if (token == nullptr) return SG_INVALID_ARGUMENT;
    Bytes token_pub;
    SG_TRY(EncodeTokenPublic(claims, &token_pub));
    crypto::Sha256Digest k_tok;
    SG_TRY(DeriveEnrollmentKey(server_token_key, token_pub, &k_tok));
    SecureBytes raw(token_pub.begin(), token_pub.end());
    raw.insert(raw.end(), k_tok.begin(), k_tok.end());
    *token = ser::Base64UrlEncode(ByteView(raw));
    SecureZero(k_tok.data(), k_tok.size());
    return OkStatus();
}

Status ParseEnrollmentToken(const std::string& token, Bytes* token_pub, crypto::Sha256Digest* k_tok)
{
    if (token_pub == nullptr || k_tok == nullptr || token.empty() || token.size() > kMaxTokenStringLength) {
        return SG_INVALID_ARGUMENT;
    }
    SecureBytes raw;
    SG_TRY(ser::Base64UrlDecode(token, &raw));
    if (raw.size() <= crypto::kSha256Size) return SG_INVALID_ARGUMENT;
    const size_t pub_len = raw.size() - crypto::kSha256Size;
    EnrollmentClaims claims;
    if (!DecodeTokenPublic(ByteView(raw.data(), pub_len), &claims).ok()) return SG_INVALID_ARGUMENT;
    token_pub->assign(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(pub_len));
    std::copy(raw.begin() + static_cast<std::ptrdiff_t>(pub_len), raw.end(), k_tok->begin());
    return OkStatus();
}

}  // namespace sg::proto
