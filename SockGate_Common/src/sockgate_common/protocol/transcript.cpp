#include "sockgate_common/protocol/transcript.h"

#include "sockgate_common/serialization/byte_order.h"
#include "sockgate_common/serialization/writer.h"

#include <cstring>

namespace sg::proto {
namespace {

ByteView Label(const char* s) { return ByteView(reinterpret_cast<const uint8_t*>(s), std::strlen(s)); }

}  // namespace

Status ComputeTranscriptHash(uint16_t version, const crypto::Sha256Digest& channel_binding,
                             ByteView client_hello_frame, ByteView server_hello_frame, crypto::Sha256Digest* out)
{
    crypto::Sha256Hasher h;
    SG_TRY(h.Update(Label(kTranscriptLabel)));
    SG_TRY(h.UpdateU16(version));
    SG_TRY(h.Update(channel_binding));
    SG_TRY(h.UpdateWithLength(client_hello_frame));
    SG_TRY(h.UpdateWithLength(server_hello_frame));
    return h.Final(out);
}

Status ComputeServerTranscriptHash(const crypto::Sha256Digest& th1, ByteView client_proof_frame,
                                   ByteView auth_result_signed_prefix, crypto::Sha256Digest* out)
{
    crypto::Sha256Hasher h;
    SG_TRY(h.Update(Label(kServerTranscriptLabel)));
    SG_TRY(h.Update(th1));
    SG_TRY(h.UpdateWithLength(client_proof_frame));
    SG_TRY(h.UpdateWithLength(auth_result_signed_prefix));
    return h.Final(out);
}

Status ComputeReauthTranscriptHash(const SessionId& session_id, uint32_t epoch,
                                   const crypto::Sha256Digest& channel_binding, const crypto::Sha256Digest& prev_th,
                                   ByteView reauth_request_f, ByteView reauth_challenge_f, crypto::Sha256Digest* out)
{
    crypto::Sha256Hasher h;
    SG_TRY(h.Update(Label(kReauthTranscriptLabel)));
    SG_TRY(h.Update(session_id));
    SG_TRY(h.UpdateU32(epoch));
    SG_TRY(h.Update(channel_binding));
    SG_TRY(h.Update(prev_th));
    SG_TRY(h.UpdateWithLength(reauth_request_f));
    SG_TRY(h.UpdateWithLength(reauth_challenge_f));
    return h.Final(out);
}

Bytes SignedData(const char* context, const crypto::Sha256Digest& hash)
{
    Bytes out;
    Append(out, Label(context));
    out.push_back(0x00);
    Append(out, hash);
    return out;
}

Status DeriveInstallationId(const crypto::P256PublicKey& public_key, InstallationId* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    crypto::Sha256Digest digest;
    SG_TRY(crypto::Sha256({Label(kInstallationIdContext), ByteView(public_key)}, &digest));
    std::memcpy(out->data(), digest.data(), out->size());
    return OkStatus();
}

Status ComputeEnrollmentProof(const crypto::Sha256Digest& k_tok, const crypto::Sha256Digest& th1,
                              crypto::Sha256Digest* out)
{
    static const uint8_t kZero = 0;
    return crypto::HmacSha256(k_tok, {Label(kEnrollProofContext), ByteView(&kZero, 1), ByteView(th1)}, out);
}

Status DeriveChannelKeys(ByteView km, const SessionId& session_id, uint32_t epoch, crypto::AeadKey* c2s,
                         crypto::AeadKey* s2c)
{
    if (c2s == nullptr || s2c == nullptr || km.size() < 32) return SG_INVALID_ARGUMENT;
    uint8_t epoch_be[4];
    ser::StoreBE32(epoch_be, epoch);

    Bytes info_c2s;
    Append(info_c2s, Label(kC2SKeyInfo));
    Append(info_c2s, ByteView(epoch_be, sizeof(epoch_be)));
    Bytes info_s2c;
    Append(info_s2c, Label(kS2CKeyInfo));
    Append(info_s2c, ByteView(epoch_be, sizeof(epoch_be)));

    SG_TRY(crypto::HkdfSha256(km, session_id, info_c2s, c2s->data(), c2s->size()));
    const Status st = crypto::HkdfSha256(km, session_id, info_s2c, s2c->data(), s2c->size());
    if (!st.ok()) SecureZero(c2s->data(), c2s->size());
    return st;
}

}  // namespace sg::proto
