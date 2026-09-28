#include "sockgate_common/protocol/messages.h"

#include "sockgate_common/serialization/reader.h"
#include "sockgate_common/serialization/tlv.h"
#include "sockgate_common/serialization/writer.h"

namespace sg::proto {
namespace {

using ser::Reader;
using ser::TlvSection;
using ser::TlvWriter;
using ser::Writer;

Status ReadString(const ser::TlvEntry& e, size_t max, std::string* out)
{
    if (e.value.empty() || e.value.size() > max || !ser::IsValidProtocolString(e.value)) return SG_PROTOCOL_ERROR;
    out->assign(reinterpret_cast<const char*>(e.value.data()), e.value.size());
    return OkStatus();
}

Status CheckString(const std::string& s, size_t max)
{
    if (s.empty()) return OkStatus();  // absent
    if (s.size() > max || !ser::IsValidProtocolString(ser::AsBytes(s))) return SG_INVALID_ARGUMENT;
    return OkStatus();
}

bool IsKnownResult(uint8_t v) { return v <= static_cast<uint8_t>(AuthResultCode::kUnsupportedVersion); }
bool IsKnownPolicy(uint8_t v) { return v <= static_cast<uint8_t>(SessionPolicy::kRestricted); }
bool IsKnownProofAlgorithm(uint8_t v) { return v == kProofAlgorithmNone || v == kProofAlgorithmEcdsaP256Sha256; }

Status ReadSignature(Reader& r, crypto::P256Signature* out)
{
    ByteView sig;
    SG_TRY(r.Vec16(crypto::kP256SignatureSize, crypto::kP256SignatureSize, &sig));
    std::copy(sig.begin(), sig.end(), out->begin());
    return OkStatus();
}

// Messages without defined extensions still carry an (empty) TLV section so
// that future versions can extend them without changing the fixed layout.
Status SkipExtensions(Reader& r)
{
    TlvSection tlv;
    return tlv.Parse(r);
}

}  // namespace

// ---- IntegrityReport ----------------------------------------------------------

Status EncodeIntegrityReport(const IntegrityReport& in, Bytes* out)
{
    Writer w(out);
    w.U8(1);  // report_version
    w.U8(in.platform);
    w.U32(in.observation_flags);
    w.Raw(in.executable_sha256);
    w.Raw(in.library_sha256);
    return w.Vec16(in.build_id, kMaxBuildIdLength);
}

Status DecodeIntegrityReport(ByteView in, IntegrityReport* out)
{
    Reader r(in);
    uint8_t version = 0;
    SG_TRY(r.U8(&version));
    if (version != 1) return SG_PROTOCOL_ERROR;
    SG_TRY(r.U8(&out->platform));
    if (out->platform < 1 || out->platform > 3) return SG_PROTOCOL_ERROR;
    SG_TRY(r.U32(&out->observation_flags));
    SG_TRY(r.Fixed(&out->executable_sha256));
    SG_TRY(r.Fixed(&out->library_sha256));
    ByteView build_id;
    SG_TRY(r.Vec16(0, kMaxBuildIdLength, &build_id));
    out->build_id = build_id.ToBytes();
    return r.ExpectEnd();
}

// ---- CLIENT_HELLO -------------------------------------------------------------

Status EncodeClientHello(const ClientHello& in, Bytes* out)
{
    SG_TRY(CheckString(in.product_id, kMaxProductIdLength));
    SG_TRY(CheckString(in.product_version, kMaxProductVersionLength));
    SG_TRY(CheckString(in.license_id, kMaxLicenseIdLength));
    Writer w(out);
    w.U16(in.version_min);
    w.U16(in.version_max);
    w.U16(in.client_version_major);
    w.U16(in.client_version_minor);
    w.U16(in.client_version_patch);
    w.Raw(in.client_nonce);
    w.Raw(in.installation_id);
    w.U8(in.key_algorithm);
    w.U8(static_cast<uint8_t>(in.auth_mode));

    TlvWriter tlv;
    if (!in.product_id.empty()) tlv.AddString(tlv::kProductId, in.product_id);
    if (!in.product_version.empty()) tlv.AddString(tlv::kProductVersion, in.product_version);
    if (!in.license_id.empty()) tlv.AddString(tlv::kLicenseId, in.license_id);
    if (in.has_requested_features) tlv.AddU64(tlv::kRequestedFeatures, in.requested_features);
    if (in.has_integrity) {
        Bytes report;
        SG_TRY(EncodeIntegrityReport(in.integrity, &report));
        tlv.Add(tlv::kIntegrityReport, report);
    }
    if (!in.enrollment_token_id.empty()) {
        if (in.enrollment_token_id.size() > kMaxEnrollmentTokenIdLength) return SG_INVALID_ARGUMENT;
        tlv.Add(tlv::kEnrollmentTokenId, in.enrollment_token_id);
    }
    if (in.has_public_key) tlv.Add(tlv::kPublicKey, in.public_key);
    return tlv.Finish(w);
}

Status DecodeClientHello(ByteView in, ClientHello* out)
{
    Reader r(in);
    *out = ClientHello();
    SG_TRY(r.U16(&out->version_min));
    SG_TRY(r.U16(&out->version_max));
    SG_TRY(r.U16(&out->client_version_major));
    SG_TRY(r.U16(&out->client_version_minor));
    SG_TRY(r.U16(&out->client_version_patch));
    SG_TRY(r.Fixed(&out->client_nonce));
    SG_TRY(r.Fixed(&out->installation_id));
    SG_TRY(r.U8(&out->key_algorithm));
    uint8_t mode = 0;
    SG_TRY(r.U8(&mode));
    if (out->version_min == 0 || out->version_min > out->version_max) return SG_PROTOCOL_ERROR;
    if (out->key_algorithm != kKeyAlgorithmEcdsaP256Sha256) return SG_PROTOCOL_ERROR;
    if (mode != static_cast<uint8_t>(AuthMode::kAuthenticate) && mode != static_cast<uint8_t>(AuthMode::kEnroll)) {
        return SG_PROTOCOL_ERROR;
    }
    out->auth_mode = static_cast<AuthMode>(mode);

    TlvSection tlv;
    SG_TRY(tlv.Parse(r));
    SG_TRY(r.ExpectEnd());

    for (const auto& e : tlv.entries()) {
        switch (e.type) {
        case tlv::kProductId:
            SG_TRY(ReadString(e, kMaxProductIdLength, &out->product_id));
            break;
        case tlv::kProductVersion:
            SG_TRY(ReadString(e, kMaxProductVersionLength, &out->product_version));
            break;
        case tlv::kLicenseId:
            SG_TRY(ReadString(e, kMaxLicenseIdLength, &out->license_id));
            break;
        case tlv::kRequestedFeatures: {
            Reader fr(e.value);
            SG_TRY(fr.U64(&out->requested_features));
            SG_TRY(fr.ExpectEnd());
            out->has_requested_features = true;
            break;
        }
        case tlv::kIntegrityReport:
            if (e.value.size() > kMaxIntegrityReportLength) return SG_PROTOCOL_ERROR;
            SG_TRY(DecodeIntegrityReport(e.value, &out->integrity));
            out->has_integrity = true;
            break;
        case tlv::kEnrollmentTokenId:
            if (e.value.empty() || e.value.size() > kMaxEnrollmentTokenIdLength) return SG_PROTOCOL_ERROR;
            out->enrollment_token_id = e.value.ToBytes();
            break;
        case tlv::kPublicKey:
            if (e.value.size() != crypto::kP256PublicKeySize || e.value[0] != 0x04) return SG_PROTOCOL_ERROR;
            std::copy(e.value.begin(), e.value.end(), out->public_key.begin());
            out->has_public_key = true;
            break;
        default:
            break;  // unknown extensions are ignored (forward compatibility)
        }
    }

    const bool enroll = out->auth_mode == AuthMode::kEnroll;
    const bool has_enroll_fields = !out->enrollment_token_id.empty() || out->has_public_key;
    if (enroll) {
        if (out->enrollment_token_id.empty() || !out->has_public_key) return SG_PROTOCOL_ERROR;
    } else if (has_enroll_fields) {
        return SG_PROTOCOL_ERROR;
    }
    return OkStatus();
}

// ---- SERVER_HELLO -------------------------------------------------------------

Status EncodeServerHello(const ServerHello& in, Bytes* out)
{
    Writer w(out);
    w.U16(in.selected_version);
    w.Raw(in.server_nonce);
    w.Raw(in.challenge);
    w.U32(in.challenge_ttl_ms);
    w.U8(in.server_proof_algorithm);
    return TlvWriter().Finish(w);
}

Status DecodeServerHello(ByteView in, ServerHello* out)
{
    Reader r(in);
    SG_TRY(r.U16(&out->selected_version));
    SG_TRY(r.Fixed(&out->server_nonce));
    SG_TRY(r.Fixed(&out->challenge));
    SG_TRY(r.U32(&out->challenge_ttl_ms));
    SG_TRY(r.U8(&out->server_proof_algorithm));
    SG_TRY(SkipExtensions(r));
    SG_TRY(r.ExpectEnd());
    if (out->selected_version == 0 || out->challenge_ttl_ms == 0) return SG_PROTOCOL_ERROR;
    if (!IsKnownProofAlgorithm(out->server_proof_algorithm)) return SG_PROTOCOL_ERROR;
    return OkStatus();
}

// ---- CLIENT_PROOF -------------------------------------------------------------

Status EncodeClientProof(const ClientProof& in, Bytes* out)
{
    Writer w(out);
    w.U8(in.signature_algorithm);
    SG_TRY(w.Vec16(in.signature));
    TlvWriter tlv;
    if (in.has_enrollment_proof) tlv.Add(tlv::kEnrollmentProof, in.enrollment_proof);
    return tlv.Finish(w);
}

Status DecodeClientProof(ByteView in, ClientProof* out)
{
    Reader r(in);
    *out = ClientProof();
    SG_TRY(r.U8(&out->signature_algorithm));
    if (out->signature_algorithm != kKeyAlgorithmEcdsaP256Sha256) return SG_PROTOCOL_ERROR;
    SG_TRY(ReadSignature(r, &out->signature));
    TlvSection tlv;
    SG_TRY(tlv.Parse(r));
    SG_TRY(r.ExpectEnd());
    if (const auto* e = tlv.Find(tlv::kEnrollmentProof)) {
        if (e->value.size() != crypto::kSha256Size) return SG_PROTOCOL_ERROR;
        std::copy(e->value.begin(), e->value.end(), out->enrollment_proof.begin());
        out->has_enrollment_proof = true;
    }
    return OkStatus();
}

// ---- AUTH_RESULT --------------------------------------------------------------

Status EncodeAuthResult(const AuthResult& in, Bytes* out)
{
    if (in.has_server_signature != (in.server_proof_algorithm == kProofAlgorithmEcdsaP256Sha256)) {
        return SG_INVALID_ARGUMENT;
    }
    Writer w(out);
    w.U8(static_cast<uint8_t>(in.result));
    w.U8(static_cast<uint8_t>(in.policy));
    w.U64(in.granted_features);
    w.U32(in.session_lifetime_ms);
    w.U64(in.license_expires_at_ms);
    w.U8(in.server_proof_algorithm);
    if (in.has_server_signature) return w.Vec16(in.server_signature);
    w.U16(0);
    return OkStatus();
}

Status DecodeAuthResult(ByteView in, AuthResult* out)
{
    Reader r(in);
    *out = AuthResult();
    uint8_t result = 0;
    uint8_t policy = 0;
    SG_TRY(r.U8(&result));
    SG_TRY(r.U8(&policy));
    SG_TRY(r.U64(&out->granted_features));
    SG_TRY(r.U32(&out->session_lifetime_ms));
    SG_TRY(r.U64(&out->license_expires_at_ms));
    SG_TRY(r.U8(&out->server_proof_algorithm));
    if (!IsKnownResult(result) || !IsKnownPolicy(policy) || !IsKnownProofAlgorithm(out->server_proof_algorithm)) {
        return SG_PROTOCOL_ERROR;
    }
    out->result = static_cast<AuthResultCode>(result);
    out->policy = static_cast<SessionPolicy>(policy);

    const size_t sig_len = out->server_proof_algorithm == kProofAlgorithmNone ? 0 : crypto::kP256SignatureSize;
    ByteView sig;
    SG_TRY(r.Vec16(sig_len, sig_len, &sig));
    SG_TRY(r.ExpectEnd());
    if (sig_len != 0) {
        std::copy(sig.begin(), sig.end(), out->server_signature.begin());
        out->has_server_signature = true;
    }

    if (out->result == AuthResultCode::kOk) {
        if (out->policy == SessionPolicy::kNone || out->session_lifetime_ms == 0) return SG_PROTOCOL_ERROR;
    } else {
        // Rejections carry no further information and no signature.
        if (out->policy != SessionPolicy::kNone || out->granted_features != 0 || out->session_lifetime_ms != 0 ||
            out->license_expires_at_ms != 0 || out->server_proof_algorithm != kProofAlgorithmNone) {
            return SG_PROTOCOL_ERROR;
        }
    }
    return OkStatus();
}

// ---- PING / PONG ------------------------------------------------------------------

Status EncodePingPong(const PingPong& in, Bytes* out)
{
    Writer(out).U64(in.opaque);
    return OkStatus();
}

Status DecodePingPong(ByteView in, PingPong* out)
{
    Reader r(in);
    SG_TRY(r.U64(&out->opaque));
    return r.ExpectEnd();
}

// ---- REAUTH_* -----------------------------------------------------------------

Status EncodeReauthRequest(const ReauthRequest& in, Bytes* out)
{
    Writer(out).Raw(in.client_nonce);
    return OkStatus();
}

Status DecodeReauthRequest(ByteView in, ReauthRequest* out)
{
    Reader r(in);
    SG_TRY(r.Fixed(&out->client_nonce));
    return r.ExpectEnd();
}

Status EncodeReauthChallenge(const ReauthChallenge& in, Bytes* out)
{
    Writer w(out);
    w.Raw(in.server_nonce);
    w.Raw(in.challenge);
    w.U32(in.challenge_ttl_ms);
    return OkStatus();
}

Status DecodeReauthChallenge(ByteView in, ReauthChallenge* out)
{
    Reader r(in);
    SG_TRY(r.Fixed(&out->server_nonce));
    SG_TRY(r.Fixed(&out->challenge));
    SG_TRY(r.U32(&out->challenge_ttl_ms));
    SG_TRY(r.ExpectEnd());
    return out->challenge_ttl_ms == 0 ? Status(SG_PROTOCOL_ERROR) : OkStatus();
}

Status EncodeReauthProof(const ReauthProof& in, Bytes* out)
{
    Writer w(out);
    w.U8(in.signature_algorithm);
    return w.Vec16(in.signature);
}

Status DecodeReauthProof(ByteView in, ReauthProof* out)
{
    Reader r(in);
    SG_TRY(r.U8(&out->signature_algorithm));
    if (out->signature_algorithm != kKeyAlgorithmEcdsaP256Sha256) return SG_PROTOCOL_ERROR;
    SG_TRY(ReadSignature(r, &out->signature));
    return r.ExpectEnd();
}

Status EncodeReauthResult(const ReauthResult& in, Bytes* out)
{
    Writer w(out);
    w.U8(static_cast<uint8_t>(in.result));
    w.U32(in.session_lifetime_ms);
    w.U32(in.new_epoch);
    return OkStatus();
}

Status DecodeReauthResult(ByteView in, ReauthResult* out)
{
    Reader r(in);
    uint8_t result = 0;
    SG_TRY(r.U8(&result));
    SG_TRY(r.U32(&out->session_lifetime_ms));
    SG_TRY(r.U32(&out->new_epoch));
    SG_TRY(r.ExpectEnd());
    if (!IsKnownResult(result) || result == static_cast<uint8_t>(AuthResultCode::kUnsupportedVersion)) {
        return SG_PROTOCOL_ERROR;
    }
    out->result = static_cast<AuthResultCode>(result);
    if (out->result == AuthResultCode::kOk && out->session_lifetime_ms == 0) return SG_PROTOCOL_ERROR;
    if (out->result != AuthResultCode::kOk && (out->session_lifetime_ms != 0 || out->new_epoch != 0)) {
        return SG_PROTOCOL_ERROR;
    }
    return OkStatus();
}

// ---- CLOSE --------------------------------------------------------------------

Status EncodeClose(const CloseMessage& in, Bytes* out)
{
    Writer(out).U16(static_cast<uint16_t>(in.reason));
    return OkStatus();
}

Status DecodeClose(ByteView in, CloseMessage* out)
{
    Reader r(in);
    uint16_t reason = 0;
    SG_TRY(r.U16(&reason));
    SG_TRY(r.ExpectEnd());
    if (reason > static_cast<uint16_t>(CloseReason::kLimitExceeded)) return SG_PROTOCOL_ERROR;
    out->reason = static_cast<CloseReason>(reason);
    return OkStatus();
}

}  // namespace sg::proto
