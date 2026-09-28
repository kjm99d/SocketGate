#include "auth/client_handshake.h"

#include "sockgate_common/protocol/transcript.h"

#include <algorithm>

namespace sg::client {
namespace {

bool IsZero(const proto::SessionId& id)
{
    return std::all_of(id.begin(), id.end(), [](uint8_t b) { return b == 0; });
}

}  // namespace

ClientHandshake::ClientHandshake(ClientHandshakeConfig config, IKeyStore& key_store, std::string key_name)
    : config_(std::move(config)), key_store_(key_store), key_name_(std::move(key_name))
{
}

ClientHandshake::~ClientHandshake()
{
    SecureZero(k_tok_.data(), k_tok_.size());
    SecureZero(th1_.data(), th1_.size());
    SecureZero(channel_binding_.data(), channel_binding_.size());
}

Status ClientHandshake::Start(const crypto::Sha256Digest& channel_binding, const EnrollmentMaterial* enrollment,
                              Bytes* frame_out)
{
    if (frame_out == nullptr) return SG_INVALID_ARGUMENT;
    if (started_) return SG_INVALID_STATE;
    started_ = true;
    channel_binding_ = channel_binding;

    proto::ClientHello hello;
    hello.version_min = config_.version_min;
    hello.version_max = config_.version_max;
    hello.client_version_major = config_.client_version_major;
    hello.client_version_minor = config_.client_version_minor;
    hello.client_version_patch = config_.client_version_patch;
    SG_TRY(crypto::RandomArray(&hello.client_nonce));
    hello.product_id = config_.product_id;
    hello.product_version = config_.product_version;
    hello.license_id = config_.license_id;
    hello.has_requested_features = config_.has_requested_features;
    hello.requested_features = config_.requested_features;
    hello.has_integrity = config_.has_integrity;
    hello.integrity = config_.integrity;

    crypto::P256PublicKey public_key;
    SG_TRY(key_store_.GetPublicKey(key_name_, &public_key));
    SG_TRY(proto::DeriveInstallationId(public_key, &hello.installation_id));

    if (enrollment != nullptr) {
        if (enrollment->token_pub.empty()) return SG_INVALID_ARGUMENT;
        enroll_ = true;
        k_tok_ = enrollment->k_tok;
        hello.auth_mode = proto::AuthMode::kEnroll;
        hello.enrollment_token_id = enrollment->token_pub;
        hello.has_public_key = true;
        hello.public_key = public_key;
    }

    Bytes payload;
    SG_TRY(proto::EncodeClientHello(hello, &payload));
    proto::FrameHeader header;
    header.type = proto::MessageType::kClientHello;
    header.sequence = 1;
    client_hello_frame_.clear();
    SG_TRY(proto::EncodeFrame(header, payload, ByteView(), &client_hello_frame_));
    *frame_out = client_hello_frame_;
    phase_ = proto::Phase::kAwaitServerHello;
    return OkStatus();
}

Status ClientHandshake::OnServerHello(const proto::DecodedFrame& frame, Bytes* frame_out)
{
    if (frame_out == nullptr) return SG_INVALID_ARGUMENT;
    if (!started_ || phase_ != proto::Phase::kAwaitServerHello) return SG_INVALID_STATE;
    const proto::FrameHeader& h = frame.header();
    if (h.type != proto::MessageType::kServerHello || h.sequence != 1 || IsZero(h.session_id)) {
        return SG_PROTOCOL_ERROR;
    }
    proto::ServerHello sh;
    SG_TRY(proto::DecodeServerHello(frame.payload(), &sh));
    if (sh.selected_version < config_.version_min || sh.selected_version > config_.version_max) {
        return SG_PROTOCOL_ERROR;
    }
    // A configured proof key makes the server proof mandatory, whatever the server advertises.
    if (!config_.server_proof_keys.empty() && sh.server_proof_algorithm != proto::kProofAlgorithmEcdsaP256Sha256) {
        return SG_INVALID_SIGNATURE;
    }
    session_id_ = h.session_id;
    selected_version_ = sh.selected_version;
    server_proof_algorithm_ = sh.server_proof_algorithm;

    SG_TRY(proto::ComputeTranscriptHash(selected_version_, channel_binding_, client_hello_frame_, frame.wire(), &th1_));

    proto::ClientProof proof;
    const Bytes signed_data = proto::SignedData(proto::kClientProofContext, th1_);
    SG_TRY(key_store_.Sign(key_name_, signed_data, &proof.signature));
    if (enroll_) {
        proof.has_enrollment_proof = true;
        SG_TRY(proto::ComputeEnrollmentProof(k_tok_, th1_, &proof.enrollment_proof));
        SecureZero(k_tok_.data(), k_tok_.size());  // no longer needed
    }

    Bytes payload;
    SG_TRY(proto::EncodeClientProof(proof, &payload));
    proto::FrameHeader header;
    header.type = proto::MessageType::kClientProof;
    header.session_id = session_id_;
    header.sequence = 2;
    client_proof_frame_.clear();
    SG_TRY(proto::EncodeFrame(header, payload, ByteView(), &client_proof_frame_));
    *frame_out = client_proof_frame_;
    phase_ = proto::Phase::kAwaitAuthResult;
    return OkStatus();
}

Status ClientHandshake::OnAuthResult(const proto::DecodedFrame& frame, ClientHandshakeResult* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    const proto::FrameHeader& h = frame.header();
    if (h.type != proto::MessageType::kAuthResult) return SG_PROTOCOL_ERROR;

    proto::AuthResult result;
    SG_TRY(proto::DecodeAuthResult(frame.payload(), &result));

    if (phase_ == proto::Phase::kAwaitServerHello) {
        // Only a version-negotiation failure may replace SERVER_HELLO.
        phase_ = proto::Phase::kClosed;
        if (result.result == proto::AuthResultCode::kUnsupportedVersion && h.sequence == 1 && IsZero(h.session_id)) {
            return SG_VERSION_MISMATCH;
        }
        return SG_PROTOCOL_ERROR;
    }
    if (phase_ != proto::Phase::kAwaitAuthResult) return SG_INVALID_STATE;
    phase_ = proto::Phase::kClosed;
    if (h.sequence != 2 || h.session_id != session_id_) return SG_PROTOCOL_ERROR;

    switch (result.result) {
    case proto::AuthResultCode::kOk:
        break;
    case proto::AuthResultCode::kUnsupportedVersion:
        return SG_VERSION_MISMATCH;
    case proto::AuthResultCode::kRejected:
    case proto::AuthResultCode::kRetryLater:
        return SG_SERVER_REJECTED;
    }

    if (result.server_proof_algorithm != server_proof_algorithm_) return SG_PROTOCOL_ERROR;
    if (!config_.server_proof_keys.empty()) {
        if (!result.has_server_signature) return SG_INVALID_SIGNATURE;
        // R = header || payload prefix up to (and including) server_proof_algorithm.
        const ByteView signed_prefix =
            frame.wire().Sub(0, proto::kHeaderSize + proto::kAuthResultSignedPayloadPrefix);
        crypto::Sha256Digest th2;
        SG_TRY(proto::ComputeServerTranscriptHash(th1_, client_proof_frame_, signed_prefix, &th2));
        const Bytes signed_data = proto::SignedData(proto::kServerProofContext, th2);
        bool verified = false;
        for (const auto& key : config_.server_proof_keys) {
            if (crypto::VerifyP256(key, signed_data, result.server_signature).ok()) {
                verified = true;
                break;
            }
        }
        if (!verified) return SG_INVALID_SIGNATURE;
    }

    out->session_id = session_id_;
    out->transcript_hash = th1_;
    out->auth_result = result;
    out->protocol_version = selected_version_;
    phase_ = proto::Phase::kActive;
    return OkStatus();
}

}  // namespace sg::client
