// Transcript hashes, signed-data construction and derived identifiers
// (docs/design/04-protocol-specification.md §6). Both peers use exactly
// these functions, so the byte layout of everything that is signed or MACed
// has a single implementation.
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"

namespace sg::proto {

// TH1 = SHA-256(label || u16 version || channel_binding || u32 len || CH || u32 len || SH)
Status ComputeTranscriptHash(uint16_t version, const crypto::Sha256Digest& channel_binding,
                             ByteView client_hello_frame, ByteView server_hello_frame, crypto::Sha256Digest* out);

// TH2 = SHA-256(label || TH1 || u32 len || CLIENT_PROOF frame || u32 len || AUTH_RESULT signed prefix)
Status ComputeServerTranscriptHash(const crypto::Sha256Digest& th1, ByteView client_proof_frame,
                                   ByteView auth_result_signed_prefix, crypto::Sha256Digest* out);

// THr = SHA-256(label || session_id || u32 epoch || channel_binding || prev_th
//               || u32 len || F(REAUTH_REQUEST) || u32 len || F(REAUTH_CHALLENGE))
// where F(x) = header (auth_length = 16) || plaintext payload.
Status ComputeReauthTranscriptHash(const SessionId& session_id, uint32_t epoch,
                                   const crypto::Sha256Digest& channel_binding, const crypto::Sha256Digest& prev_th,
                                   ByteView reauth_request_f, ByteView reauth_challenge_f, crypto::Sha256Digest* out);

// context || 0x00 || hash — the exact byte string that gets signed.
Bytes SignedData(const char* context, const crypto::Sha256Digest& hash);

// installation_id = SHA-256("SockGate/v1/iid" || SEC1 public key)[0..16)
Status DeriveInstallationId(const crypto::P256PublicKey& public_key, InstallationId* out);

// HMAC-SHA256(K_tok, "SockGate/v1/enroll-proof" || 0x00 || TH1)
Status ComputeEnrollmentProof(const crypto::Sha256Digest& k_tok, const crypto::Sha256Digest& th1,
                              crypto::Sha256Digest* out);

// Per-direction channel keys:
//   k = HKDF-SHA256(ikm = km, salt = session_id, info = label || u32 epoch, L = 32)
Status DeriveChannelKeys(ByteView km, const SessionId& session_id, uint32_t epoch, crypto::AeadKey* c2s,
                         crypto::AeadKey* s2c);

}  // namespace sg::proto
