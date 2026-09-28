#pragma once
/**
 * @file
 * @brief Transcript hashes, signed-data construction and derived identifiers
 * (docs/design/04-protocol-specification.md §6).
 *
 * Both peers use exactly
 * these functions, so the byte layout of everything that is signed or MACed
 * has a single implementation.
 *
 * Notation: `||` is concatenation, integers are big endian, labels are the ASCII constants of constants.h
 * without a terminator, and `u32 len || X` is X prefixed with its length in bytes.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"

namespace sg::proto {

/**
 * @brief Computes the handshake transcript hash TH1.
 *
 * TH1 = SHA-256(label || u16 version || channel_binding || u32 len || CH || u32 len || SH),
 * with label = kTranscriptLabel and CH / SH the complete CLIENT_HELLO / SERVER_HELLO frames (header
 * included). The frames contain the nonces, the challenge, the installation id and the session id, so
 * TH1 covers them all. TH1 is signed by CLIENT_PROOF and is the exporter context of the epoch-0 keys.
 *
 * @param[in]  version            Selected protocol version.
 * @param[in]  channel_binding    32-byte RFC 9266 tls-exporter value of the local TLS connection.
 * @param[in]  client_hello_frame CLIENT_HELLO wire bytes (header || payload).
 * @param[in]  server_hello_frame SERVER_HELLO wire bytes (header || payload).
 * @param[out] out                Receives TH1.
 * @retval OK                  Hash computed.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, or an input frame exceeds 2^32-1 bytes.
 * @retval SG_CRYPTO_ERROR     Hash failure.
 */
Status ComputeTranscriptHash(uint16_t version, const crypto::Sha256Digest& channel_binding,
                             ByteView client_hello_frame, ByteView server_hello_frame, crypto::Sha256Digest* out);

/**
 * @brief Computes the server transcript hash TH2 signed by the optional server proof.
 *
 * TH2 = SHA-256(label || TH1 || u32 len || CLIENT_PROOF frame || u32 len || AUTH_RESULT signed prefix),
 * with label = kServerTranscriptLabel. The signed prefix R is the AUTH_RESULT header (48 bytes, whose
 * payload_length already counts the signature) followed by the payload up to and including
 * `server_proof_algorithm` (kAuthResultSignedPayloadPrefix bytes; the trailing vec16 signature excluded).
 *
 * @param[in]  th1                       TH1 of this handshake.
 * @param[in]  client_proof_frame        CLIENT_PROOF wire bytes (header || payload).
 * @param[in]  auth_result_signed_prefix R as described above.
 * @param[out] out                       Receives TH2.
 * @retval OK                  Hash computed.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, or an input frame exceeds 2^32-1 bytes.
 * @retval SG_CRYPTO_ERROR     Hash failure.
 */
Status ComputeServerTranscriptHash(const crypto::Sha256Digest& th1, ByteView client_proof_frame,
                                   ByteView auth_result_signed_prefix, crypto::Sha256Digest* out);

/**
 * @brief Computes the reauthentication transcript hash THr.
 *
 * THr = SHA-256(label || session_id || u32 epoch || channel_binding || prev_th
 *               || u32 len || F(REAUTH_REQUEST) || u32 len || F(REAUTH_CHALLENGE))
 * where F(x) = header (auth_length = 16) || plaintext payload, and label = kReauthTranscriptLabel.
 * F(x) excludes the tag and uses the plaintext whether or not the frame was ENCRYPTED
 * (ProtectedChannel::Open() produces it for a received frame). THr is signed by REAUTH_PROOF and is the
 * exporter context of the next epoch's keys.
 *
 * @param[in]  session_id         Session id.
 * @param[in]  epoch              Current epoch (the one being replaced).
 * @param[in]  channel_binding    32-byte tls-exporter channel binding of the local TLS connection.
 * @param[in]  prev_th            Transcript hash of the previous authentication (TH1 or the previous THr).
 * @param[in]  reauth_request_f   F(REAUTH_REQUEST).
 * @param[in]  reauth_challenge_f F(REAUTH_CHALLENGE).
 * @param[out] out                Receives THr.
 * @retval OK                  Hash computed.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, or an input frame exceeds 2^32-1 bytes.
 * @retval SG_CRYPTO_ERROR     Hash failure.
 */
Status ComputeReauthTranscriptHash(const SessionId& session_id, uint32_t epoch,
                                   const crypto::Sha256Digest& channel_binding, const crypto::Sha256Digest& prev_th,
                                   ByteView reauth_request_f, ByteView reauth_challenge_f, crypto::Sha256Digest* out);

/**
 * @brief Builds context || 0x00 || hash — the exact byte string that gets signed.
 * @param[in] context NUL-terminated label (kClientProofContext, kServerProofContext or kReauthProofContext);
 *                    the terminator is not included. Must not be nullptr.
 * @param[in] hash    Transcript hash (TH1, TH2 or THr).
 * @return The signed-data bytes.
 */
Bytes SignedData(const char* context, const crypto::Sha256Digest& hash);

/**
 * @brief Derives the installation id from the installation public key.
 *
 * installation_id = SHA-256("SockGate/v1/iid" || SEC1 public key)[0..16)
 *
 * @param[in]  public_key 65-byte SEC1 uncompressed P-256 public key.
 * @param[out] out        Receives the first 16 bytes of the digest.
 * @retval OK                  Id derived.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr.
 * @retval SG_CRYPTO_ERROR     Hash failure.
 */
Status DeriveInstallationId(const crypto::P256PublicKey& public_key, InstallationId* out);

/**
 * @brief Computes the CLIENT_PROOF ENROLLMENT_PROOF value.
 *
 * HMAC-SHA256(K_tok, "SockGate/v1/enroll-proof" || 0x00 || TH1)
 *
 * @param[in]  k_tok Enrollment token key (see enrollment_token.h).
 * @param[in]  th1   TH1 of this handshake (binds the proof to the TLS channel).
 * @param[out] out   Receives the 32-byte MAC.
 * @retval OK                  Proof computed.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr.
 * @retval SG_CRYPTO_ERROR     MAC failure.
 */
Status ComputeEnrollmentProof(const crypto::Sha256Digest& k_tok, const crypto::Sha256Digest& th1,
                              crypto::Sha256Digest* out);

/**
 * @brief Derives the per-direction channel keys of one epoch.
 *
 * Per-direction channel keys:
 *   k = HKDF-SHA256(ikm = km, salt = session_id, info = label || u32 epoch, L = 32)
 * with label kC2SKeyInfo for @p c2s and kS2CKeyInfo for @p s2c.
 *
 * @param[in]  km         32-byte TLS exporter output (kKeyExporterLabel; context TH1, or THr for a new epoch).
 * @param[in]  session_id Session id (HKDF salt).
 * @param[in]  epoch      Key epoch (0 after the handshake, +1 per successful reauthentication).
 * @param[out] c2s        Receives the client-to-server key; wiped if deriving @p s2c fails.
 * @param[out] s2c        Receives the server-to-client key.
 * @retval OK                  Keys derived.
 * @retval SG_INVALID_ARGUMENT @p c2s or @p s2c is nullptr, or @p km is not 32 bytes.
 * @retval SG_CRYPTO_ERROR     HKDF failure.
 * @warning The outputs are secrets; the caller wipes them after use.
 */
Status DeriveChannelKeys(ByteView km, const SessionId& session_id, uint32_t epoch, crypto::AeadKey* c2s,
                         crypto::AeadKey* s2c);

}  // namespace sg::proto
