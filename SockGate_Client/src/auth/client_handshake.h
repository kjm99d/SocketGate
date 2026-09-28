#pragma once
/**
 * @file
 * @brief Client side of the SockGate authentication handshake (sans-IO).
 *
 * @verbatim
   Start()          -> CLIENT_HELLO frame
   OnServerHello()  -> CLIENT_PROOF frame (signature over the channel-bound transcript)
   OnAuthResult()   -> outcome (+ optional server proof verification)
   @endverbatim
 *
 * The caller moves frames over TLS and supplies the channel binding value of its own TLS connection.
 */

#include "crypto/key_store.h"

#include "sockgate_common/protocol/frame.h"
#include "sockgate_common/protocol/messages.h"
#include "sockgate_common/protocol/rules.h"

#include <string>
#include <vector>

namespace sg::client {

/**
 * @brief What the client offers and claims in CLIENT_HELLO, and which server proof it requires.
 *
 * @warning product_id, product_version, license_id, requested_features and the integrity report are client claims;
 *          the server decides what to grant. They are sent in CLIENT_HELLO, before any server proof is checked
 *          (OnAuthResult()), so only TLS server authentication keeps them from a fake server.
 */
struct ClientHandshakeConfig {
    uint16_t version_min = proto::kMinProtocolVersion;  ///< Lowest protocol version offered.
    uint16_t version_max = proto::kMaxProtocolVersion;  ///< Highest protocol version offered.
    uint16_t client_version_major = 0;                  ///< Application version (major), sent in CLIENT_HELLO.
    uint16_t client_version_minor = 0;                  ///< Application version (minor).
    uint16_t client_version_patch = 0;                  ///< Application version (patch).
    std::string product_id;                             ///< Product identifier (claim).
    std::string product_version;                        ///< Product version (claim).
    std::string license_id;                             ///< License identifier (claim).
    bool has_requested_features = false;                ///< True to send requested_features.
    uint64_t requested_features = 0;                    ///< Feature bits requested from the server (claim).
    bool has_integrity = false;                         ///< True to send integrity.
    proto::IntegrityReport integrity;                   ///< Integrity report (platform/integrity.h; claim).
    /**
     * @brief Server proof keys. When non-empty the server MUST prove possession of one of these keys.
     *
     * The server must then advertise ECDSA-P256-SHA256 in SERVER_HELLO and sign AUTH_RESULT(OK); a missing or
     * wrong proof fails the handshake with SG_INVALID_SIGNATURE. When empty, no server signature is verified.
     */
    std::vector<crypto::P256PublicKey> server_proof_keys;
};

/**
 * @brief Enrollment token material for ENROLL mode (from proto::ParseEnrollmentToken()).
 *
 * @warning k_tok is secret. ClientHandshake::Start() copies it; the handshake wipes its copy once the enrollment
 *          proof is built and on destruction. The caller wipes its own copy (ClientSession does so right after
 *          Start()).
 */
struct EnrollmentMaterial {
    Bytes token_pub;          ///< Sent in CLIENT_HELLO; must not be empty.
    crypto::Sha256Digest k_tok{};  ///< Never sent; used for the channel-bound proof (HMAC over TH1).
};

/** @brief Outcome of a successful handshake, filled by ClientHandshake::OnAuthResult(). */
struct ClientHandshakeResult {
    proto::SessionId session_id{};           ///< Session id assigned by the server in SERVER_HELLO.
    crypto::Sha256Digest transcript_hash{};  ///< TH1, input to the channel key schedule.
    proto::AuthResult auth_result;           ///< Decoded AUTH_RESULT (policy, granted features, lifetime, ...).
    uint16_t protocol_version = proto::kProtocolVersion;  ///< Protocol version selected by the server.
};

/**
 * @brief Sans-IO state machine for one client authentication (AUTHENTICATE or ENROLL mode).
 *
 * Builds CLIENT_HELLO and CLIENT_PROOF and checks SERVER_HELLO and AUTH_RESULT. The installation key is used only
 * through IKeyStore (public key lookup and Sign()); private key bytes are never seen here. One instance serves one
 * handshake.
 *
 * @note No internal locking: one thread at a time drives an instance.
 * @note The channel binding, TH1 and K_tok are wiped on destruction; K_tok also right after CLIENT_PROOF is built.
 */
class ClientHandshake {
public:
    /**
     * @brief Prepares a handshake; no I/O and no key store access happen here.
     * @param[in] config    Offered versions, claims and server proof keys (stored by value).
     * @param[in] key_store Store holding the installation key; referenced, so it must outlive this object.
     * @param[in] key_name  Name of the installation key in @p key_store.
     */
    ClientHandshake(ClientHandshakeConfig config, IKeyStore& key_store, std::string key_name);
    /** @brief Wipes the channel binding, TH1 and K_tok. */
    ~ClientHandshake();

    ClientHandshake(const ClientHandshake&) = delete;
    ClientHandshake& operator=(const ClientHandshake&) = delete;

    /**
     * @brief Builds the CLIENT_HELLO frame (sequence 1, zero session id).
     *
     * Reads the public key of the installation key, derives the installation id from it and draws a fresh client
     * nonce. In ENROLL mode the frame also carries token_pub and the public key. Only the first call with a
     * non-null @p frame_out can succeed. Key store errors (SG_KEYSTORE_ERROR, SG_IDENTITY_LOST, ...) and encoding
     * errors are passed through.
     *
     * @param[in]  channel_binding Channel binding of the caller's TLS connection (kept for TH1).
     * @param[in]  enrollment      enrollment == nullptr: AUTHENTICATE mode. Otherwise ENROLL mode; k_tok is copied.
     * @param[out] frame_out       Receives the encoded frame.
     * @retval SG_OK               Frame built; the handshake awaits SERVER_HELLO.
     * @retval SG_INVALID_ARGUMENT @p frame_out is nullptr, or @p enrollment has an empty token_pub.
     * @retval SG_INVALID_STATE    Start() was already called.
     * @retval SG_NOT_FOUND        The installation key does not exist.
     */
    Status Start(const crypto::Sha256Digest& channel_binding, const EnrollmentMaterial* enrollment, Bytes* frame_out);

    /**
     * @brief Checks SERVER_HELLO and builds the CLIENT_PROOF frame (sequence 2).
     *
     * Requires the SERVER_HELLO type, sequence 1, a non-zero session id and a selected version within
     * [version_min, version_max]; with server proof keys configured, the server must advertise ECDSA-P256-SHA256.
     * Then computes TH1 over the channel binding and both hello frames and signs it with the installation key. In
     * ENROLL mode it also adds the enrollment proof (HMAC with K_tok over TH1) and wipes K_tok. Decoding and key
     * store (signing) errors are passed through.
     *
     * @param[in]  frame     Decoded SERVER_HELLO frame.
     * @param[out] frame_out Receives the encoded CLIENT_PROOF frame.
     * @retval SG_OK                Proof built; the handshake awaits AUTH_RESULT.
     * @retval SG_INVALID_ARGUMENT  @p frame_out is nullptr.
     * @retval SG_INVALID_STATE     Start() has not run, or SERVER_HELLO was already handled.
     * @retval SG_PROTOCOL_ERROR    Wrong type or sequence, zero session id, or version outside the offered range.
     * @retval SG_INVALID_SIGNATURE Server proof keys are configured but the server offers no ECDSA-P256-SHA256 proof.
     */
    Status OnServerHello(const proto::DecodedFrame& frame, Bytes* frame_out);

    /**
     * @brief Checks AUTH_RESULT and, with server proof keys configured, the server proof.
     *
     * Also accepts an AUTH_RESULT that arrives instead of SERVER_HELLO: only UNSUPPORTED_VERSION with sequence 1
     * and a zero session id counts (SG_VERSION_MISMATCH). After SERVER_HELLO the frame must carry sequence 2 and
     * the session id, and repeat the server proof algorithm SERVER_HELLO advertised. With proof keys, the signature
     * over TH2 (TH1, CLIENT_PROOF and the signed AUTH_RESULT prefix) must verify under one of them. Once the frame
     * is decoded the handshake is over: phase() is kActive on success, kClosed otherwise. Decoding errors are passed
     * through.
     *
     * @param[in]  frame Decoded AUTH_RESULT frame.
     * @param[out] out   Receives the session id, TH1, the AUTH_RESULT and the protocol version (on success only).
     * @retval SG_OK                OK: authenticated.
     * @retval SG_SERVER_REJECTED   The server answered REJECTED or RETRY_LATER.
     * @retval SG_VERSION_MISMATCH  The server answered UNSUPPORTED_VERSION.
     * @retval SG_INVALID_SIGNATURE Server proof required but missing or not valid under any configured key.
     * @retval SG_PROTOCOL_ERROR    Wrong type, sequence or session id, or a changed proof algorithm.
     * @retval SG_INVALID_ARGUMENT  @p out is nullptr.
     * @retval SG_INVALID_STATE     The handshake is already over.
     * @warning Only AUTH_RESULT(OK) is covered by the server proof: SG_SERVER_REJECTED and SG_VERSION_MISMATCH
     *          are returned without any server signature check.
     */
    Status OnAuthResult(const proto::DecodedFrame& frame, ClientHandshakeResult* out);

    /**
     * @brief Current phase of the handshake.
     * @return kAwaitServerHello until SERVER_HELLO is handled, then kAwaitAuthResult; kActive after a successful
     *         OnAuthResult(), kClosed after a failed one.
     */
    proto::Phase phase() const noexcept { return phase_; }

private:
    ClientHandshakeConfig config_;  ///< Offered versions, claims and server proof keys.
    IKeyStore& key_store_;          ///< Store holding the installation key (not owned).
    const std::string key_name_;    ///< Name of the installation key.

    proto::Phase phase_ = proto::Phase::kAwaitServerHello;  ///< See phase().
    bool started_ = false;                     ///< True once Start() has passed its argument check.
    bool enroll_ = false;                      ///< True in ENROLL mode.
    crypto::Sha256Digest channel_binding_{};   ///< From Start(); wiped on destruction.
    crypto::Sha256Digest k_tok_{};             ///< ENROLL: copy of K_tok; wiped after use and on destruction.
    Bytes client_hello_frame_;                 ///< Encoded CLIENT_HELLO (TH1 input).
    Bytes client_proof_frame_;                 ///< Encoded CLIENT_PROOF (TH2 input).
    proto::SessionId session_id_{};            ///< Session id from SERVER_HELLO.
    uint16_t selected_version_ = 0;            ///< Protocol version selected in SERVER_HELLO.
    uint8_t server_proof_algorithm_ = proto::kProofAlgorithmNone;  ///< Advertised in SERVER_HELLO.
    crypto::Sha256Digest th1_{};               ///< TH1; wiped on destruction.
};

}  // namespace sg::client
