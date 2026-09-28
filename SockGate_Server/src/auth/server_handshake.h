#pragma once
/**
 * @file
 * @brief Server side of the SockGate authentication handshake (sans-IO).
 *
 *     OnClientHello()  -> SERVER_HELLO (fresh session id, nonce, single-use challenge)
 *                         or AUTH_RESULT(UNSUPPORTED_VERSION)
 *     OnClientProof()  -> AUTH_RESULT (OK or a generic REJECTED)
 *
 * Rejections are deliberately indistinguishable on the wire; the precise
 * reason is available through failure_reason() for server logs.
 */

#include "auth/authorizer.h"
#include "storage/client_registry.h"

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/protocol/frame.h"
#include "sockgate_common/protocol/messages.h"
#include "sockgate_common/protocol/rules.h"

#include <functional>
#include <memory>
#include <string>

namespace sg::server {

/**
 * @brief Input of an external enrollment validator (EnrollValidator).
 *
 * @warning Every field except the peer address comes from the client's CLIENT_HELLO and is unverified when the
 *          validator runs: the channel-bound token proof, the key-derived installation id and the signature
 *          are checked only after the validator returned K_tok.
 */
struct EnrollmentRequest {
    proto::InstallationId installation_id{};  ///< Claimed installation id.
    crypto::P256PublicKey public_key{};       ///< Public key the client wants to enroll.
    Bytes token_pub;          ///< Public part of the enrollment token as sent by the client.
    std::string product_id;   ///< Client claim from CLIENT_HELLO (may be empty).
    std::string license_id;   ///< Client claim from CLIENT_HELLO (may be empty).
    std::string peer_address; ///< Peer address of the connection.
};

/**
 * @brief External enrollment validation: returns OK and the token's K_tok, or an error to reject.
 *
 * It is responsible for any single-use tracking of its own. In addition, the handshake consumes a token id
 * derived from SHA-256(token_pub) in the registry (IClientRegistry::EnrollAtomically), so the same token_pub
 * cannot enroll twice in that registry (an in-memory registry forgets consumed tokens on restart). When a
 * validator is configured it replaces the built-in token checks (expiry, issue time, lifetime, claim match).
 * The client must then prove possession of K_tok over the channel-bound transcript; K_tok is wiped after use.
 *
 * @warning An installation enrolled through a validator is registered with the client's claimed product id as
 *          its product binding and with no license binding (the license claim only goes through authorization).
 *
 * @note Runs on an I/O worker thread without any connection lock held.
 */
using EnrollValidator = std::function<Status(const EnrollmentRequest&, crypto::Sha256Digest* k_tok)>;

/** @brief Handshake settings shared by every connection of a server (validated by ServerAuthContext::Create). */
struct HandshakeConfig {
    uint32_t challenge_ttl_ms = 30'000;  ///< Validity of a handshake or reauthentication challenge; non-zero.
    uint32_t default_session_lifetime_ms = 3'600'000;  ///< Lifetime when the decision asks for 0; non-zero.
    uint32_t max_session_lifetime_ms = 7u * 24 * 3'600'000;  ///< Upper bound; >= default_session_lifetime_ms.
    uint16_t min_protocol_version = proto::kMinProtocolVersion;  ///< Lowest accepted version; non-zero.
    uint16_t max_protocol_version = proto::kMaxProtocolVersion;  ///< Highest accepted version; >= the minimum.
    bool allow_enrollment = false;  ///< Accept ENROLL requests; otherwise enrollment is rejected.
    /** Secret, >= 32 bytes, enables built-in enrollment tokens (K_tok derivation). Empty: built-in tokens fail. */
    SecureBytes token_key;
    /** Optional server proof key; when set, AUTH_RESULT(OK) carries a signature over the server transcript. */
    std::shared_ptr<const crypto::SoftwareP256Key> proof_key;
    EnrollValidator enroll_validator;  ///< Optional; replaces built-in token validation (see EnrollValidator).
    // Injectable clocks (tests); default to the real monotonic / wall clocks.
    std::function<uint64_t()> monotonic_ms;  ///< Monotonic clock in ms (challenge freshness).
    std::function<uint64_t()> unix_ms;       ///< Wall clock in Unix ms (token and license expiry).
};

/**
 * @brief Shared by all connections of a server.
 *
 * @note Immutable after Create(); shared read-only by every connection through a
 *       `std::shared_ptr<const ServerAuthContext>`. The registry and authorizer are not owned and must
 *       outlive every handshake that uses the context.
 */
struct ServerAuthContext {
    HandshakeConfig config;                ///< Validated handshake settings.
    IClientRegistry* registry = nullptr;   ///< Installation registry (not owned).
    IAuthorizer* authorizer = nullptr;     ///< Authorization policy (not owned).
    crypto::P256PublicKey dummy_key{};     ///< Verification target for unknown installations (timing).

    /**
     * @brief Validates @p config and creates a context.
     *
     * Also generates the throw-away #dummy_key: signatures checked against it always fail but cost the same
     * as a real verification.
     *
     * @param[in]  config     Handshake settings (moved in).
     * @param[in]  registry   Installation registry; must not be null.
     * @param[in]  authorizer Authorization policy; must not be null.
     * @param[out] out        Receives the new context.
     * @retval SG_OK               Created.
     * @retval SG_INVALID_ARGUMENT A null argument, a zero challenge TTL or default lifetime, a maximum lifetime
     *                             below the default, a zero or inverted protocol version range, or a non-empty
     *                             token key shorter than 32 bytes.
     * @retval other               Key generation failures.
     */
    static Status Create(HandshakeConfig config, IClientRegistry* registry, IAuthorizer* authorizer,
                         std::shared_ptr<ServerAuthContext>* out);

    /** @brief Monotonic time. @return Milliseconds from config.monotonic_ms if set, else MonotonicMs(). */
    uint64_t Now() const;
    /** @brief Wall-clock time. @return Unix ms from config.unix_ms if set, else UnixTimeMs(). */
    uint64_t UnixNow() const;
};

/** @brief Result of a successful OnClientProof(): the verified identity and the authorization of the session. */
struct HandshakeOutcome {
    proto::SessionId session_id{};            ///< Session id assigned in SERVER_HELLO.
    proto::InstallationId installation_id{};  ///< Verified installation id.
    crypto::Sha256Digest transcript_hash{};  ///< TH1.
    crypto::Sha256Digest channel_binding{};  ///< TLS channel binding the handshake was bound to.
    uint16_t protocol_version = proto::kProtocolVersion;  ///< Negotiated protocol version.
    ClientRecord record;                      ///< Registry record used for verification (or just enrolled).
    AuthorizationDecision decision;           ///< Authorization decision (allowed).
    uint32_t session_lifetime_ms = 0;         ///< Effective session lifetime sent to the client (>= 1).
    bool enrolled = false;                    ///< True if this handshake enrolled the installation.
    /** The client's CLIENT_HELLO; its product, license, feature and integrity fields are claims. */
    proto::ClientHello hello;
};

/**
 * @brief Server handshake state machine for one connection (sans-IO: consumes decoded frames, produces reply
 *        frames).
 *
 * Phases: kAwaitClientHello -> kAwaitClientProof -> kActive. Any failure moves to kClosed; exactly one
 * authentication attempt is possible per connection.
 *
 * @note Not thread-safe; the owning connection drives it from one thread at a time. OnClientProof() calls the
 *       registry, the authorizer and an EnrollValidator, i.e. application code: do not call it while holding
 *       a lock that application code may need.
 */
class ServerHandshake {
public:
    /**
     * @brief Creates a handshake in phase kAwaitClientHello.
     * @param[in] context Shared server context (kept alive by the handshake).
     */
    explicit ServerHandshake(std::shared_ptr<const ServerAuthContext> context);
    /** @brief Wipes the challenge and the channel binding. */
    ~ServerHandshake();

    ServerHandshake(const ServerHandshake&) = delete;
    ServerHandshake& operator=(const ServerHandshake&) = delete;

    /**
     * @brief Processes CLIENT_HELLO: negotiates the version and issues SERVER_HELLO with a fresh session id,
     *        server nonce and single-use challenge.
     *
     * The challenge is issued even for unknown installations (no enumeration oracle). Once the argument and
     * phase checks passed, any non-OK result leaves the handshake in phase kClosed.
     *
     * @param[in]  frame           Decoded CLIENT_HELLO frame (sequence 1, zero session id).
     * @param[in]  channel_binding TLS channel binding of the connection.
     * @param[in]  peer_address    Peer address (for logs and the authorization request).
     * @param[out] reply           Receives the reply frame; cleared first.
     * @retval SG_OK               *reply holds SERVER_HELLO.
     * @retval SG_VERSION_MISMATCH *reply holds AUTH_RESULT(UNSUPPORTED_VERSION), close afterwards.
     * @retval SG_INVALID_ARGUMENT @p reply is null.
     * @retval other               Protocol violation (wrong phase, type, sequence or session id; malformed
     *                             message) or internal failure: close without reply.
     */
    Status OnClientHello(const proto::DecodedFrame& frame, const crypto::Sha256Digest& channel_binding,
                         const std::string& peer_address, Bytes* reply);

    /**
     * @brief Processes CLIENT_PROOF: verifies the client's proof (or enrollment) and asks the authorizer.
     *
     * Once the argument and phase checks passed, the handshake leaves phase kAwaitClientProof for good (kActive
     * on success, kClosed otherwise): exactly one authentication attempt per connection. The challenge is
     * consumed before any verification, so it can never be retried. Unknown or revoked
     * installations are verified against ServerAuthContext::dummy_key so that the response time does not
     * reveal registry membership. The client's claims never grant anything by themselves: the authorizer
     * decides. The lifetime sent to the client is the decision's (or the default), capped by the configured
     * maximum and by the remaining license validity.
     *
     * @warning In enrollment mode the installation is registered and its token consumed before authorization
     *          runs; a later denial does not undo the registration. An allowed authorization may already have
     *          taken a license seat; on OK this is reported in `outcome->decision.seat_newly_taken`, and
     *          Connection gives it back through ServerEngine::ReleaseNewSeat() when it rejects the session
     *          afterwards.
     *
     * @param[in]  frame   Decoded CLIENT_PROOF frame (sequence 2, the assigned session id).
     * @param[out] reply   Receives the reply frame; cleared first.
     * @param[out] outcome Filled on success (and may be partly written otherwise).
     * @retval SG_OK               Authenticated: *reply holds AUTH_RESULT(OK), *outcome filled.
     * @retval SG_AUTH_FAILED      *reply holds AUTH_RESULT(REJECTED), close afterwards; failure_reason() says
     *                             why (unknown or revoked installation, bad signature, expired challenge,
     *                             enrollment failure, authorization denied, invalid policy, expired license).
     * @retval SG_INVALID_ARGUMENT @p reply or @p outcome is null.
     * @retval other               Protocol violation (wrong phase, type, sequence or session id; enrollment
     *                             proof not matching the auth mode; malformed message) or internal failure:
     *                             close without reply. Internal failures during enrollment verification are
     *                             rejections instead (SG_AUTH_FAILED with AUTH_RESULT(REJECTED)).
     */
    Status OnClientProof(const proto::DecodedFrame& frame, Bytes* reply, HandshakeOutcome* outcome);

    /**
     * @brief Replaces a successful outcome with AUTH_RESULT(REJECTED) in *reply; returns SG_AUTH_FAILED.
     *
     * Records @p reason as failure_reason() and moves to phase kClosed.
     *
     * @param[in]  reason Log-only reason.
     * @param[out] reply  Receives AUTH_RESULT(REJECTED); must not be null.
     * @retval SG_AUTH_FAILED The rejection frame is in *reply.
     * @retval other          Encoding failure.
     */
    Status Reject(const std::string& reason, Bytes* reply);

    /**
     * @brief Sets the session handle passed to the authorizer (AuthorizationRequest::session_handle).
     * @param[in] handle Handle of the owning connection.
     */
    void set_session_handle(uint64_t handle) noexcept { session_handle_ = handle; }
    /** @brief Current handshake phase. @return The phase. */
    proto::Phase phase() const noexcept { return phase_; }
    /**
     * @brief Precise reason of the last rejection, for server logs only (never sent to the client).
     * @return The reason (empty if none).
     */
    const std::string& failure_reason() const noexcept { return failure_reason_; }
    /** @brief Session id issued in SERVER_HELLO. @return The id (all zero before). */
    const proto::SessionId& session_id() const noexcept { return session_id_; }
    /**
     * @brief Installation id from CLIENT_HELLO.
     * @return The claimed id.
     * @warning A client claim; verified only once OnClientProof() returned OK.
     */
    const proto::InstallationId& claimed_installation_id() const noexcept { return hello_.installation_id; }

private:
    /**
     * @brief Verifies an enrollment and registers the installation.
     *
     * Steps: K_tok from the EnrollValidator or re-derived from the token key; channel-bound proof of token
     * possession; built-in token claims (expiry, issue time, lifetime, product and license match); installation
     * id derived from the enrolled key; proof of possession of the private key; then the token is consumed and
     * the installation registered atomically. Built-in tokens carry server-issued bindings; an external
     * validator only approves the token.
     *
     * @param[in]  proof       Decoded CLIENT_PROOF.
     * @param[in]  th1         Transcript hash TH1.
     * @param[in]  signed_data Data the client signed.
     * @param[out] record      Receives the registered record.
     * @retval SG_OK          Enrolled and registered.
     * @retval SG_AUTH_FAILED Rejected; failure_reason_ is set.
     * @retval other          Internal (cryptographic) failure.
     */
    Status VerifyEnrollment(const proto::ClientProof& proof, const crypto::Sha256Digest& th1,
                            const Bytes& signed_data, ClientRecord* record);
    /**
     * @brief Encodes AUTH_RESULT(OK) and, with a proof key, signs the server transcript TH2 into it.
     * @param[in]  decision    Allowed decision (policy, features, license expiry).
     * @param[in]  lifetime_ms Effective session lifetime.
     * @param[in]  proof_frame The CLIENT_PROOF frame (part of TH2).
     * @param[in]  th1         Transcript hash TH1.
     * @param[out] reply       Receives the frame.
     * @retval SG_OK The frame is in *reply.
     * @retval other Encoding or signing failure.
     */
    Status BuildAuthResult(const AuthorizationDecision& decision, uint32_t lifetime_ms,
                           const proto::DecodedFrame& proof_frame, const crypto::Sha256Digest& th1, Bytes* reply);

    std::shared_ptr<const ServerAuthContext> ctx_;  ///< Shared server context.
    proto::Phase phase_ = proto::Phase::kAwaitClientHello;  ///< Current phase.
    std::string failure_reason_;  ///< Log-only reason of the last rejection.

    std::string peer_address_;      ///< Peer address given to OnClientHello().
    proto::ClientHello hello_;      ///< Decoded CLIENT_HELLO (client claims).
    Bytes client_hello_frame_;      ///< CLIENT_HELLO wire bytes (transcript input).
    Bytes server_hello_frame_;      ///< SERVER_HELLO wire bytes (transcript input).
    crypto::Sha256Digest channel_binding_{};  ///< TLS channel binding (wiped on destruction).
    proto::SessionId session_id_{};           ///< Session id issued in SERVER_HELLO.
    proto::Challenge challenge_{};            ///< Single-use challenge (wiped on destruction).
    uint64_t challenge_issued_at_ = 0;        ///< Monotonic ms at which the challenge was issued.
    bool challenge_consumed_ = false;         ///< The challenge was used by a proof attempt.
    uint16_t selected_version_ = 0;           ///< Negotiated protocol version.
    uint64_t session_handle_ = 0;             ///< Handle passed to the authorizer.
};

/**
 * @brief Generates a random, non-zero session id.
 * @param[out] out Receives the session id.
 * @retval SG_OK Generated.
 * @retval other Random number generator failure.
 */
Status GenerateSessionId(proto::SessionId* out);

}  // namespace sg::server
