#pragma once
/**
 * @file
 * @brief Authenticated frame protection for established sessions
 * (docs/design/04-protocol-specification.md §7-§9).
 *
 * Every post-authentication frame carries:
 *   - a per-direction sequence number that must be exactly previous + 1
 *     (replay, duplication, reordering and deletion are all detected),
 *   - a 16-byte AES-256-GCM tag keyed per direction and epoch, with the
 *     48-byte header as AAD (payload too when not encrypted),
 *   - KEY_PHASE = epoch & 1, selecting the receive key during a key switch.
 *
 * The AEAD nonce (12 bytes) is u32(0) || u64(sequence), big endian; keys differ per direction and epoch and a
 * sequence number never repeats within a direction, so a nonce is never reused. The header is authenticated
 * with auth_length = 16 already filled in.
 *
 * Request ids of requests are strictly increasing per direction; responses
 * must refer to a request id the receiver actually issued (checked as: not above the highest request id the
 * receiver allocated or sent).
 *
 * Thread-safety: Seal() calls (send side) and Open() calls (receive side)
 * may run concurrently with each other, each side serialised by its owner.
 * They touch disjoint state except the poison flag and the request-id
 * high-water marks (ours and the peer's), which are atomic. SwitchSendKey needs the send lock,
 * SwitchReceiveKey/StageReceiveKey the receive lock; Initialize both.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/frame.h"
#include "sockgate_common/protocol/rules.h"

#include <atomic>

namespace sg::proto {

/**
 * @brief First sequence number after the two handshake frames of each direction.
 *
 * Handshake frames use sequence 1 and 2 in each direction; the ProtectedChannel starts at 3 on both sides.
 */
constexpr uint64_t kFirstSessionSequence = 3;

/** @brief Per-frame options for ProtectedChannel::Seal(). */
struct SealOptions {
    bool encrypt = false;          ///< Application-layer AEAD over the payload (sets kFlagEncrypted).
    uint64_t request_id = 0;       ///< DATA only; 0 = none.
    bool response = false;         ///< request_id refers to the peer's request (sets kFlagResponse; DATA only).
};

/**
 * @brief Per-session frame protection: sequence numbers, AES-256-GCM tags, optional payload encryption,
 * request-id rules and per-direction key switching (KEY_PHASE).
 *
 * Both directions start at epoch 0 with keys derived by DeriveChannelKeys() from the TLS exporter output
 * and the session id. The client sends with the c2s key and receives with the s2c key; the server the
 * reverse. Any receive-side verification failure, and exhaustion of the send sequence, poisons the channel:
 * every later Seal(), Open() and key switch returns SG_INVALID_STATE.
 *
 * @note See the file description for the locking contract. Keys are wiped when replaced and on destruction.
 */
class ProtectedChannel {
public:
    /**
     * @brief Creates an uninitialised channel.
     * @param[in] local_role Role of this endpoint; selects which derived key sends and which receives.
     */
    explicit ProtectedChannel(Role local_role) noexcept : role_(local_role) {}
    /** @brief Wipes the send, receive and staged keys. */
    ~ProtectedChannel();

    ProtectedChannel(const ProtectedChannel&) = delete;             ///< Not copyable (owns key material).
    ProtectedChannel& operator=(const ProtectedChannel&) = delete;  ///< Not copy-assignable.

    /**
     * @brief Installs epoch-0 keys derived from the TLS exporter output @p km.
     *
     * Requires both the send and the receive lock.
     *
     * @param[in] km         32-byte key material from the TLS exporter (kKeyExporterLabel, context TH1).
     * @param[in] session_id Session id; bound into every frame and used as the HKDF salt.
     * @retval OK                  Keys installed; both directions start at kFirstSessionSequence, epoch 0.
     * @retval SG_INVALID_STATE    Already initialised.
     * @retval SG_INVALID_ARGUMENT @p km is not 32 bytes.
     * @return Otherwise the key derivation error.
     */
    Status Initialize(ByteView km, const SessionId& session_id);

    // ---- sending (under the owner's send lock) ------------------------------
    /**
     * @brief Protects one outgoing frame and appends it to @p frame_out.
     *
     * Builds the header (session id, next send sequence, KEY_PHASE of the send epoch, auth_length = 16) and
     * computes the tag: with @c options.encrypt the payload is encrypted and the header is the AAD; otherwise
     * header || payload is the AAD and the payload is sent in the clear. The send sequence advances only on
     * success. A request (request_id != 0 without response) raises the high-water mark of our request ids.
     *
     * Responses must refer to a request id the peer actually sent
     * (SG_INVALID_ARGUMENT otherwise): the peer would reject them and drop
     * the session. The check is 0 < request_id <= the highest request id received from the peer.
     *
     * @param[in]     type      Message type.
     * @param[in]     payload   Plaintext payload.
     * @param[in]     options   Encryption, request id and response flag.
     * @param[in,out] frame_out The frame is appended; restored to its original size if sealing fails.
     * @retval OK                  Frame appended.
     * @retval SG_INVALID_ARGUMENT @p frame_out is nullptr, payload larger than kAbsoluteMaxPayload, request id
     *                             or response on a non-DATA type, or an invalid response request id.
     * @retval SG_INVALID_STATE    Not initialised, or poisoned.
     * @retval SG_SESSION_EXPIRED  The send sequence reached 2^64-1; the channel is poisoned.
     * @return Otherwise the AEAD error.
     * @note Only kAbsoluteMaxPayload is enforced here; the receiver also applies the limits of
     *       CheckHeaderForState() (kMaxHandshakePayload for non-DATA frames).
     */
    Status Seal(MessageType type, ByteView payload, const SealOptions& options, Bytes* frame_out);
    /**
     * @brief Allocates the next request id (strictly increasing, never 0).
     * @return One more than the current high-water mark of our request ids, which becomes the new mark.
     * @note The high-water mark is atomic; Open() reads it to validate responses.
     */
    uint64_t NextRequestId() noexcept;

    // ---- receiving (under the owner's receive lock) -------------------------
    /**
     * @brief Verifies one incoming authenticated frame and decrypts it in place.
     *
     * Verifies sequence, request id rules, KEY_PHASE and tag; decrypts the
     * payload in place when ENCRYPTED. On any verification failure the channel is poisoned.
     * Order of checks: auth_length, session id, sequence, KEY_PHASE (key selection), tag, then the request id
     * rules (only once the tag has established authenticity). A frame whose KEY_PHASE matches a staged key
     * (StageReceiveKey()) makes that key the receive key and wipes the old one. The message type is not
     * checked here (CheckHeaderForState()).
     *
     * @param[in,out] frame               Frame from FrameDecoder; its payload is replaced by the plaintext
     *                                    when kFlagEncrypted is set.
     * @param[out]    plaintext_frame_out Optional (nullptr to skip); receives F(x) = header || plaintext
     *                                    payload (tag excluded), as used by the reauthentication transcript.
     * @retval OK                  Frame authentic and in order; the receive sequence advanced.
     * @retval SG_INVALID_ARGUMENT @p frame is nullptr (the channel is not poisoned).
     * @retval SG_INVALID_STATE    Not initialised, or already poisoned.
     * @retval SG_REPLAY_DETECTED  Sequence below the expected one, or a request id not above the last request
     *                             id received from the peer (duplicate request).
     * @retval SG_PROTOCOL_ERROR   auth_length not 16, session id mismatch, sequence above the expected one,
     *                             KEY_PHASE matching no available key, tag verification failure, or a response
     *                             id above the high-water mark of our request ids.
     * @retval SG_SESSION_EXPIRED  Sequence 2^64-1.
     */
    Status Open(DecodedFrame* frame, Bytes* plaintext_frame_out = nullptr);

    // ---- key switching (04 §7.3) ---------------------------------------------
    /**
     * @brief Derives epoch @p epoch keys from @p km and switches the local send key.
     *
     * Frames sealed afterwards use the new key and carry KeyPhaseFlag(epoch). Requires the send lock.
     *
     * @param[in] km    32-byte TLS exporter output for the new epoch (context THr).
     * @param[in] epoch New epoch; must be send_epoch() + 1.
     * @retval OK                  Send key switched.
     * @retval SG_INVALID_STATE    Not initialised, or poisoned.
     * @retval SG_INVALID_ARGUMENT @p epoch is not send_epoch() + 1, or @p km is not 32 bytes.
     * @return Otherwise the key derivation error.
     */
    Status SwitchSendKey(ByteView km, uint32_t epoch);
    /**
     * @brief Client: the peer switched right after REAUTH_RESULT; switch receive now.
     *
     * Replaces the receive key immediately (no staging). Requires the receive lock.
     *
     * @param[in] km    32-byte TLS exporter output for the new epoch (context THr).
     * @param[in] epoch New epoch; must be receive_epoch() + 1.
     * @retval OK                  Receive key switched.
     * @retval SG_INVALID_STATE    Not initialised, or poisoned.
     * @retval SG_INVALID_ARGUMENT @p epoch is not receive_epoch() + 1, a key is staged, or @p km is not 32 bytes.
     * @return Otherwise the key derivation error.
     */
    Status SwitchReceiveKey(ByteView km, uint32_t epoch);
    /**
     * @brief Server: keep the current receive key until the first frame of the new
     * phase arrives, then drop it for good.
     *
     * Stages the new receive key; Open() selects between the current and the staged key by KEY_PHASE and
     * promotes the staged key on the first frame that uses it. After that, a frame of the old phase is a
     * protocol error. Requires the receive lock.
     *
     * @param[in] km    32-byte TLS exporter output for the new epoch (context THr).
     * @param[in] epoch New epoch; must be receive_epoch() + 1.
     * @retval OK                  Key staged.
     * @retval SG_INVALID_STATE    Not initialised, or poisoned.
     * @retval SG_INVALID_ARGUMENT @p epoch is not receive_epoch() + 1, a key is already staged, or @p km is not
     *                             32 bytes.
     * @return Otherwise the key derivation error.
     */
    Status StageReceiveKey(ByteView km, uint32_t epoch);
    /** @brief Staging state (receive side). @return True while a staged key waits for its first frame. */
    bool HasStagedReceiveKey() const noexcept { return has_staged_; }

    /** @brief Send epoch (send side). @return Epoch of the current send key. */
    uint32_t send_epoch() const noexcept { return send_epoch_; }
    /**
     * @brief Receive epoch (receive side).
     * @return Epoch of the current receive key; a staged key is not counted until promoted.
     */
    uint32_t receive_epoch() const noexcept { return recv_epoch_; }
    /** @brief Next send sequence (send side). @return Sequence number the next sealed frame will carry. */
    uint64_t next_send_sequence() const noexcept { return next_send_seq_; }
    /**
     * @brief Next receive sequence (receive side).
     * @return Sequence number the next opened frame must carry.
     */
    uint64_t next_receive_sequence() const noexcept { return next_recv_seq_; }
    /** @brief Initialisation state. @return True once Initialize() succeeded. */
    bool initialized() const noexcept { return initialized_; }
    /** @brief Session id. @return Session id set by Initialize() (all zero before). */
    const SessionId& session_id() const noexcept { return session_id_; }

private:
    /**
     * @brief Derives the epoch @p epoch keys and assigns c2s / s2c to @p send / @p recv according to role_.
     * @param[in]  km    32-byte TLS exporter output.
     * @param[in]  epoch Key epoch.
     * @param[out] send  Receives the key this role sends with.
     * @param[out] recv  Receives the key this role receives with.
     * @return DeriveChannelKeys() status.
     */
    Status DeriveForRole(ByteView km, uint32_t epoch, crypto::AeadKey* send, crypto::AeadKey* recv) const;
    /**
     * @brief Marks the channel poisoned, wipes the receive and staged keys, and returns @p s.
     *
     * Receive side only; the send key is left to the destructor (a concurrent Seal() may still use it).
     * @param[in] s Error to return.
     * @return @p s.
     */
    Status Poison(Status s) noexcept;

    const Role role_;                ///< Local role.
    bool initialized_ = false;       ///< Initialize() succeeded.
    std::atomic<bool> poisoned_{false};  ///< Terminal failure; shared by both sides.
    SessionId session_id_{};         ///< Session id checked on every received frame.

    crypto::AeadKey send_key_{};                ///< Send key of send_epoch_.
    uint32_t send_epoch_ = 0;                   ///< Current send epoch.
    uint64_t next_send_seq_ = kFirstSessionSequence;  ///< Next send sequence number.
    std::atomic<uint64_t> last_request_id_{0};  ///< Ids issued by us (high-water mark); read by Open().

    crypto::AeadKey recv_key_{};                ///< Receive key of recv_epoch_.
    uint32_t recv_epoch_ = 0;                   ///< Current receive epoch.
    uint64_t next_recv_seq_ = kFirstSessionSequence;  ///< Expected receive sequence number.
    /// Highest request id received from the peer; read by Seal() for response validation.
    std::atomic<uint64_t> last_peer_request_id_{0};

    bool has_staged_ = false;        ///< staged_key_ is valid.
    crypto::AeadKey staged_key_{};   ///< Next-epoch receive key awaiting its first frame (server).
    uint32_t staged_epoch_ = 0;      ///< Epoch of staged_key_.
};

/**
 * @brief KEY_PHASE flag value for an epoch.
 * @param[in] epoch Key epoch.
 * @return kFlagKeyPhase for an odd epoch, 0 for an even one.
 */
constexpr uint16_t KeyPhaseFlag(uint32_t epoch) noexcept { return (epoch & 1u) != 0 ? kFlagKeyPhase : 0; }

}  // namespace sg::proto
