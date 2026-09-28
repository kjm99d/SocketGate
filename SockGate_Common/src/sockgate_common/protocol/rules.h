#pragma once
/**
 * @file
 * @brief State-dependent frame rules and a small message dispatcher.
 *
 * CheckHeaderForState() is used as the FrameDecoder header hook, so a frame
 * that is not allowed in the current state (wrong direction, wrong phase,
 * oversized for the phase, wrong auth length or flags) is rejected after its
 * 48 header bytes, before any of its body is buffered.
 */

#include "sockgate_common/protocol/frame.h"

#include <array>
#include <functional>

namespace sg::proto {

/** @brief Local endpoint role (selects the send / receive direction keys and the allowed frame types). */
enum class Role : uint8_t { kClient, /**< Client endpoint. */ kServer /**< Server endpoint. */ };

/**
 * @brief Receiver-side connection phase.
 *
 * kActive and kRefreshing are the authenticated phases; all others are pre-authentication.
 */
enum class Phase : uint8_t {
    kAwaitClientHello,  ///< Server: waiting for CLIENT_HELLO.
    kAwaitServerHello,  ///< Client: waiting for SERVER_HELLO (or AUTH_RESULT UNSUPPORTED_VERSION).
    kAwaitClientProof,  ///< Server: waiting for CLIENT_PROOF.
    kAwaitAuthResult,   ///< Client: waiting for AUTH_RESULT.
    kActive,            ///< Both: authenticated session.
    kRefreshing,        ///< Both: authenticated session with a reauthentication in progress.
    kClosed,            ///< Both: nothing is accepted any more.
};

/**
 * @brief Returns a log name for a phase ("await_client_hello", "active", ...).
 * @param[in] phase Phase.
 * @return Static string; "unknown" for an undefined value. Never nullptr.
 */
const char* PhaseName(Phase phase) noexcept;

/** @brief Configurable payload limits applied by CheckHeaderForState(). */
struct FrameLimits {
    /// DATA frames while authenticated, in bytes. Not clamped here; DecodeHeader() caps every frame at
    /// kAbsoluteMaxPayload.
    uint32_t max_data_payload = kDefaultMaxPayload;
};

/**
 * @brief Checks whether a frame header is acceptable for the receiver's role and phase.
 *
 * Rules, in order:
 * - kClosed accepts nothing.
 * - The type must be allowed for the receiver role and phase: CLIENT_HELLO (server, kAwaitClientHello),
 *   SERVER_HELLO (client, kAwaitServerHello), CLIENT_PROOF (server, kAwaitClientProof), AUTH_RESULT (client,
 *   kAwaitAuthResult or kAwaitServerHello), DATA / PING / PONG (either role, authenticated phases),
 *   REAUTH_REQUEST (server, kActive), REAUTH_CHALLENGE / REAUTH_RESULT (client, kRefreshing), REAUTH_PROOF
 *   (server, kRefreshing), CLOSE (any role and phase).
 * - auth_length is kAuthTagSize in authenticated phases and 0 before.
 * - Before authentication: flags == 0 and request_id == 0.
 * - After authentication: kFlagResponse only on DATA and only with request_id != 0; request_id != 0 only on
 *   DATA.
 * - The payload limit depends on the connection phase, never on the type alone: limits.max_data_payload for
 *   DATA in authenticated phases, kMaxHandshakePayload for everything else (including every frame before
 *   authentication).
 *
 * @param[in] header   Structurally valid header (DecodeHeader()).
 * @param[in] receiver Role of the local (receiving) endpoint.
 * @param[in] phase    Current receiver phase.
 * @param[in] limits   Payload limits.
 * @retval OK                A frame with this header may be received by @p receiver in @p phase.
 * @retval SG_PROTOCOL_ERROR Otherwise.
 * @note AUTH_RESULT in kAwaitServerHello is valid only for UNSUPPORTED_VERSION; the handler checks that.
 */
Status CheckHeaderForState(const FrameHeader& header, Role receiver, Phase phase, const FrameLimits& limits);

/**
 * @brief Routes decoded frames to per-type handlers.
 *
 * @note Not synchronised: On() and Dispatch() must not run concurrently.
 */
class MessageDispatcher {
public:
    /** @brief Handler for one message type; its status is returned by Dispatch(). */
    using Handler = std::function<Status(const DecodedFrame&)>;

    /**
     * @brief Registers (or replaces) the handler for @p type.
     * @param[in] type    Message type.
     * @param[in] handler Handler (moved in); an empty handler unregisters the type.
     */
    void On(MessageType type, Handler handler);
    /**
     * @brief Invokes the handler registered for the frame's type.
     * @param[in] frame Decoded frame.
     * @retval SG_PROTOCOL_ERROR No handler is registered for the frame's type.
     * @return Otherwise the handler's status.
     */
    Status Dispatch(const DecodedFrame& frame) const;

private:
    std::array<Handler, 256> handlers_;  ///< Indexed by the MessageType byte value.
};

}  // namespace sg::proto
