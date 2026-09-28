#include "sockgate_common/protocol/rules.h"

namespace sg::proto {
namespace {

bool IsAuthenticatedPhase(Phase p) { return p == Phase::kActive || p == Phase::kRefreshing; }

}  // namespace

const char* PhaseName(Phase phase) noexcept
{
    switch (phase) {
    case Phase::kAwaitClientHello: return "await_client_hello";
    case Phase::kAwaitServerHello: return "await_server_hello";
    case Phase::kAwaitClientProof: return "await_client_proof";
    case Phase::kAwaitAuthResult: return "await_auth_result";
    case Phase::kActive: return "active";
    case Phase::kRefreshing: return "refreshing";
    case Phase::kClosed: return "closed";
    }
    return "unknown";
}

Status CheckHeaderForState(const FrameHeader& h, Role receiver, Phase phase, const FrameLimits& limits)
{
    if (phase == Phase::kClosed) return SG_PROTOCOL_ERROR;
    const bool authenticated = IsAuthenticatedPhase(phase);
    const bool server = receiver == Role::kServer;

    bool allowed = false;
    switch (h.type) {
    case MessageType::kClientHello:
        allowed = server && phase == Phase::kAwaitClientHello;
        break;
    case MessageType::kServerHello:
        allowed = !server && phase == Phase::kAwaitServerHello;
        break;
    case MessageType::kClientProof:
        allowed = server && phase == Phase::kAwaitClientProof;
        break;
    case MessageType::kAuthResult:
        // AwaitServerHello only for UNSUPPORTED_VERSION (checked by the handler).
        allowed = !server && (phase == Phase::kAwaitAuthResult || phase == Phase::kAwaitServerHello);
        break;
    case MessageType::kData:
    case MessageType::kPing:
    case MessageType::kPong:
        allowed = authenticated;
        break;
    case MessageType::kReauthRequest:
        allowed = server && phase == Phase::kActive;
        break;
    case MessageType::kReauthChallenge:
    case MessageType::kReauthResult:
        allowed = !server && phase == Phase::kRefreshing;
        break;
    case MessageType::kReauthProof:
        allowed = server && phase == Phase::kRefreshing;
        break;
    case MessageType::kClose:
        allowed = true;
        break;
    }
    if (!allowed) return SG_PROTOCOL_ERROR;

    // Authentication data is mandatory after authentication and forbidden before.
    if (h.auth_length != (authenticated ? kAuthTagSize : 0)) return SG_PROTOCOL_ERROR;

    if (!authenticated) {
        if (h.flags != 0) return SG_PROTOCOL_ERROR;
    } else {
        if ((h.flags & kFlagResponse) != 0 && h.type != MessageType::kData) return SG_PROTOCOL_ERROR;
        if ((h.flags & kFlagResponse) != 0 && h.request_id == 0) return SG_PROTOCOL_ERROR;
        if (h.type != MessageType::kData && h.request_id != 0) return SG_PROTOCOL_ERROR;
    }

    // Size limit depends on the connection phase, never on the type alone:
    // before authentication every frame is capped at the handshake limit.
    const uint32_t limit =
        (authenticated && h.type == MessageType::kData) ? limits.max_data_payload : kMaxHandshakePayload;
    if (h.payload_length > limit) return SG_PROTOCOL_ERROR;
    return OkStatus();
}

void MessageDispatcher::On(MessageType type, Handler handler)
{
    handlers_[static_cast<uint8_t>(type)] = std::move(handler);
}

Status MessageDispatcher::Dispatch(const DecodedFrame& frame) const
{
    const Handler& h = handlers_[static_cast<uint8_t>(frame.header().type)];
    if (!h) return SG_PROTOCOL_ERROR;
    return h(frame);
}

}  // namespace sg::proto
