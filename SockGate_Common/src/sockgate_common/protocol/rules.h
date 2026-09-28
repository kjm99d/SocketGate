// State-dependent frame rules and a small message dispatcher.
//
// CheckHeaderForState() is used as the FrameDecoder header hook, so a frame
// that is not allowed in the current state (wrong direction, wrong phase,
// oversized for the phase, wrong auth length or flags) is rejected after its
// 48 header bytes, before any of its body is buffered.
#pragma once

#include "sockgate_common/protocol/frame.h"

#include <array>
#include <functional>

namespace sg::proto {

enum class Role : uint8_t { kClient, kServer };

// Receiver-side connection phase.
enum class Phase : uint8_t {
    kAwaitClientHello,  // server
    kAwaitServerHello,  // client
    kAwaitClientProof,  // server
    kAwaitAuthResult,   // client
    kActive,            // both
    kRefreshing,        // both
    kClosed,            // both: nothing is accepted any more
};

const char* PhaseName(Phase phase) noexcept;

struct FrameLimits {
    uint32_t max_data_payload = kDefaultMaxPayload;  // DATA frames while authenticated
};

// Returns OK if a frame with this header may be received by `receiver` in
// `phase`; SG_PROTOCOL_ERROR otherwise.
Status CheckHeaderForState(const FrameHeader& header, Role receiver, Phase phase, const FrameLimits& limits);

// Routes decoded frames to per-type handlers.
class MessageDispatcher {
public:
    using Handler = std::function<Status(const DecodedFrame&)>;

    void On(MessageType type, Handler handler);
    // SG_PROTOCOL_ERROR when no handler is registered for the frame's type.
    Status Dispatch(const DecodedFrame& frame) const;

private:
    std::array<Handler, 256> handlers_;
};

}  // namespace sg::proto
