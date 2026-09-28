// Fuzz target: streaming frame decoder + per-state header rules + message
// dispatcher (every decoded frame is routed to its payload decoder).
//
// Input layout: byte 0 selects receiver role/phase and data-size limit,
// byte 1 selects the chunking pattern, the rest is the byte stream.
#include "fuzz_target.h"

#include "sockgate_common/protocol/frame.h"
#include "sockgate_common/protocol/messages.h"
#include "sockgate_common/protocol/rules.h"

#include <cstdlib>

using namespace sg;
using namespace sg::proto;

namespace {

struct Mode {
    Role role;
    Phase phase;
};

constexpr Mode kModes[] = {
    {Role::kServer, Phase::kAwaitClientHello}, {Role::kServer, Phase::kAwaitClientProof},
    {Role::kServer, Phase::kActive},           {Role::kServer, Phase::kRefreshing},
    {Role::kClient, Phase::kAwaitServerHello}, {Role::kClient, Phase::kAwaitAuthResult},
    {Role::kClient, Phase::kActive},           {Role::kClient, Phase::kRefreshing},
};

MessageDispatcher BuildDispatcher()
{
    MessageDispatcher d;
    d.On(MessageType::kClientHello, [](const DecodedFrame& f) { ClientHello m; return DecodeClientHello(f.payload(), &m); });
    d.On(MessageType::kServerHello, [](const DecodedFrame& f) { ServerHello m; return DecodeServerHello(f.payload(), &m); });
    d.On(MessageType::kClientProof, [](const DecodedFrame& f) { ClientProof m; return DecodeClientProof(f.payload(), &m); });
    d.On(MessageType::kAuthResult, [](const DecodedFrame& f) { AuthResult m; return DecodeAuthResult(f.payload(), &m); });
    d.On(MessageType::kPing, [](const DecodedFrame& f) { PingPong m; return DecodePingPong(f.payload(), &m); });
    d.On(MessageType::kPong, [](const DecodedFrame& f) { PingPong m; return DecodePingPong(f.payload(), &m); });
    d.On(MessageType::kReauthRequest, [](const DecodedFrame& f) { ReauthRequest m; return DecodeReauthRequest(f.payload(), &m); });
    d.On(MessageType::kReauthChallenge, [](const DecodedFrame& f) { ReauthChallenge m; return DecodeReauthChallenge(f.payload(), &m); });
    d.On(MessageType::kReauthProof, [](const DecodedFrame& f) { ReauthProof m; return DecodeReauthProof(f.payload(), &m); });
    d.On(MessageType::kReauthResult, [](const DecodedFrame& f) { ReauthResult m; return DecodeReauthResult(f.payload(), &m); });
    d.On(MessageType::kClose, [](const DecodedFrame& f) { CloseMessage m; return DecodeClose(f.payload(), &m); });
    d.On(MessageType::kData, [](const DecodedFrame&) { return OkStatus(); });
    return d;
}

void Check(bool condition)
{
    if (!condition) std::abort();  // invariant violation: report as a crash
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2) return 0;
    const Mode mode = kModes[data[0] % (sizeof(kModes) / sizeof(kModes[0]))];
    FrameLimits limits;
    limits.max_data_payload = (data[0] & 0x80) ? 64 : kDefaultMaxPayload;
    const size_t chunk_seed = data[1];
    data += 2;
    size -= 2;

    static const MessageDispatcher dispatcher = BuildDispatcher();
    FrameDecoder decoder([&](const FrameHeader& h) { return CheckHeaderForState(h, mode.role, mode.phase, limits); });

    size_t offset = 0;
    size_t step = 1 + chunk_seed % 97;
    while (offset < size) {
        const size_t n = std::min(step, size - offset);
        if (!decoder.Append(ByteView(data + offset, n)).ok()) return 0;
        offset += n;
        step = 1 + (step * 31 + 7) % 257;
        for (;;) {
            DecodedFrame frame;
            bool ready = false;
            if (!decoder.Next(&frame, &ready).ok()) return 0;
            if (!ready) break;
            // Invariants that must hold for every accepted frame.
            const FrameHeader& h = frame.header();
            Check(frame.wire().size() == kHeaderSize + h.payload_length + h.auth_length);
            Check(h.payload_length <= kAbsoluteMaxPayload);
            Check(CheckHeaderForState(h, mode.role, mode.phase, limits).ok());
            (void)dispatcher.Dispatch(frame);
        }
    }
    return 0;
}

std::vector<std::vector<uint8_t>> SockGateFuzzSeeds()
{
    std::vector<std::vector<uint8_t>> seeds;
    auto add = [&](uint8_t mode, MessageType type, const Bytes& payload, uint16_t auth, uint16_t flags = 0) {
        FrameHeader h;
        h.type = type;
        h.flags = flags;
        h.sequence = 1;
        Bytes wire = {mode, 13};
        Bytes tag(auth, 0xAB);
        (void)EncodeFrame(h, payload, tag, &wire);
        seeds.push_back(wire);
    };
    ClientHello ch;
    ch.product_id = "p";
    ch.has_requested_features = true;
    Bytes chw;
    (void)EncodeClientHello(ch, &chw);
    add(0, MessageType::kClientHello, chw, 0);

    ServerHello sh;
    sh.challenge_ttl_ms = 1000;
    Bytes shw;
    (void)EncodeServerHello(sh, &shw);
    add(4, MessageType::kServerHello, shw, 0);

    ClientProof cp;
    Bytes cpw;
    (void)EncodeClientProof(cp, &cpw);
    add(1, MessageType::kClientProof, cpw, 0);

    AuthResult ar;
    ar.result = AuthResultCode::kOk;
    ar.policy = SessionPolicy::kNormal;
    ar.session_lifetime_ms = 1;
    Bytes arw;
    (void)EncodeAuthResult(ar, &arw);
    add(5, MessageType::kAuthResult, arw, 0);

    Bytes ping;
    (void)EncodePingPong({7}, &ping);
    add(2, MessageType::kPing, ping, kAuthTagSize);
    add(6, MessageType::kData, Bytes(32, 0x41), kAuthTagSize, kFlagEncrypted);

    ReauthChallenge rc;
    rc.challenge_ttl_ms = 5;
    Bytes rcw;
    (void)EncodeReauthChallenge(rc, &rcw);
    add(7, MessageType::kReauthChallenge, rcw, kAuthTagSize);

    Bytes close;
    (void)EncodeClose({CloseReason::kNormal}, &close);
    add(0, MessageType::kClose, close, 0);
    return seeds;
}
