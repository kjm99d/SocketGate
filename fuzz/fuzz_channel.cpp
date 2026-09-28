// Fuzz target: the protected session channel receiving arbitrary bytes
// (frame decoding + sequence / key phase / AEAD tag checks) under fixed
// session keys. Invariants: accepted frames carry strictly consecutive
// sequence numbers starting at kFirstSessionSequence, and once a frame is
// rejected the channel stays poisoned; nothing is accepted afterwards.
#include "fuzz_target.h"

#include "sockgate_common/protocol/channel.h"
#include "sockgate_common/protocol/frame.h"

#include <cstdlib>

using namespace sg;
using namespace sg::proto;

namespace {

void Check(bool condition)
{
    if (!condition) std::abort();
}

const Bytes& Km()
{
    static const Bytes km(32, 0x42);
    return km;
}

SessionId Sid()
{
    SessionId id{};
    id.fill(0x11);
    return id;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ProtectedChannel server(Role::kServer);
    Check(server.Initialize(Km(), Sid()).ok());
    FrameDecoder decoder([](const FrameHeader&) { return OkStatus(); });
    decoder.SetMaxBuffered(kPreAuthDecoderBuffer * 8);
    if (!decoder.Append(ByteView(data, size)).ok()) return 0;
    bool failed = false;
    uint64_t expected = kFirstSessionSequence;
    for (int i = 0; i < 64; ++i) {
        DecodedFrame frame;
        bool ready = false;
        if (!decoder.Next(&frame, &ready).ok() || !ready) break;
        const uint64_t sequence = frame.header().sequence;
        Bytes plaintext;
        const Status opened = server.Open(&frame, &plaintext);
        if (failed) Check(!opened.ok());  // poisoned channels never recover
        if (!opened.ok()) {
            failed = true;
            continue;
        }
        // No replay, reordering or gap is ever accepted.
        Check(sequence == expected);
        ++expected;
        Check(server.next_receive_sequence() == expected);
    }
    return 0;
}

std::vector<std::vector<uint8_t>> SockGateFuzzSeeds()
{
    std::vector<std::vector<uint8_t>> seeds;
    ProtectedChannel client(Role::kClient);
    if (!client.Initialize(Km(), Sid()).ok()) return seeds;
    std::vector<uint8_t> stream;
    auto seal = [&](MessageType type, const Bytes& payload, bool encrypt) {
        SealOptions options;
        options.encrypt = encrypt;
        Bytes frame;
        if (client.Seal(type, payload, options, &frame).ok()) {
            stream.insert(stream.end(), frame.begin(), frame.end());
        }
        // Each single-frame seed comes from a fresh channel, so it carries the
        // first sequence number and reaches the acceptance path on its own.
        ProtectedChannel single(Role::kClient);
        Bytes alone;
        if (single.Initialize(Km(), Sid()).ok() && single.Seal(type, payload, options, &alone).ok()) {
            seeds.push_back(alone);
        }
    };
    seal(MessageType::kData, Bytes{'h', 'e', 'l', 'l', 'o'}, false);
    seal(MessageType::kData, Bytes(100, 7), true);
    seal(MessageType::kPing, Bytes(8, 1), false);
    seal(MessageType::kData, Bytes(), true);
    seeds.push_back(stream);  // a valid sequence of frames
    return seeds;
}
