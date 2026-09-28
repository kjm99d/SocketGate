// Phase 5: post-authentication frame protection (sequence, tags, key phases).
#include "sg_test.h"

#include "sockgate_common/protocol/channel.h"

#include <algorithm>
#include <cstring>
#include <iterator>

using namespace sg;
using namespace sg::proto;

namespace {

struct Pair {
    ProtectedChannel client{Role::kClient};
    ProtectedChannel server{Role::kServer};
    Bytes km = Bytes(32, 0);
    SessionId sid{};

    Pair()
    {
        SG_ASSERT_OK(crypto::RandomBytes(km.data(), km.size()));
        SG_ASSERT_OK(crypto::RandomArray(&sid));
        SG_ASSERT_OK(client.Initialize(km, sid));
        SG_ASSERT_OK(server.Initialize(km, sid));
    }
};

DecodedFrame Decode(const Bytes& wire)
{
    FrameDecoder d([](const FrameHeader&) { return OkStatus(); });
    SG_ASSERT_OK(d.Append(wire));
    DecodedFrame f;
    bool ready = false;
    SG_ASSERT_OK(d.Next(&f, &ready));
    SG_ASSERT(ready);
    return f;
}

Bytes SealData(ProtectedChannel& ch, const std::string& text, SealOptions opts = SealOptions())
{
    Bytes out;
    SG_ASSERT_OK(ch.Seal(MessageType::kData, ByteView(reinterpret_cast<const uint8_t*>(text.data()), text.size()),
                         opts, &out));
    return out;
}

std::string PayloadText(const DecodedFrame& f) { return std::string(f.payload().begin(), f.payload().end()); }

}  // namespace

SG_TEST(Channel, RoundTripPlainAndEncrypted)
{
    Pair p;
    DecodedFrame f = Decode(SealData(p.client, "hello"));
    SG_ASSERT_OK(p.server.Open(&f));
    SG_EXPECT_EQ(PayloadText(f), std::string("hello"));
    SG_EXPECT_EQ(f.header().sequence, kFirstSessionSequence);

    SealOptions enc;
    enc.encrypt = true;
    const Bytes wire = SealData(p.server, "secret reply", enc);
    // The plaintext does not appear on the wire.
    static const char kNeedle[] = "secret";
    SG_EXPECT(std::search(wire.begin(), wire.end(), kNeedle, kNeedle + sizeof(kNeedle) - 1) == wire.end());
    DecodedFrame g = Decode(wire);
    SG_ASSERT_OK(p.client.Open(&g));
    SG_EXPECT_EQ(PayloadText(g), std::string("secret reply"));
    SG_EXPECT(g.header().flags & kFlagEncrypted);
}

SG_TEST(Channel, ReplayAndDuplicationDetected)
{
    Pair p;
    const Bytes wire = SealData(p.client, "once");
    DecodedFrame a = Decode(wire);
    SG_ASSERT_OK(p.server.Open(&a));
    DecodedFrame again = Decode(wire);
    SG_EXPECT_STATUS(p.server.Open(&again), SG_REPLAY_DETECTED);
}

SG_TEST(Channel, ReorderingAndDeletionDetected)
{
    {
        Pair p;
        const Bytes first = SealData(p.client, "1");
        const Bytes second = SealData(p.client, "2");
        DecodedFrame f2 = Decode(second);
        SG_EXPECT_STATUS(p.server.Open(&f2), SG_PROTOCOL_ERROR);  // arrives before "1"
        (void)first;
    }
    {
        Pair p;
        (void)SealData(p.client, "dropped");
        DecodedFrame f = Decode(SealData(p.client, "after-gap"));
        SG_EXPECT_STATUS(p.server.Open(&f), SG_PROTOCOL_ERROR);
    }
}

SG_TEST(Channel, AnyModificationIsRejected)
{
    const size_t offsets[] = {
        5,                 // type
        7,                 // flags (low byte)
        8,                 // session id
        31,                // sequence low byte (becomes a gap or replay)
        39,                // request id low byte
        kHeaderSize,       // first payload byte
        kHeaderSize + 4,   // last payload byte
        kHeaderSize + 5,   // tag
    };
    for (size_t off : offsets) {
        Pair p;
        Bytes wire = SealData(p.client, "abcde");
        wire[off] ^= 0x01;
        FrameDecoder d([](const FrameHeader&) { return OkStatus(); });
        if (!d.Append(wire).ok()) continue;
        DecodedFrame f;
        bool ready = false;
        if (!d.Next(&f, &ready).ok() || !ready) continue;  // structurally invalid is also a rejection
        const Status st = p.server.Open(&f);
        if (st.ok()) sgtest::ReportFailure(__FILE__, __LINE__, "modification at offset " + std::to_string(off) + " accepted");
        // After a failure the channel is poisoned for good.
        DecodedFrame valid = Decode(SealData(p.client, "next"));
        SG_EXPECT(!p.server.Open(&valid).ok());
    }
}

SG_TEST(Channel, CrossSessionAndReflectionRejected)
{
    Pair a;
    Pair b;
    // Frame from session A injected into session B.
    DecodedFrame injected = Decode(SealData(a.client, "x"));
    SG_EXPECT(!b.server.Open(&injected).ok());

    // Server-to-client frame reflected back to the server: direction keys differ.
    Pair p;
    DecodedFrame reflected = Decode(SealData(p.server, "reflect"));
    SG_EXPECT_STATUS(p.server.Open(&reflected), SG_PROTOCOL_ERROR);
}

SG_TEST(Channel, RequestIdRules)
{
    Pair p;
    SealOptions req;
    req.request_id = p.client.NextRequestId();
    DecodedFrame r1 = Decode(SealData(p.client, "req1", req));
    SG_ASSERT_OK(p.server.Open(&r1));

    // Server responds to request 1.
    SealOptions resp;
    resp.request_id = r1.header().request_id;
    resp.response = true;
    DecodedFrame answer = Decode(SealData(p.server, "resp1", resp));
    SG_ASSERT_OK(p.client.Open(&answer));

    // A response to a request the peer never sent is refused by the sender...
    SealOptions bogus;
    bogus.request_id = 999;
    bogus.response = true;
    Bytes refused;
    SG_EXPECT_STATUS(p.server.Seal(MessageType::kData, ByteView(), bogus, &refused), SG_INVALID_ARGUMENT);
    // ...and by the receiver when a misbehaving peer sends it anyway. A shadow
    // server channel (same keys) that did receive request 999 from a shadow
    // client produces a correctly sealed response the real client never asked for.
    ProtectedChannel shadow_client(Role::kClient);
    ProtectedChannel shadow_server(Role::kServer);
    SG_ASSERT_OK(shadow_client.Initialize(p.km, p.sid));
    SG_ASSERT_OK(shadow_server.Initialize(p.km, p.sid));
    SealOptions high;
    high.request_id = 999;
    DecodedFrame high_req = Decode(SealData(shadow_client, "x", high));
    SG_ASSERT_OK(shadow_server.Open(&high_req));
    (void)SealData(shadow_server, "pad");  // seq 3, already used by "resp1" towards p.client
    SealOptions unsolicited;
    unsolicited.request_id = 999;
    unsolicited.response = true;
    DecodedFrame forged = Decode(SealData(shadow_server, "unsolicited", unsolicited));  // seq 4
    SG_EXPECT_STATUS(p.client.Open(&forged), SG_PROTOCOL_ERROR);

    // Duplicate request id (a well-formed, correctly sequenced frame).
    Pair q;
    SealOptions dup;
    dup.request_id = 5;
    DecodedFrame d1 = Decode(SealData(q.client, "a", dup));
    SG_ASSERT_OK(q.server.Open(&d1));
    DecodedFrame d2 = Decode(SealData(q.client, "b", dup));
    SG_EXPECT_STATUS(q.server.Open(&d2), SG_REPLAY_DETECTED);

    // Option validation.
    Bytes out;
    SealOptions ping_with_id;
    ping_with_id.request_id = 1;
    SG_EXPECT_STATUS(q.client.Seal(MessageType::kPing, ByteView(), ping_with_id, &out), SG_INVALID_ARGUMENT);
    SealOptions response_without_id;
    response_without_id.response = true;
    SG_EXPECT_STATUS(q.client.Seal(MessageType::kData, ByteView(), response_without_id, &out), SG_INVALID_ARGUMENT);
}

SG_TEST(Channel, PerDirectionKeySwitchToleratesInFlightFrames)
{
    // Models REAUTH: the server switches s2c right after REAUTH_RESULT and
    // stages the new c2s key; client frames already in flight under the old
    // epoch must still be accepted until the first new-phase frame arrives.
    Pair p;
    Bytes new_km(32, 0);
    SG_ASSERT_OK(crypto::RandomBytes(new_km.data(), new_km.size()));

    const Bytes in_flight_1 = SealData(p.client, "old-epoch-1");
    const Bytes in_flight_2 = SealData(p.client, "old-epoch-2");

    // Server side of the switch.
    SG_ASSERT_OK(p.server.SwitchSendKey(new_km, 1));
    SG_ASSERT_OK(p.server.StageReceiveKey(new_km, 1));
    SG_EXPECT(p.server.HasStagedReceiveKey());
    DecodedFrame s2c = Decode(SealData(p.server, "new-epoch-from-server"));
    SG_EXPECT(s2c.header().flags & kFlagKeyPhase);

    // Old-epoch client frames still verify.
    DecodedFrame f1 = Decode(in_flight_1);
    SG_ASSERT_OK(p.server.Open(&f1));
    DecodedFrame f2 = Decode(in_flight_2);
    SG_ASSERT_OK(p.server.Open(&f2));

    // Client processes REAUTH_RESULT: switches both directions.
    SG_ASSERT_OK(p.client.SwitchReceiveKey(new_km, 1));
    SG_ASSERT_OK(p.client.SwitchSendKey(new_km, 1));
    SG_ASSERT_OK(p.client.Open(&s2c));

    // First new-phase frame promotes the staged key and retires the old one.
    DecodedFrame n1 = Decode(SealData(p.client, "new-epoch-1"));
    SG_ASSERT_OK(p.server.Open(&n1));
    SG_EXPECT(!p.server.HasStagedReceiveKey());
    SG_EXPECT_EQ(p.server.receive_epoch(), 1u);
}

SG_TEST(Channel, OldEpochRejectedAfterSwitchCompleted)
{
    Pair p;
    Bytes new_km(32, 7);
    // A frame sealed under epoch 0 but held back by an attacker...
    ProtectedChannel shadow(Role::kClient);
    SG_ASSERT_OK(shadow.Initialize(p.km, p.sid));

    SG_ASSERT_OK(p.server.SwitchSendKey(new_km, 1));
    SG_ASSERT_OK(p.server.StageReceiveKey(new_km, 1));
    SG_ASSERT_OK(p.client.SwitchSendKey(new_km, 1));
    DecodedFrame n1 = Decode(SealData(p.client, "new"));
    SG_ASSERT_OK(p.server.Open(&n1));

    // ...then injected with the right sequence number: the old key is gone.
    (void)SealData(shadow, "pad");  // seq 3 (consumed)
    DecodedFrame late = Decode(SealData(shadow, "late-old-epoch"));  // seq 4, epoch 0
    SG_EXPECT_STATUS(p.server.Open(&late), SG_PROTOCOL_ERROR);
}

SG_TEST(Channel, KeySwitchPreconditions)
{
    Pair p;
    const Bytes km(32, 3);
    SG_EXPECT_STATUS(p.server.SwitchSendKey(km, 2), SG_INVALID_ARGUMENT);   // must be epoch + 1
    SG_EXPECT_STATUS(p.client.SwitchReceiveKey(km, 0), SG_INVALID_ARGUMENT);
    SG_ASSERT_OK(p.server.StageReceiveKey(km, 1));
    SG_EXPECT_STATUS(p.server.StageReceiveKey(km, 1), SG_INVALID_ARGUMENT);  // one switch at a time
    ProtectedChannel uninit(Role::kClient);
    Bytes out;
    SG_EXPECT_STATUS(uninit.Seal(MessageType::kData, ByteView(), SealOptions(), &out), SG_INVALID_STATE);
    SG_EXPECT_STATUS(uninit.Initialize(Bytes(31, 0), p.sid), SG_INVALID_ARGUMENT);
}

SG_TEST(Channel, PlaintextFrameViewForTranscripts)
{
    Pair p;
    SealOptions enc;
    enc.encrypt = true;
    DecodedFrame f = Decode(SealData(p.client, "reauth-body", enc));
    Bytes plain_frame;
    SG_ASSERT_OK(p.server.Open(&f, &plain_frame));
    SG_EXPECT_EQ(plain_frame.size(), kHeaderSize + 11);
    SG_EXPECT(std::memcmp(plain_frame.data() + kHeaderSize, "reauth-body", 11) == 0);
}
