#include "sg_test.h"

#include "sockgate_common/protocol/frame.h"
#include "sockgate_common/protocol/rules.h"
#include "sockgate_common/serialization/byte_order.h"

#include <chrono>
#include <random>

using namespace sg;
using namespace sg::proto;

namespace {

FrameHeader SampleHeader(MessageType type = MessageType::kData)
{
    FrameHeader h;
    h.type = type;
    h.flags = 0;
    for (size_t i = 0; i < h.session_id.size(); ++i) h.session_id[i] = static_cast<uint8_t>(i + 1);
    h.sequence = 42;
    h.request_id = 7;
    return h;
}

Bytes EncodedFrame(const FrameHeader& h, size_t payload_size, bool with_tag)
{
    Bytes payload(payload_size, 0x5A);
    Bytes tag(with_tag ? kAuthTagSize : 0, 0xEE);
    Bytes out;
    if (!EncodeFrame(h, payload, tag, &out).ok()) throw std::runtime_error("encode");
    return out;
}

FrameDecoder AcceptAll()
{
    return FrameDecoder([](const FrameHeader&) { return OkStatus(); });
}

Status DecodeOne(const Bytes& wire, DecodedFrame* out = nullptr)
{
    FrameDecoder d = AcceptAll();
    SG_TRY(d.Append(wire));
    DecodedFrame f;
    bool ready = false;
    SG_TRY(d.Next(&f, &ready));
    if (!ready) return kStatusWouldBlock;
    if (out != nullptr) *out = f;
    return OkStatus();
}

}  // namespace

SG_TEST(Frame, HeaderRoundTrip)
{
    FrameHeader h = SampleHeader();
    h.flags = kFlagEncrypted | kFlagKeyPhase;
    const Bytes wire = EncodedFrame(h, 100, true);
    SG_EXPECT_EQ(wire.size(), kHeaderSize + 100 + kAuthTagSize);
    SG_EXPECT_EQ(ser::LoadBE32(wire.data()), kMagic);

    DecodedFrame f;
    SG_ASSERT_OK(DecodeOne(wire, &f));
    SG_EXPECT(f.header().type == MessageType::kData);
    SG_EXPECT_EQ(f.header().flags, static_cast<uint16_t>(kFlagEncrypted | kFlagKeyPhase));
    SG_EXPECT(f.header().session_id == h.session_id);
    SG_EXPECT_EQ(f.header().sequence, uint64_t{42});
    SG_EXPECT_EQ(f.header().request_id, uint64_t{7});
    SG_EXPECT_EQ(f.payload().size(), size_t{100});
    SG_EXPECT_EQ(f.auth_tag().size(), kAuthTagSize);
    SG_EXPECT(f.wire().size() == wire.size());
}

SG_TEST(Frame, MalformedHeadersRejected)
{
    const Bytes good = EncodedFrame(SampleHeader(), 4, false);
    struct Case {
        size_t offset;
        uint8_t value;
        SG_Status expected;
        const char* what;
    };
    const Case cases[] = {
        {0, 0x00, SG_PROTOCOL_ERROR, "bad magic"},
        {4, 0x02, SG_VERSION_MISMATCH, "future wire version"},
        {4, 0x00, SG_VERSION_MISMATCH, "version zero"},
        {5, 0x05, SG_PROTOCOL_ERROR, "unknown type"},
        {5, 0xFF, SG_PROTOCOL_ERROR, "unknown type 0xFF"},
        {6, 0x80, SG_PROTOCOL_ERROR, "reserved flag bit"},
        {7, 0x08, SG_PROTOCOL_ERROR, "reserved flag bit 3"},
        {45, 0x08, SG_PROTOCOL_ERROR, "auth length 8"},
        {47, 0x01, SG_PROTOCOL_ERROR, "reserved field"},
    };
    for (const auto& c : cases) {
        Bytes bad = good;
        bad[c.offset] = c.value;
        const Status st = DecodeOne(bad);
        if (st.code() != c.expected) {
            sgtest::ReportFailure(__FILE__, __LINE__, std::string(c.what) + " -> " + st.name());
        }
    }
}

SG_TEST(Frame, OversizedAndOverflowingLengthsRejectedAtHeader)
{
    Bytes wire = EncodedFrame(SampleHeader(), 0, false);
    // payload_length = 0xFFFFFFFF: must be rejected without attempting to buffer
    // or computing 48 + len + tag in 32 bits.
    ser::StoreBE32(wire.data() + 40, 0xFFFFFFFFu);
    SG_EXPECT_STATUS(DecodeOne(wire), SG_PROTOCOL_ERROR);
    ser::StoreBE32(wire.data() + 40, kAbsoluteMaxPayload + 1);
    SG_EXPECT_STATUS(DecodeOne(wire), SG_PROTOCOL_ERROR);
}

SG_TEST(Frame, TruncatedFramesWaitForMoreData)
{
    const Bytes wire = EncodedFrame(SampleHeader(), 1000, true);
    FrameDecoder d = AcceptAll();
    DecodedFrame f;
    bool ready = true;
    // Header split across appends, then body arriving byte by byte.
    for (size_t i = 0; i < wire.size(); ++i) {
        SG_ASSERT_OK(d.Append(ByteView(wire.data() + i, 1)));
        SG_ASSERT_OK(d.Next(&f, &ready));
        if (i + 1 < wire.size()) SG_ASSERT(!ready);
    }
    SG_EXPECT(ready);
    SG_EXPECT_EQ(f.payload().size(), size_t{1000});
}

SG_TEST(Frame, MultipleFramesInOneBuffer)
{
    Bytes wire;
    for (int i = 0; i < 5; ++i) {
        FrameHeader h = SampleHeader();
        h.sequence = static_cast<uint64_t>(i + 1);
        const Bytes one = EncodedFrame(h, static_cast<size_t>(i * 10), true);
        wire.insert(wire.end(), one.begin(), one.end());
    }
    FrameDecoder d = AcceptAll();
    SG_ASSERT_OK(d.Append(wire));
    for (int i = 0; i < 5; ++i) {
        DecodedFrame f;
        bool ready = false;
        SG_ASSERT_OK(d.Next(&f, &ready));
        SG_ASSERT(ready);
        SG_EXPECT_EQ(f.header().sequence, static_cast<uint64_t>(i + 1));
        SG_EXPECT_EQ(f.payload().size(), static_cast<size_t>(i * 10));
    }
    DecodedFrame f;
    bool ready = true;
    SG_ASSERT_OK(d.Next(&f, &ready));
    SG_EXPECT(!ready);
    SG_EXPECT_EQ(d.Buffered(), size_t{0});
}

SG_TEST(Frame, HeaderCheckRunsBeforeBodyIsBuffered)
{
    // A pre-authentication peer announces a 1 MiB DATA frame. The state check
    // must reject it after the 48 header bytes, without buffering the body.
    FrameHeader h = SampleHeader(MessageType::kData);
    h.auth_length = 0;
    Bytes header(kHeaderSize);
    h.payload_length = kDefaultMaxPayload;
    EncodeHeader(h, header.data());

    FrameLimits limits;
    FrameDecoder d([&](const FrameHeader& hdr) {
        return CheckHeaderForState(hdr, Role::kServer, Phase::kAwaitClientHello, limits);
    });
    SG_ASSERT_OK(d.Append(header));
    DecodedFrame f;
    bool ready = false;
    SG_EXPECT_STATUS(d.Next(&f, &ready), SG_PROTOCOL_ERROR);
    SG_EXPECT(d.failed());
    // The failure is sticky.
    SG_EXPECT_STATUS(d.Append(ByteView(header.data(), 1)), SG_PROTOCOL_ERROR);
    SG_EXPECT_EQ(d.Buffered(), size_t{0});
}

SG_TEST(Frame, DecoderWithoutCheckFailsClosed)
{
    FrameDecoder d(nullptr);
    const Bytes wire = EncodedFrame(SampleHeader(), 4, false);
    SG_EXPECT_STATUS(d.Append(wire), SG_INVALID_ARGUMENT);
    DecodedFrame f;
    bool ready = false;
    SG_EXPECT_STATUS(d.Next(&f, &ready), SG_INVALID_ARGUMENT);
    SG_EXPECT(!ready);
}

SG_TEST(Frame, BufferCapIsConfigurable)
{
    FrameDecoder d = AcceptAll();
    d.SetMaxBuffered(kPreAuthDecoderBuffer);
    const Bytes chunk(kPreAuthDecoderBuffer, 0);
    SG_EXPECT_OK(d.Append(chunk));
    SG_EXPECT_STATUS(d.Append(ByteView(chunk.data(), 1)), SG_PROTOCOL_ERROR);  // one byte over
    FrameDecoder big = AcceptAll();
    SG_EXPECT_STATUS(big.Append(Bytes(kMaxDecoderBuffer + 1, 0)), SG_PROTOCOL_ERROR);
}

SG_TEST(Frame, PipelinedFramesAreProcessedInLinearTime)
{
    // Many small frames in one append must not cause repeated large moves.
    Bytes wire;
    for (int i = 0; i < 20000; ++i) {
        const Bytes one = EncodedFrame(SampleHeader(), 16, true);
        wire.insert(wire.end(), one.begin(), one.end());
    }
    FrameDecoder d = AcceptAll();
    const auto start = std::chrono::steady_clock::now();
    for (size_t off = 0; off < wire.size(); off += 64 * 1024) {
        SG_ASSERT_OK(d.Append(ByteView(wire.data() + off, std::min<size_t>(64 * 1024, wire.size() - off))));
        for (int k = 0; k < 3; ++k) {  // deliberately drain only a few frames per append
            DecodedFrame f;
            bool ready = false;
            SG_ASSERT_OK(d.Next(&f, &ready));
            if (!ready) break;
        }
    }
    int drained = 0;
    for (;;) {
        DecodedFrame f;
        bool ready = false;
        SG_ASSERT_OK(d.Next(&f, &ready));
        if (!ready) break;
        ++drained;
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    SG_EXPECT(drained > 0);
    SG_EXPECT(ms < 5000);
}

SG_TEST(Frame, RandomGarbageNeverCrashes)
{
    std::mt19937 rng(1234);
    for (int iter = 0; iter < 2000; ++iter) {
        Bytes junk(static_cast<size_t>(rng() % 200));
        for (auto& b : junk) b = static_cast<uint8_t>(rng());
        if (junk.size() >= 4 && (iter % 2) == 0) ser::StoreBE32(junk.data(), kMagic);  // get past the magic
        FrameDecoder d = AcceptAll();
        if (!d.Append(junk).ok()) continue;
        for (int k = 0; k < 4; ++k) {
            DecodedFrame f;
            bool ready = false;
            if (!d.Next(&f, &ready).ok() || !ready) break;
            SG_EXPECT(f.wire().size() == kHeaderSize + f.header().payload_length + f.header().auth_length);
        }
    }
}

SG_TEST(Frame, EncodeRejectsInvalidInput)
{
    Bytes out;
    const Bytes bad_tag(5, 0);
    SG_EXPECT_STATUS(EncodeFrame(SampleHeader(), ByteView(), bad_tag, &out), SG_INVALID_ARGUMENT);
    SG_EXPECT_STATUS(EncodeFrame(SampleHeader(), ByteView(), ByteView(), nullptr), SG_INVALID_ARGUMENT);
}
