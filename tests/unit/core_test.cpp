#include "sg_test.h"

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/clock.h"
#include "sockgate_common/core/log.h"
#include "sockgate_common/core/status.h"

#include <cstring>
#include <string>
#include <thread>

SG_TEST(Status, DefaultIsOk)
{
    sg::Status s;
    SG_EXPECT(s.ok());
    SG_EXPECT_EQ(s.code(), SG_OK);
}

SG_TEST(Status, InternalCodesNeverLeakThroughAbi)
{
    SG_EXPECT_EQ(sg::ToPublicStatus(sg::kStatusWouldBlock), SG_INTERNAL_ERROR);
    SG_EXPECT_EQ(sg::ToPublicStatus(SG_TIMEOUT), SG_TIMEOUT);
    SG_EXPECT_EQ(sg::ToPublicStatus(-5), SG_INTERNAL_ERROR);
}

SG_TEST(Status, EveryPublicCodeHasAName)
{
    for (SG_Status c = SG_OK; c <= SG_STORAGE_ERROR; ++c) {
        SG_EXPECT(std::string(SG_StatusString(c)) != "SG_UNKNOWN_STATUS");
    }
    SG_EXPECT(std::string(SG_StatusString(9999)) == "SG_UNKNOWN_STATUS");
}

SG_TEST(Bytes, ConstantTimeEqual)
{
    const uint8_t a[] = {1, 2, 3, 4};
    const uint8_t b[] = {1, 2, 3, 4};
    const uint8_t c[] = {1, 2, 3, 5};
    SG_EXPECT(sg::ConstantTimeEqual(a, sizeof(a), b, sizeof(b)));
    SG_EXPECT(!sg::ConstantTimeEqual(a, sizeof(a), c, sizeof(c)));
    SG_EXPECT(!sg::ConstantTimeEqual(a, 4, b, 3));
    SG_EXPECT(sg::ConstantTimeEqual(nullptr, 0, nullptr, 0));
}

SG_TEST(Bytes, SecureZeroClears)
{
    uint8_t buf[32];
    std::memset(buf, 0xAB, sizeof(buf));
    sg::SecureZero(buf, sizeof(buf));
    for (uint8_t v : buf) SG_EXPECT_EQ(v, 0);
    sg::SecureZero(nullptr, 10);  // must not crash
}

SG_TEST(Bytes, HexAndShortId)
{
    const sg::Bytes b = {0x00, 0x0f, 0xa0, 0xff};
    SG_EXPECT_EQ(sg::ToHex(b), std::string("000fa0ff"));
    const sg::Bytes id(16, 0x11);
    SG_EXPECT_EQ(sg::ShortId(id), std::string("1111111111111111"));
}

SG_TEST(Bytes, ByteViewSubIsBoundsChecked)
{
    const sg::Bytes b = {1, 2, 3, 4, 5};
    const sg::ByteView v(b);
    SG_EXPECT_EQ(v.Sub(1, 3).size(), size_t{3});
    SG_EXPECT_EQ(v.Sub(1, 3)[0], 2);
    SG_EXPECT(v.Sub(4, 2).empty());
    SG_EXPECT(v.Sub(6, 0).empty());
    SG_EXPECT(v.Sub(SIZE_MAX, 1).empty());
    SG_EXPECT(v.Sub(1, SIZE_MAX).empty());
}

SG_TEST(Bytes, SecureBytesBehavesLikeVector)
{
    sg::SecureBytes s;
    for (int i = 0; i < 1000; ++i) s.push_back(static_cast<uint8_t>(i));  // forces reallocations
    SG_EXPECT_EQ(s.size(), size_t{1000});
    SG_EXPECT_EQ(s[999], static_cast<uint8_t>(999 & 0xFF));
}

SG_TEST(Clock, DeadlineExpires)
{
    sg::Deadline d(20);
    SG_EXPECT(!d.Expired());
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    SG_EXPECT(d.Expired());
    SG_EXPECT_EQ(d.RemainingMs(1000), 0u);
    sg::Deadline inf = sg::Deadline::Infinite();
    SG_EXPECT(!inf.Expired());
    SG_EXPECT_EQ(inf.RemainingMs(123), 123u);
}

namespace {
struct LogCapture {
    int count = 0;
    std::string last;
};
void SG_CALL CaptureLog(void* user, uint32_t, const char* message)
{
    auto* cap = static_cast<LogCapture*>(user);
    ++cap->count;
    cap->last = message;
}
}  // namespace

SG_TEST(Logger, RespectsLevelAndCallback)
{
    LogCapture cap;
    sg::Logger logger(&CaptureLog, &cap, SG_LOG_WARN);
    SG_LOGE(logger, "event=%s code=%d", "x", 7);
    SG_LOGI(logger, "should not appear");
    SG_EXPECT_EQ(cap.count, 1);
    SG_EXPECT(cap.last.find("event=x code=7") != std::string::npos);
    SG_EXPECT(cap.last.rfind("ts=", 0) == 0);

    sg::Logger silent;
    SG_LOGE(silent, "nothing");  // no callback: must be a no-op
}
