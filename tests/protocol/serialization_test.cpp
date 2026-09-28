#include "sg_test.h"

#include "sockgate_common/serialization/base64.h"
#include "sockgate_common/serialization/byte_order.h"
#include "sockgate_common/serialization/reader.h"
#include "sockgate_common/serialization/tlv.h"
#include "sockgate_common/serialization/writer.h"

#include <string>

using namespace sg;
using namespace sg::ser;

namespace {
ByteView Str(const std::string& s) { return AsBytes(s); }
}  // namespace

SG_TEST(Serialization, ByteOrderIsBigEndian)
{
    uint8_t b[8];
    StoreBE16(b, 0x1234);
    SG_EXPECT(b[0] == 0x12 && b[1] == 0x34);
    StoreBE32(b, 0x01020304u);
    SG_EXPECT(b[0] == 1 && b[3] == 4);
    StoreBE64(b, 0x0102030405060708ull);
    SG_EXPECT(b[0] == 1 && b[7] == 8);
    SG_EXPECT_EQ(LoadBE64(b), 0x0102030405060708ull);
    SG_EXPECT_EQ(LoadBE32(b), 0x01020304u);
    SG_EXPECT_EQ(LoadBE16(b), static_cast<uint16_t>(0x0102));
}

SG_TEST(Serialization, WriterReaderRoundTrip)
{
    Bytes buf;
    Writer w(&buf);
    w.U8(0xAB);
    w.U16(0xBEEF);
    w.U32(0xDEADBEEFu);
    w.U64(0x0123456789ABCDEFull);
    SG_ASSERT_OK(w.Vec16(Str("hello")));
    w.Raw(Str("xyz"));

    Reader r(buf);
    uint8_t a = 0;
    uint16_t b = 0;
    uint32_t c = 0;
    uint64_t d = 0;
    ByteView v;
    ByteView raw;
    SG_ASSERT_OK(r.U8(&a));
    SG_ASSERT_OK(r.U16(&b));
    SG_ASSERT_OK(r.U32(&c));
    SG_ASSERT_OK(r.U64(&d));
    SG_ASSERT_OK(r.Vec16(0, 10, &v));
    SG_ASSERT_OK(r.View(3, &raw));
    SG_EXPECT_OK(r.ExpectEnd());
    SG_EXPECT_EQ(a, 0xAB);
    SG_EXPECT_EQ(b, static_cast<uint16_t>(0xBEEF));
    SG_EXPECT_EQ(c, 0xDEADBEEFu);
    SG_EXPECT_EQ(d, 0x0123456789ABCDEFull);
    SG_EXPECT(std::string(v.begin(), v.end()) == "hello");
}

SG_TEST(Serialization, TruncatedReadsFailAndLatch)
{
    const Bytes three = {1, 2, 3};
    Reader r(three);
    uint32_t v = 0;
    SG_EXPECT_STATUS(r.U32(&v), SG_PROTOCOL_ERROR);
    // Once failed, even reads that would fit are refused.
    uint8_t b = 0;
    SG_EXPECT_STATUS(r.U8(&b), SG_PROTOCOL_ERROR);
    SG_EXPECT_EQ(r.Remaining(), size_t{0});
    SG_EXPECT_STATUS(r.status(), SG_PROTOCOL_ERROR);
}

SG_TEST(Serialization, HugeLengthsDoNotOverflow)
{
    const Bytes small = {0, 1, 2, 3};
    Reader r(small);
    ByteView v;
    SG_EXPECT_STATUS(r.View(SIZE_MAX, &v), SG_PROTOCOL_ERROR);
    Reader r2(small);
    uint8_t out[4];
    SG_EXPECT_STATUS(r2.Fixed(out, SIZE_MAX - 1), SG_PROTOCOL_ERROR);
}

SG_TEST(Serialization, Vec16BoundsAndTrailingData)
{
    Bytes buf;
    Writer w(&buf);
    SG_ASSERT_OK(w.Vec16(Str("abcdef")));
    {
        Reader r(buf);
        ByteView v;
        SG_EXPECT_STATUS(r.Vec16(0, 5, &v), SG_PROTOCOL_ERROR);  // too long
    }
    {
        Reader r(buf);
        ByteView v;
        SG_EXPECT_STATUS(r.Vec16(7, 100, &v), SG_PROTOCOL_ERROR);  // too short
    }
    {
        // Declared length larger than the remaining input.
        const Bytes lying = {0x00, 0x10, 'a', 'b'};
        Reader r(lying);
        ByteView v;
        SG_EXPECT_STATUS(r.Vec16(0, 100, &v), SG_PROTOCOL_ERROR);
    }
    {
        Bytes trailing = buf;
        trailing.push_back(0);
        Reader r(trailing);
        ByteView v;
        SG_ASSERT_OK(r.Vec16(0, 100, &v));
        SG_EXPECT_STATUS(r.ExpectEnd(), SG_PROTOCOL_ERROR);
    }
    Bytes big(70000, 0);
    SG_EXPECT_STATUS(w.Vec16(big), SG_INVALID_ARGUMENT);
}

SG_TEST(Serialization, TlvRules)
{
    auto parse = [](const Bytes& section) {
        Reader r(section);
        TlvSection tlv;
        Status st = tlv.Parse(r);
        if (st.ok()) st = r.ExpectEnd();
        return st;
    };
    Bytes good;
    {
        Writer w(&good);
        TlvWriter t;
        t.AddString(1, "a");
        t.AddU64(2, 7);
        t.Add(900, Str("unknown-but-valid"));
        SG_ASSERT_OK(t.Finish(w));
    }
    SG_EXPECT_OK(parse(good));

    // Duplicate type.
    Bytes dup;
    {
        Writer w(&dup);
        TlvWriter t;
        t.AddString(1, "a");
        t.AddString(1, "b");
        SG_ASSERT_OK(t.Finish(w));
    }
    SG_EXPECT_STATUS(parse(dup), SG_PROTOCOL_ERROR);

    // Too many entries.
    Bytes many;
    {
        Writer w(&many);
        TlvWriter t;
        for (uint16_t i = 0; i < 17; ++i) t.AddU64(static_cast<uint16_t>(i + 1), i);
        SG_ASSERT_OK(t.Finish(w));
    }
    SG_EXPECT_STATUS(parse(many), SG_PROTOCOL_ERROR);

    // Total length shorter than the entries it claims to contain.
    Bytes mismatch = good;
    mismatch[1] = static_cast<uint8_t>(mismatch[1] - 1);
    SG_EXPECT(!parse(mismatch).ok());

    // Entry length running past the section end.
    const Bytes overrun = {0x00, 0x06, 0x00, 0x01, 0x00, 0x09, 'a', 'b'};
    SG_EXPECT_STATUS(parse(overrun), SG_PROTOCOL_ERROR);

    // Empty section is valid.
    const Bytes empty = {0x00, 0x00};
    SG_EXPECT_OK(parse(empty));
}

SG_TEST(Serialization, Base64Url)
{
    for (size_t n = 0; n < 40; ++n) {
        Bytes data(n);
        for (size_t i = 0; i < n; ++i) data[i] = static_cast<uint8_t>(i * 37 + 11);
        const std::string enc = Base64UrlEncode(data);
        SG_EXPECT(enc.find('=') == std::string::npos);
        SecureBytes dec;
        SG_ASSERT_OK(Base64UrlDecode(enc, &dec));
        SG_EXPECT(Bytes(dec.begin(), dec.end()) == data);
    }
    SecureBytes out;
    SG_EXPECT_STATUS(Base64UrlDecode("ab+c", &out), SG_INVALID_ARGUMENT);   // standard alphabet
    SG_EXPECT_STATUS(Base64UrlDecode("abc=", &out), SG_INVALID_ARGUMENT);   // padding
    SG_EXPECT_STATUS(Base64UrlDecode("ab c", &out), SG_INVALID_ARGUMENT);   // whitespace
    SG_EXPECT_STATUS(Base64UrlDecode("abcde", &out), SG_INVALID_ARGUMENT);  // impossible length
    SG_EXPECT_STATUS(Base64UrlDecode("AB", &out), SG_INVALID_ARGUMENT);     // non-canonical bits
}

SG_TEST(Serialization, ProtocolStringValidation)
{
    auto ok = [](const std::string& s) { return IsValidProtocolString(AsBytes(s)); };
    SG_EXPECT(ok("product-1.2"));
    SG_EXPECT(ok("\xed\x95\x9c\xea\xb8\x80"));      // Hangul
    SG_EXPECT(ok("\xf0\x9f\x94\x92"));              // 4-byte sequence
    SG_EXPECT(!ok(std::string("a\0b", 3)));         // NUL
    SG_EXPECT(!ok("a\nb"));                         // C0 control
    SG_EXPECT(!ok("a\x7f"));                        // DEL
    SG_EXPECT(!ok("\xc2\x85"));                     // C1 control (NEL)
    SG_EXPECT(!ok("\xc0\xaf"));                     // overlong '/'
    SG_EXPECT(!ok("\xe0\x80\xaf"));                 // overlong 3-byte
    SG_EXPECT(!ok("\xed\xa0\x80"));                 // surrogate
    SG_EXPECT(!ok("\xf4\x90\x80\x80"));             // > U+10FFFF
    SG_EXPECT(!ok("\xe2\x82"));                     // truncated
    SG_EXPECT(!ok("\x80"));                         // stray continuation
}
