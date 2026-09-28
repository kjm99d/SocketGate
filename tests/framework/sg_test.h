// Minimal, dependency-free test framework for SockGate.
//
//   SG_TEST(Suite, Name) { SG_EXPECT(...); SG_ASSERT_OK(...); }
//
// SG_EXPECT_* record a failure and continue; SG_ASSERT_* abort the test.
// Each test binary accepts --filter=<substring> and --list.
#pragma once

#include <cstdint>
#include <exception>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

#include "sockgate_common/core/status.h"

namespace sgtest {

// Reads a whole binary stream into bytes. Copies explicitly: building a
// std::vector<uint8_t> from istreambuf_iterator<char> converts char to
// uint8_t implicitly (flagged by -fsanitize=integer) and trips GCC's
// -Wnull-dereference inside libstdc++.
inline std::vector<uint8_t> ReadAllBytes(std::istream& in)
{
    std::vector<uint8_t> out;
    char buf[4096];
    for (;;) {
        in.read(buf, sizeof(buf));
        const std::streamsize n = in.gcount();
        if (n > 0) {
            const auto* p = reinterpret_cast<const uint8_t*>(buf);
            out.insert(out.end(), p, p + n);
        }
        if (!in) break;
    }
    return out;
}

struct TestCase {
    const char* suite;
    const char* name;
    void (*fn)();
};

std::vector<TestCase>& Registry();

struct Registrar {
    Registrar(const char* suite, const char* name, void (*fn)()) { Registry().push_back({suite, name, fn}); }
};

struct AssertionFailure : std::exception {
    const char* what() const noexcept override { return "assertion failure"; }
};

void ReportFailure(const char* file, int line, const std::string& message);

template <class T>
std::string Describe(const T& value)
{
    if constexpr (std::is_same_v<T, sg::Status>) {
        return std::string(value.name());
    } else if constexpr (std::is_same_v<T, bool>) {
        return value ? "true" : "false";
    } else if constexpr (std::is_enum_v<T>) {
        return std::to_string(static_cast<long long>(value));
    } else if constexpr (std::is_integral_v<T>) {
        return std::to_string(value);
    } else if constexpr (std::is_convertible_v<T, std::string>) {
        return "\"" + std::string(value) + "\"";
    } else {
        std::ostringstream os;
        os << value;
        return os.str();
    }
}

template <class A, class B>
bool CheckEq(const A& a, const B& b, const char* ea, const char* eb, const char* file, int line)
{
    if (a == b) return true;
    ReportFailure(file, line, std::string(ea) + " == " + eb + "  (" + Describe(a) + " vs " + Describe(b) + ")");
    return false;
}

inline bool CheckStatus(sg::Status actual, SG_Status expected, const char* expr, const char* file, int line)
{
    if (actual.code() == expected) return true;
    ReportFailure(file, line, std::string(expr) + " returned " + actual.name() + ", expected " +
                                  SG_StatusString(expected));
    return false;
}

}  // namespace sgtest

#define SG_TEST(suite, name)                                                                        \
    static void sgtest_##suite##_##name();                                                          \
    static ::sgtest::Registrar sgtest_registrar_##suite##_##name(#suite, #name, &sgtest_##suite##_##name); \
    static void sgtest_##suite##_##name()

#define SG_EXPECT(cond)                                                                       \
    do {                                                                                      \
        if (!(cond)) ::sgtest::ReportFailure(__FILE__, __LINE__, "expected: " #cond);          \
    } while (false)

#define SG_ASSERT(cond)                                                                       \
    do {                                                                                      \
        if (!(cond)) {                                                                        \
            ::sgtest::ReportFailure(__FILE__, __LINE__, "assertion: " #cond);                 \
            throw ::sgtest::AssertionFailure();                                               \
        }                                                                                     \
    } while (false)

#define SG_EXPECT_EQ(a, b) (void)::sgtest::CheckEq((a), (b), #a, #b, __FILE__, __LINE__)
#define SG_ASSERT_EQ(a, b)                                                                    \
    do {                                                                                      \
        if (!::sgtest::CheckEq((a), (b), #a, #b, __FILE__, __LINE__)) throw ::sgtest::AssertionFailure(); \
    } while (false)

#define SG_EXPECT_STATUS(expr, code) (void)::sgtest::CheckStatus(::sg::Status(expr), (code), #expr, __FILE__, __LINE__)
#define SG_ASSERT_STATUS(expr, code)                                                          \
    do {                                                                                      \
        if (!::sgtest::CheckStatus(::sg::Status(expr), (code), #expr, __FILE__, __LINE__))    \
            throw ::sgtest::AssertionFailure();                                               \
    } while (false)

#define SG_EXPECT_OK(expr) SG_EXPECT_STATUS(expr, SG_OK)
#define SG_ASSERT_OK(expr) SG_ASSERT_STATUS(expr, SG_OK)
