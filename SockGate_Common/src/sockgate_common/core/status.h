// Internal status type. Every fallible internal function returns sg::Status,
// which is [[nodiscard]] so that ignoring a security-relevant failure is a
// compile-time warning.
#pragma once

#include <sockgate/error.h>

namespace sg {

// Internal-only codes. They never cross the C ABI; the API layer maps any
// unexpected value to SG_INTERNAL_ERROR.
constexpr SG_Status kStatusWouldBlock = 1000;

class [[nodiscard]] Status {
public:
    constexpr Status() noexcept = default;
    constexpr Status(SG_Status code) noexcept : code_(code) {}  // NOLINT(google-explicit-constructor)

    constexpr bool ok() const noexcept { return code_ == SG_OK; }
    constexpr SG_Status code() const noexcept { return code_; }
    const char* name() const noexcept { return SG_StatusString(code_); }

    friend constexpr bool operator==(Status a, Status b) noexcept { return a.code_ == b.code_; }
    friend constexpr bool operator!=(Status a, Status b) noexcept { return a.code_ != b.code_; }

    // Explicitly discard a status where failure is acceptable (e.g. best-effort cleanup).
    constexpr void IgnoreError() const noexcept {}

private:
    SG_Status code_ = SG_OK;
};

inline constexpr Status OkStatus() noexcept { return Status(); }

// Maps internal-only codes to a public code before returning through the C ABI.
inline SG_Status ToPublicStatus(Status status) noexcept
{
    const SG_Status code = status.code();
    return (code >= SG_OK && code <= SG_IDENTITY_LOST) ? code : SG_INTERNAL_ERROR;
}

}  // namespace sg

#define SG_TRY(expr)                                   \
    do {                                               \
        const ::sg::Status sg_try_status_ = (expr);    \
        if (!sg_try_status_.ok()) return sg_try_status_; \
    } while (false)
