#pragma once
/**
 * @file
 * @brief Internal status type.
 *
 * Every fallible internal function returns sg::Status, which is [[nodiscard]] so that ignoring a
 * security-relevant failure is a compile-time warning.
 */

#include <sockgate/error.h>

namespace sg {

/**
 * @brief Internal-only code: the operation cannot make progress now (non-blocking I/O would block).
 *
 * Internal-only codes never cross the C ABI; the API layer maps any unexpected value to SG_INTERNAL_ERROR
 * (see ToPublicStatus()).
 */
constexpr SG_Status kStatusWouldBlock = 1000;

/**
 * @brief Result of a fallible internal operation: a public SG_Status code or an internal-only code.
 *
 * Default-constructed as SG_OK. The class is [[nodiscard]]: discarding a returned Status is a compile-time
 * warning; use IgnoreError() where failure is acceptable.
 */
class [[nodiscard]] Status {
public:
    /** @brief Creates a success status (SG_OK). */
    constexpr Status() noexcept = default;
    /** @brief Wraps a status code (implicit, so functions can `return SG_...;`). @param[in] code Status code. */
    constexpr Status(SG_Status code) noexcept : code_(code) {}  // NOLINT(google-explicit-constructor)

    /** @brief Returns whether the status is a success. @return true when the code is SG_OK. */
    constexpr bool ok() const noexcept { return code_ == SG_OK; }
    /** @brief Returns the raw code. @return The code; may be internal-only (see ToPublicStatus()). */
    constexpr SG_Status code() const noexcept { return code_; }
    /**
     * @brief Returns the static name of the code (SG_StatusString()).
     * @return Never null; "SG_UNKNOWN_STATUS" for internal-only codes.
     */
    const char* name() const noexcept { return SG_StatusString(code_); }

    /** @brief Compares codes. @param[in] a Status. @param[in] b Status. @return true when the codes are equal. */
    friend constexpr bool operator==(Status a, Status b) noexcept { return a.code_ == b.code_; }
    /** @brief Compares codes. @param[in] a Status. @param[in] b Status. @return true when the codes differ. */
    friend constexpr bool operator!=(Status a, Status b) noexcept { return a.code_ != b.code_; }

    /** @brief Explicitly discards a status where failure is acceptable (e.g. best-effort cleanup). */
    constexpr void IgnoreError() const noexcept {}

private:
    SG_Status code_ = SG_OK;  ///< Public or internal-only status code.
};

/** @brief Returns a success status. @return Status(SG_OK). */
inline constexpr Status OkStatus() noexcept { return Status(); }

/**
 * @brief Maps internal-only codes to a public code before returning through the C ABI.
 * @param[in] status Internal status.
 * @return The code itself when it is a public code (SG_OK .. SG_IDENTITY_LOST); SG_INTERNAL_ERROR otherwise
 *         (e.g. for kStatusWouldBlock).
 */
inline SG_Status ToPublicStatus(Status status) noexcept
{
    const SG_Status code = status.code();
    return (code >= SG_OK && code <= SG_IDENTITY_LOST) ? code : SG_INTERNAL_ERROR;
}

}  // namespace sg

/**
 * @brief Evaluates @p expr once and returns its status from the enclosing function when it is not SG_OK.
 * @param expr Expression yielding a sg::Status (or an SG_Status code).
 */
#define SG_TRY(expr)                                   \
    do {                                               \
        const ::sg::Status sg_try_status_ = (expr);    \
        if (!sg_try_status_.ok()) return sg_try_status_; \
    } while (false)
