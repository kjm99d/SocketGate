#pragma once
/**
 * @file
 * @brief Helpers for the versioned C structures of the public API.
 */

#include "sockgate_common/core/status.h"

#include <cstddef>
#include <cstdint>

namespace sg {

/**
 * @brief Upper bound, in bytes, for how far a caller's structure may extend beyond the one this build knows.
 *
 * Larger sizes are garbage, not a newer header.
 */
constexpr size_t kMaxUnknownTail = 4096;

/**
 * @brief Checks that the part of an input structure unknown to this build is all zero.
 *
 * Input structures from a newer header may carry fields this build does not know. They must be zero: silently
 * ignoring e.g. a security setting would downgrade the caller.
 *
 * @param[in] object Start of the caller's structure; at least @p size bytes must be readable.
 * @param[in] size   Size of the structure as declared by the caller (its `size` field), in bytes.
 * @param[in] known  Size of the structure this build knows, in bytes.
 * @retval SG_OK               @p size is at most @p known, or every byte in [@p known, @p size) is zero.
 * @retval SG_INVALID_ARGUMENT Implausible size: @p size exceeds @p known by more than kMaxUnknownTail.
 * @retval SG_NOT_SUPPORTED    A byte beyond @p known is non-zero (a field this build does not know is set).
 */
inline Status CheckUnknownTail(const void* object, size_t size, size_t known) noexcept
{
    if (size <= known) return OkStatus();
    if (size - known > kMaxUnknownTail) return SG_INVALID_ARGUMENT;
    const auto* bytes = static_cast<const uint8_t*>(object);
    for (size_t i = known; i < size; ++i) {
        if (bytes[i] != 0) return SG_NOT_SUPPORTED;
    }
    return OkStatus();
}

}  // namespace sg

/**
 * @brief Compile-time check that a public input structure ends exactly after its last member.
 *
 * A public input structure must have no implicit tail padding: otherwise appending a field in a later header
 * could make uninitialised padding look like a set unknown field (see sg::CheckUnknownTail()).
 *
 * @param type The structure type.
 * @param last The structure's last member.
 */
#define SG_ASSERT_NO_TAIL_PADDING(type, last) \
    static_assert(sizeof(type) == offsetof(type, last) + sizeof(((type*)nullptr)->last), \
                  #type " must not end in padding")
