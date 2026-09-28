// Helpers for the versioned C structures of the public API.
#pragma once

#include "sockgate_common/core/status.h"

#include <cstddef>
#include <cstdint>

namespace sg {

// Upper bound for how far a caller's structure may extend beyond the one
// this build knows (larger sizes are garbage, not a newer header).
constexpr size_t kMaxUnknownTail = 4096;

// Input structures from a newer header may carry fields this build does not
// know. They must be zero: silently ignoring e.g. a security setting would
// downgrade the caller. SG_NOT_SUPPORTED for non-zero unknown fields,
// SG_INVALID_ARGUMENT for implausible sizes.
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

// A public input structure must end exactly after its last member (no
// implicit tail padding): otherwise appending a field in a later header
// could make uninitialised padding look like a set unknown field.
#define SG_ASSERT_NO_TAIL_PADDING(type, last) \
    static_assert(sizeof(type) == offsetof(type, last) + sizeof(((type*)nullptr)->last), \
                  #type " must not end in padding")
