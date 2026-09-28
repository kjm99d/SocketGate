#include "sockgate_common/core/log.h"

#include "sockgate_common/core/clock.h"

#include <cstdarg>
#include <cstdio>

namespace sg {

void Logger::Write(uint32_t level, const char* format, ...) const noexcept
{
    if (!Enabled(level) || format == nullptr) return;

    char message[768];
    const int prefix = std::snprintf(message, sizeof(message), "ts=%llu ",
                                     static_cast<unsigned long long>(UnixTimeMs()));
    size_t used = prefix > 0 ? static_cast<size_t>(prefix) : 0;
    if (used >= sizeof(message)) used = sizeof(message) - 1;

    va_list args;
    va_start(args, format);
    const int n = std::vsnprintf(message + used, sizeof(message) - used, format, args);
    va_end(args);
    if (n < 0) return;

    // Never let a misbehaving callback take the library down.
    try {
        callback_(user_, level, message);
    } catch (...) {
    }
}

}  // namespace sg
