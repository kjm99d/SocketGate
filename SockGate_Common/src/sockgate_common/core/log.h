// Structured logging routed to an application callback.
//
// Rules (enforced by review, see SECURITY.md):
//  - Never log key material, session keys, exporter values, transcript hashes,
//    signatures, tokens, passwords or payload bytes.
//  - Identifiers (session id prefix, installation id prefix) are allowed.
//  - Debug/trace statements are compiled out of release builds unless
//    SOCKGATE_ENABLE_DEBUG_LOG is defined.
#pragma once

#include <sockgate/types.h>

#include <cstdint>

namespace sg {

class Logger {
public:
    Logger() noexcept = default;
    Logger(SG_LogCallback callback, void* user, uint32_t max_level) noexcept
        : callback_(callback), user_(user), max_level_(max_level) {}

    bool Enabled(uint32_t level) const noexcept
    {
        return callback_ != nullptr && level != SG_LOG_NONE && level <= max_level_;
    }

#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 3, 4)))
#endif
    void Write(uint32_t level, const char* format, ...) const noexcept;

private:
    SG_LogCallback callback_ = nullptr;
    void* user_ = nullptr;
    uint32_t max_level_ = SG_LOG_NONE;
};

}  // namespace sg

#define SG_LOG_AT(logger, level, ...)                                  \
    do {                                                               \
        if ((logger).Enabled(level)) (logger).Write((level), __VA_ARGS__); \
    } while (false)

#define SG_LOGE(logger, ...) SG_LOG_AT(logger, SG_LOG_ERROR, __VA_ARGS__)
#define SG_LOGW(logger, ...) SG_LOG_AT(logger, SG_LOG_WARN, __VA_ARGS__)
#define SG_LOGI(logger, ...) SG_LOG_AT(logger, SG_LOG_INFO, __VA_ARGS__)

#if !defined(NDEBUG) || defined(SOCKGATE_ENABLE_DEBUG_LOG)
#define SG_LOGD(logger, ...) SG_LOG_AT(logger, SG_LOG_DEBUG, __VA_ARGS__)
#define SG_LOGT(logger, ...) SG_LOG_AT(logger, SG_LOG_TRACE, __VA_ARGS__)
#else
#define SG_LOGD(logger, ...) do { (void)(logger); } while (false)
#define SG_LOGT(logger, ...) do { (void)(logger); } while (false)
#endif
