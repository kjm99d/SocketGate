#pragma once
/**
 * @file
 * @brief Structured logging routed to an application callback.
 *
 * Rules (enforced by review, see SECURITY.md):
 * - Never log key material, session keys, exporter values, transcript hashes, signatures, tokens, passwords or
 *   payload bytes.
 * - Identifiers (session id prefix, installation id prefix) are allowed.
 * - Debug/trace statements are compiled out of release builds unless SOCKGATE_ENABLE_DEBUG_LOG is defined.
 *
 * The SG_LOGE / SG_LOGW / SG_LOGI / SG_LOGD / SG_LOGT macros check Logger::Enabled() first, so the format
 * arguments are not evaluated when the level is disabled.
 */

#include <sockgate/types.h>

#include <cstdint>

namespace sg {

/**
 * @brief Filters log messages by level and forwards them to the application's SG_LogCallback.
 *
 * @note The logger is immutable after construction, so its methods may be called concurrently from any thread.
 *       The callback runs synchronously on the calling thread and must itself tolerate concurrent calls.
 */
class Logger {
public:
    /** @brief Creates a disabled logger (no callback, level SG_LOG_NONE). */
    Logger() noexcept = default;
    /**
     * @brief Creates a logger that forwards messages up to @p max_level to @p callback.
     * @param[in] callback  Application callback; null disables logging.
     * @param[in] user      Opaque pointer passed back to @p callback unchanged.
     * @param[in] max_level Most verbose level delivered (SG_LOG_ERROR .. SG_LOG_TRACE); SG_LOG_NONE disables logging.
     */
    Logger(SG_LogCallback callback, void* user, uint32_t max_level) noexcept
        : callback_(callback), user_(user), max_level_(max_level) {}

    /**
     * @brief Returns true when a message at @p level would be delivered.
     * @param[in] level Message level (SG_LOG_ERROR .. SG_LOG_TRACE).
     * @return true when a callback is set, @p level is not SG_LOG_NONE and @p level is at most the maximum level.
     */
    bool Enabled(uint32_t level) const noexcept
    {
        return callback_ != nullptr && level != SG_LOG_NONE && level <= max_level_;
    }

    /**
     * @brief Formats a printf-style message and passes it to the callback.
     *
     * The message is prefixed with `ts=<Unix epoch ms> ` and truncated to fit a 768-byte buffer (including the
     * terminating NUL). Nothing is delivered when the level is disabled, @p format is null or formatting fails.
     * An exception thrown by the callback is caught and discarded.
     *
     * @param[in] level  Message level.
     * @param[in] format printf-style format string; must never carry secrets (see the file rules).
     * @param[in] ...    Format arguments.
     */
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 3, 4)))
#endif
    void Write(uint32_t level, const char* format, ...) const noexcept;

private:
    SG_LogCallback callback_ = nullptr;  ///< Application callback; null = logging disabled.
    void* user_ = nullptr;               ///< Opaque callback context.
    uint32_t max_level_ = SG_LOG_NONE;   ///< Most verbose level delivered.
};

}  // namespace sg

/**
 * @brief Logs at @p level through @p logger; the arguments are evaluated only when the level is enabled.
 * @param logger A sg::Logger (evaluated more than once).
 * @param level  Message level.
 * @param ...    printf-style format string and arguments.
 */
#define SG_LOG_AT(logger, level, ...)                                  \
    do {                                                               \
        if ((logger).Enabled(level)) (logger).Write((level), __VA_ARGS__); \
    } while (false)

/** @brief Logs at SG_LOG_ERROR. @param logger A sg::Logger. @param ... Format string and arguments. */
#define SG_LOGE(logger, ...) SG_LOG_AT(logger, SG_LOG_ERROR, __VA_ARGS__)
/** @brief Logs at SG_LOG_WARN. @param logger A sg::Logger. @param ... Format string and arguments. */
#define SG_LOGW(logger, ...) SG_LOG_AT(logger, SG_LOG_WARN, __VA_ARGS__)
/** @brief Logs at SG_LOG_INFO. @param logger A sg::Logger. @param ... Format string and arguments. */
#define SG_LOGI(logger, ...) SG_LOG_AT(logger, SG_LOG_INFO, __VA_ARGS__)

#if !defined(NDEBUG) || defined(SOCKGATE_ENABLE_DEBUG_LOG)
/**
 * @brief Logs at SG_LOG_DEBUG.
 *
 * Compiled out of release builds (NDEBUG) unless SOCKGATE_ENABLE_DEBUG_LOG is defined. When compiled out, only
 * @p logger is evaluated, not the format arguments.
 *
 * @param logger A sg::Logger.
 * @param ...    Format string and arguments.
 */
#define SG_LOGD(logger, ...) SG_LOG_AT(logger, SG_LOG_DEBUG, __VA_ARGS__)
/**
 * @brief Logs at SG_LOG_TRACE; compiled out like SG_LOGD.
 * @param logger A sg::Logger.
 * @param ...    Format string and arguments.
 */
#define SG_LOGT(logger, ...) SG_LOG_AT(logger, SG_LOG_TRACE, __VA_ARGS__)
#else
#define SG_LOGD(logger, ...) do { (void)(logger); } while (false)
#define SG_LOGT(logger, ...) do { (void)(logger); } while (false)
#endif
