#pragma once
/**
 * @file
 * @brief Strict parser for TLV extension sections (see PROTOCOL.md §4).
 *
 * Wire format: u16 total_length, then {u16 type, u16 length, value} repeated.
 *
 * Rules: total_length must match exactly, at most kMaxTlvCount entries, no duplicate types. Unknown types are
 * retained (callers ignore them) but still length-validated.
 */

#include "sockgate_common/serialization/reader.h"

#include <vector>

namespace sg::ser {

/** @brief Maximum number of entries in one TLV section. */
constexpr size_t kMaxTlvCount = 16;

/** @brief One parsed TLV entry. */
struct TlvEntry {
    uint16_t type = 0;  ///< Entry type.
    ByteView value;     ///< Entry value; a view into the parsed input (valid while that input is alive).
};

/**
 * @brief A parsed TLV extension section.
 *
 * @note Not synchronised: use one instance from one thread at a time.
 */
class TlvSection {
public:
    /**
     * @brief Reads the section from `reader` (u16 total length + entries).
     *
     * Replaces any previously parsed entries. The entries must fill total_length exactly. On failure entries()
     * may hold the entries parsed before the error; do not use them.
     *
     * @param[in,out] reader Reader positioned at the section; advanced past it (a truncated section latches
     *                       @p reader). Errors inside the section (count, duplicates, entry truncation) do not
     *                       latch @p reader, so check the returned status.
     * @retval SG_OK             Success.
     * @retval SG_PROTOCOL_ERROR The section is truncated, an entry overruns total_length, more than
     *                           #kMaxTlvCount entries, or a duplicate type.
     */
    Status Parse(Reader& reader);

    /**
     * @brief Returns the entry with @p type.
     * @param[in] type Entry type.
     * @return The entry, or null when absent; valid until the next Parse() or destruction.
     */
    const TlvEntry* Find(uint16_t type) const noexcept;
    /** @brief Returns all parsed entries. @return Entries in wire order (unknown types included). */
    const std::vector<TlvEntry>& entries() const noexcept { return entries_; }

private:
    std::vector<TlvEntry> entries_;  ///< Parsed entries in wire order; types are unique.
};

}  // namespace sg::ser
