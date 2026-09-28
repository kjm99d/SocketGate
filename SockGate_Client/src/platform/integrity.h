#pragma once
/**
 * @file
 * @brief Client integrity observations (SG_CLIENT_FLAG_INTEGRITY_REPORT).
 *
 * @warning Everything collected here can be spoofed by a determined attacker who controls the client machine: the
 *          server uses reports only to LOWER trust (restrict or reject a session), never to grant anything. The
 *          absence of a flag proves nothing.
 *
 * @verbatim
   Windows: executable / SockGate module SHA-256, Authenticode status of the
            executable (WinVerifyTrust, no network), debugger, ASLR (PE
            DYNAMIC_BASE), DEP and CFG process policies, modules loaded from
            the temp directory.
   Linux:   /proc/self/exe and SockGate module SHA-256, GNU build-id,
            LD_PRELOAD / LD_AUDIT / /etc/ld.so.preload, TracerPid, ASLR
            (randomize_va_space, non-PIE executable), writable executable,
            modules loaded from /tmp, /var/tmp or /dev/shm.
   @endverbatim
 *
 * Details: Windows counts only a valid, trusted embedded Authenticode signature as signed (no revocation lookups,
 * no UI); SG_INTEGRITY_DEP_DISABLED is only set in 32-bit processes (64-bit processes always run with DEP), and
 * SG_INTEGRITY_CFG_DISABLED also when the policy cannot be read; the temp directory is the user's (GetTempPathW).
 * Linux also reports ASLR disabled for this process (ADDR_NO_RANDOMIZE), counts an executable writable by group or
 * others as writable, and flags code (the executable or a shared object) from /tmp/, /var/tmp/, /dev/shm/,
 * /memfd:, /proc/ paths or from world-writable files; it never sets SG_INTEGRITY_UNSIGNED_EXECUTABLE.
 */

#include "sockgate_common/core/status.h"
#include "sockgate_common/protocol/messages.h"

namespace sg::client::os {

/**
 * @brief Collects the integrity report of the current process.
 *
 * Fills `out`. File hashes are computed once per process and cached; the dynamic observations (debugger, preload,
 * ...) are re-evaluated every call. Hashing failures set SG_INTEGRITY_HASH_UNAVAILABLE instead of failing.
 *
 * Only successful results are cached, so a failed hash (or, on Windows, a signature check that could not read the
 * file) is retried by the next call. @p out is reset first; observation_flags is masked with
 * SG_INTEGRITY_KNOWN_FLAGS. With SG_CLIENT_FLAG_INTEGRITY_REPORT, ClientSession collects a fresh report for every
 * authentication and SG_Client_Create() calls this once to compute the hashes off the timed authentication path.
 *
 * @note Thread-safe: the cache is guarded by a process-wide mutex.
 *
 * @param[out] out Receives the report.
 * @retval SG_OK               Report filled (also when hashing failed).
 * @retval SG_INVALID_ARGUMENT @p out is nullptr.
 */
Status CollectIntegrityReport(proto::IntegrityReport* out);

}  // namespace sg::client::os
