// Client integrity observations (SG_CLIENT_FLAG_INTEGRITY_REPORT).
//
// Everything collected here can be spoofed by a determined attacker who
// controls the client machine: the server uses reports only to LOWER trust
// (restrict or reject a session), never to grant anything.
//
//   Windows: executable / SockGate module SHA-256, Authenticode status of the
//            executable (WinVerifyTrust, no network), debugger, ASLR (PE
//            DYNAMIC_BASE), DEP and CFG process policies, modules loaded from
//            the temp directory.
//   Linux:   /proc/self/exe and SockGate module SHA-256, GNU build-id,
//            LD_PRELOAD / LD_AUDIT / /etc/ld.so.preload, TracerPid, ASLR
//            (randomize_va_space, non-PIE executable), writable executable,
//            modules loaded from /tmp, /var/tmp or /dev/shm.
#pragma once

#include "sockgate_common/core/status.h"
#include "sockgate_common/protocol/messages.h"

namespace sg::client::os {

// Fills `out`. File hashes are computed once per process and cached; the
// dynamic observations (debugger, preload, ...) are re-evaluated every call.
// Hashing failures set SG_INTEGRITY_HASH_UNAVAILABLE instead of failing.
Status CollectIntegrityReport(proto::IntegrityReport* out);

}  // namespace sg::client::os
