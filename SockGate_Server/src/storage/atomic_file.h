// Durable file helpers for server storage (registry, licenses).
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <string>

namespace sg::server {

// Upper bound for storage files read back into memory.
constexpr size_t kMaxStorageFileSize = 512u * 1024 * 1024;

// Reads a whole regular file. SG_NOT_FOUND if it does not exist,
// SG_STORAGE_ERROR on I/O errors, symlinks (POSIX) or oversized files.
Status ReadWholeFile(const std::string& path, Bytes* out);

// Writes `data` to a new temporary file next to `path` (owner-only
// permissions on POSIX), flushes it to stable storage and atomically
// replaces `path`. Readers observe either the old or the new content.
Status WriteFileAtomically(const std::string& path, ByteView data);

}  // namespace sg::server
