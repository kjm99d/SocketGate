// Durable file helpers for server storage (registry, licenses).
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <memory>
#include <string>

namespace sg::server {

// Upper bound for storage files read back into memory.
constexpr size_t kMaxStorageFileSize = 512u * 1024 * 1024;

// Reads a whole regular file. SG_NOT_FOUND if it does not exist,
// SG_STORAGE_ERROR on I/O errors, symlinks (POSIX) or oversized files.
Status ReadWholeFile(const std::string& path, Bytes* out);

// Writes `data` to a new temporary file next to `path` with owner-only
// access (POSIX mode 0600; Windows: protected DACL for the user, SYSTEM and
// Administrators), flushes it to stable storage and atomically replaces
// `path`. Readers observe either the old or the new content.
Status WriteFileAtomically(const std::string& path, ByteView data);

// Exclusive advisory lock on "<path>.lock" (owner-only), held while a file
// store is open. The stores rewrite their whole file on every change, so two
// processes (e.g. a running server and sg_admin) editing the same store would
// silently lose updates - including revocations. A second holder gets
// SG_INVALID_STATE; the lock is released when the object is destroyed or the
// process exits.
class StoreLock {
public:
    virtual ~StoreLock() = default;
};
Status LockStore(const std::string& path, std::unique_ptr<StoreLock>* out);

}  // namespace sg::server
