#pragma once
/**
 * @file
 * @brief Durable file helpers for server storage (registry, licenses).
 *
 * Implemented per platform (platform/linux/atomic_file_posix.cpp, platform/windows/atomic_file_win.cpp).
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <memory>
#include <string>

namespace sg::server {

/**
 * @brief Upper bound for storage files read back into memory, in bytes (512 MiB).
 *
 * The file stores also refuse to write a larger file (SG_LIMIT_EXCEEDED), so they never write one they could
 * not load.
 */
constexpr size_t kMaxStorageFileSize = 512u * 1024 * 1024;

/**
 * @brief Reads a whole regular file.
 *
 * On POSIX the file is opened without following a symlink and must be a regular file.
 *
 * @param[in]  path File path (UTF-8).
 * @param[out] out  Receives the content.
 * @retval SG_OK               Read.
 * @retval SG_NOT_FOUND        The file does not exist.
 * @retval SG_STORAGE_ERROR    I/O errors, symlinks (POSIX), files that are not regular (POSIX) or oversized
 *                             files (above kMaxStorageFileSize).
 * @retval SG_INVALID_ARGUMENT @p out is null, or @p path is empty (or not valid UTF-8 on Windows).
 */
Status ReadWholeFile(const std::string& path, Bytes* out);

/**
 * @brief Writes a file atomically and durably with owner-only access.
 *
 * Writes `data` to a new temporary file next to `path` with owner-only
 * access (POSIX mode 0600; Windows: protected DACL for the user, SYSTEM and
 * Administrators), flushes it to stable storage and atomically replaces
 * `path`. Readers observe either the old or the new content. The temporary
 * file is removed on failure. On POSIX the containing directory is also
 * synced (best effort) to make the rename durable.
 *
 * @param[in] path Destination path (UTF-8); the temporary file is `path` plus a random ".tmp-" suffix.
 * @param[in] data Content to write.
 * @retval SG_OK               Written and replaced.
 * @retval SG_STORAGE_ERROR    Creating, writing, flushing or renaming failed (or, on Windows, the security
 *                             descriptor cannot be built).
 * @retval SG_INVALID_ARGUMENT @p path is empty (or not valid UTF-8 on Windows).
 * @retval other               Random number generator failure.
 */
Status WriteFileAtomically(const std::string& path, ByteView data);

/**
 * @brief Exclusive store lock; destroying the object releases it.
 *
 * Exclusive advisory lock on `<path>.lock` (owner-only), held while a file
 * store is open. The stores rewrite their whole file on every change, so two
 * processes (e.g. a running server and sg_admin) editing the same store would
 * silently lose updates - including revocations. A second holder gets
 * SG_INVALID_STATE; the lock is released when the object is destroyed or the
 * process exits.
 */
class StoreLock {
public:
    virtual ~StoreLock() = default;  ///< Releases the lock.
};

/**
 * @brief Acquires the exclusive lock of a file store without waiting (see StoreLock).
 *
 * The lock file is created with owner-only access if it does not exist (POSIX mode 0600, not following a
 * symlink; Windows: protected DACL for the user, SYSTEM and Administrators). The lock belongs to the returned
 * object, so a second LockStore() on the same path fails even within one process.
 *
 * @param[in]  path Store file path; the lock file is `<path>.lock`.
 * @param[out] out  Receives the lock.
 * @retval SG_OK               Locked.
 * @retval SG_INVALID_STATE    The store is locked by another holder.
 * @retval SG_STORAGE_ERROR    The lock file cannot be opened or locked (or, on Windows, its security
 *                             descriptor cannot be built).
 * @retval SG_INVALID_ARGUMENT @p out is null, @p path is empty (POSIX) or not valid UTF-8 (Windows).
 */
Status LockStore(const std::string& path, std::unique_ptr<StoreLock>* out);

}  // namespace sg::server
