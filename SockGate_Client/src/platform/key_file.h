#pragma once
/**
 * @file
 * @brief Per-user protected key files (FILE key store backend).
 *
 * Files live in one directory per user and are created atomically and exclusively; every read re-checks that the
 * file is a plain file of the current user that nobody else can access. Linux relies on owner-only permissions;
 * Windows additionally wraps the key blob with DPAPI and restricts the key directory to the user (and SYSTEM).
 *
 * What is checked, per platform:
 * - Linux: every call opens the directory without following a final symlink and requires it to be owned by the
 *   effective user and not writable by group or others; files are then accessed relative to that directory
 *   descriptor (no path re-resolution). A key file must be a regular file of the effective user, without group or
 *   other permission bits, with one link and at most kMaxKeyFileSize bytes.
 * - Windows: every call re-verifies the directory by path: not a reparse point, owned by a trusted principal (the
 *   user, SYSTEM, Administrators, CREATOR OWNER or OWNER RIGHTS), a DACL present, and no allow ACE grants modify
 *   rights to anyone else (allow ACEs of other types than ACCESS_ALLOWED, e.g. conditional or object ones, are
 *   refused; deny ACEs are ignored). A key file must not be a reparse point, must have one link and at most
 *   kMaxKeyFileSize bytes, and reads also require its owner to be a trusted principal. The file's own DACL is not
 *   checked: directories created here get a
 *   protected DACL for the user and SYSTEM only, existing directories are used as they are, and the key blob itself
 *   is DPAPI-protected.
 */

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <string>

namespace sg::client::os {

/** @brief Largest key or locator file that is written or read (64 KiB); larger files are refused. */
constexpr size_t kMaxKeyFileSize = 64 * 1024;

/**
 * @brief Returns the per-user default key directory.
 *
 * - Windows: `%LOCALAPPDATA%\SockGate\keys`
 * - Linux: `$XDG_DATA_HOME/sockgate/keys`, else `~/.local/share/sockgate/keys`
 *
 * On Linux the environment is read with secure_getenv() (ignored in setuid/setgid processes) and only absolute
 * values count; without a usable $HOME the home directory comes from the password database.
 *
 * @param[out] out Receives the directory path (UTF-8).
 * @retval SG_OK               Path returned (the directory may not exist yet).
 * @retval SG_INVALID_ARGUMENT @p out is nullptr.
 * @retval SG_KEYSTORE_ERROR   No base directory can be determined.
 */
Status DefaultKeyDirectory(std::string* out);

/**
 * @brief Creates and verifies the key directory.
 *
 * Creates `dir` (missing components with owner-only access) and checks the final directory: a real directory (no
 * symlink / reparse point) of the current user that others cannot write to. SG_KEYSTORE_ERROR otherwise.
 *
 * Linux creates missing components with mode 0700 and also removes stale temporaries of CreateKeyFile()
 * (".<name>.<sgkey|sgref|tpm2key>.<16 hex>.tmp", older than 10 minutes) that a crash may have left with key
 * material. Windows creates missing components with a protected DACL (user and SYSTEM only), ignoring creation
 * errors, and also accepts a directory owned by another trusted principal (see above). Existing components are
 * left unchanged on both platforms. On Windows an embedded NUL is not rejected: the path is used up to it.
 *
 * @param[in] dir Directory path (UTF-8).
 * @retval SG_OK               The directory exists and passed the checks.
 * @retval SG_INVALID_ARGUMENT @p dir is empty, (Linux) contains NUL, or (Windows) is not valid UTF-8.
 * @retval SG_NOT_FOUND        The directory does not exist after the attempt to create it; on Windows this is how
 *                             a failed creation is reported.
 * @retval SG_KEYSTORE_ERROR   The checks failed, or (Linux) creation failed.
 */
Status PrepareKeyDirectory(const std::string& dir);

/**
 * @brief Protection of the key blob at rest.
 *
 * `context` binds the blob to its key name (DPAPI entropy), so blobs cannot be swapped between names. The value is
 * stored in each key file. kOwnerOnlyFile (Linux): the blob is stored as is and file permissions are the only
 * protection; the context is not used. kDpapiUser (Windows): DPAPI in the user's scope, with the context as entropy.
 */
enum class BlobProtection : uint8_t { kOwnerOnlyFile = 1, /**< Linux */ kDpapiUser = 2 /**< Windows */ };
/**
 * @brief The protection this platform uses.
 * @return kDpapiUser on Windows, kOwnerOnlyFile on Linux.
 */
BlobProtection PlatformBlobProtection() noexcept;
/**
 * @brief Wraps a private key blob for storage.
 *
 * Windows: CryptProtectData() in the user's scope with @p context as entropy, without UI. Linux: copies @p plain
 * unchanged and ignores @p context.
 *
 * @warning On Linux @p out holds the plaintext key, and it is a plain Bytes buffer: the caller wipes it
 *          (FileKeyStore does).
 *
 * @param[in]  plain   Blob to protect (PKCS#8).
 * @param[in]  context Binding context (the key name); used on Windows only.
 * @param[out] out     Receives the protected blob.
 * @retval SG_OK               Blob protected.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, or (Windows) @p plain exceeds kMaxKeyFileSize.
 * @retval SG_KEYSTORE_ERROR   DPAPI failed.
 */
Status ProtectKeyBlob(ByteView plain, ByteView context, Bytes* out);
/**
 * @brief Unwraps a blob produced by ProtectKeyBlob().
 *
 * Windows: CryptUnprotectData() with @p context as entropy (DPAPI's output buffer is wiped); a blob of another user
 * or bound to another context fails. Linux: copies @p blob unchanged and ignores @p context.
 *
 * @param[in]  blob    Protected blob.
 * @param[in]  context Binding context used when protecting (the key name).
 * @param[out] out     Receives the plain blob (wiped on release).
 * @retval SG_OK               Blob unwrapped.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr, or (Windows) @p blob exceeds kMaxKeyFileSize.
 * @retval SG_KEYSTORE_ERROR   DPAPI failed.
 */
Status UnprotectKeyBlob(ByteView blob, ByteView context, SecureBytes* out);

/**
 * @brief Creates a key file.
 *
 * Writes dir/file exclusively and atomically (temporary file + no-replace publish, flushed to disk).
 * SG_ALREADY_EXISTS if it exists.
 *
 * Calls PrepareKeyDirectory() first, so a removed directory is recreated. Linux writes an anonymous O_TMPFILE and
 * links it into place (the key never exists under a temporary name); where that is unavailable it falls back to a
 * named 0600 temporary published with renameat2(RENAME_NOREPLACE) or linkat(). File and directory are fsync()ed.
 * Windows writes a temporary file (write-through) and publishes it with MoveFileExW() without replacing.
 *
 * @param[in] dir  Key directory.
 * @param[in] file Plain file name (no path separator, not "." or "..").
 * @param[in] data File content, at most kMaxKeyFileSize bytes.
 * @retval SG_OK               File created.
 * @retval SG_ALREADY_EXISTS   dir/file already exists.
 * @retval SG_INVALID_ARGUMENT Invalid file name or oversized @p data.
 * @retval SG_KEYSTORE_ERROR   Directory checks or I/O failed.
 */
Status CreateKeyFile(const std::string& dir, const std::string& file, ByteView data);
/**
 * @brief Reads a key file after the checks listed in the file description.
 *
 * SG_NOT_FOUND if absent; SG_KEYSTORE_ERROR for links, foreign owners, permissive modes or oversized files
 * (permission bits are checked on Linux only, see above).
 *
 * @param[in]  dir  Key directory.
 * @param[in]  file Plain file name.
 * @param[out] out  Receives the content (wiped on release).
 * @retval SG_OK               Content read.
 * @retval SG_NOT_FOUND        The file (or the directory) does not exist.
 * @retval SG_INVALID_ARGUMENT @p out is nullptr or invalid file name.
 * @retval SG_KEYSTORE_ERROR   A check or the read failed.
 */
Status ReadKeyFile(const std::string& dir, const std::string& file, SecureBytes* out);
/**
 * @brief Deletes a key file.
 *
 * Overwrites the content, then removes the file. SG_NOT_FOUND if absent.
 *
 * The overwrite (zeros) is best effort: the storage medium may keep old blocks.
 *
 * @param[in] dir  Key directory.
 * @param[in] file Plain file name.
 * @retval SG_OK               File removed.
 * @retval SG_NOT_FOUND        The file (or the directory) does not exist.
 * @retval SG_INVALID_ARGUMENT Invalid file name.
 * @retval SG_KEYSTORE_ERROR   A check or the removal failed.
 */
Status DeleteKeyFile(const std::string& dir, const std::string& file);

}  // namespace sg::client::os
