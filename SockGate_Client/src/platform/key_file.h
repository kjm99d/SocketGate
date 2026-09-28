// Per-user protected key files (FILE key store backend).
//
// Files live in one directory per user and are created atomically and
// exclusively; every read re-checks that the file is a plain file of the
// current user that nobody else can access. Linux relies on owner-only
// permissions; Windows additionally wraps the key blob with DPAPI and
// restricts the key directory to the user (and SYSTEM).
#pragma once

#include "sockgate_common/core/bytes.h"
#include "sockgate_common/core/status.h"

#include <string>

namespace sg::client::platform {

constexpr size_t kMaxKeyFileSize = 64 * 1024;

// Windows: %LOCALAPPDATA%\SockGate\keys
// Linux:   $XDG_DATA_HOME/sockgate/keys, else ~/.local/share/sockgate/keys
Status DefaultKeyDirectory(std::string* out);

// Creates `dir` (missing components with owner-only access) and checks the
// final directory: a real directory (no symlink / reparse point) of the
// current user that others cannot write to. SG_KEYSTORE_ERROR otherwise.
Status PrepareKeyDirectory(const std::string& dir);

// Protection of the key blob at rest. `context` binds the blob to its key
// name (DPAPI entropy), so blobs cannot be swapped between names.
enum class BlobProtection : uint8_t { kOwnerOnlyFile = 1, kDpapiUser = 2 };
BlobProtection PlatformBlobProtection() noexcept;
Status ProtectKeyBlob(ByteView plain, ByteView context, Bytes* out);
Status UnprotectKeyBlob(ByteView blob, ByteView context, SecureBytes* out);

// Writes dir/file exclusively and atomically (temporary file + no-replace
// publish, flushed to disk). SG_ALREADY_EXISTS if it exists.
Status CreateKeyFile(const std::string& dir, const std::string& file, ByteView data);
// SG_NOT_FOUND if absent; SG_KEYSTORE_ERROR for links, foreign owners,
// permissive modes or oversized files.
Status ReadKeyFile(const std::string& dir, const std::string& file, SecureBytes* out);
// Overwrites the content, then removes the file. SG_NOT_FOUND if absent.
Status DeleteKeyFile(const std::string& dir, const std::string& file);

}  // namespace sg::client::platform
