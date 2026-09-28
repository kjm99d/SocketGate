// POSIX implementation of platform/key_file.h: owner-only files accessed
// relative to a verified directory descriptor (no path re-resolution).
#include "platform/key_file.h"

#include "sockgate_common/crypto/crypto.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>

namespace sg::client::platform {
namespace {

class Fd {
public:
    Fd() = default;
    explicit Fd(int fd) : fd_(fd) {}
    ~Fd()
    {
        if (fd_ >= 0) ::close(fd_);
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const noexcept { return fd_; }
    void reset(int fd) noexcept
    {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

const char* EnvValue(const char* name)
{
    // Ignore the environment in privileged (setuid/setgid) processes.
    return ::secure_getenv(name);
}

// Opens `dir` without following a final symlink and verifies ownership/mode.
Status OpenVerifiedDirectory(const std::string& dir, Fd* out)
{
    const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? Status(SG_NOT_FOUND) : Status(SG_KEYSTORE_ERROR);
    out->reset(fd);
    struct stat st;
    if (::fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return SG_KEYSTORE_ERROR;
    }
    return OkStatus();
}

// The file must be a regular, singly linked file of the current user that
// nobody else can read or write.
Status VerifyKeyFile(int fd, off_t* size)
{
    struct stat st;
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != ::geteuid() ||
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0 || st.st_nlink != 1 || st.st_size < 0 ||
        static_cast<uint64_t>(st.st_size) > kMaxKeyFileSize) {
        return SG_KEYSTORE_ERROR;
    }
    if (size != nullptr) *size = st.st_size;
    return OkStatus();
}

Status WriteAll(int fd, ByteView data)
{
    size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return SG_KEYSTORE_ERROR;
        }
        done += static_cast<size_t>(n);
    }
    return ::fsync(fd) == 0 ? OkStatus() : Status(SG_KEYSTORE_ERROR);
}

// ".<name>.<sgkey|sgref|tpm2key>.<16 hex>.tmp": the named temporaries of
// CreateKeyFile's fallback path (other files in a shared directory are not ours).
bool IsOurTemporary(const std::string& name)
{
    static const char* const kSuffixes[] = {".sgkey.", ".sgref.", ".tpm2key."};
    if (name.size() < 1 + 1 + 6 + 16 + 4 || name[0] != '.' || name.compare(name.size() - 4, 4, ".tmp") != 0) {
        return false;
    }
    const std::string hex = name.substr(name.size() - 4 - 16, 16);
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    const std::string stem = name.substr(0, name.size() - 4 - 16);  // ".<name>.<ext>."
    for (const char* suffix : kSuffixes) {
        const size_t n = std::strlen(suffix);
        if (stem.size() > n + 1 && stem.compare(stem.size() - n, n, suffix) == 0) return true;
    }
    return false;
}

// Temporaries left by a crash in the named-temporary fallback may hold key
// material: remove ours once clearly abandoned.
void RemoveStaleTemporaries(int dirfd)
{
    const int dup = ::fcntl(dirfd, F_DUPFD_CLOEXEC, 0);
    if (dup < 0) return;
    DIR* d = ::fdopendir(dup);
    if (d == nullptr) {
        ::close(dup);
        return;
    }
    const time_t now = ::time(nullptr);
    while (const dirent* e = ::readdir(d)) {
        const std::string name = e->d_name;
        if (!IsOurTemporary(name)) continue;
        struct stat st;
        if (::fstatat(dirfd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode) ||
            st.st_uid != ::geteuid() || now - st.st_mtime < 600) {
            continue;
        }
        ::unlinkat(dirfd, name.c_str(), 0);
    }
    ::closedir(d);
}

// renameat2(RENAME_NOREPLACE) through the raw system call: the libc wrapper
// needs glibc >= 2.28 and does not exist in musl.
int RenameNoReplace(int dirfd, const std::string& from, const std::string& to)
{
#if defined(SYS_renameat2)
    constexpr unsigned kRenameNoReplace = 1;  // RENAME_NOREPLACE
    return static_cast<int>(::syscall(SYS_renameat2, dirfd, from.c_str(), dirfd, to.c_str(), kRenameNoReplace));
#else
    (void)dirfd;
    (void)from;
    (void)to;
    errno = ENOSYS;
    return -1;
#endif
}

bool ValidFileName(const std::string& file)
{
    return !file.empty() && file != "." && file != ".." && file.find('/') == std::string::npos &&
           file.find('\0') == std::string::npos;
}

}  // namespace

BlobProtection PlatformBlobProtection() noexcept { return BlobProtection::kOwnerOnlyFile; }

Status ProtectKeyBlob(ByteView plain, ByteView context, Bytes* out)
{
    (void)context;
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    out->assign(plain.begin(), plain.end());  // file permissions are the protection
    return OkStatus();
}

Status UnprotectKeyBlob(ByteView blob, ByteView context, SecureBytes* out)
{
    (void)context;
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    out->assign(blob.begin(), blob.end());
    return OkStatus();
}

Status DefaultKeyDirectory(std::string* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    const char* xdg = EnvValue("XDG_DATA_HOME");
    if (xdg != nullptr && xdg[0] == '/') {
        *out = std::string(xdg) + "/sockgate/keys";
        return OkStatus();
    }
    std::string home;
    const char* env_home = EnvValue("HOME");
    if (env_home != nullptr && env_home[0] == '/') {
        home = env_home;
    } else {
        long hint = ::sysconf(_SC_GETPW_R_SIZE_MAX);
        std::vector<char> buf(hint > 0 ? static_cast<size_t>(hint) : 16384);
        struct passwd pw;
        struct passwd* result = nullptr;
        if (::getpwuid_r(::geteuid(), &pw, buf.data(), buf.size(), &result) != 0 || result == nullptr ||
            result->pw_dir == nullptr || result->pw_dir[0] != '/') {
            return SG_KEYSTORE_ERROR;
        }
        home = result->pw_dir;
    }
    *out = home + "/.local/share/sockgate/keys";
    return OkStatus();
}

Status PrepareKeyDirectory(const std::string& dir)
{
    if (dir.empty() || dir.find('\0') != std::string::npos) return SG_INVALID_ARGUMENT;
    // Create missing components (owner-only); existing ones are left alone.
    for (size_t pos = 1; pos <= dir.size(); ++pos) {
        if (pos != dir.size() && dir[pos] != '/') continue;
        const std::string prefix = dir.substr(0, pos);
        if (prefix.empty() || prefix.back() == '/') continue;
        if (::mkdir(prefix.c_str(), 0700) != 0 && errno != EEXIST) return SG_KEYSTORE_ERROR;
    }
    Fd fd;
    SG_TRY(OpenVerifiedDirectory(dir, &fd));
    RemoveStaleTemporaries(fd.get());
    return OkStatus();
}

Status CreateKeyFile(const std::string& dir, const std::string& file, ByteView data)
{
    if (!ValidFileName(file) || data.size() > kMaxKeyFileSize) return SG_INVALID_ARGUMENT;
    SG_TRY(PrepareKeyDirectory(dir));  // recreated if it was removed
    Fd dirfd;
    SG_TRY(OpenVerifiedDirectory(dir, &dirfd));

    // 1. Anonymous O_TMPFILE, linked into place in one step: the key never
    //    exists under a temporary name, not even after a crash.
    Fd anon(::openat(dirfd.get(), ".", O_TMPFILE | O_WRONLY | O_CLOEXEC, 0600));
    if (anon.get() >= 0) {
        SG_TRY(::fchmod(anon.get(), 0600) == 0 ? OkStatus() : Status(SG_KEYSTORE_ERROR));
        SG_TRY(WriteAll(anon.get(), data));
        char proc_path[64];
        std::snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", anon.get());
        if (::linkat(AT_FDCWD, proc_path, dirfd.get(), file.c_str(), AT_SYMLINK_FOLLOW) == 0) {
            // The published file must be the one we wrote (a fake /proc could
            // have linked something else).
            struct stat written;
            struct stat published;
            if (::fstat(anon.get(), &written) != 0 ||
                ::fstatat(dirfd.get(), file.c_str(), &published, AT_SYMLINK_NOFOLLOW) != 0 ||
                written.st_ino != published.st_ino || written.st_dev != published.st_dev) {
                return SG_KEYSTORE_ERROR;
            }
            return ::fsync(dirfd.get()) == 0 ? OkStatus() : Status(SG_KEYSTORE_ERROR);
        }
        if (errno == EEXIST) return SG_ALREADY_EXISTS;
        // /proc not mounted or linkat unsupported: fall through.
    }

    // 2. Named temporary file published with renameat2(RENAME_NOREPLACE) or,
    //    where the file system lacks it, linkat() (EEXIST keeps it exclusive).
    uint8_t rnd[8];
    SG_TRY(crypto::RandomBytes(rnd, sizeof(rnd)));
    const std::string tmp = "." + file + "." + ToHex(ByteView(rnd, sizeof(rnd))) + ".tmp";
    Fd fd(::openat(dirfd.get(), tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (fd.get() < 0) return SG_KEYSTORE_ERROR;
    Status st = ::fchmod(fd.get(), 0600) == 0 ? OkStatus() : Status(SG_KEYSTORE_ERROR);
    if (st.ok()) st = WriteAll(fd.get(), data);
    fd.reset(-1);
    if (!st.ok()) {
        ::unlinkat(dirfd.get(), tmp.c_str(), 0);
        return st;
    }
    if (RenameNoReplace(dirfd.get(), tmp, file) != 0) {
        int err = errno;
        if (err == EINVAL || err == ENOSYS || err == ENOTSUP) {
            err = ::linkat(dirfd.get(), tmp.c_str(), dirfd.get(), file.c_str(), 0) == 0 ? 0 : errno;
        }
        ::unlinkat(dirfd.get(), tmp.c_str(), 0);
        if (err == EEXIST) return SG_ALREADY_EXISTS;
        if (err != 0) return SG_KEYSTORE_ERROR;
    }
    return ::fsync(dirfd.get()) == 0 ? OkStatus() : Status(SG_KEYSTORE_ERROR);
}

Status ReadKeyFile(const std::string& dir, const std::string& file, SecureBytes* out)
{
    if (out == nullptr || !ValidFileName(file)) return SG_INVALID_ARGUMENT;
    Fd dirfd;
    SG_TRY(OpenVerifiedDirectory(dir, &dirfd));
    Fd fd(::openat(dirfd.get(), file.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY));
    if (fd.get() < 0) return errno == ENOENT ? Status(SG_NOT_FOUND) : Status(SG_KEYSTORE_ERROR);
    off_t size = 0;
    SG_TRY(VerifyKeyFile(fd.get(), &size));
    out->assign(static_cast<size_t>(size), 0);
    size_t done = 0;
    while (done < out->size()) {
        const ssize_t n = ::read(fd.get(), out->data() + done, out->size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return SG_KEYSTORE_ERROR;
        done += static_cast<size_t>(n);
    }
    return OkStatus();
}

Status DeleteKeyFile(const std::string& dir, const std::string& file)
{
    if (!ValidFileName(file)) return SG_INVALID_ARGUMENT;
    Fd dirfd;
    SG_TRY(OpenVerifiedDirectory(dir, &dirfd));
    Fd fd(::openat(dirfd.get(), file.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY));
    if (fd.get() < 0) return errno == ENOENT ? Status(SG_NOT_FOUND) : Status(SG_KEYSTORE_ERROR);
    off_t size = 0;
    SG_TRY(VerifyKeyFile(fd.get(), &size));
    // Best effort: the storage medium may keep old blocks (see limitations).
    const Bytes zeros(static_cast<size_t>(size), 0);
    WriteAll(fd.get(), zeros).IgnoreError();
    fd.reset(-1);
    if (::unlinkat(dirfd.get(), file.c_str(), 0) != 0) return SG_KEYSTORE_ERROR;
    ::fsync(dirfd.get());
    return OkStatus();
}

}  // namespace sg::client::platform
