#include "storage/atomic_file.h"

#include "sockgate_common/crypto/crypto.h"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace sg::server {
namespace {

struct FdCloser {
    int fd;
    ~FdCloser()
    {
        if (fd >= 0) ::close(fd);
    }
};

std::string DirectoryOf(const std::string& path)
{
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return ".";
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

}  // namespace

Status ReadWholeFile(const std::string& path, Bytes* out)
{
    if (out == nullptr || path.empty()) return SG_INVALID_ARGUMENT;
    FdCloser file{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (file.fd < 0) return errno == ENOENT ? Status(SG_NOT_FOUND) : Status(SG_STORAGE_ERROR);
    struct stat st;
    if (::fstat(file.fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        static_cast<unsigned long long>(st.st_size) > kMaxStorageFileSize) {
        return SG_STORAGE_ERROR;
    }
    out->resize(static_cast<size_t>(st.st_size));
    size_t done = 0;
    while (done < out->size()) {
        const ssize_t n = ::read(file.fd, out->data() + done, out->size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return SG_STORAGE_ERROR;
        done += static_cast<size_t>(n);
    }
    return OkStatus();
}

Status WriteFileAtomically(const std::string& path, ByteView data)
{
    if (path.empty()) return SG_INVALID_ARGUMENT;
    uint8_t rnd[8];
    SG_TRY(crypto::RandomBytes(rnd, sizeof(rnd)));
    char suffix[32];
    std::snprintf(suffix, sizeof(suffix), ".tmp-%02x%02x%02x%02x%02x%02x%02x%02x", rnd[0], rnd[1], rnd[2], rnd[3],
                  rnd[4], rnd[5], rnd[6], rnd[7]);
    const std::string tmp = path + suffix;

    {
        FdCloser file{::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)};
        if (file.fd < 0) return SG_STORAGE_ERROR;
        size_t done = 0;
        while (done < data.size()) {
            const ssize_t n = ::write(file.fd, data.data() + done, data.size() - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) {
                ::unlink(tmp.c_str());
                return SG_STORAGE_ERROR;
            }
            done += static_cast<size_t>(n);
        }
        if (::fsync(file.fd) != 0) {
            ::unlink(tmp.c_str());
            return SG_STORAGE_ERROR;
        }
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return SG_STORAGE_ERROR;
    }
    // Make the rename itself durable.
    FdCloser dir{::open(DirectoryOf(path).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (dir.fd >= 0) ::fsync(dir.fd);
    return OkStatus();
}

}  // namespace sg::server
