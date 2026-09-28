// Linux integrity observations (see platform/integrity.h).
#include "platform/integrity.h"

#include "sockgate_common/crypto/crypto.h"

#include <sockgate/types.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mutex>
#include <string>
#include <vector>

namespace sg::client::os {
namespace {

bool HashFd(int fd, crypto::Sha256Digest* out)
{
    crypto::Sha256Hasher hasher;
    std::vector<uint8_t> buf(1 << 16);
    for (;;) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return false;
        if (n == 0) break;
        if (!hasher.Update(ByteView(buf.data(), static_cast<size_t>(n))).ok()) return false;
    }
    return hasher.Final(out).ok();
}

// Regular files only: a FIFO or device named by a spoofed path must not
// block or feed endless data into the hash.
bool HashPath(const char* path, crypto::Sha256Digest* out)
{
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd < 0) return false;
    struct stat st;
    const bool ok = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && HashFd(fd, out);
    ::close(fd);
    return ok;
}

// Reads a small /proc or /sys file.
std::string ReadSmallFile(const char* path)
{
    std::string out;
    FILE* f = std::fopen(path, "re");
    if (f == nullptr) return out;
    char buf[4096];
    size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0 && out.size() < 65536) out.append(buf, n);
    std::fclose(f);
    return out;
}

bool BeingTraced()
{
    const std::string status = ReadSmallFile("/proc/self/status");
    const size_t pos = status.find("TracerPid:");
    if (pos == std::string::npos) return false;
    return std::strtol(status.c_str() + pos + 10, nullptr, 10) != 0;
}

bool PreloadConfigured()
{
    const char* preload = std::getenv("LD_PRELOAD");
    const char* audit = std::getenv("LD_AUDIT");
    if ((preload != nullptr && preload[0] != '\0') || (audit != nullptr && audit[0] != '\0')) return true;
    struct stat st;
    return ::stat("/etc/ld.so.preload", &st) == 0 && st.st_size > 0;
}

bool ExecutableIsPie()
{
    const int fd = ::open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return true;  // unknown: do not claim otherwise
    ElfW(Ehdr) header;
    const ssize_t n = ::read(fd, &header, sizeof(header));
    ::close(fd);
    if (n != static_cast<ssize_t>(sizeof(header)) || std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) return true;
    return header.e_type == ET_DYN;
}

// ASLR off: disabled system-wide (randomize_va_space 0; 1 is still
// randomised), for this process (setarch -R / debuggers), or a non-PIE
// executable that is always mapped at the same address.
bool AslrDisabled()
{
    const std::string value = ReadSmallFile("/proc/sys/kernel/randomize_va_space");
    const bool system_off = !value.empty() && std::strtol(value.c_str(), nullptr, 10) == 0;
    const int persona = ::personality(0xffffffff);
    const bool process_off = persona != -1 && (persona & ADDR_NO_RANDOMIZE) != 0;
    return system_off || process_off || !ExecutableIsPie();
}

bool ExecutableWritableByOthers()
{
    struct stat st;
    return ::stat("/proc/self/exe", &st) == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)) != 0;
}

struct ModuleScan {
    std::vector<std::string> modules;  // shared objects (checked after the scan)
    std::vector<uint8_t> build_id;     // of the main program
    uintptr_t probe = 0;               // an address inside SockGate's own code
    std::string self_path;             // object containing `probe` ("" = main program)
    bool self_found = false;
    bool scan_failed = false;          // out of memory while scanning
};

// Code from temp directories, memory file descriptors or world-writable files.
bool UntrustedLocation(const std::string& path)
{
    // "/proc/": code dlopen()ed through /proc/self/fd/N (e.g. from a memfd).
    static const char* const kPrefixes[] = {"/tmp/", "/var/tmp/", "/dev/shm/", "/memfd:", "/proc/"};
    for (const char* prefix : kPrefixes) {
        if (path.compare(0, std::strlen(prefix), prefix) == 0) return true;
    }
    struct stat st;
    return ::stat(path.c_str(), &st) == 0 && (st.st_mode & S_IWOTH) != 0;
}

int ScanModuleImpl(struct dl_phdr_info* info, ModuleScan* scan)
{
    const bool main_program = info->dlpi_name == nullptr || info->dlpi_name[0] == '\0';
    if (!main_program) scan->modules.emplace_back(info->dlpi_name);
    for (ElfW(Half) i = 0; !scan->self_found && i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        const uintptr_t start = info->dlpi_addr + ph.p_vaddr;
        if (ph.p_type == PT_LOAD && scan->probe >= start && scan->probe - start < ph.p_memsz) {
            scan->self_found = true;
            scan->self_path = main_program ? std::string() : std::string(info->dlpi_name);
        }
    }
    if (!main_program || !scan->build_id.empty()) return 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_NOTE) continue;
        const auto* p = reinterpret_cast<const uint8_t*>(info->dlpi_addr + ph.p_vaddr);
        size_t left = ph.p_memsz;
        while (left >= sizeof(ElfW(Nhdr))) {
            ElfW(Nhdr) note;
            std::memcpy(&note, p, sizeof(note));
            const size_t name_size = (note.n_namesz + 3u) & ~size_t{3};
            const size_t desc_size = (note.n_descsz + 3u) & ~size_t{3};
            const size_t total = sizeof(note) + name_size + desc_size;
            if (total > left) break;
            if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
                std::memcmp(p + sizeof(note), "GNU", 4) == 0 && note.n_descsz <= proto::kMaxBuildIdLength) {
                const uint8_t* desc = p + sizeof(note) + name_size;
                scan->build_id.assign(desc, desc + note.n_descsz);
                return 0;
            }
            p += total;
            left -= total;
        }
    }
    return 0;
}

// Runs under the dynamic loader's lock: no system calls here, and no
// exception may unwind through the loader.
int ScanModule(struct dl_phdr_info* info, size_t, void* data) noexcept
{
    try {
        return ScanModuleImpl(info, static_cast<ModuleScan*>(data));
    } catch (...) {
        static_cast<ModuleScan*>(data)->scan_failed = true;
        return 1;  // stop iterating
    }
}

struct StaticObservations {
    bool executable_hashed = false;
    bool library_hashed = false;
    crypto::Sha256Digest executable{};
    crypto::Sha256Digest library{};
};

// File hashes are expensive: computed once and cached - only when they
// succeeded, so a transient failure is retried by the next collection.
StaticObservations Static(const ModuleScan& scan)
{
    static std::mutex mutex;
    static StaticObservations cache;
    std::lock_guard<std::mutex> lock(mutex);
    if (!cache.executable_hashed) cache.executable_hashed = HashPath("/proc/self/exe", &cache.executable);
    if (!cache.library_hashed && scan.self_found) {
        if (scan.self_path.empty()) {
            // Linked into the executable (the loader's own map, not argv[0]).
            cache.library_hashed = cache.executable_hashed;
            cache.library = cache.executable;
        } else if (scan.self_path[0] == '/') {
            cache.library_hashed = HashPath(scan.self_path.c_str(), &cache.library);
        }
    }
    return cache;
}

bool ExecutableFromUntrustedLocation()
{
    char target[4096];
    const ssize_t n = ::readlink("/proc/self/exe", target, sizeof(target) - 1);
    if (n <= 0) return false;
    return UntrustedLocation(std::string(target, static_cast<size_t>(n)));
}

}  // namespace

Status CollectIntegrityReport(proto::IntegrityReport* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    *out = proto::IntegrityReport();
    out->platform = SG_INTEGRITY_PLATFORM_LINUX;
    ModuleScan scan;
    scan.probe = reinterpret_cast<uintptr_t>(&CollectIntegrityReport);
    ::dl_iterate_phdr(&ScanModule, &scan);
    const StaticObservations s = Static(scan);
    uint32_t flags = 0;
    if (s.executable_hashed) {
        out->executable_sha256 = s.executable;
    } else {
        flags |= SG_INTEGRITY_HASH_UNAVAILABLE;
    }
    if (s.library_hashed) {
        out->library_sha256 = s.library;
    } else {
        flags |= SG_INTEGRITY_HASH_UNAVAILABLE;
    }
    if (BeingTraced()) flags |= SG_INTEGRITY_DEBUGGER_PRESENT;
    if (PreloadConfigured()) flags |= SG_INTEGRITY_PRELOAD_PRESENT;
    if (AslrDisabled()) flags |= SG_INTEGRITY_ASLR_DISABLED;
    if (ExecutableWritableByOthers()) flags |= SG_INTEGRITY_EXECUTABLE_WRITABLE;
    bool unexpected = ExecutableFromUntrustedLocation();
    for (const std::string& module : scan.modules) unexpected = unexpected || UntrustedLocation(module);
    if (unexpected || scan.scan_failed) flags |= SG_INTEGRITY_UNEXPECTED_MODULES;
    out->build_id.assign(scan.build_id.begin(), scan.build_id.end());
    out->observation_flags = flags & SG_INTEGRITY_KNOWN_FLAGS;
    return OkStatus();
}

}  // namespace sg::client::os
