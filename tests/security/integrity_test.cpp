// Phase 9: client integrity observations. They are claims the server may use
// to lower trust; these tests check that what is reported matches reality
// for this (test) process, computed independently.
#include "sg_test.h"

#include "platform/integrity.h"

#include "sockgate_common/crypto/crypto.h"

#include <sockgate/types.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>

#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace sg;

namespace {

crypto::Sha256Digest HashOfOwnExecutable()
{
#ifdef _WIN32
    wchar_t path[MAX_PATH * 4];
    const DWORD n = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    SG_ASSERT(n > 0 && n < std::size(path));
    std::ifstream f(path, std::ios::binary);
#else
    std::ifstream f("/proc/self/exe", std::ios::binary);
#endif
    SG_ASSERT(f.good());
    const Bytes content = sgtest::ReadAllBytes(f);
    crypto::Sha256Digest digest;
    SG_ASSERT_OK(crypto::Sha256(content, &digest));
    return digest;
}

}  // namespace

SG_TEST(Integrity, ReportDescribesThisProcess)
{
    proto::IntegrityReport report;
    SG_ASSERT_OK(client::os::CollectIntegrityReport(&report));
#ifdef _WIN32
    SG_EXPECT_EQ(report.platform, uint8_t{SG_INTEGRITY_PLATFORM_WINDOWS});
#else
    SG_EXPECT_EQ(report.platform, uint8_t{SG_INTEGRITY_PLATFORM_LINUX});
#endif
    SG_EXPECT((report.observation_flags & SG_INTEGRITY_HASH_UNAVAILABLE) == 0);
    SG_EXPECT((report.observation_flags & ~SG_INTEGRITY_KNOWN_FLAGS) == 0);
    SG_EXPECT(report.executable_sha256 == HashOfOwnExecutable());
    // The SockGate code is linked into this test executable.
    SG_EXPECT(report.library_sha256 == report.executable_sha256);
    SG_EXPECT(report.build_id.size() <= proto::kMaxBuildIdLength);

    // Stable across calls (hashes are cached, flags re-evaluated).
    proto::IntegrityReport again;
    SG_ASSERT_OK(client::os::CollectIntegrityReport(&again));
    SG_EXPECT(again.executable_sha256 == report.executable_sha256);
    SG_EXPECT_EQ(again.observation_flags, report.observation_flags);
    SG_EXPECT_STATUS(client::os::CollectIntegrityReport(nullptr), SG_INVALID_ARGUMENT);
    std::fprintf(stderr, "    observation flags: 0x%03x\n", report.observation_flags);
}

#ifdef _WIN32
SG_TEST(Integrity, WindowsObservationsMatchTheImage)
{
    proto::IntegrityReport report;
    SG_ASSERT_OK(client::os::CollectIntegrityReport(&report));
    const uint32_t flags = report.observation_flags;
    SG_EXPECT(((flags & SG_INTEGRITY_DEBUGGER_PRESENT) != 0) == (IsDebuggerPresent() != FALSE));
    // Test binaries are not Authenticode-signed.
    SG_EXPECT((flags & SG_INTEGRITY_UNSIGNED_EXECUTABLE) != 0);

    // ASLR / CFG as built into this executable's PE header (the hardening flags).
    const auto* base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const WORD characteristics = nt->OptionalHeader.DllCharacteristics;
    SG_EXPECT(((flags & SG_INTEGRITY_ASLR_DISABLED) != 0) ==
              ((characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0));
    SG_EXPECT(((flags & SG_INTEGRITY_CFG_DISABLED) != 0) == ((characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) == 0));
    SG_EXPECT((flags & SG_INTEGRITY_DEP_DISABLED) == 0);  // always on for 64-bit processes
    std::fprintf(stderr, "    DYNAMIC_BASE=%d GUARD_CF=%d\n",
                 (characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0 ? 1 : 0,
                 (characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0 ? 1 : 0);
}
#else
SG_TEST(Integrity, LinuxObservationsMatchTheProcess)
{
    proto::IntegrityReport report;
    SG_ASSERT_OK(client::os::CollectIntegrityReport(&report));

    // Preload detection follows the environment.
    struct stat st;
    const bool global_preload = ::stat("/etc/ld.so.preload", &st) == 0 && st.st_size > 0;
    ::setenv("LD_PRELOAD", "/nonexistent/sockgate-test.so", 1);
    proto::IntegrityReport with_preload;
    SG_ASSERT_OK(client::os::CollectIntegrityReport(&with_preload));
    ::unsetenv("LD_PRELOAD");
    SG_EXPECT((with_preload.observation_flags & SG_INTEGRITY_PRELOAD_PRESENT) != 0);
    proto::IntegrityReport without;
    SG_ASSERT_OK(client::os::CollectIntegrityReport(&without));
    if (!global_preload && std::getenv("LD_AUDIT") == nullptr) {
        SG_EXPECT((without.observation_flags & SG_INTEGRITY_PRELOAD_PRESENT) == 0);
    }

    // The test executable is linked as PIE (-pie hardening flag).
    std::ifstream exe("/proc/self/exe", std::ios::binary);
    char header[18] = {};
    exe.read(header, sizeof(header));
    const bool pie = header[16] == 3;  // e_type ET_DYN (little endian)
    std::ifstream aslr("/proc/sys/kernel/randomize_va_space");
    int level = 2;
    aslr >> level;
    const int persona = ::personality(0xffffffff);
    const bool no_randomize = persona != -1 && (persona & ADDR_NO_RANDOMIZE) != 0;
    SG_EXPECT(((report.observation_flags & SG_INTEGRITY_ASLR_DISABLED) != 0) == (!pie || level == 0 || no_randomize));
    std::fprintf(stderr, "    PIE=%d randomize_va_space=%d build-id bytes=%zu\n", pie ? 1 : 0, level,
                 report.build_id.size());
}
#endif

SG_TEST(Integrity, ModulesLoadedFromTempAreReported)
{
    namespace fs = std::filesystem;
    const fs::path probe = SG_INTEGRITY_PROBE;
    uint8_t rnd[6];
    SG_ASSERT_OK(crypto::RandomBytes(rnd, sizeof(rnd)));
    const std::string name = "sg-probe-" + ToHex(ByteView(rnd, sizeof(rnd))) + probe.extension().string();
#ifdef _WIN32
    // The temp directory as the process sees it (may be an 8.3 short path).
    const fs::path copy = fs::temp_directory_path() / name;
#else
    const fs::path copy = fs::path("/tmp") / name;
#endif
    fs::copy_file(probe, copy);
    struct Remove {
        fs::path path;
        ~Remove()
        {
            std::error_code ec;
            fs::remove(path, ec);
        }
    } remove_copy{copy};

    proto::IntegrityReport before;
    SG_ASSERT_OK(client::os::CollectIntegrityReport(&before));
    SG_EXPECT((before.observation_flags & SG_INTEGRITY_UNEXPECTED_MODULES) == 0);

#ifdef _WIN32
    HMODULE module = LoadLibraryW(copy.wstring().c_str());
#else
    void* module = ::dlopen(copy.c_str(), RTLD_NOW | RTLD_LOCAL);
#endif
    SG_ASSERT(module != nullptr);
    proto::IntegrityReport after;
    const Status collected = client::os::CollectIntegrityReport(&after);
#ifdef _WIN32
    FreeLibrary(module);
#else
    ::dlclose(module);
#endif
    SG_ASSERT_OK(collected);
    SG_EXPECT((after.observation_flags & SG_INTEGRITY_UNEXPECTED_MODULES) != 0);
}
