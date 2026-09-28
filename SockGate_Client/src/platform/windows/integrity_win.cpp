// Windows integrity observations (see platform/integrity.h).
#include "platform/integrity.h"

#include "sockgate_common/crypto/crypto.h"

#include <sockgate/types.h>

#include <windows.h>
#include <psapi.h>
#include <softpub.h>
#include <wintrust.h>

#include <mutex>
#include <string>
#include <vector>

namespace sg::client::os {
namespace {

std::wstring ModulePath(HMODULE module)
{
    std::wstring path(512, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
        if (n == 0) return std::wstring();
        if (n < path.size()) {
            path.resize(n);
            return path;
        }
        if (path.size() >= 32768) return std::wstring();
        path.resize(path.size() * 2);
    }
}

bool HashFile(const std::wstring& path, crypto::Sha256Digest* out)
{
    if (path.empty()) return false;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    crypto::Sha256Hasher hasher;
    std::vector<uint8_t> buf(1 << 16);
    bool ok = true;
    for (;;) {
        DWORD n = 0;
        if (!ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr)) {
            ok = false;
            break;
        }
        if (n == 0) break;
        if (!hasher.Update(ByteView(buf.data(), n)).ok()) {
            ok = false;
            break;
        }
    }
    CloseHandle(h);
    return ok && hasher.Final(out).ok();
}

enum class Signature { kSigned, kUnsigned, kUnknown };

// Authenticode signature of a file, checked offline (no revocation lookups,
// no UI). Only a valid, trusted embedded signature counts as signed. Every
// other verdict (no signature, bad digest, untrusted, expired...) is
// definite; only failures to read the file are unknown and retried.
Signature CheckSignature(const std::wstring& path)
{
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG result = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    if (result == ERROR_SUCCESS) return Signature::kSigned;
    const auto code = static_cast<uint32_t>(result);
    auto is = [code](DWORD win32) {
        return code == win32 || code == static_cast<uint32_t>(HRESULT_FROM_WIN32(win32));
    };
    const bool transient = is(ERROR_SHARING_VIOLATION) || is(ERROR_LOCK_VIOLATION) || is(ERROR_NOT_READY) ||
                           is(ERROR_BAD_NETPATH) || is(ERROR_NETNAME_DELETED) || is(ERROR_UNEXP_NET_ERR) ||
                           is(ERROR_NOT_ENOUGH_MEMORY) || code == static_cast<uint32_t>(CRYPT_E_FILE_ERROR) ||
                           code == static_cast<uint32_t>(E_OUTOFMEMORY);
    return transient ? Signature::kUnknown : Signature::kUnsigned;
}

// The main executable must be built for ASLR (/DYNAMICBASE).
bool ExecutableHasDynamicBase()
{
    const auto* base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
    if (base == nullptr) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    return (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
}

// Long form of a path: GetTempPathW (and paths passed to LoadLibrary) may use
// 8.3 short names while other APIs report long names.
std::wstring LongPath(const std::wstring& path)
{
    if (path.find(L'~') == std::wstring::npos) return path;  // only 8.3 names need expanding
    std::wstring out(32768, L'\0');
    const DWORD n = GetLongPathNameW(path.c_str(), out.data(), static_cast<DWORD>(out.size()));
    if (n == 0 || n >= out.size()) return path;
    out.resize(n);
    return out;
}

bool ModulesFromTempDirectory()
{
    wchar_t buffer[MAX_PATH + 1];
    const DWORD n = GetTempPathW(MAX_PATH + 1, buffer);
    if (n == 0 || n > MAX_PATH) return false;
    std::wstring temp = LongPath(std::wstring(buffer, n));
    if (temp.empty()) return false;
    if (temp.back() != L'\\') temp.push_back(L'\\');
    const int temp_len = static_cast<int>(temp.size());
    std::vector<HMODULE> modules(256);
    DWORD needed = 0;
    for (;;) {
        if (!EnumProcessModules(GetCurrentProcess(), modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                &needed)) {
            return false;
        }
        if (needed <= modules.size() * sizeof(HMODULE)) break;
        modules.resize(needed / sizeof(HMODULE));
    }
    modules.resize(needed / sizeof(HMODULE));
    for (HMODULE m : modules) {
        const std::wstring path = LongPath(ModulePath(m));
        if (static_cast<int>(path.size()) >= temp_len &&
            CompareStringOrdinal(path.c_str(), temp_len, temp.c_str(), temp_len, TRUE) == CSTR_EQUAL) {
            return true;
        }
    }
    return false;
}

struct StaticObservations {
    bool executable_hashed = false;
    bool library_hashed = false;
    Signature signature = Signature::kUnknown;
    crypto::Sha256Digest executable{};
    crypto::Sha256Digest library{};
};

// File hashes and the signature check are expensive: computed once and
// cached - but only when they succeeded, so a transient failure (a scanner
// holding the file, a share hiccup) is retried instead of sticking for the
// life of the process.
StaticObservations Static()
{
    static std::mutex mutex;
    static StaticObservations cache;
    std::lock_guard<std::mutex> lock(mutex);
    const std::wstring exe = ModulePath(nullptr);
    if (!cache.executable_hashed) cache.executable_hashed = HashFile(exe, &cache.executable);
    if (!cache.library_hashed) {
        HMODULE self = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(&CollectIntegrityReport), &self)) {
            if (self == GetModuleHandleW(nullptr)) {
                // Linked into the executable: same file, do not read it twice.
                cache.library_hashed = cache.executable_hashed;
                cache.library = cache.executable;
            } else {
                cache.library_hashed = HashFile(ModulePath(self), &cache.library);
            }
        }
    }
    if (cache.signature == Signature::kUnknown && !exe.empty()) cache.signature = CheckSignature(exe);
    return cache;
}

}  // namespace

Status CollectIntegrityReport(proto::IntegrityReport* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    *out = proto::IntegrityReport();
    out->platform = SG_INTEGRITY_PLATFORM_WINDOWS;
    const StaticObservations s = Static();
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
    if (s.signature != Signature::kSigned) flags |= SG_INTEGRITY_UNSIGNED_EXECUTABLE;

    BOOL remote = FALSE;
    if (IsDebuggerPresent() || (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote)) {
        flags |= SG_INTEGRITY_DEBUGGER_PRESENT;
    }
    if (!ExecutableHasDynamicBase()) flags |= SG_INTEGRITY_ASLR_DISABLED;
    PROCESS_MITIGATION_DEP_POLICY dep{};
    if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDEPPolicy, &dep, sizeof(dep))) {
#if !defined(_WIN64)
        if (!dep.Enable) flags |= SG_INTEGRITY_DEP_DISABLED;
#endif
        // 64-bit processes always run with DEP.
    }
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)) ||
        !cfg.EnableControlFlowGuard) {
        flags |= SG_INTEGRITY_CFG_DISABLED;
    }
    if (ModulesFromTempDirectory()) flags |= SG_INTEGRITY_UNEXPECTED_MODULES;
    out->observation_flags = flags & SG_INTEGRITY_KNOWN_FLAGS;
    return OkStatus();
}

}  // namespace sg::client::os
