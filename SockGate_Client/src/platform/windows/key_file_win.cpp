// Windows implementation of platform/key_file.h: DPAPI-wrapped key blobs in
// a per-user directory whose DACL admits only the user and SYSTEM.
#include "platform/key_file.h"

#include "sockgate_common/crypto/crypto.h"

#include <windows.h>
#include <aclapi.h>
#include <dpapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <algorithm>
#include <climits>
#include <vector>

namespace sg::client::platform {
namespace {

bool ToWide(const std::string& in, std::wstring* out)
{
    if (in.empty() || in.size() > static_cast<size_t>(INT_MAX)) return false;
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()), nullptr, 0);
    if (n <= 0) return false;
    out->resize(static_cast<size_t>(n));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()), out->data(), n) == n;
}

bool ToUtf8(const std::wstring& in, std::string* out)
{
    if (in.empty() || in.size() > static_cast<size_t>(INT_MAX)) return false;
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()), nullptr, 0,
                                      nullptr, nullptr);
    if (n <= 0) return false;
    out->resize(static_cast<size_t>(n));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()), out->data(), n,
                               nullptr, nullptr) == n;
}

class Handle {
public:
    explicit Handle(HANDLE h) : h_(h) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const noexcept { return h_; }
    bool valid() const noexcept { return h_ != INVALID_HANDLE_VALUE && h_ != nullptr; }
    void reset() noexcept
    {
        if (valid()) CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }

private:
    HANDLE h_;
};

bool ValidFileName(const std::string& file)
{
    return !file.empty() && file != "." && file != ".." && file.find_first_of("/\\:") == std::string::npos &&
           file.find('\0') == std::string::npos;
}

Status JoinPath(const std::string& dir, const std::string& file, std::wstring* out)
{
    if (!ValidFileName(file)) return SG_INVALID_ARGUMENT;
    std::wstring wdir;
    std::wstring wfile;
    if (!ToWide(dir, &wdir) || !ToWide(file, &wfile)) return SG_INVALID_ARGUMENT;
    if (wdir.back() != L'\\' && wdir.back() != L'/') wdir.push_back(L'\\');
    *out = wdir + wfile;
    return OkStatus();
}

// TOKEN_USER of the current process (the buffer owns the SID).
Status CurrentUser(std::vector<uint8_t>* buf, PSID* sid)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return SG_KEYSTORE_ERROR;
    Handle token_guard(token);
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0) return SG_KEYSTORE_ERROR;
    buf->assign(size, 0);
    if (!GetTokenInformation(token, TokenUser, buf->data(), size, &size)) return SG_KEYSTORE_ERROR;
    *sid = reinterpret_cast<const TOKEN_USER*>(buf->data())->User.Sid;
    return OkStatus();
}

// "D:P(A;OICI;FA;;;<user>)(A;OICI;FA;;;SY)": protected DACL, the current
// user and SYSTEM only (no inheritance from the parent directory).
Status OwnerOnlySecurityDescriptor(PSECURITY_DESCRIPTOR* out)
{
    std::vector<uint8_t> buf;
    PSID user = nullptr;
    SG_TRY(CurrentUser(&buf, &user));
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(user, &sid)) return SG_KEYSTORE_ERROR;
    const std::wstring sddl = std::wstring(L"D:P(A;OICI;FA;;;") + sid + L")(A;OICI;FA;;;SY)";
    LocalFree(sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, out, nullptr)) {
        return SG_KEYSTORE_ERROR;
    }
    return OkStatus();
}

bool IsWellKnown(PSID sid, WELL_KNOWN_SID_TYPE type)
{
    return IsWellKnownSid(sid, type) != FALSE;
}

// Principals allowed to own or modify the key directory.
bool Trusted(PSID sid, PSID user)
{
    return EqualSid(sid, user) || IsWellKnown(sid, WinLocalSystemSid) || IsWellKnown(sid, WinBuiltinAdministratorsSid) ||
           IsWellKnown(sid, WinCreatorOwnerSid) || IsWellKnown(sid, WinCreatorOwnerRightsSid);
}

// The key directory must be a real directory owned by the user (or SYSTEM /
// Administrators) that nobody else can modify - including through
// inherit-only entries, which key files would inherit.
Status VerifyDirectory(const std::wstring& path)
{
    HANDLE raw = CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (raw == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        return err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND ? Status(SG_NOT_FOUND)
                                                                          : Status(SG_KEYSTORE_ERROR);
    }
    Handle h(raw);
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(raw, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return SG_KEYSTORE_ERROR;
    }
    std::vector<uint8_t> user_buf;
    PSID user = nullptr;
    SG_TRY(CurrentUser(&user_buf, &user));
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(raw, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
                        &dacl, nullptr, &sd) != ERROR_SUCCESS) {
        return SG_KEYSTORE_ERROR;
    }
    constexpr ACCESS_MASK kModify = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD |
                                    FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE |
                                    GENERIC_ALL;
    bool ok = owner != nullptr && Trusted(owner, user) && dacl != nullptr;  // NULL DACL = everyone
    for (DWORD i = 0; ok && i < dacl->AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(dacl, i, &ace)) {
            ok = false;
            break;
        }
        const auto* header = static_cast<const ACE_HEADER*>(ace);
        if (header->AceType == ACCESS_DENIED_ACE_TYPE || header->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
            header->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE ||
            header->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE) {
            continue;  // deny entries only restrict
        }
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            ok = false;  // conditional / object allow entries: not evaluated, so refused
            break;
        }
        const auto* allowed = static_cast<const ACCESS_ALLOWED_ACE*>(ace);
        PSID sid = const_cast<DWORD*>(&allowed->SidStart);
        if ((allowed->Mask & kModify) != 0 && !Trusted(sid, user)) ok = false;
    }
    LocalFree(sd);
    return ok ? OkStatus() : Status(SG_KEYSTORE_ERROR);
}

// Files placed by anyone but the user (or SYSTEM / Administrators) are refused.
Status VerifyOwner(HANDLE file)
{
    std::vector<uint8_t> user_buf;
    PSID user = nullptr;
    SG_TRY(CurrentUser(&user_buf, &user));
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &sd) !=
        ERROR_SUCCESS) {
        return SG_KEYSTORE_ERROR;
    }
    const bool ok = owner != nullptr && Trusted(owner, user);
    LocalFree(sd);
    return ok ? OkStatus() : Status(SG_KEYSTORE_ERROR);
}

// Every operation re-checks the directory: it is looked up by path again.
Status VerifiedDirectory(const std::string& dir)
{
    std::wstring wdir;
    if (!ToWide(dir, &wdir)) return SG_INVALID_ARGUMENT;
    while (wdir.size() > 3 && (wdir.back() == L'\\' || wdir.back() == L'/')) wdir.pop_back();
    return VerifyDirectory(wdir);
}

DATA_BLOB Blob(ByteView v)
{
    DATA_BLOB b;
    b.cbData = static_cast<DWORD>(v.size());
    b.pbData = const_cast<BYTE*>(v.data());
    return b;
}

// Opens dir/file without following reparse points. SG_NOT_FOUND if absent.
// Sharing violations are transient on Windows (a concurrent publish still
// holds its rename handle, antivirus scanners): retry for up to 250 ms.
Status OpenKeyFile(const std::wstring& path, DWORD access, DWORD share, HANDLE* out)
{
    const ULONGLONG deadline = GetTickCount64() + 250;
    for (;;) {
        *out = CreateFileW(path.c_str(), access, share, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (*out != INVALID_HANDLE_VALUE) return OkStatus();
        const DWORD err = GetLastError();
        if (err == ERROR_SHARING_VIOLATION && GetTickCount64() < deadline) {
            Sleep(1);
            continue;
        }
        return err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND ? Status(SG_NOT_FOUND)
                                                                          : Status(SG_KEYSTORE_ERROR);
    }
}

// A plain (no reparse point, singly linked) file of bounded size.
Status VerifyKeyFile(HANDLE h, uint64_t* size)
{
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(h, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || info.nNumberOfLinks != 1) {
        return SG_KEYSTORE_ERROR;
    }
    *size = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    return *size <= kMaxKeyFileSize ? OkStatus() : Status(SG_KEYSTORE_ERROR);
}

Status WriteAll(HANDLE h, ByteView data)
{
    size_t done = 0;
    while (done < data.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(data.size() - done, 1u << 20));
        DWORD written = 0;
        if (!WriteFile(h, data.data() + done, chunk, &written, nullptr) || written == 0) return SG_KEYSTORE_ERROR;
        done += written;
    }
    return FlushFileBuffers(h) ? OkStatus() : Status(SG_KEYSTORE_ERROR);
}

}  // namespace

BlobProtection PlatformBlobProtection() noexcept { return BlobProtection::kDpapiUser; }

Status ProtectKeyBlob(ByteView plain, ByteView context, Bytes* out)
{
    if (out == nullptr || plain.size() > kMaxKeyFileSize) return SG_INVALID_ARGUMENT;
    DATA_BLOB in = Blob(plain);
    DATA_BLOB entropy = Blob(context);
    DATA_BLOB result{};
    if (!CryptProtectData(&in, L"SockGate installation key", &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                          &result)) {
        return SG_KEYSTORE_ERROR;
    }
    out->assign(result.pbData, result.pbData + result.cbData);
    LocalFree(result.pbData);
    return OkStatus();
}

Status UnprotectKeyBlob(ByteView blob, ByteView context, SecureBytes* out)
{
    if (out == nullptr || blob.size() > kMaxKeyFileSize) return SG_INVALID_ARGUMENT;
    DATA_BLOB in = Blob(blob);
    DATA_BLOB entropy = Blob(context);
    DATA_BLOB result{};
    if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &result)) {
        return SG_KEYSTORE_ERROR;
    }
    out->assign(result.pbData, result.pbData + result.cbData);
    SecureZeroMemory(result.pbData, result.cbData);
    LocalFree(result.pbData);
    return OkStatus();
}

Status DefaultKeyDirectory(std::string* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    PWSTR base = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &base))) {
        if (base != nullptr) CoTaskMemFree(base);
        return SG_KEYSTORE_ERROR;
    }
    const std::wstring path = std::wstring(base) + L"\\SockGate\\keys";
    CoTaskMemFree(base);
    return ToUtf8(path, out) ? OkStatus() : Status(SG_KEYSTORE_ERROR);
}

Status PrepareKeyDirectory(const std::string& dir)
{
    std::wstring wdir;
    if (!ToWide(dir, &wdir)) return SG_INVALID_ARGUMENT;
    while (wdir.size() > 3 && (wdir.back() == L'\\' || wdir.back() == L'/')) wdir.pop_back();
    if (GetFileAttributesW(wdir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // Components below the root (drive or \\server\share) that may need creating.
        auto is_sep = [](wchar_t c) { return c == L'\\' || c == L'/'; };
        size_t start = 0;
        if (wdir.rfind(L"\\\\", 0) == 0) {
            size_t p = wdir.find_first_of(L"\\/", 2);
            if (p != std::wstring::npos) p = wdir.find_first_of(L"\\/", p + 1);
            start = p == std::wstring::npos ? wdir.size() : p + 1;
        } else if (wdir.size() >= 2 && wdir[1] == L':') {
            start = 3;
        }
        PSECURITY_DESCRIPTOR sd = nullptr;
        SG_TRY(OwnerOnlySecurityDescriptor(&sd));
        SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
        for (size_t pos = start; pos <= wdir.size(); ++pos) {
            if (pos != wdir.size() && !is_sep(wdir[pos])) continue;
            if (pos == 0 || is_sep(wdir[pos - 1])) continue;
            // Existing components (possibly not creatable by us) are fine.
            CreateDirectoryW(wdir.substr(0, pos).c_str(), &sa);
        }
        LocalFree(sd);
    }
    return VerifyDirectory(wdir);
}

Status CreateKeyFile(const std::string& dir, const std::string& file, ByteView data)
{
    if (data.size() > kMaxKeyFileSize) return SG_INVALID_ARGUMENT;
    SG_TRY(PrepareKeyDirectory(dir));  // recreated if it was removed
    std::wstring target;
    SG_TRY(JoinPath(dir, file, &target));
    uint8_t rnd[8];
    SG_TRY(crypto::RandomBytes(rnd, sizeof(rnd)));
    std::wstring tmp;
    SG_TRY(JoinPath(dir, "." + file + "." + ToHex(ByteView(rnd, sizeof(rnd))) + ".tmp", &tmp));

    Handle h(CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (!h.valid()) return SG_KEYSTORE_ERROR;
    const Status written = WriteAll(h.get(), data);
    h.reset();
    if (!written.ok()) {
        DeleteFileW(tmp.c_str());
        return written;
    }
    // No MOVEFILE_REPLACE_EXISTING: fails if the key already exists.
    if (!MoveFileExW(tmp.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) {
        const DWORD err = GetLastError();
        DeleteFileW(tmp.c_str());
        return err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS ? Status(SG_ALREADY_EXISTS)
                                                                       : Status(SG_KEYSTORE_ERROR);
    }
    return OkStatus();
}

Status ReadKeyFile(const std::string& dir, const std::string& file, SecureBytes* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    std::wstring path;
    SG_TRY(JoinPath(dir, file, &path));
    SG_TRY(VerifiedDirectory(dir));
    HANDLE raw = INVALID_HANDLE_VALUE;
    // FILE_SHARE_DELETE lets a concurrent publish finish its rename; the
    // content is verified after reading anyway.
    SG_TRY(OpenKeyFile(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_DELETE, &raw));
    Handle h(raw);
    uint64_t size = 0;
    SG_TRY(VerifyKeyFile(raw, &size));
    SG_TRY(VerifyOwner(raw));
    out->assign(static_cast<size_t>(size), 0);
    size_t done = 0;
    while (done < out->size()) {
        DWORD n = 0;
        if (!ReadFile(raw, out->data() + done, static_cast<DWORD>(out->size() - done), &n, nullptr) || n == 0) {
            return SG_KEYSTORE_ERROR;
        }
        done += n;
    }
    return OkStatus();
}

Status DeleteKeyFile(const std::string& dir, const std::string& file)
{
    std::wstring path;
    SG_TRY(JoinPath(dir, file, &path));
    SG_TRY(VerifiedDirectory(dir));
    HANDLE raw = INVALID_HANDLE_VALUE;
    SG_TRY(OpenKeyFile(path, GENERIC_WRITE | DELETE, 0, &raw));
    Handle h(raw);
    uint64_t size = 0;
    SG_TRY(VerifyKeyFile(raw, &size));
    // Best effort: the storage medium may keep old blocks (see limitations).
    WriteAll(raw, Bytes(static_cast<size_t>(size), 0)).IgnoreError();
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    if (!SetFileInformationByHandle(raw, FileDispositionInfo, &disposition, sizeof(disposition))) {
        return SG_KEYSTORE_ERROR;
    }
    return OkStatus();
}

}  // namespace sg::client::platform
