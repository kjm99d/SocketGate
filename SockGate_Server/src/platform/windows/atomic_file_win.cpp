#include "storage/atomic_file.h"

#include "sockgate_common/crypto/crypto.h"

#include <windows.h>

#include <algorithm>
#include <climits>
#include <cwchar>

namespace sg::server {
namespace {

bool ToWide(const std::string& in, std::wstring* out)
{
    if (in.empty() || in.size() > static_cast<size_t>(INT_MAX)) return false;
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()), nullptr, 0);
    if (n <= 0) return false;
    out->resize(static_cast<size_t>(n));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()), out->data(), n) == n;
}

struct HandleCloser {
    HANDLE h;
    ~HandleCloser()
    {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};

}  // namespace

Status ReadWholeFile(const std::string& path, Bytes* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    std::wstring wpath;
    if (!ToWide(path, &wpath)) return SG_INVALID_ARGUMENT;
    HandleCloser file{CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (file.h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        return (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? Status(SG_NOT_FOUND)
                                                                             : Status(SG_STORAGE_ERROR);
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file.h, &size) || size.QuadPart < 0 ||
        static_cast<unsigned long long>(size.QuadPart) > kMaxStorageFileSize) {
        return SG_STORAGE_ERROR;
    }
    out->resize(static_cast<size_t>(size.QuadPart));
    size_t done = 0;
    while (done < out->size()) {
        DWORD chunk = 0;
        const DWORD want = static_cast<DWORD>(std::min<size_t>(out->size() - done, 1u << 20));
        if (!ReadFile(file.h, out->data() + done, want, &chunk, nullptr) || chunk == 0) return SG_STORAGE_ERROR;
        done += chunk;
    }
    return OkStatus();
}

Status WriteFileAtomically(const std::string& path, ByteView data)
{
    std::wstring wpath;
    if (!ToWide(path, &wpath)) return SG_INVALID_ARGUMENT;
    uint8_t rnd[8];
    SG_TRY(crypto::RandomBytes(rnd, sizeof(rnd)));
    wchar_t suffix[32];
    swprintf(suffix, 32, L".tmp-%02x%02x%02x%02x%02x%02x%02x%02x", rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5],
             rnd[6], rnd[7]);
    const std::wstring tmp = wpath + suffix;

    {
        HandleCloser file{CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (file.h == INVALID_HANDLE_VALUE) return SG_STORAGE_ERROR;
        size_t done = 0;
        while (done < data.size()) {
            DWORD chunk = 0;
            const DWORD want = static_cast<DWORD>(std::min<size_t>(data.size() - done, 1u << 20));
            if (!WriteFile(file.h, data.data() + done, want, &chunk, nullptr) || chunk == 0) {
                CloseHandle(file.h);
                file.h = INVALID_HANDLE_VALUE;
                DeleteFileW(tmp.c_str());
                return SG_STORAGE_ERROR;
            }
            done += chunk;
        }
        if (!FlushFileBuffers(file.h)) {
            CloseHandle(file.h);
            file.h = INVALID_HANDLE_VALUE;
            DeleteFileW(tmp.c_str());
            return SG_STORAGE_ERROR;
        }
    }
    if (!MoveFileExW(tmp.c_str(), wpath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        return SG_STORAGE_ERROR;
    }
    return OkStatus();
}

}  // namespace sg::server
