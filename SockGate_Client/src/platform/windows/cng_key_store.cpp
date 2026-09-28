// Windows CNG key store (NCrypt): per-user persisted ECDSA P-256 keys in the
// Microsoft Platform Crypto Provider (TPM) or the Microsoft Software KSP.
// Private keys are never exported: the TPM keeps them inside the chip, the
// software KSP stores them DPAPI-protected and marked non-exportable.
#include "crypto/key_store.h"

#include <windows.h>
#include <ncrypt.h>
#include <tbs.h>

#include <atomic>
#include <climits>
#include <cstring>
#include <vector>

namespace sg::client {
namespace {

constexpr wchar_t kKeyPrefix[] = L"SockGate-";

bool ToWide(const std::string& in, std::wstring* out)
{
    if (in.empty() || in.size() > static_cast<size_t>(INT_MAX)) return false;
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()), nullptr, 0);
    if (n <= 0) return false;
    out->resize(static_cast<size_t>(n));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()), out->data(), n) == n;
}

class KeyHandle {
public:
    KeyHandle() = default;
    ~KeyHandle()
    {
        if (h_ != 0) NCryptFreeObject(h_);
    }
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    NCRYPT_KEY_HANDLE* put() noexcept { return &h_; }
    NCRYPT_KEY_HANDLE get() const noexcept { return h_; }
    void release() noexcept { h_ = 0; }

private:
    NCRYPT_KEY_HANDLE h_ = 0;
};

class CngKeyStore final : public IKeyStore {
public:
    enum class Creation { kSupported, kUnsupported, kUnknown };

    CngKeyStore(NCRYPT_PROV_HANDLE provider, bool tpm, Creation creation)
        : provider_(provider), tpm_(tpm), creation_(creation)
    {
    }

    static Creation QueryCreation()
    {
        TPM_DEVICE_INFO info{};
        const TBS_RESULT r = Tbsi_GetDeviceInfo(sizeof(info), &info);
        if (r == TBS_SUCCESS) return info.tpmVersion == TPM_VERSION_20 ? Creation::kSupported : Creation::kUnsupported;
        if (r == static_cast<TBS_RESULT>(TBS_E_TPM_NOT_FOUND) || r == static_cast<TBS_RESULT>(TBS_E_SERVICE_DISABLED)) {
            return Creation::kUnsupported;
        }
        return Creation::kUnknown;  // e.g. TBS still starting
    }
    ~CngKeyStore() override { NCryptFreeObject(provider_); }

    KeyStoreKind Kind() const noexcept override { return tpm_ ? KeyStoreKind::kCngTpm : KeyStoreKind::kCngSoftware; }
    bool HardwareBacked() const noexcept override { return tpm_; }

    Status GenerateKeyPair(const std::string& name) override
    {
        std::wstring key_name;
        SG_TRY(KeyName(name, &key_name));
        Creation creation = creation_.load();
        if (creation == Creation::kUnknown) {
            creation = QueryCreation();  // may have become known since
            creation_.store(creation);
        }
        if (creation == Creation::kUnsupported) return SG_NOT_SUPPORTED;
        if (creation == Creation::kUnknown) return SG_KEYSTORE_ERROR;  // TPM state not known: try again later
        KeyHandle key;
        SECURITY_STATUS s = NCryptCreatePersistedKey(provider_, key.put(), BCRYPT_ECDSA_P256_ALGORITHM,
                                                     key_name.c_str(), 0, 0);
        if (s == NTE_EXISTS) return SG_ALREADY_EXISTS;
        if (s != ERROR_SUCCESS) return CreationFailure(s);

        DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
        s = NCryptSetProperty(key.get(), NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof(usage),
                              0);
        if (s != ERROR_SUCCESS) return CreationFailure(s);
        if (!tpm_) {
            DWORD export_policy = 0;  // not exportable, not even as plaintext archive
            s = NCryptSetProperty(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&export_policy),
                                  sizeof(export_policy), NCRYPT_PERSIST_FLAG);
            if (s != ERROR_SUCCESS) return CreationFailure(s);
        }
        s = NCryptFinalizeKey(key.get(), NCRYPT_SILENT_FLAG);
        if (s == NTE_EXISTS) return SG_ALREADY_EXISTS;
        if (s != ERROR_SUCCESS) return CreationFailure(s);
        return OkStatus();
    }

    Status GetPublicKey(const std::string& name, crypto::P256PublicKey* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        KeyHandle key;
        SG_TRY(Open(name, &key));
        return ExportPublic(key.get(), out);
    }

    Status Sign(const std::string& name, ByteView message, crypto::P256Signature* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        KeyHandle key;
        SG_TRY(Open(name, &key));
        crypto::Sha256Digest digest;
        SG_TRY(crypto::Sha256(message, &digest));
        DWORD written = 0;
        // ECDSA signatures from CNG are r || s (P1363), 32 bytes each for P-256.
        const SECURITY_STATUS s = NCryptSignHash(key.get(), nullptr, digest.data(), static_cast<DWORD>(digest.size()),
                                                 out->data(), static_cast<DWORD>(out->size()), &written,
                                                 NCRYPT_SILENT_FLAG);
        if (s != ERROR_SUCCESS || written != out->size()) return SG_KEYSTORE_ERROR;
        return OkStatus();
    }

    Status DeleteKey(const std::string& name) override
    {
        KeyHandle key;
        SG_TRY(Open(name, &key));
        // No NCRYPT_SILENT_FLAG: the Platform Crypto Provider rejects it for
        // deletion (NTE_BAD_FLAGS); our keys carry no UI policy anyway.
        if (NCryptDeleteKey(key.get(), 0) != ERROR_SUCCESS) return SG_KEYSTORE_ERROR;
        key.release();  // NCryptDeleteKey freed the handle
        return OkStatus();
    }

private:
    // Only a definite "cannot do this" lets AUTO create the identity in the
    // next (weaker) store; transient TPM failures (busy, lockout, service
    // starting) are errors so the identity is not permanently downgraded.
    Status CreationFailure(SECURITY_STATUS s) const
    {
        return tpm_ && DefinitelyUnsupported(s) ? Status(SG_NOT_SUPPORTED) : Status(SG_KEYSTORE_ERROR);
    }

    // CNG / TPM 2.0 answers that will not change by retrying: algorithm or
    // curve not supported, owner hierarchy disabled. TPM 2.0 errors arrive
    // as 0x80280000 | response code (parameter bits removed here).
    static bool DefinitelyUnsupported(SECURITY_STATUS s)
    {
        if (s == NTE_NOT_SUPPORTED || s == NTE_BAD_ALGID) return true;
        const auto code = static_cast<uint32_t>(s);
        if ((code & 0xFFFF0000u) != 0x80280000u) return false;
        const uint32_t rc = code & 0xFFFu;
        const uint32_t base = (rc & 0x80u) != 0 ? (rc & 0xBFu) : rc;
        const uint32_t hr = 0x80280000u | base;
        return hr == static_cast<uint32_t>(TPM_20_E_ASYMMETRIC) || hr == static_cast<uint32_t>(TPM_20_E_HASH) ||
               hr == static_cast<uint32_t>(TPM_20_E_HIERARCHY) || hr == static_cast<uint32_t>(TPM_20_E_KEY_SIZE) ||
               hr == static_cast<uint32_t>(TPM_20_E_SCHEME) || hr == static_cast<uint32_t>(TPM_20_E_CURVE);
    }


    static Status KeyName(const std::string& name, std::wstring* out)
    {
        SG_TRY(ValidateKeyName(name));
        std::wstring wide;
        if (!ToWide(name, &wide)) return SG_INVALID_ARGUMENT;
        *out = std::wstring(kKeyPrefix) + wide;
        return OkStatus();
    }

    Status Open(const std::string& name, KeyHandle* key)
    {
        std::wstring key_name;
        SG_TRY(KeyName(name, &key_name));
        const SECURITY_STATUS s = NCryptOpenKey(provider_, key->put(), key_name.c_str(), 0, NCRYPT_SILENT_FLAG);
        if (s == NTE_BAD_KEYSET || s == NTE_NO_KEY) return SG_NOT_FOUND;
        // Any other failure is an error, never "absent": AUTO must not create
        // a new identity elsewhere because the TPM is temporarily unavailable.
        if (s != ERROR_SUCCESS) return SG_KEYSTORE_ERROR;
        return OkStatus();
    }

    static Status ExportPublic(NCRYPT_KEY_HANDLE key, crypto::P256PublicKey* out)
    {
        DWORD size = 0;
        if (NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &size, 0) != ERROR_SUCCESS ||
            size != sizeof(BCRYPT_ECCKEY_BLOB) + 64) {
            return SG_KEYSTORE_ERROR;
        }
        std::vector<uint8_t> blob(size);
        if (NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), size, &size, 0) != ERROR_SUCCESS) {
            return SG_KEYSTORE_ERROR;
        }
        BCRYPT_ECCKEY_BLOB header;
        std::memcpy(&header, blob.data(), sizeof(header));
        if (header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || header.cbKey != 32) return SG_KEYSTORE_ERROR;
        (*out)[0] = 0x04;  // SEC1 uncompressed point: X || Y follow the header
        std::memcpy(out->data() + 1, blob.data() + sizeof(header), 64);
        return crypto::ValidateP256PublicKey(*out);
    }

    NCRYPT_PROV_HANDLE provider_;
    const bool tpm_;
    std::atomic<Creation> creation_;
};

}  // namespace

Status CreateCngKeyStore(bool tpm, std::unique_ptr<IKeyStore>* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    NCRYPT_PROV_HANDLE provider = 0;
    const SECURITY_STATUS s =
        NCryptOpenStorageProvider(&provider, tpm ? MS_PLATFORM_CRYPTO_PROVIDER : MS_KEY_STORAGE_PROVIDER, 0);
    if (s != ERROR_SUCCESS) return SG_NOT_SUPPORTED;
    // New TPM keys need a TPM 2.0 (ECC P-256). Without one the store still
    // looks up existing keys. "No TPM" must be a definite answer; a TBS
    // service that cannot be asked right now leaves it unknown.
    const auto creation = tpm ? CngKeyStore::QueryCreation() : CngKeyStore::Creation::kSupported;
    *out = std::make_unique<CngKeyStore>(provider, tpm, creation);
    return OkStatus();
}

}  // namespace sg::client
