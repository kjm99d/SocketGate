// FILE key store: one file "<name>.sgkey" per key in a per-user directory.
//
// File format (big endian):
//   u32 magic "SGKY" | u16 version (1) | u8 protection | u8 reserved (0) |
//   public key[65] | u32 length | protected PKCS#8 (ECDSA P-256)
// The protection id must match this platform's (DPAPI on Windows, owner-only
// file on Linux). The loaded private key must match the stored public key,
// (checked by signing), which detects corruption where the protection has no
// integrity check of its own. The private key is only held in memory while it is used.
#include "crypto/key_store.h"

#include "platform/key_file.h"

#include "sockgate_common/serialization/reader.h"
#include "sockgate_common/serialization/writer.h"

namespace sg::client {
namespace {

constexpr uint32_t kKeyFileMagic = 0x53474B59;  // "SGKY"
constexpr uint16_t kKeyFileVersion = 1;
constexpr char kContextPrefix[] = "SockGate/v1/file-key/";
constexpr char kProbeMessage[] = "SockGate/v1/file-key-check";

std::string FileName(const std::string& name) { return name + ".sgkey"; }

Bytes Context(const std::string& name)
{
    Bytes ctx(kContextPrefix, kContextPrefix + sizeof(kContextPrefix) - 1);
    const ByteView bytes = ser::AsBytes(name);
    ctx.insert(ctx.end(), bytes.begin(), bytes.end());
    return ctx;
}

class FileKeyStore final : public IKeyStore {
public:
    explicit FileKeyStore(std::string directory) : dir_(std::move(directory)) {}

    KeyStoreKind Kind() const noexcept override { return KeyStoreKind::kFile; }
    bool HardwareBacked() const noexcept override { return false; }

    Status GenerateKeyPair(const std::string& name) override
    {
        SG_TRY(ValidateKeyName(name));
        std::unique_ptr<crypto::SoftwareP256Key> key;
        SG_TRY(crypto::SoftwareP256Key::Generate(&key));
        SecureBytes pkcs8;
        SG_TRY(key->ToPkcs8Der(&pkcs8));
        crypto::P256PublicKey public_key;
        SG_TRY(key->PublicKey(&public_key));
        Bytes protected_blob;
        SG_TRY(os::ProtectKeyBlob(pkcs8, Context(name), &protected_blob));

        Bytes file;
        ser::Writer w(&file);
        w.U32(kKeyFileMagic);
        w.U16(kKeyFileVersion);
        w.U8(static_cast<uint8_t>(os::PlatformBlobProtection()));
        w.U8(0);
        w.Raw(public_key);
        w.U32(static_cast<uint32_t>(protected_blob.size()));
        w.Raw(protected_blob);
        SecureZero(protected_blob.data(), protected_blob.size());
        const Status st = os::CreateKeyFile(dir_, FileName(name), file);
        SecureZero(file.data(), file.size());
        return st;
    }

    Status GetPublicKey(const std::string& name, crypto::P256PublicKey* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        std::unique_ptr<crypto::SoftwareP256Key> key;
        return Load(name, &key, out);
    }

    Status Sign(const std::string& name, ByteView message, crypto::P256Signature* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        std::unique_ptr<crypto::SoftwareP256Key> key;
        crypto::P256PublicKey public_key;
        SG_TRY(Load(name, &key, &public_key));
        return key->Sign(message, out);
    }

    Status DeleteKey(const std::string& name) override
    {
        SG_TRY(ValidateKeyName(name));
        return os::DeleteKeyFile(dir_, FileName(name));
    }

private:
    // Loads and verifies the key; *public_key receives the verified public key.
    Status Load(const std::string& name, std::unique_ptr<crypto::SoftwareP256Key>* out,
                crypto::P256PublicKey* public_key)
    {
        SG_TRY(ValidateKeyName(name));
        SecureBytes data;
        SG_TRY(os::ReadKeyFile(dir_, FileName(name), &data));
        ser::Reader r(data);
        uint32_t magic = 0;
        uint16_t version = 0;
        uint8_t protection = 0;
        uint8_t reserved = 1;
        uint32_t length = 0;
        crypto::P256PublicKey stored_public{};
        ByteView blob;
        if (!r.U32(&magic).ok() || magic != kKeyFileMagic || !r.U16(&version).ok() || version != kKeyFileVersion ||
            !r.U8(&protection).ok() || protection != static_cast<uint8_t>(os::PlatformBlobProtection()) ||
            !r.U8(&reserved).ok() || reserved != 0 || !r.Fixed(&stored_public).ok() || !r.U32(&length).ok() ||
            !r.View(length, &blob).ok() || !r.ExpectEnd().ok()) {
            SecureZero(data.data(), data.size());
            return SG_KEYSTORE_ERROR;
        }
        SecureBytes pkcs8;
        const Status unwrapped = os::UnprotectKeyBlob(blob, Context(name), &pkcs8);
        SecureZero(data.data(), data.size());
        SG_TRY(unwrapped);
        // The private scalar must match the stored public key (pairwise check
        // by signing), and so must the public key OpenSSL reports for it.
        std::unique_ptr<crypto::SoftwareP256Key> key;
        crypto::P256PublicKey derived{};
        crypto::P256Signature probe{};
        const ByteView probe_message(reinterpret_cast<const uint8_t*>(kProbeMessage), sizeof(kProbeMessage) - 1);
        if (!crypto::SoftwareP256Key::FromPkcs8Der(pkcs8, &key).ok() || !key->PublicKey(&derived).ok() ||
            derived != stored_public || !key->Sign(probe_message, &probe).ok() ||
            !crypto::VerifyP256(stored_public, probe_message, probe).ok()) {
            return SG_KEYSTORE_ERROR;
        }
        *out = std::move(key);
        *public_key = stored_public;
        return OkStatus();
    }

    const std::string dir_;
};

}  // namespace

Status CreateFileKeyStore(const std::string& directory, std::unique_ptr<IKeyStore>* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    std::string dir = directory;
    if (dir.empty()) SG_TRY(os::DefaultKeyDirectory(&dir));
    SG_TRY(os::PrepareKeyDirectory(dir));
    *out = std::make_unique<FileKeyStore>(std::move(dir));
    return OkStatus();
}

}  // namespace sg::client
