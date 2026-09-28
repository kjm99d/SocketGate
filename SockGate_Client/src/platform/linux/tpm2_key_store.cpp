// Linux TPM 2.0 key store (tpm2-tss ESAPI), built with SOCKGATE_WITH_TPM2.
//
// Every key is an ECDSA P-256 signing key created inside the TPM under a
// primary storage key that is re-derived on demand from a fixed template in
// the owner hierarchy (nothing is persisted in the TPM). The TPM returns the
// private part encrypted to that primary; it is stored with the public part
// in "<name>.tpm2key" (owner-only file, see platform/key_file.h):
//
//   u32 magic "SGT2" | u16 version (1) | u16 len | TPM2B_PUBLIC | u16 len | TPM2B_PRIVATE
//
// The blob is useless without this machine's TPM.
#include "crypto/key_store.h"

#include "platform/key_file.h"

#include "sockgate_common/serialization/reader.h"
#include "sockgate_common/serialization/writer.h"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#include <cstdlib>
#include <cstring>
#include <mutex>
#include <unistd.h>

namespace sg::client {
namespace {

constexpr uint32_t kTpmKeyMagic = 0x53475432;  // "SGT2"
constexpr uint16_t kTpmKeyVersion = 1;
constexpr char kResourceManager[] = "/dev/tpmrm0";

std::string FileName(const std::string& name) { return name + ".tpm2key"; }

// TPM response code without the parameter/handle/session number bits.
TSS2_RC BaseCode(TSS2_RC rc)
{
    if ((rc & TSS2_RC_LAYER_MASK) != TSS2_TPM_RC_LAYER) return rc;
    return (rc & TPM2_RC_FMT1) != 0 ? (rc & (TPM2_RC_FMT1 | 0x3Fu)) : (rc & 0xFFFu);
}

// Definite "this TPM cannot create our key here" answers: AUTO may then
// create the identity in the next store. Everything else is transient.
bool DefinitelyUnsupported(TSS2_RC rc)
{
    const TSS2_RC base = BaseCode(rc);
    return base == TPM2_RC_BAD_AUTH || base == TPM2_RC_AUTH_FAIL ||  // owner hierarchy has an auth value
           base == TPM2_RC_HIERARCHY ||                             // owner hierarchy disabled
           base == TPM2_RC_CURVE || base == TPM2_RC_SCHEME || base == TPM2_RC_ASYMMETRIC ||
           base == TPM2_RC_KEY_SIZE || base == TPM2_RC_HASH;
}

// Connection-level failures (TCTI or the tabrmd resource manager): reconnect.
bool TransportError(TSS2_RC rc)
{
    const TSS2_RC layer = rc & TSS2_RC_LAYER_MASK;
    return layer == TSS2_TCTI_RC_LAYER || layer == TSS2_RESMGR_RC_LAYER || layer == TSS2_RESMGR_TPM_RC_LAYER;
}

// A TPM is only used through the kernel resource manager /dev/tpmrm0. It
// does not exist for TPM 1.2 or on kernels before 4.12, and is created
// together with /sys/class/tpm/tpm0, so a missing or inaccessible device is a
// lasting state: no TPM for SockGate (not in the tss group counts as well).
bool ResourceManagerUsable() { return ::access(kResourceManager, R_OK | W_OK) == 0; }

// SOCKGATE_TPM2_TCTI may only name the well-known TCTIs (never a library path).
bool AllowedTcti(const std::string& conf)
{
    const std::string name = conf.substr(0, conf.find(':'));
    return name == "device" || name == "tabrmd" || name == "swtpm" || name == "mssim";
}

// Primary storage key: TCG-style ECC P-256 SRK template.
TPM2B_PUBLIC PrimaryTemplate()
{
    TPM2B_PUBLIC t;
    std::memset(&t, 0, sizeof(t));
    TPMT_PUBLIC& p = t.publicArea;
    p.type = TPM2_ALG_ECC;
    p.nameAlg = TPM2_ALG_SHA256;
    p.objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
                         TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
                         TPMA_OBJECT_NODA;
    p.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    p.parameters.eccDetail.symmetric.keyBits.aes = 128;
    p.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    p.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    p.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    p.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    p.unique.ecc.x.size = 32;
    p.unique.ecc.y.size = 32;
    return t;
}

// Signing key: ECDSA P-256 / SHA-256, bound to this TPM and parent.
TPM2B_PUBLIC SigningTemplate()
{
    TPM2B_PUBLIC t;
    std::memset(&t, 0, sizeof(t));
    TPMT_PUBLIC& p = t.publicArea;
    p.type = TPM2_ALG_ECC;
    p.nameAlg = TPM2_ALG_SHA256;
    p.objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                         TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA;
    p.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    p.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
    p.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    p.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    p.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    return t;
}

// Left-pads a TPM ECC parameter to 32 bytes.
bool CopyCoordinate(const TPM2B_ECC_PARAMETER& in, uint8_t* out32)
{
    if (in.size > 32) return false;
    std::memset(out32, 0, 32);
    std::memcpy(out32 + (32 - in.size), in.buffer, in.size);
    return true;
}

Status PublicFromTpm(const TPM2B_PUBLIC& pub, crypto::P256PublicKey* out)
{
    const TPMT_PUBLIC& p = pub.publicArea;
    if (p.type != TPM2_ALG_ECC || p.parameters.eccDetail.curveID != TPM2_ECC_NIST_P256 ||
        p.parameters.eccDetail.scheme.scheme != TPM2_ALG_ECDSA ||
        (p.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT) == 0 || (p.objectAttributes & TPMA_OBJECT_FIXEDTPM) == 0) {
        return SG_KEYSTORE_ERROR;
    }
    (*out)[0] = 0x04;
    if (!CopyCoordinate(p.unique.ecc.x, out->data() + 1) || !CopyCoordinate(p.unique.ecc.y, out->data() + 33)) {
        return SG_KEYSTORE_ERROR;
    }
    return crypto::ValidateP256PublicKey(*out);
}

class Tpm2KeyStore final : public IKeyStore {
public:
    Tpm2KeyStore(std::string dir, std::string tcti_conf) : dir_(std::move(dir)), tcti_conf_(std::move(tcti_conf)) {}

    ~Tpm2KeyStore() override { Disconnect(); }

    KeyStoreKind Kind() const noexcept override { return KeyStoreKind::kTpm2; }
    bool HardwareBacked() const noexcept override { return true; }

    Status GenerateKeyPair(const std::string& name) override
    {
        SG_TRY(ValidateKeyName(name));
        std::lock_guard<std::mutex> lock(mutex_);
        // SG_NOT_SUPPORTED (AUTO moves on to the next store) only for
        // definite answers; transient TPM trouble must not downgrade a new
        // identity for good.
        if (tcti_conf_.empty()) return SG_NOT_SUPPORTED;  // no usable TPM
        if (!Connect()) return SG_KEYSTORE_ERROR;
        ESYS_TR primary = ESYS_TR_NONE;
        SG_TRY(CreatePrimary(&primary));
        TPM2B_SENSITIVE_CREATE sensitive;
        std::memset(&sensitive, 0, sizeof(sensitive));
        const TPM2B_PUBLIC in_public = SigningTemplate();
        TPM2B_DATA outside;
        std::memset(&outside, 0, sizeof(outside));
        TPML_PCR_SELECTION pcrs;
        std::memset(&pcrs, 0, sizeof(pcrs));
        TPM2B_PRIVATE* out_private = nullptr;
        TPM2B_PUBLIC* out_public = nullptr;
        TPM2B_CREATION_DATA* creation_data = nullptr;
        TPM2B_DIGEST* creation_hash = nullptr;
        TPMT_TK_CREATION* creation_ticket = nullptr;
        const TSS2_RC rc = Esys_Create(esys_, primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive,
                                       &in_public, &outside, &pcrs, &out_private, &out_public, &creation_data,
                                       &creation_hash, &creation_ticket);
        Esys_FlushContext(esys_, primary);
        Esys_Free(creation_data);
        Esys_Free(creation_hash);
        Esys_Free(creation_ticket);
        Status st = Classify(rc);
        Bytes file;
        if (st.ok()) st = Encode(*out_public, *out_private, &file);
        Esys_Free(out_private);
        Esys_Free(out_public);
        SG_TRY(st);
        return platform::CreateKeyFile(dir_, FileName(name), file);
    }

    Status GetPublicKey(const std::string& name, crypto::P256PublicKey* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        TPM2B_PUBLIC pub;
        TPM2B_PRIVATE priv;
        SG_TRY(Read(name, &pub, &priv));
        return PublicFromTpm(pub, out);
    }

    Status Sign(const std::string& name, ByteView message, crypto::P256Signature* out) override
    {
        if (out == nullptr) return SG_INVALID_ARGUMENT;
        TPM2B_PUBLIC pub;
        TPM2B_PRIVATE priv;
        SG_TRY(Read(name, &pub, &priv));
        crypto::P256PublicKey public_key;
        SG_TRY(PublicFromTpm(pub, &public_key));
        crypto::Sha256Digest digest;
        SG_TRY(crypto::Sha256(message, &digest));

        std::lock_guard<std::mutex> lock(mutex_);
        if (!Connect()) return SG_KEYSTORE_ERROR;  // an existing TPM key without its TPM
        ESYS_TR primary = ESYS_TR_NONE;
        if (!CreatePrimary(&primary).ok()) return SG_KEYSTORE_ERROR;
        ESYS_TR key = ESYS_TR_NONE;
        TSS2_RC rc = Esys_Load(esys_, primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &priv, &pub, &key);
        Esys_FlushContext(esys_, primary);
        if (rc != TSS2_RC_SUCCESS) {
            Classify(rc).IgnoreError();  // resets the connection after transport errors
            return SG_KEYSTORE_ERROR;
        }

        TPM2B_DIGEST tpm_digest;
        std::memset(&tpm_digest, 0, sizeof(tpm_digest));
        tpm_digest.size = static_cast<UINT16>(digest.size());
        std::memcpy(tpm_digest.buffer, digest.data(), digest.size());
        TPMT_SIG_SCHEME scheme;
        std::memset(&scheme, 0, sizeof(scheme));
        scheme.scheme = TPM2_ALG_ECDSA;
        scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
        // Unrestricted key: no hash check ticket needed (NULL ticket).
        TPMT_TK_HASHCHECK validation;
        std::memset(&validation, 0, sizeof(validation));
        validation.tag = TPM2_ST_HASHCHECK;
        validation.hierarchy = TPM2_RH_NULL;
        TPMT_SIGNATURE* signature = nullptr;
        rc = Esys_Sign(esys_, key, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &tpm_digest, &scheme, &validation,
                       &signature);
        Esys_FlushContext(esys_, key);
        if (rc != TSS2_RC_SUCCESS || signature == nullptr) {
            Esys_Free(signature);
            if (rc != TSS2_RC_SUCCESS) Classify(rc).IgnoreError();
            return SG_KEYSTORE_ERROR;
        }
        const bool ok = signature->sigAlg == TPM2_ALG_ECDSA &&
                        CopyCoordinate(signature->signature.ecdsa.signatureR, out->data()) &&
                        CopyCoordinate(signature->signature.ecdsa.signatureS, out->data() + 32);
        Esys_Free(signature);
        if (!ok) return SG_KEYSTORE_ERROR;
        // Fault check: never hand out a signature the public key does not verify.
        return crypto::VerifyP256(public_key, message, *out).ok() ? OkStatus() : Status(SG_KEYSTORE_ERROR);
    }

    Status DeleteKey(const std::string& name) override
    {
        SG_TRY(ValidateKeyName(name));
        return platform::DeleteKeyFile(dir_, FileName(name));
    }

private:
    // Maps a TPM result for key creation; drops a broken connection so the
    // next call reconnects. Caller holds mutex_.
    Status Classify(TSS2_RC rc)
    {
        if (rc == TSS2_RC_SUCCESS) return OkStatus();
        if (TransportError(rc)) Disconnect();
        return DefinitelyUnsupported(rc) ? Status(SG_NOT_SUPPORTED) : Status(SG_KEYSTORE_ERROR);
    }

    void Disconnect()
    {
        if (esys_ != nullptr) Esys_Finalize(&esys_);
        if (tcti_ != nullptr) Tss2_TctiLdr_Finalize(&tcti_);
        esys_ = nullptr;
        tcti_ = nullptr;
    }

    // Lazily opens the TPM; false if it is not reachable. Caller holds mutex_.
    bool Connect()
    {
        if (esys_ != nullptr) return true;
        if (tcti_conf_.empty()) return false;
        if (Tss2_TctiLdr_Initialize(tcti_conf_.c_str(), &tcti_) != TSS2_RC_SUCCESS) {
            tcti_ = nullptr;
            return false;
        }
        if (Esys_Initialize(&esys_, tcti_, nullptr) != TSS2_RC_SUCCESS) {
            esys_ = nullptr;
            Tss2_TctiLdr_Finalize(&tcti_);
            tcti_ = nullptr;
            return false;
        }
        return true;
    }

    Status CreatePrimary(ESYS_TR* out)
    {
        TPM2B_SENSITIVE_CREATE sensitive;
        std::memset(&sensitive, 0, sizeof(sensitive));
        const TPM2B_PUBLIC in_public = PrimaryTemplate();
        TPM2B_DATA outside;
        std::memset(&outside, 0, sizeof(outside));
        TPML_PCR_SELECTION pcrs;
        std::memset(&pcrs, 0, sizeof(pcrs));
        TPM2B_PUBLIC* out_public = nullptr;
        TPM2B_CREATION_DATA* creation_data = nullptr;
        TPM2B_DIGEST* creation_hash = nullptr;
        TPMT_TK_CREATION* creation_ticket = nullptr;
        const TSS2_RC rc = Esys_CreatePrimary(esys_, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                              &sensitive, &in_public, &outside, &pcrs, out, &out_public,
                                              &creation_data, &creation_hash, &creation_ticket);
        Esys_Free(out_public);
        Esys_Free(creation_data);
        Esys_Free(creation_hash);
        Esys_Free(creation_ticket);
        return Classify(rc);
    }

    static Status Encode(const TPM2B_PUBLIC& pub, const TPM2B_PRIVATE& priv, Bytes* out)
    {
        uint8_t pub_buf[sizeof(TPM2B_PUBLIC)];
        uint8_t priv_buf[sizeof(TPM2B_PRIVATE)];
        size_t pub_len = 0;
        size_t priv_len = 0;
        if (Tss2_MU_TPM2B_PUBLIC_Marshal(&pub, pub_buf, sizeof(pub_buf), &pub_len) != TSS2_RC_SUCCESS ||
            Tss2_MU_TPM2B_PRIVATE_Marshal(&priv, priv_buf, sizeof(priv_buf), &priv_len) != TSS2_RC_SUCCESS) {
            return SG_KEYSTORE_ERROR;
        }
        ser::Writer w(out);
        w.U32(kTpmKeyMagic);
        w.U16(kTpmKeyVersion);
        SG_TRY(w.Vec16(ByteView(pub_buf, pub_len)));
        SG_TRY(w.Vec16(ByteView(priv_buf, priv_len)));
        return OkStatus();
    }

    Status Read(const std::string& name, TPM2B_PUBLIC* pub, TPM2B_PRIVATE* priv)
    {
        SG_TRY(ValidateKeyName(name));
        SecureBytes data;
        SG_TRY(platform::ReadKeyFile(dir_, FileName(name), &data));
        ser::Reader r(data);
        uint32_t magic = 0;
        uint16_t version = 0;
        ByteView pub_bytes;
        ByteView priv_bytes;
        if (!r.U32(&magic).ok() || magic != kTpmKeyMagic || !r.U16(&version).ok() || version != kTpmKeyVersion ||
            !r.Vec16(1, sizeof(TPM2B_PUBLIC), &pub_bytes).ok() ||
            !r.Vec16(1, sizeof(TPM2B_PRIVATE), &priv_bytes).ok() || !r.ExpectEnd().ok()) {
            return SG_KEYSTORE_ERROR;
        }
        std::memset(pub, 0, sizeof(*pub));
        std::memset(priv, 0, sizeof(*priv));
        size_t off = 0;
        if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(pub_bytes.data(), pub_bytes.size(), &off, pub) != TSS2_RC_SUCCESS ||
            off != pub_bytes.size()) {
            return SG_KEYSTORE_ERROR;
        }
        off = 0;
        if (Tss2_MU_TPM2B_PRIVATE_Unmarshal(priv_bytes.data(), priv_bytes.size(), &off, priv) != TSS2_RC_SUCCESS ||
            off != priv_bytes.size()) {
            return SG_KEYSTORE_ERROR;
        }
        return OkStatus();
    }

    const std::string dir_;
    const std::string tcti_conf_;  // empty: no usable TPM
    std::mutex mutex_;             // ESAPI contexts are not thread-safe
    TSS2_TCTI_CONTEXT* tcti_ = nullptr;
    ESYS_CONTEXT* esys_ = nullptr;
};

}  // namespace

Status CreateTpm2KeyStore(const std::string& directory, std::unique_ptr<IKeyStore>* out)
{
    if (out == nullptr) return SG_INVALID_ARGUMENT;
    std::string dir = directory;
    if (dir.empty()) SG_TRY(platform::DefaultKeyDirectory(&dir));
    SG_TRY(platform::PrepareKeyDirectory(dir));
    // Only the kernel resource manager (or an explicit TCTI) is used; the raw
    // /dev/tpm0 is exclusive and not shared with other TPM users.
    std::string tcti;
    const char* configured = ::secure_getenv("SOCKGATE_TPM2_TCTI");
    if (configured != nullptr && configured[0] != '\0') {
        if (!AllowedTcti(configured)) return SG_INVALID_ARGUMENT;
        tcti = configured;
    } else if (ResourceManagerUsable()) {
        tcti = std::string("device:") + kResourceManager;
    }
    *out = std::make_unique<Tpm2KeyStore>(std::move(dir), std::move(tcti));
    return OkStatus();
}

}  // namespace sg::client
