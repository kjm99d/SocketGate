// Server-side registry of client installations (public keys + status) and of
// consumed enrollment tokens.
#pragma once

#include "sockgate_common/core/status.h"
#include "sockgate_common/crypto/crypto.h"
#include "sockgate_common/protocol/constants.h"
#include "sockgate_common/protocol/enrollment_token.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace sg::server {

enum class ClientStatus : uint8_t { kActive = 1, kRevoked = 2 };

struct ClientRecord {
    proto::InstallationId installation_id{};
    crypto::P256PublicKey public_key{};
    uint8_t key_algorithm = proto::kKeyAlgorithmEcdsaP256Sha256;
    ClientStatus status = ClientStatus::kActive;
    std::string product_id;   // optional binding
    std::string license_id;   // optional binding
    uint64_t created_at_ms = 0;
};

class IClientRegistry {
public:
    virtual ~IClientRegistry() = default;

    // SG_NOT_FOUND when unknown.
    virtual Status Find(const proto::InstallationId& id, ClientRecord* out) = 0;

    // SG_ALREADY_EXISTS if the installation id is known (active or revoked).
    virtual Status Register(const ClientRecord& record) = 0;

    // SG_NOT_FOUND when unknown. Idempotent for already revoked records.
    virtual Status Revoke(const proto::InstallationId& id) = 0;

    // Atomically consumes `token_id` and inserts `record`. Fails without any
    // change with SG_ALREADY_EXISTS if either the token was already used or
    // the installation id is known. The change is durable when this returns OK.
    virtual Status EnrollAtomically(const ClientRecord& record, const proto::TokenId& token_id,
                                    uint64_t token_expires_at_ms) = 0;

    virtual bool IsTokenUsed(const proto::TokenId& token_id) = 0;

    virtual size_t Count() = 0;
    virtual void ForEach(const std::function<void(const ClientRecord&)>& fn) = 0;
};

std::unique_ptr<IClientRegistry> CreateMemoryClientRegistry();

// Registry persisted to `path` (atomic replace on every change). Loads the
// existing file, validating every record as untrusted input.
Status CreateFileClientRegistry(const std::string& path, std::unique_ptr<IClientRegistry>* out);

}  // namespace sg::server
