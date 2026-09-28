# SockGate_Common

**English** | [한국어](README.ko.md) | [日本語](README.ja.md)

The detailed documents and the design documents referenced below are written in Korean.

> The common implementation layer of SockGate. It is an **internal static library**, not something applications link to directly.
> The only public APIs are the C ABIs of `SockGate_Client` (`sockgate/client.h`) and `SockGate_Server` (`sockgate/server.h`).

## 1. Role

SockGate_Common provides two things.

1. **Internal static library `sockgate_common`** (CMake alias `SockGate::Common`)
   - Holds **a single copy** of the security-sensitive code (serialization, frame/message parsers, cryptographic primitives, TLS engine, socket abstraction).
     Because Client and Server use the same parsers and the same validation code, a fix can never land on only one side
     ([01-architecture.md §2](../docs/design/01-architecture.md)).
   - `sockgate_client_core` and `sockgate_server_core` link it as `PUBLIC`. The test and fuzz targets also link it directly.
   - The `src/sockgate_common/**` headers are internal only. They are not installed and have no ABI/API stability guarantee.
   - In the installed package (`find_package(SockGate)`), it is not included in shared builds; only in static builds is `SockGate::Common`
     exported, as a dependency of the Client/Server archives. Applications do not link to it directly ([BUILD.md §1](BUILD.md)).
2. **Common public C headers** (`include/sockgate/`)
   - Common definitions that the public headers of both Client and Server include. They are installed with the Client/Server packages
     (the installed public headers are only these 4 plus 3 from Client and 1 from Server, 8 in total).

| Header | Contents |
|---|---|
| `sockgate/version.h` | `SOCKGATE_VERSION_MAJOR/MINOR/PATCH` (currently 0.1.0), `SOCKGATE_API_VERSION` (1), `SOCKGATE_PROTOCOL_VERSION` (1). The top-level `CMakeLists.txt` reads the project version from this file (the single source of truth for the version) |
| `sockgate/export.h` | `SG_CLIENT_API` / `SG_SERVER_API`, `SG_CALL`, `SG_EXTERN_C_BEGIN/END` |
| `sockgate/error.h` | `SG_Status` (`int32_t`), error codes 0–29, `SG_StatusString()` (`static inline`) |
| `sockgate/types.h` | ID/hash/public key structs, log levels and callback, client states, session policy, integrity observation bits, `SG_MessageInfo` |

Error codes and ABI rules are summarized in [INTEGRATION.md](INTEGRATION.md).

## 2. Components

| Module | Namespace | Contents |
|---|---|---|
| `core/` | `sg` | `Status` (`[[nodiscard]]`), `ToPublicStatus`, `SecureBytes`/`SecureZero`/`ConstantTimeEqual`, monotonic clock/`Deadline`, log callback `Logger`, ABI helpers (`abi.h`) |
| `serialization/` | `sg::ser` | big-endian `Reader`/`Writer`, strict TLV parser, base64url, protocol string (UTF-8) validation |
| `protocol/` | `sg::proto` | wire constants, 48-byte `FrameHeader` codec, `FrameDecoder`, per-stage rules `CheckHeaderForState`, message codecs, transcript/key derivation, enrollment token, post-authentication frame protection `ProtectedChannel` |
| `crypto/` | `sg::crypto` | OpenSSL 3 EVP wrappers: SHA-256, HMAC-SHA256, HKDF-SHA256, AES-256-GCM, ECDSA P-256 (P1363), CSPRNG, `SoftwareP256Key` |
| `tls/` | `sg::tls` | sans-IO TLS engine (`ITlsProvider` / `ITlsContext` / `ITlsEngine`, OpenSSL memory BIO), certificate and hostname verification, SPKI pinning, exporter / channel binding, detection of outdated bundled OpenSSL |
| `net/` | `sg::net` | byte stream abstraction `ITransport`, `Endpoint` |
| `platform/` | `sg::platform` | Winsock2 / POSIX socket primitives, address resolution, OS trust store loading |

For the dependency direction between modules and the design, see [ARCHITECTURE.md](ARCHITECTURE.md); for the wire format, see [PROTOCOL.md](PROTOCOL.md).

## 3. Directory

```text
SockGate_Common/
├── CMakeLists.txt                     target: sockgate_common (STATIC), alias SockGate::Common
├── include/sockgate/                  common public C headers (compile as both C and C++)
│   ├── error.h  export.h  types.h  version.h
└── src/sockgate_common/               internal implementation (not installed)
    ├── core/            status.h  bytes.h/.cpp  clock.h  log.h/.cpp  abi.h
    ├── serialization/   byte_order.h  reader.*  writer.*  tlv.*  base64.*
    ├── protocol/        constants.h  frame.*  rules.*  messages.*  transcript.*
    │                    enrollment_token.*  channel.*
    ├── crypto/          crypto.h  openssl_crypto.cpp
    ├── tls/             tls.h  openssl_tls.cpp
    ├── net/             transport.h
    └── platform/        socket.h  trust_store.h
        ├── windows/     socket_win.cpp  trust_store_win.cpp
        └── linux/       socket_posix.cpp  trust_store_linux.cpp
```

- Internal include form: `#include "sockgate_common/protocol/frame.h"`. Public headers: `#include <sockgate/types.h>`.
- Only files under `platform/windows` and `platform/linux` include OS headers. CMake removes the files for the other platform
  from the source list (`SOCKGATE_PLATFORM`).

## 4. Dependencies

- OpenSSL ≥ 3.0 (`OpenSSL::SSL`, `OpenSSL::Crypto`), `Threads::Threads` — linked as `PUBLIC`.
- Windows: `ws2_32`, `crypt32`.
- There are no other external libraries. For details, see [BUILD.md](BUILD.md) and [12-dependencies.md](../docs/design/12-dependencies.md).

## 5. Documents

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module structure, error model, memory wiping, TLS engine, frame decoder, channel protection, platform abstraction |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threats to the parser/cryptography layers and mitigations, residual risks |
| [PROTOCOL.md](PROTOCOL.md) | Wire format summary (header, messages, TLV, stage rules, transcript, key derivation, token) |
| [SECURITY.md](SECURITY.md) | Cryptographic choices, TLS configuration, wiping, constant-time comparison, parser hardening, fuzzing, vulnerability reporting |
| [BUILD.md](BUILD.md) | Build, OpenSSL requirements, presets, fuzzers, tests |
| [INTEGRATION.md](INTEGRATION.md) | For SockGate developers: using the modules, adding messages/TLVs, common headers, ABI rules |
| [CHANGELOG.md](CHANGELOG.md) | Change history |

The reference design documents are in [docs/design](../docs/design/) (01–13). In particular,
[01 Architecture](../docs/design/01-architecture.md), [04 Protocol Specification](../docs/design/04-protocol-specification.md),
[05 Handshake Sequence](../docs/design/05-handshake-sequence.md), [08 Directory Structure](../docs/design/08-directory-structure.md),
and [09 Public C API](../docs/design/09-public-c-api.md) relate directly to this library.
