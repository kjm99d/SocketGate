# SockGate

**English** | [한국어](README.ko.md) | [日本語](README.ja.md)

A C/C++ **network authentication gate** library that you embed in your application (0.1.0, unreleased).
Each client installation proves itself to the server with its own unique asymmetric key, and the server makes every
authentication, license, and policy decision on the server side. After that, traffic runs over TLS 1.3 with every
frame protected by a sequence number and an AES-256-GCM authentication tag; encrypting the payload as well (AEAD) is
optional.

```c
#include <sockgate/client.h>   /* same API on Windows and Linux */
```

## Components

| Project | Role | Documents |
|---|---|---|
| [SockGate_Client](SockGate_Client/README.md) | Client library that goes into your application (`SockGate::Client`) | README, ARCHITECTURE, THREAT_MODEL, PROTOCOL, SECURITY, BUILD, INTEGRATION, CHANGELOG |
| [SockGate_Server](SockGate_Server/README.md) | Authentication gate server library (`SockGate::Server`) | Same |
| [SockGate_Common](SockGate_Common/README.md) | Protocol, cryptography, TLS, and serialization layer and common headers shared by both libraries | Same |

Design documents: [docs/design](docs/README.md) — architecture, threat model, trust boundary, protocol, handshake,
key and session lifecycle, public C API, platform layers, dependencies, and **what is not guaranteed**.
Apart from the READMEs, the per-project documents and the design documents are written in Korean.

## Security summary

- **TLS 1.3 by default**; TLS 1.2 only when explicitly allowed (EMS required). Certificate chain, hostname, and validity
  period verification, optional multiple SPKI pinning, optional server proof key signature.
- **Per-installation keys**: TPM (Windows CNG Platform Crypto Provider / Linux TPM2), CNG Software KSP (non-exportable),
  DPAPI / 0600 file storage. No secrets in the binary. The installation id is derived from the public key.
- **Challenge-response**: one-time challenge, signature over the TLS channel binding and the transcript — prevents relay and replay.
- **The server decides**: the product, license, feature, and integrity values the client sends are all *claims*.
  granted = requested ∩ license, license expiry caps the session lifetime, and revocation ends sessions immediately.
- **Strict parser**: big-endian binary protocol, per-stage header rules, pre-authentication size limits, fuzzing.
- **DoS mitigation**: a connection limit plus a separate limit on unauthenticated connections, handshake and idle timeouts,
  minimum re-authentication interval.
- **No reliance on proxy detection**: certificate verification, pinning, and channel binding stop MITM.
- What it does not do: custom cryptographic algorithms, hardcoded master secrets, private keys in the binary, decisions based
  on client booleans. For the detailed limitations, see [docs/design/13-security-limitations.md](docs/design/13-security-limitations.md).

## Quick start

```sh
# Windows (Developer PowerShell, VCPKG_ROOT set)             # Linux (libssl-dev, ninja, cmake)
cmake --preset windows-msvc-release                          cmake --preset linux-gcc-release
cmake --build --preset windows-msvc-release                  cmake --build --preset linux-gcc-release
ctest --preset windows-msvc-release                          ctest --preset linux-gcc-release
```

Run the examples with development certificates (`out/build/<preset>/bin`):

```sh
sg_admin dev-pki ./dev                        # development-only CA + localhost server certificate; prints the SPKI pin
sg_admin token-key ./dev/token.key
sg_echo_server --cert dev/server.crt --key dev/server.key --port 7443 \
               --registry dev/registry.bin --token-key dev/token.key --issue-token sockgate-echo
# Save the one-time enrollment token the server prints to dev/token.txt (do not put it on the command line), then:
sg_echo_client --host localhost --port 7443 --ca dev/ca.crt --pin <SPKI pin> \
               --key-dir dev/keys --enroll-file dev/token.txt
```

While running, the server locks the registry and license files (`<path>.lock`). Stop the server before you modify these files with `sg_admin`.

After installing, from another CMake project:

```cmake
find_package(SockGate 0.1 REQUIRED)
target_link_libraries(app PRIVATE SockGate::Client)   # or SockGate::Server
```

API reference (all headers, Doxygen comments): `doxygen Doxyfile` from the repository root, or `cmake --build --preset <preset> --target docs` when CMake found Doxygen; the output is `out/doxygen/html/index.html`.

## Repository layout

```text
SockGate_Common/   common headers (error/types/version/export) + internal common library
SockGate_Client/   client library (C API: include/sockgate/client.h, config.h)
SockGate_Server/   server library (C API: include/sockgate/server.h)
examples/          C examples: sg_echo_server, sg_echo_client
tools/             sg_admin: offline administration (pins, tokens, licenses, clients, dev PKI)
tests/             unit / protocol / security / integration tests (CTest labels), package consumer
fuzz/              libFuzzer targets + deterministic mutation driver for CTest
cmake/             options, compiler hardening, sanitizers, install/package
docs/design/       design documents 01–13
.github/workflows/ CI (Windows/Linux/ARM64, sanitizers, TPM2(swtpm), package, container, fuzz)
```

## Status

0.1.0 is not yet released and is the ABI baseline. During 0.x, the ABI can change with every minor version
(soname `libsockgate_*.so.0.1`, CMake package compatibility SameMinorVersion). For the change history, see each project's CHANGELOG.md.
Report vulnerabilities privately to the maintainers, not in public issues.

## License

SockGate is released under the [MIT License](LICENSE). Third-party components (OpenSSL, tpm2-tss) keep their own
licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
