# SockGate_Client

**English** | [한국어](README.ko.md) | [日本語](README.ja.md)

> Version 0.1.0 (Unreleased) · C ABI version `SOCKGATE_API_VERSION = 1` · wire protocol v1

SockGate_Client is an **authentication gate client library** that you embed in C/C++ applications.
It is not a plain socket wrapper: over a TLS channel whose server has been verified, it performs challenge-response authentication
with a per-installation key, and it protects every frame of an authenticated session with a sequence number and an AEAD tag.
The server always decides authorization (policy, features, lifetime).

The design rationale is in documents 01–13 in [docs/design](../docs/design/); the documents in this directory describe,
from the client's perspective, **what the current code actually does**. The detailed documents and the design documents are written in Korean.

## Features

| Area | Description |
|---|---|
| TLS | TLS 1.3 on OpenSSL 3 (TLS 1.2 only with `SG_CLIENT_FLAG_ALLOW_TLS12`, Extended Master Secret required). Chain, hostname/IP, and validity period verification; no partial wildcards; no session resumption, compression, or renegotiation |
| Server authentication | A CA supplied by the application (`ca_file` / `ca_pem`) or the OS trust store (`SG_TRUST_SYSTEM_STORE`), optional **SPKI pinning** (up to 8, compared only against the verified chain), optional **server proof key** (up to 4; when set, a server signature is required) |
| Installation key | Keeps an ECDSA P-256 key in the **TPM** (Windows CNG Platform Crypto Provider / Linux TPM2), **CNG Software KSP** (DPAPI-protected, non-exportable), **FILE** (Windows DPAPI, Linux 0600), or **MEMORY**. `SG_KEYSTORE_AUTO` picks the strongest store, and a locator file keeps the identity from moving between stores |
| Authentication | A signature over a transcript that includes the server challenge and the TLS exporter channel binding (`SG_Client_Authenticate`). Enrollment of a new installation with a one-time enrollment token (`SG_Client_Enroll`) — the token secret is never transmitted |
| Protected channel | Per-direction sequence (exactly +1), monotonically increasing request IDs, an AES-256-GCM tag on every frame. `SG_CLIENT_FLAG_APP_ENCRYPTION` also encrypts the DATA payload at the application layer |
| Re-authentication | `SG_Client_Refresh` or `SG_CLIENT_FLAG_AUTO_REFRESH` (once 80% of the lifetime has elapsed): new signature, per-direction key rotation (epoch+1), TLS 1.3 KeyUpdate |
| Proxy | **DIRECT** by default (reads neither system settings nor environment variables). `SG_PROXY_MODE_SYSTEM` (queries OS settings only when requested), `SG_PROXY_MODE_EXPLICIT` (HTTP CONNECT / SOCKS4a / SOCKS5). The proxy relays only TLS ciphertext |
| Integrity | With `SG_CLIENT_FLAG_INTEGRITY_REPORT`, reports observations such as the executable/library SHA-256, debugger, and ASLR to the server. This is a claim that **the server uses only to lower trust** |
| Execution model | Synchronous (blocking) API with timeouts. The library creates no threads. Supports concurrent Send/Receive calls and waking a waiting call by calling Disconnect from another thread |

## Same API on Windows and Linux

A single `#include <sockgate/client.h>` is enough for the public API (it also includes `config.h`, `types.h`, `error.h`, `export.h`,
and `version.h`). The headers compile as both C99 and C++ and include no OS headers, C++ types, or STL.
Function names, struct layouts, error code values, and behavioral contracts are the same on both platforms. The only platform
differences are the following, and all of them surface as **return values of the same API**.

- Requesting a key store type the platform lacks (for example, `SG_KEYSTORE_CNG_TPM` on Linux, or `SG_KEYSTORE_TPM2` in a build without tpm2-tss) makes `SG_Client_Create` return `SG_NOT_SUPPORTED`.
- The default key directory, the settings source for `SG_PROXY_MODE_SYSTEM`, and the integrity observations differ by OS.

```c
#include <sockgate/client.h>   /* identical on Windows (MSVC, clang-cl) and Linux (GCC, Clang) */
```

## Minimal example

A trimmed-down version of [examples/echo_client.c](../examples/echo_client.c) (pure C, public API only).

```c
#include <sockgate/client.h>
#include <stdio.h>

int echo_once(const char* host, uint16_t port, const char* ca_file, const SG_Sha256* pin)
{
    SG_ClientConfig config;
    SG_ServerConfig server;
    SG_IdentityInfo id;
    SG_MessageInfo info;
    SG_Client* client = NULL;
    char reply[1024];
    size_t received = 0;
    uint64_t request_id = 0;
    SG_Status st;

    SG_ClientConfig_Init(&config);                      /* fill in defaults (including size/version) */
    config.identity_name = "com.example.sockgate-echo"; /* reverse-DNS: a name shared per user */
    config.key_store_type = SG_KEYSTORE_AUTO;           /* default: TPM first */
    config.product_id = "sockgate-echo";                /* only a claim; the server decides */
    config.flags = SG_CLIENT_FLAG_APP_ENCRYPTION | SG_CLIENT_FLAG_AUTO_REFRESH;
    st = SG_Client_Create(&config, &client);
    if (st != SG_OK) return (int)st;

    SG_IdentityInfo_Init(&id);
    st = SG_Client_EnsureIdentity(client, &id);         /* creates it if missing, loads it if present */
    if (st == SG_OK) {
        /* Register id.public_key (65 bytes) with the server, or use SG_Client_Enroll. */
        SG_ServerConfig_Init(&server);
        server.host = host;
        server.port = port;
        server.ca_file = ca_file;                       /* private CA */
        server.spki_pins = pin;                         /* pinning recommended in production */
        server.spki_pin_count = pin != NULL ? 1u : 0u;

        st = SG_Client_Connect(client, &server);        /* TCP (+proxy) + TLS + server verification */
        if (st == SG_OK) st = SG_Client_Authenticate(client);
        if (st == SG_OK) st = SG_Client_SendEx(client, "hello", 5, 0, &request_id);
        if (st == SG_OK) {
            SG_MessageInfo_Init(&info);
            st = SG_Client_ReceiveEx(client, reply, sizeof(reply), &received, &info, SG_WAIT_DEFAULT);
        }
        if (st != SG_OK) fprintf(stderr, "sockgate: %s\n", SG_StatusString(st));
    }
    SG_Client_Disconnect(client);
    SG_Client_Destroy(client);
    return (int)st;
}
```

The example executable `sg_echo_client` is included in builds with `SOCKGATE_BUILD_EXAMPLES=ON` (the default).

```text
sg_echo_client --host HOST --port N --ca FILE [--pin HEX] [--identity NAME]
               [--key-dir DIR] [--product ID] [--enroll-file FILE]
```

- On startup, it prints the installation ID and the public key in hex. If the installation is not registered, register that public key
  with the server or enroll with `--enroll-file FILE` ([INTEGRATION.md §9](INTEGRATION.md#9-installation-등록-out-of-band-vs-enrollment)).
  So that the token does not remain in the process list or shell history, it is read from a **file** (one line), not from the command line,
  and wiped with volatile stores right after use (the compiler can remove `memset`; your application should do the same with `SecureZeroMemory` / `explicit_bzero` / a volatile loop).
- `--port` accepts only a decimal number in 1..65535. With `--key-dir`, the FILE key store is used; otherwise AUTO.
- Received responses are treated as untrusted data: it checks that `SG_MESSAGE_FLAG_RESPONSE` is set and that `request_id` is the ID of the request it just sent,
  and it escapes unprintable bytes as `\xNN`.

## Build and link

```cmake
find_package(SockGate 0.1 REQUIRED)                    # during 0.x, only the same minor version is compatible
target_link_libraries(myapp PRIVATE SockGate::Client)
```

The installed package contains only the 8 public headers, the libraries, and the CMake configuration. For presets, options,
shared vs. static differences, and the soname, see [BUILD.md](BUILD.md).

## Directory layout

```text
SockGate_Client/
├── CMakeLists.txt                sockgate_client_core (internal static) + sockgate_client (public, SockGate::Client)
├── include/sockgate/
│   ├── client.h                  client C API
│   ├── config.h                  SG_ClientConfig, SG_ServerConfig, SG_ProxyConfig, constants
│   └── sockgate.h                umbrella header (version/error/types/config/client)
├── src/
│   ├── core/client_api.cpp       C ABI: argument validation, struct size/version, exceptions → SG_Status
│   ├── session/                  ClientSession: state machine, connection generation, locking, re-authentication
│   ├── auth/                     ClientHandshake: CLIENT_HELLO / CLIENT_PROOF / AUTH_RESULT (sans-IO)
│   ├── tls/                      TlsChannel: blocking TLS over ITransport
│   ├── transport/                TcpTransport, proxy negotiation, transport_factory (proxy policy)
│   ├── crypto/                   IKeyStore, MEMORY / FILE / AUTO key stores, factory
│   └── platform/
│       ├── windows/              CNG key store, DPAPI key file, system proxy (WinHTTP), integrity
│       └── linux/                POSIX key file, TPM2 key store, system proxy (environment variables), integrity
└── *.md                          these documents
```

Protocol serialization, frame protection, the TLS engine, and socket primitives exist only once, in
[SockGate_Common](../SockGate_Common/README.md), which is shared with the server.

## Documents

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, state machine, connection generation and locking, key stores, thread safety |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Client-side threats and mitigations, residual risks |
| [PROTOCOL.md](PROTOCOL.md) | Handshake/re-authentication/channel rules as the client sees them, and the mapping to SG_* codes |
| [SECURITY.md](SECURITY.md) | Secure configuration, key store selection, security tests, vulnerability reporting |
| [BUILD.md](BUILD.md) | Requirements, presets, options, tests, install and `find_package(SockGate)`, CI |
| [INTEGRATION.md](INTEGRATION.md) | Step-by-step embedding guide: configuration fields and defaults, call order, error handling, ABI rules |
| [CHANGELOG.md](CHANGELOG.md) | Change history |

Design documents: [01 Architecture](../docs/design/01-architecture.md) ·
[02 Threat Model](../docs/design/02-threat-model.md) ·
[04 Protocol](../docs/design/04-protocol-specification.md) ·
[05 Handshake](../docs/design/05-handshake-sequence.md) ·
[06 Key Lifecycle](../docs/design/06-key-lifecycle.md) ·
[07 Session Lifecycle](../docs/design/07-session-lifecycle.md) ·
[09 Public C API](../docs/design/09-public-c-api.md) ·
[13 Security Limitations](../docs/design/13-security-limitations.md)
