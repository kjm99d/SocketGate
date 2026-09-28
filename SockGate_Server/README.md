# SockGate_Server

**English** | [한국어](README.ko.md) | [日本語](README.ja.md)

The **server library** of SockGate. It embeds in a C/C++ server application, cryptographically authenticates client
installations over TLS, makes the final license, feature, and integrity policy decisions **on the server**, and then
delivers messages from authenticated sessions to application callbacks. The only public interface is a single C ABI (`sockgate/server.h`).

- Version: 0.1.0 (unreleased), `SOCKGATE_API_VERSION` 1, wire protocol v1
- Platforms: Windows 10/11 x64 (IOCP), Linux x64/ARM64 (epoll)
- Runtime dependency: OpenSSL ≥ 3.0 ([BUILD.md](BUILD.md))

The reference design documents are 01–13 in [`docs/design`](../docs/design/). The documents in this directory describe the
actual implementation of the server library; where the design and the implementation differ, they follow the implementation.
The detailed documents in this directory and the design documents are written in Korean.

## Features

| Area | Description |
|---|---|
| Transport security | TLS 1.3 (default). When `SG_SERVER_OPT_ALLOW_TLS12` allows TLS 1.2, the server uses only ECDHE + AEAD suites and accepts **only connections that negotiated Extended Master Secret**. Compression, renegotiation, and session resumption (tickets, session cache) are disabled |
| Client authentication | Per-installation ECDSA P-256 key + one-time challenge signature. The signed transcript includes the TLS exporter channel binding (RFC 9266) → an intermediary that terminates TLS cannot create an authenticated session |
| Registration | ① direct public key registration with `SG_Server_RegisterClient`, ② a one-time enrollment token issued by `SG_Server_IssueEnrollmentToken` (the token secret is never transmitted; it is proven only through a channel-bound HMAC), ③ an externally issued token verified by the `on_enroll` callback |
| Server proof (optional) | When `proof_key_file` / `proof_key_pem` is set, the server attaches a server signature to AUTH_RESULT(OK) (server authentication independent of the TLS PKI; rejection responses are not signed) |
| License | Server-side license store (in memory or file), built-in authorization (`BuiltinAuthorizer`): registry binding takes precedence, `granted = requested & license.features`, expiry limits the session lifetime, seats (`max_installations`), `SG_SERVER_OPT_REQUIRE_LICENSE`, `SG_SERVER_OPT_LICENSE_ACTIVATION` |
| Application authorization | The `on_authorize` callback sees the built-in decision and can reject, narrow, or widen it |
| Integrity policy | Evaluates client reports (`SG_INTEGRITY_*`) and server-side conditions (no report, executable not in the allowlist) against `integrity_reject_mask` / `integrity_restrict_mask`. Used **only to lower trust** |
| Revocation | `SG_Server_RevokeClient` / `SG_Server_RevokeLicense` / `SG_Server_ReleaseLicenseSeat` immediately end the affected active sessions. Races with connections still being authorized are resolved by rechecking a revocation generation counter. A revocation that fails to persist still takes effect within the process, and calling it again retries the save |
| Session protection | After authentication, every frame carries a per-direction sequence + AES-256-GCM tag; optional payload encryption (`SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION`); on re-authentication, a per-epoch rekey + TLS KeyUpdate |
| Resource protection | `max_connections`, a limit on unauthenticated connections (`max_unauthenticated`), handshake timeout, 4 KiB payload limit for frames before authentication (and non-DATA frames after it), session lifetime and idle timeout, minimum re-authentication interval, receive/send backpressure limits |
| I/O | Windows IOCP (`AcceptEx`/`WSARecv`/`WSASend`), Linux epoll (`EPOLLONESHOT`). Default worker thread count = number of hardware threads (at most 64, also for an explicit value) |
| Storage | Persists the client registry / license store to files (owner-only temporary file + atomic rename, validated as untrusted input on load, `<path>.lock` blocks other processes from using them while open) |

For what is not guaranteed, see the residual risks in [THREAT_MODEL.md](THREAT_MODEL.md) and
[13-security-limitations.md](../docs/design/13-security-limitations.md).

## Minimal example

A skeleton trimmed down from [`examples/echo_server.c`](../examples/echo_server.c). It sends each received message back as the response to its request ID.

```c
#include <sockgate/server.h>
#include <stdio.h>

static SG_Server* g_server = NULL;

static void SG_CALL on_log(void* user, uint32_t level, const char* message)
{
    (void)user;
    fprintf(stderr, "[sockgate:%u] %s\n", (unsigned)level, message);
}

static void SG_CALL on_message(void* user, SG_SessionHandle session, const void* data, size_t size,
                               const SG_MessageInfo* info)
{
    (void)user;
    /* Calling SG_Server_SendEx inside the callback is allowed (the callback runs with no internal lock held). */
    SG_Status st = SG_Server_SendEx(g_server, session, data, size, info->request_id);
    if (st != SG_OK) fprintf(stderr, "echo failed: %s\n", SG_StatusString(st));
}

static void SG_CALL on_closed(void* user, SG_SessionHandle session, SG_Status reason)
{
    (void)user;
    printf("session %llu closed (%s)\n", (unsigned long long)session, SG_StatusString(reason));
}

int main(void)
{
    SG_ServerCallbacks callbacks;
    SG_ServerOptions options;
    SG_Status st;
    uint16_t port = 0;

    SG_ServerCallbacks_Init(&callbacks);
    callbacks.on_message = on_message;
    callbacks.on_session_closed = on_closed;

    SG_ServerOptions_Init(&options);            /* all defaults + size/version */
    options.port = 7443;
    options.tls_cert_chain_file = "server.crt"; /* leaf first, then intermediate certificates */
    options.tls_private_key_file = "server.key";
    options.registry_path = "registry.bin";     /* NULL = in-memory registry */
    options.license_path = "licenses.bin";      /* NULL = in-memory license store */
    options.callbacks = &callbacks;             /* copied by SG_Server_Create */
    options.log_callback = on_log;
    options.log_level = SG_LOG_INFO;

    st = SG_Server_Create(&options, &g_server);
    if (st != SG_OK) { fprintf(stderr, "create: %s\n", SG_StatusString(st)); return 1; }
    st = SG_Server_Start(g_server);
    if (st != SG_OK) { fprintf(stderr, "start: %s\n", SG_StatusString(st)); SG_Server_Destroy(g_server); return 1; }
    SG_Server_GetPort(g_server, &port);
    printf("listening on %u, press Enter to stop\n", (unsigned)port);

    (void)getchar();
    SG_Server_Destroy(g_server);                /* includes Stop: frees after closing sessions */
    return 0;
}
```

To accept a client, first register its installation (`SG_Server_RegisterClient`, `sg_admin client register`),
or allow enrollment and issue a token. [INTEGRATION.md](INTEGRATION.md) has step-by-step instructions.

Running the built examples (create the development PKI with `sg_admin dev-pki`):

```text
sg_admin dev-pki ./pki --host localhost
sg_echo_server --cert ./pki/server.crt --key ./pki/server.key --port 7443 \
               --registry registry.bin --issue-token example-product
(save the printed token to token.txt)
sg_echo_client --host localhost --port 7443 --ca ./pki/ca.crt --product example-product --enroll-file token.txt
```

- Without `--bind`, `sg_echo_server` listens only on `127.0.0.1` (the library's own `bind_address` default is `0.0.0.0`).
  `--port` accepts only a decimal number in 0–65535 (0 = any free port). `--issue-token PRODUCT [--license ID]` allows enrollment and prints a one-time token.
  `--token-key FILE` must be a file of 32–256 bytes (a longer file is an error). The license ID is not printed.
- `sg_echo_client` reads the token from the `--enroll-file` file, not from the command line (so that it does not remain in the process list or shell history).
  Without `--enroll-file`, it authenticates as an already registered installation and prints the public key for out-of-band registration.

## Directory layout

```text
SockGate_Server/
├── CMakeLists.txt              sockgate_server_core (internal static) + sockgate_server (public, SockGate::Server)
├── include/sockgate/
│   └── server.h                public C API (SG_ServerOptions, callbacks, registry/license management)
└── src/
    ├── core/
    │   ├── server_api.cpp      C ABI boundary: argument/struct validation, option parsing, callback bridge, exception barrier
    │   └── server_engine.*     ServerEngine: accept, connection table, sweeper, management API, revocation generation counter
    ├── session/
    │   └── connection.*        Connection: TLS + FrameDecoder + handshake + ProtectedChannel + re-authentication + event queue
    ├── auth/
    │   ├── server_handshake.*  CLIENT_HELLO / CLIENT_PROOF handling, enrollment verification, AUTH_RESULT
    │   ├── authorizer.h        IAuthorizer, AuthorizationRequest / AuthorizationDecision
    │   └── builtin_authorizer.* built-in license/integrity authorization + on_authorize hook + seat commit
    ├── storage/
    │   ├── client_registry.*   installation records + used token IDs (memory / file "SGRG")
    │   ├── license_store.*     licenses and seats (memory / file "SGLC")
    │   └── atomic_file.h       ReadWholeFile / WriteFileAtomically
    ├── transport/
    │   └── io_service.h        IIoService / AsyncStream (completion-style asynchronous I/O abstraction)
    └── platform/
        ├── windows/            iocp_io_service.cpp, atomic_file_win.cpp
        └── linux/              epoll_io_service.cpp, atomic_file_posix.cpp
```

The protocol codec, TLS engine, cryptographic primitives, and channel protection (`ProtectedChannel`) exist only once, in
`SockGate_Common`, which is shared with the client. The related tool and example are `tools/sg_admin.cpp` and
`examples/echo_server.c` at the repository root.

## Documents

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, thread model, callback threading contract, storage formats, sweeper, revocation generation counter |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Server-side assets, attackers, trust boundaries, mitigation per threat, residual risks |
| [PROTOCOL.md](PROTOCOL.md) | The wire protocol as the server sees it: frames allowed per stage, message validation, rejection behavior, key/sequence rules |
| [SECURITY.md](SECURITY.md) | Security properties, secure deployment guidelines, hardening, known limitations, vulnerability reporting |
| [BUILD.md](BUILD.md) | Requirements, presets, CMake options, tests, sanitizers/fuzzing, install and `find_package(SockGate)` |
| [INTEGRATION.md](INTEGRATION.md) | Step-by-step embedding guide: option defaults, callbacks, registration/licenses/integrity, error handling, `sg_admin`, ABI rules |
| [CHANGELOG.md](CHANGELOG.md) | Change history |
