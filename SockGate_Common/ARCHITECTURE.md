# SockGate_Common Architecture

> 설계 기준: [01-architecture.md](../docs/design/01-architecture.md), [08-directory-structure.md](../docs/design/08-directory-structure.md).
> 이 문서는 SockGate_Common 의 **실제 구현** 구조를 설명한다. 코드와 설계가 어긋나면 코드가 기준이다.

## 1. 위치

```text
 Application
     │  C ABI (sockgate/client.h, sockgate/server.h)
     ▼
 sockgate_client / sockgate_server           (public, shared 기본)
     │
 sockgate_client_core / sockgate_server_core (internal static: 세션, 핸드셰이크, key store, IoService ...)
     │  PUBLIC link
     ▼
 sockgate_common                             (internal static: 이 라이브러리)
     │
 OpenSSL 3 (libssl, libcrypto), OS socket API
```

Common 은 **상태 머신을 갖지 않는다**. 연결/세션 상태(`ClientSession`, 서버 `Connection`)와 핸드셰이크 판단은
Client/Server core 에 있고, Common 은 그들이 공유하는 부품(코덱, 규칙 표, 암호, TLS 엔진, 소켓)을 제공한다.

## 2. 모듈과 의존 방향

| 모듈 | 의존 대상 (Common 내부) | 외부 의존 |
|---|---|---|
| `core` | 없음 (`include/sockgate/*.h` 만) | OpenSSL `crypto.h` (`OPENSSL_cleanse`, `CRYPTO_memcmp`) |
| `serialization` | `core` | - |
| `crypto` | `core` | OpenSSL EVP |
| `protocol` | `core`, `serialization`, `crypto` | - |
| `tls` | `core`, `crypto`, `platform/trust_store.h` | OpenSSL SSL |
| `net` | `core` | - |
| `platform` | `core` | Winsock2 / POSIX, `wincrypt` (Windows trust store), OpenSSL X509 |

```text
 protocol ──▶ serialization ──▶ core ◀── net
    │                            ▲  ▲
    └──────▶ crypto ─────────────┘  │
               ▲                    │
 tls ──────────┘──▶ platform ───────┘
```

- 의존은 한 방향이다. `protocol` 은 TLS 를 모른다: 채널 바인딩 값과 exporter 출력(`km`)은 호출자(Client/Server)가
  `ITlsEngine` 에서 얻어 `protocol` 함수에 바이트로 넘긴다.
- `net/transport.h` 는 인터페이스만 있다. 구현(`TcpTransport`, 서버 `IIoService`)은 Client/Server core 에 있다.

## 3. 에러 모델: `sg::Status`

`core/status.h`

- 모든 실패 가능한 내부 함수는 `sg::Status` 를 반환한다. 클래스 자체가 `[[nodiscard]]` 이므로 반환값을 무시하면
  컴파일 경고다. 의도적으로 무시할 때는 `IgnoreError()` 를 호출한다.
- `SG_TRY(expr)` 는 실패를 그대로 전파한다.
- 내부 전용 코드 `kStatusWouldBlock` (= 1000) 은 "더 기다려라" (TLS 엔진, 논블로킹 소켓) 를 뜻하며 C ABI 를 넘지 않는다.
- `ToPublicStatus(status)` 는 `SG_OK` … `SG_IDENTITY_LOST` 범위의 값만 통과시키고 나머지는 `SG_INTERNAL_ERROR` 로 바꾼다.
  Client/Server 의 C ABI 진입점(`Guard()`)이 이 함수를 쓰며, 예외는 `std::bad_alloc` → `SG_OUT_OF_MEMORY`,
  그 밖 → `SG_INTERNAL_ERROR` 로 바꾼다.
- 코드 목록과 wire 로 나가는 일반화 규칙은 [INTEGRATION.md §2.1](INTEGRATION.md) 참고.

## 4. 바이트와 비밀값 소거

`core/bytes.h`

| 타입 / 함수 | 설명 |
|---|---|
| `Bytes` | `std::vector<uint8_t>` |
| `SecureBytes` | `ZeroingAllocator` 를 쓰는 vector. **메모리를 해제할 때마다**(재할당 포함) `SecureZero` 로 지운다 |
| `ByteView` | 소유하지 않는 읽기 전용 view. `Sub()` 는 범위를 벗어나면 빈 view 를 돌려준다 |
| `SecureZero(p, n)` | `OPENSSL_cleanse` — 최적화로 제거되지 않는 소거 |
| `ConstantTimeEqual(a, an, b, bn)` | 길이가 다르면 즉시 false (길이는 비밀이 아님), 같으면 `CRYPTO_memcmp` |

- `SecureBytes` 는 해제 시점에 지운다. `clear()` 처럼 용량을 유지하는 연산은 내용을 남기므로, 즉시 지워야 하는 곳은
  `SecureZero` 를 먼저 호출한다 (예: `FrameDecoder` 의 실패 처리).
- 고정 크기 키(`crypto::AeadKey` 등 `std::array`)는 명시적으로 지운다: `ProtectedChannel` 소멸자와 poison,
  키 유도 임시값, HKDF 실패 경로, `AesGcmOpen` 실패 시 출력 버퍼, exporter 실패 시 출력, enrollment `K_tok` 임시값,
  base64 디코더 누산기.
- `SecureBytes` 를 쓰는 곳: 수신 버퍼와 `DecodedFrame` (복호화된 평문이 들어갈 수 있음), token 디코딩 중간값,
  `SoftwareP256Key::ToPkcs8Der` 출력, `TlsServerConfig::private_key_pem`.
- 키 재료는 이렇게 지우지만 **복호화된 애플리케이션 데이터 전부가 대상은 아니다**: `ProtectedChannel::Open()` 의 선택적
  `F(x)` 출력(`ENCRYPTED` 프레임이면 복호화된 payload 포함)과 `Seal()` 이 만드는 프레임은 일반 `Bytes` 이고, 호출자가 만드는 복사본도
  zeroing 대상이 아니다.

## 5. 암호 모듈

`crypto/crypto.h` 는 암호 구현의 **빌드 시점 seam** 이다 (`ICryptoProvider` 같은 가상 인터페이스가 아니라 자유 함수 집합,
구현은 `openssl_crypto.cpp` 하나). 노출하는 구성은 검증된 것뿐이다: SHA-256 (`Sha256`, `Sha256Hasher`),
HMAC-SHA256, HKDF-SHA256 (RFC 5869), AES-256-GCM (`AesGcmSeal` / `AesGcmOpen`), ECDSA P-256
(`VerifyP256`, `ValidateP256PublicKey`, DER↔P1363 변환, `SoftwareP256Key`), `RandomBytes`.
raw block cipher 나 자체 설계 구성은 없다. 세부 사항은 [SECURITY.md §1](SECURITY.md).

- 모든 진입점은 종료 시 스레드의 OpenSSL 에러 큐를 비운다 (`ErrorQueueGuard`): 남은 에러가 무관한 `SSL_get_error()`
  판단을 오염시키지 않게 한다.
- `Sha256Hasher` 는 실패를 기억하고, `Final()` 이후 재사용은 `SG_INVALID_STATE` 다.

## 6. TLS 엔진 (sans-IO)

`tls/tls.h`, `tls/openssl_tls.cpp` — 설계 [01 §4](../docs/design/01-architecture.md).

```text
 ITlsProvider ── CreateClientContext(TlsClientConfig) / CreateServerContext(TlsServerConfig)
      │                      (DefaultTlsProvider(): OpenSSL 단일 구현)
      ▼
 ITlsContext  ── CreateEngine()          SSL_CTX 1개, 설정 공유
      ▼
 ITlsEngine   ── 연결당 1개                SSL 1개 + memory BIO 2개

 transport recv ─▶ FeedIncoming() ─▶ [rbio] ─▶ Handshake() / Read() ─▶ plaintext
 plaintext ─▶ Write() ─▶ [wbio] ─▶ TakeOutgoing() / PendingOutgoing() ─▶ transport send
```

- 엔진은 소켓을 모른다. 같은 구현이 클라이언트 블로킹 transport, 서버 IOCP/epoll, proxy 터널 위, 인메모리 테스트에서 돈다.
- read BIO 는 `BIO_set_mem_eof_return(rbio, -1)` 로 설정한다: 비어 있으면 EOF 가 아니라 "나중에 다시".
- `Handshake()` 는 완료 시 OK, 입력이 더 필요하면 `kStatusWouldBlock` (먼저 `TakeOutgoing()` 으로 flush),
  그 밖은 종료 오류다. 클라이언트 검증 결과가 실패면 `SG_CERTIFICATE_ERROR`, 그 외 `SG_TLS_ERROR`.
- 핸드셰이크 직후 검사 (`PostHandshake`):
  1. TLS 1.3 이 아니면 TLS 1.2 + Extended Master Secret 이어야 한다. 아니면 `SG_TLS_ERROR`.
  2. 클라이언트: `SSL_get_verify_result == X509_V_OK`, peer 인증서 존재, pin 이 설정되어 있으면
     `SSL_get0_verified_chain` 의 인증서 중 하나의 SPKI SHA-256 이 pin 과 일치 (`SG_PINNING_ERROR`).
- 실패는 고정된다(sticky): 이후 `FeedIncoming` / `Handshake` / `Write` / `Read` 는 같은 오류를, `ExportKeyingMaterial` /
  `ChannelBinding` / `RequestKeyUpdate` 는 `SG_INVALID_STATE` 를 돌려주며, `Shutdown` 은 OK 를 돌려준다. `ErrorDetail()` 은 로그용 사유(비밀값 없음)이며
  pin 불일치 시 검증된 체인 첫 인증서(leaf)의 발급자 이름을 포함한다 (TLS 가로채기 진단용).
- `ExportKeyingMaterial()` (RFC 5705/8446), `ChannelBinding()` (RFC 9266 tls-exporter: 레이블 `EXPORTER-Channel-Binding`,
  **길이 0 context** (`use_context = 1`), 32 bytes — TLS 1.3 과 TLS 1.2 모두 표준 값), `RequestKeyUpdate()`
  (TLS 1.3 `SSL_KEY_UPDATE_REQUESTED`, TLS 1.2 에서는 아무것도 하지 않고 성공), `Shutdown()` (close_notify 큐잉).
- 엔진은 스레드 안전하지 않다. 호출자가 직렬화한다 (클라이언트 `TlsChannel` 은 TLS mutex 안에서만 `SSL_*` 를 부른다).
- 컨텍스트 설정(버전, cipher, 검증 규칙)은 [SECURITY.md §2](SECURITY.md) 에 정리한다.
- OpenSSL 버전 점검: `IsOutdatedOpenSsl(version_num)` 은 업스트림 3.0.7 (`0x30000070`) 미만이면 true.
  `OutdatedBundledOpenSslVersion()` 은 이 빌드가 OpenSSL 을 **함께 배포**하고(`SOCKGATE_BUNDLED_OPENSSL`: Windows 또는
  `OPENSSL_USE_STATIC_LIBS`, `SockGate_Common/CMakeLists.txt` 가 정의) 실행 중인 OpenSSL 이 오래된 경우에만 버전 문자열을,
  그 밖에는 `nullptr` 를 돌려준다. 배포판 OpenSSL 은 보안 수정이 버전 번호 없이 백포트되므로 실행 시 보고하지 않는다.
  경고 로그(`event=config_warning`)는 Server 가 시작 시, Client 는 프로세스당 1회 — WARN 로그가 켜진 첫 클라이언트가
  그 첫 연결 전에 — 남긴다.

## 7. 프로토콜 모듈

wire format 자체는 [PROTOCOL.md](PROTOCOL.md) 에 있다. 여기서는 구현 구조만 다룬다.

### 7.1 `FrameDecoder` (`protocol/frame.h`)

스트림 바이트를 받아 완전한 프레임을 꺼낸다. 원칙은 **헤더를 끝까지 검증하기 전에는 그 프레임의 본문을 기다리지 않는다**이다 (버퍼 양은 `SetMaxBuffered()` 가 제한).

```text
 Append(bytes) ── 버퍼 상한 검사 (초과 → SG_PROTOCOL_ERROR)
 Next()
   ├─ 48 bytes 미만 → ready=false (더 기다림)
   ├─ DecodeHeader()      구조 검증: magic, version, type, flags, auth_length, reserved, payload_length ≤ 16 MiB
   ├─ HeaderCheck(header) 호출자의 상태 검증 (보통 CheckHeaderForState) — 본문을 기다리기 전
   ├─ 전체 프레임(48 + payload + auth) 이 모일 때까지 ready=false
   └─ DecodedFrame (wire bytes 사본, SecureBytes) 반환
```

- **fail closed**: `HeaderCheck` 없이 만든 디코더는 모든 호출에 `SG_INVALID_ARGUMENT` 를 돌려준다.
- **sticky failure**: 한 번 실패하면 이후 호출은 모두 같은 오류이며, 실패 즉시 버퍼를 지우고 비운다. 오류는 연결 종료 사유다.
- **버퍼 상한**: 기본 `kMaxDecoderBuffer` = 48 + 16 MiB + 16 + 256 KiB. `SetMaxBuffered()` 로 낮출 수 있고
  (위 값으로 clamp), Client/Server 는 인증 전 `kPreAuthDecoderBuffer` (16 KiB), 인증 후
  `48 + max_payload + 16 + 64 KiB` 로 설정한다.
- **overflow 없음**: `payload_length ≤ kAbsoluteMaxPayload` 를 먼저 확인하므로 `48 + payload_length + auth_length` 덧셈이
  32bit `size_t` 에서도 넘치지 않는다.
- **선형 시간**: 소비한 앞부분이 64 KiB 이상이고 남은 부분보다 클 때만 앞으로 당긴다. 파이프라이닝된 입력도 전체 비용이 선형이다.
- `EncodeFrame()` 은 payload 16 MiB 초과, tag 길이 ∉ {0, 16} 을 거부하고, 만든 헤더를 자기 `DecodeHeader()` 로 다시 검증한다.

### 7.2 단계별 규칙과 dispatcher (`protocol/rules.h`)

- `CheckHeaderForState(header, Role receiver, Phase phase, FrameLimits)` 가 방향·단계·auth 길이·flags·request id·크기 상한을
  표 하나로 판정한다 ([PROTOCOL.md §3](PROTOCOL.md)). `FrameDecoder` 의 `HeaderCheck` 로 쓰이므로 허용되지 않는 프레임은
  헤더 48 bytes 가 모이는 즉시 거부되고 본문을 기다리지 않는다. 단 `Append()` 는 받은 chunk 를 통째로 버퍼에 넣으므로, 검사 전
  메모리 사용의 상한은 48 bytes 가 아니라 `SetMaxBuffered()` 값 (인증 전 16 KiB) 이다.
- `Phase` 는 **수신측** 단계다: `kAwaitClientHello`, `kAwaitClientProof` (서버), `kAwaitServerHello`, `kAwaitAuthResult`
  (클라이언트), `kActive`, `kRefreshing`, `kClosed` (양쪽). `kClosed` 에서는 아무것도 받지 않는다.
- `MessageDispatcher` 는 type 별 handler 표(256 칸)다. handler 가 없는 type 은 `SG_PROTOCOL_ERROR`.

### 7.3 메시지 코덱 (`protocol/messages.h`)

- **엄격한 디코딩**: 모든 필드 범위 검사, 알 수 없는 enum 거부, 고정 길이 필드는 정확히 그 길이, TLV 는
  `serialization/tlv.h` 규칙, 남는 바이트(trailing data) 오류. 디코더는 구조적 유효성만 판단하고, 서명·challenge 신선도·권한 같은
  의미 검증은 핸드셰이크 코드(Client/Server)가 한다.
- `Reader` 는 한 번 실패하면 이후 모든 읽기가 실패하도록 고정(latch)된다. 여러 번 읽고 마지막에 한 번 검사해도
  잘린 입력을 지나쳐 계속 읽지 않는다.
- **자기 검증 인코더**: `EncodeClientHello`, `EncodeServerHello`, `EncodeClientProof`, `EncodeAuthResult`,
  `EncodeReauthChallenge`, `EncodeReauthProof`, `EncodeReauthResult`, `EncodeClose`, `EncodeIntegrityReport` 는 만든 바이트를
  짝이 되는 디코더로 다시 읽는다(`SelfCheck`). `SelfCheck` 가 실패하면 출력 버퍼를 원래 길이로 되돌리고 `SG_INVALID_ARGUMENT`.
  라이브러리는 상대가 거부해야 하는 메시지를 보내지 않는다. 되돌리기는 `SelfCheck` 실패에만 적용된다: 그 전에 끝나는 오류
  (예: `EncodeClientHello` 에서 너무 긴 token id, TLV 영역 overflow) 는 `*out` 에 일부 바이트를 남길 수 있으므로,
  호출자는 실패한 인코딩의 출력을 버려야 한다. 고정 레이아웃인 `EncodePingPong`, `EncodeReauthRequest` 는
  자기 검증을 하지 않는다.
- 거부(`result != OK`) `AUTH_RESULT` 는 세션 데이터를 실을 수 없다 (인코더와 디코더 모두 검사).

### 7.4 Transcript 와 키 유도 (`protocol/transcript.h`)

TH1 / TH2 / THr, 서명 대상(`SignedData`), `installation_id` 유도, enrollment proof, 방향별 채널 키 유도(HKDF)를
**양쪽 peer 가 같은 함수**로 계산한다. 서명·MAC 대상 바이트 레이아웃의 구현은 하나뿐이다. 정의는 [PROTOCOL.md §7–8](PROTOCOL.md).

### 7.5 `ProtectedChannel` (`protocol/channel.h`)

인증 후 프레임(`auth_length = 16`)을 봉인/검증한다. AEAD 보호와 sequence/request id 검증을 한 클래스가 맡는다.

```text
 Initialize(km, session_id)      epoch 0 키 설치 (역할에 따라 c2s/s2c 를 송신/수신에 배정)
 Seal(type, payload, options)    헤더(seq, flags, KEY_PHASE) → AES-256-GCM tag → frame
 Open(DecodedFrame*)             auth_length/session_id → sequence → KEY_PHASE 키 선택 → tag 검증(+복호화) → request id
 SwitchSendKey / SwitchReceiveKey / StageReceiveKey   방향별 epoch 전환
```

- **sequence**: 방향별로 인증 후 첫 값은 `kFirstSessionSequence` (= 3, 핸드셰이크 프레임 2개 다음). 수신은 정확히 다음 값만
  허용한다. 작으면 `SG_REPLAY_DETECTED`, 크면 `SG_PROTOCOL_ERROR`. `2^64-1` 에 도달하면 `SG_SESSION_EXPIRED`.
  sequence 검사는 AEAD 전에 한다 (저렴한 검사 먼저).
- **AEAD**: 방향·epoch 별 키, nonce = `u32(0) ‖ u64(sequence)`, AAD = 48-byte 헤더(`ENCRYPTED` 가 없으면 payload 포함).
  tag 불일치는 `SG_PROTOCOL_ERROR`.
- **request id**: `NextRequestId()` 는 0 이 아닌 단조 증가 값을 준다. 수신 요청 id 는 직전보다 커야 하고(`SG_REPLAY_DETECTED`),
  응답(`RESPONSE`)은 내가 할당한 최대 요청 id 이하여야 한다(`SG_PROTOCOL_ERROR`). 송신 쪽도 상대가 보낸 최대 요청 id 보다 큰
  id 에 대한 응답은 `SG_INVALID_ARGUMENT` 로 막는다. 이 검사는 상한만 본다: 같은 요청에 대한 중복 응답, 할당만 하고 보내지 않은 id
  에 대한 응답은 거부하지 않으므로 요청-응답 짝 맞추기는 애플리케이션이 한다. request id 규칙은 tag 검증 **후**에 적용한다.
- **key phase**: `KEY_PHASE` 비트 = `epoch & 1`. 서버는 `StageReceiveKey()` 로 새 수신 키를 대기시켜 두고, 새 phase 의 첫 프레임이
  검증되는 순간 새 키로 올리고 이전 키를 지운다. 이후 이전 phase 프레임은 치명적 오류다. 클라이언트는
  `SwitchReceiveKey()` 로 즉시 전환한다. epoch 은 정확히 +1 만 허용한다. 대기 키가 있는 동안의 추가 전환은 수신 쪽
  (`SwitchReceiveKey`, `StageReceiveKey`) 만 거부하며 `SwitchSendKey` 에는 그런 검사가 없다.
- **poisoning**: `Open()` 의 어떤 실패든 채널을 poison 한다. 수신 키와 대기 키를 즉시 지우고, 이후 모든 `Seal()` / `Open()` 은
  `SG_INVALID_STATE` 다. 송신 키는 다른 스레드의 `Seal()` 이 읽고 있을 수 있어 소멸자에서 지운다.
- **동시성**: `Seal()` (송신 lock) 과 `Open()` (수신 lock) 은 동시에 돌 수 있다. 공유 상태는 poison 플래그와 request id
  최고값뿐이며 atomic 이다. `SwitchSendKey` 는 송신 lock, `SwitchReceiveKey`/`StageReceiveKey` 는 수신 lock 을 요구한다.
- `Open()` 은 재인증 transcript 용 `F(x) = 헤더 ‖ 평문 payload` 를 선택적으로 돌려준다.

### 7.6 Enrollment token (`protocol/enrollment_token.h`)

token 공개 부분(`token_pub`) 인코딩/디코딩, `K_tok` 유도, token 문자열 생성(서버)/분해(클라이언트). 형식은
[PROTOCOL.md §10](PROTOCOL.md).

token 수명 상한 `kMaxEnrollmentTokenLifetimeMs` (30 일) 도 이 헤더에 있다. Common 의 코덱은 `expires_at_ms > issued_at_ms` 만
검사하고, 상한은 공유 상수로서 서버의 발급(`SG_Server_IssueEnrollmentToken`)과 사용(enrollment 검증), 그리고 `sg_admin token issue`
가 각각 강제한다. 다른 곳에서 서버 키로 만든 token 도 이 상한을 넘을 수 없다.

## 8. 플랫폼 추상화

`platform/socket.h`, `platform/trust_store.h`, `net/transport.h` — 설계 [10](../docs/design/10-windows-platform-layer.md), [11](../docs/design/11-linux-platform-layer.md).

| 기능 | Windows (`socket_win.cpp`) | Linux (`socket_posix.cpp`) |
|---|---|---|
| 핸들 | `NativeSocket` = `std::intptr_t` (`SOCKET`), invalid = -1 | 같은 타입 (`int` fd) |
| 런타임 | `NetworkRuntime`: `WSAStartup(2.2)` 프로세스 전역 참조 카운트 | no-op |
| 주소 해석 | `GetAddrInfoW` (UTF-8 → UTF-16, 잘못된 UTF-8 거부) | `getaddrinfo` (NUL 포함 호스트 거부) |
| 소켓 생성 | `WSASocketW(... WSA_FLAG_OVERLAPPED \| WSA_FLAG_NO_HANDLE_INHERIT)`, `FIONBIO` | `SOCK_CLOEXEC` (+ `SOCK_NONBLOCK`) |
| 대기 | `select()`; 예외 집합은 connect 대기에만 사용 (urgent data 로 인한 busy wait 방지) | `poll()`; `EINTR` 은 spurious wake-up |
| 송수신 | `send`/`recv`, `WSAEWOULDBLOCK` → `kStatusWouldBlock`, `WSAESHUTDOWN`/0 → `SG_CLOSED` | `MSG_NOSIGNAL`, `EINTR` 재시도, 0 → `SG_CLOSED` |
| listener | `SO_EXCLUSIVEADDRUSE` (포트 가로채기 방지) | `SO_REUSEADDR` (TIME_WAIT 재바인딩만) |
| accept (도구/테스트용) | `accept` + 상속 해제 | `accept4(SOCK_CLOEXEC)` |
| trust store | `CertOpenSystemStoreW(0, L"ROOT")` 의 인증서를 `X509_STORE` 에 추가 | `X509_STORE_set_default_paths` |

- 주소 해석은 `AF_INET`/`AF_INET6` 결과만 쓰고, 능동 연결은 `AI_ADDRCONFIG`, bind 는 `AI_PASSIVE` 를 쓴다.
- `ShutdownSocket()` 은 양방향을 닫아 다른 스레드의 대기를 깨운다 (클라이언트 `Disconnect` 경로).
- 이 계층 위의 `TcpTransport`(클라이언트), IOCP/epoll `IIoService`(서버), proxy connector 는 Client/Server core 에 있다.
- 시간: `core/clock.h` 의 `MonotonicMs()` (`steady_clock`) 로 만료/타임아웃, `UnixTimeMs()` 로 절대 시각을 계산한다.
  `ElapsedMs()` 는 스레드 간 순서가 뒤바뀐 타임스탬프에서도 0 에서 포화한다. `Deadline(0)` 은 무한 대기다.
- 로깅: `core/log.h` 의 `Logger` 는 애플리케이션 콜백으로 보낸다 (768 bytes 버퍼, `ts=<unix ms>` 접두사, 콜백 예외 무시).
  `SG_LOGD`/`SG_LOGT` 는 `NDEBUG` 빌드에서 `SOCKGATE_ENABLE_DEBUG_LOG` 가 없으면 제거된다. 기록 금지 대상은 [SECURITY.md §4](SECURITY.md).
