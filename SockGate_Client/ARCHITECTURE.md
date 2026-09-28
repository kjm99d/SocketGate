# SockGate_Client Architecture

전체 계층 구조와 Common/Client/Server 분담은 [01-architecture.md](../docs/design/01-architecture.md),
상태 머신의 설계 의도는 [07-session-lifecycle.md](../docs/design/07-session-lifecycle.md) 를 참고한다.
이 문서는 클라이언트 코드가 **실제로** 어떻게 나뉘어 있고 어떤 잠금과 스레드 규칙을 따르는지 설명한다.

## 1. 계층

```text
 Application
     │  #include <sockgate/client.h>   (C ABI, opaque SG_Client*, 구조체 size/version)
     ▼
 client_api            src/core/client_api.cpp
     │  인자 검증, 구조체 파싱(ClientSettings / ServerTarget), 예외 → SG_Status
     ▼
 ClientSession         src/session/client_session.{h,cpp}
     │  상태 머신, 연결 세대(Link), 잠금, 수신 큐, 재인증, 자동 재인증
     ├── ClientHandshake   src/auth/client_handshake.{h,cpp}     (sans-IO 핸드셰이크)
     ├── IKeyStore         src/crypto/*, src/platform/*/         (서명만 요청, 개인키 비노출)
     ├── integrity         src/platform/*/integrity_*.cpp       (INTEGRITY_REPORT 시)
     ├── ProtectedChannel  SockGate_Common protocol/channel      (sequence, AES-256-GCM, KEY_PHASE)
     ├── FrameDecoder      SockGate_Common protocol/frame, rules (헤더 단계 상태 검증)
     ▼
 TlsChannel            src/tls/tls_channel.{h,cpp}
     │  ITlsEngine(OpenSSL, memory BIO)을 ITransport 위에서 blocking 으로 구동
     ▼
 transport_factory     src/transport/transport_factory.cpp   (proxy 정책)
     ├── TcpTransport  src/transport/tcp_transport.cpp       (non-blocking socket + poll, 타임아웃)
     └── proxy         src/transport/proxy.cpp               (HTTP CONNECT / SOCKS4a / SOCKS5)
     ▼
 Platform socket layer (SockGate_Common: Winsock2 / POSIX)
```

## 2. 구성 요소

### 2.1 client_api (`src/core/client_api.cpp`)

- 모든 진입점은 먼저 NULL·크기를 검사하고, 본문은 `Guard()` 안에서 실행한다. `std::bad_alloc` 은
  `SG_OUT_OF_MEMORY`, 그 밖의 예외는 `SG_INTERNAL_ERROR` 가 된다. 내부 전용 코드(`kStatusWouldBlock` 등)는
  `ToPublicStatus()` 가 `SG_INTERNAL_ERROR` 로 바꾸므로 **ABI 로는 `SG_Status` 값만 나간다**.
- 입력 구조체는 `size` 안에 있는 필드만 읽는다(`SG_HAS_FIELD`). 라이브러리가 모르는 뒤쪽 바이트는
  `CheckUnknownTail()` 로 검사해 0 이 아니면 `SG_NOT_SUPPORTED`, 4096 바이트를 넘게 크면 `SG_INVALID_ARGUMENT`.
  공개 입력 구조체가 끝에 암묵적 padding 을 갖지 않는지 `SG_ASSERT_NO_TAIL_PADDING` 이 컴파일 시 확인한다.
- 문자열은 상한 길이까지만 스캔해 내부 `std::string` 으로 **복사**한다. 호출이 끝나면 호출자 메모리를 참조하지 않는다
  (예외: `log_callback` / `log_user` 는 보관).
- `SG_Client_Create` 는 설정을 파싱하고 **key store 를 생성**한다(아래 2.6). `SG_CLIENT_FLAG_INTEGRITY_REPORT` 가
  있으면 인증 경로의 타임아웃을 소비하지 않도록 실행 파일 해시를 이때 미리 계산한다.
- `SG_Client_Enroll` 은 token 문자열(최대 1024 자)을 복사해 쓰고, 사용 후 `SecureZero` 로 지운다.

### 2.2 ClientSession (`src/session/`)

공개 API 뒤의 상태 머신이다. 핵심 개념은 **연결 세대(Link)** 와 **다섯 개의 잠금**이다.

#### 상태 머신 (`SG_CLIENT_STATE_*`)

```text
 DISCONNECTED ─Connect─▶ CONNECTING ─TCP/proxy 성공─▶ TLS_HANDSHAKE ─TLS+검증 성공─▶ TLS_ESTABLISHED
       ▲                     │ 실패                        │ 실패                          │ Authenticate / Enroll
       │                     ▼                             ▼                               ▼
       │                   CLOSED ◀────────────────────────┴──────── 실패 ─────────── AUTHENTICATING
       │                     ▲                                                           │ AUTH_RESULT(OK)
       │                     │                                                           ▼
       │                     │                                            AUTHENTICATED (키 설치 중, 내부 상태)
       │                     │                                                           ▼
       │                     ├──── 오류 / CLOSE 수신 / Disconnect ───────────────────── ACTIVE ◀─┐
       │                     │                                                    Refresh │     │ REAUTH_RESULT(OK)
       │                     │                                                           ▼     │
       │                     └──── 재인증 실패 / 오류 ───────────────────────────── REFRESHING ─┘
       │
       └─ (Connect 는 DISCONNECTED / CLOSED / EXPIRED 에서 허용)
                 EXPIRED: 로컬 수명 만료 또는 CLOSE(SESSION_EXPIRED) 수신
```

| 상태 | 허용되는 공개 호출 (그 외 → `SG_INVALID_STATE`) |
|---|---|
| `DISCONNECTED` | Connect, identity 함수 전부, Disconnect(no-op) |
| `CONNECTING`, `TLS_HANDSHAKE`, `AUTHENTICATING`, `AUTHENTICATED` | 내부 진행 상태. 다른 스레드에서 Disconnect 가능 |
| `TLS_ESTABLISHED` | Authenticate, Enroll, Disconnect |
| `ACTIVE` | Send(Ex), Receive(Ex), Ping, Refresh, Disconnect |
| `REFRESHING` | Send(Ex), Receive(Ex), Ping, Disconnect (Refresh 는 `SG_INVALID_STATE`) |
| `EXPIRED` | Connect(새 연결), Disconnect, DeleteIdentity. Send/Ping → `SG_SESSION_EXPIRED`, Receive 는 이미 받아 둔 메시지를 먼저 돌려준 뒤 `SG_SESSION_EXPIRED` |
| `CLOSED` | Connect(새 연결), Disconnect(no-op), DeleteIdentity. Send/Ping → `SG_CLOSED`, Receive 는 연결이 끊기기 전에 받아 둔 메시지를 먼저 돌려준 뒤 `SG_CLOSED` (Disconnect 는 받아 둔 메시지를 버린다) |

- `SG_Client_DeleteIdentity(Ex)` 는 `DISCONNECTED` / `CLOSED` / `EXPIRED` 에서만 허용된다.
- 재연결은 항상 새 TCP, 새 TLS, 새 challenge 로 시작한다. 이전 세션 정보는 재사용하지 않는다.
- `AUTHENTICATED` 는 세션 키를 설치하는 짧은 구간이다. 설치에 실패하면 `ACTIVE` 에 도달하지 않는다.
- 수명 만료는 서버가 준 `session_lifetime_ms` 로 **monotonic clock** 기준 로컬에서도 검사한다
  (Send/Receive/Ping/Refresh 진입 시). 만료되면 `SG_SESSION_EXPIRED` 와 함께 `EXPIRED`.

#### 연결 세대 (Link)

`Link = { shared_ptr<TlsChannel>, shared_ptr<ProtectedChannel>, generation }` 이다. Connect 는 새 세대 번호를
발급하고, 모든 작업은 시작할 때 현재 Link 를 복사해 그 세대에서만 일한다.

- 실패 처리 `Fail(generation, status)` 는 **같은 세대일 때만** 상태를 바꾸고 연결을 끊는다. 재연결 뒤에 끝난
  오래된 작업은 새 연결을 건드리지 못한다.
- `Disconnect()` 는 세대 번호를 올려 진행 중인 모든 작업을 "오래된 것"으로 만든다. 그래서 Disconnect 와 동시에
  끝난 Connect/Authenticate 가 끊긴 연결을 되살리지 못한다(`SetStateIfCurrent`).
- Connect 는 TLS 핸드셰이크 **전에** Link 를 게시하므로 다른 스레드의 Disconnect 가 진행 중인 핸드셰이크를 중단할
  수 있다. TCP/proxy 연결 중인 transport 도 `connecting_transport_` 로 게시되어 Disconnect 가 깨운다.
- Connect 는 시작할 때의 세대 번호를 기억한다. Disconnect 가 세대를 바꾸면 Connect 는 다음 단계에서 멈추고 `SG_CLOSED`
  (`event=connect_aborted`)를 반환한다: 시스템 proxy 조회 중(그 뒤 만들어지는 transport 는 즉시 shutdown), TCP/proxy
  단계, transport 연결과 링크 게시 사이의 틈, TLS 핸드셰이크 모두 해당한다(991a1b6). 이미 판정된 인증서/pin 실패는 그대로
  보고된다. `Fail()` 은 이미 해체된 링크의 상태를 덮어쓰지 않는다.

#### 잠금

`client_session.h` 에 정의된 순서대로만 중첩해 잡는다.

| 순서 | mutex | 보호 대상 / 잡는 곳 |
|---:|---|---|
| 1 | `control_mutex_` | 제어 작업을 한 번에 하나로: Connect, Authenticate/Enroll, Refresh, DeleteIdentity |
| 2 | `recv_mutex_` | FrameDecoder, 수신 측 채널 상태, 수신 큐, 프로토콜 phase. Receive, 핸드셰이크 읽기, 재인증 교환 |
| 3 | `send_mutex_` | 송신 측 채널(Seal) + TLS 쓰기. sequence 순서 == wire 순서. 송신 키 전환도 이 안에서 |
| 4 | `link_mutex_` | 현재 Link, 세대 번호, 연결 중 transport (짧은 구간만) |
| 5 | `info_mutex_` | 세션 정보 스냅샷(session_id, epoch, policy, 기능, 만료 시각, transcript) |

그 아래 `TlsChannel` 은 자체적으로 `tls_mutex_`(OpenSSL `SSL` 객체), `send_io_mutex_`(암호문 flush 순서),
`receive_io_mutex_` 를 갖는다. **네트워크 I/O 는 `tls_mutex_` 밖에서** 수행하고, `tls_mutex_` 안에서 만든 레코드는
큐에 쌓인 순서대로 전송된다(수신 중 생기는 TLS 1.3 KeyUpdate 응답 포함). `TcpTransport` 는 송신/수신 serial mutex
와 in-flight 카운터를 가져 `Close()` 가 사용 중인 소켓을 해제하지 않게 한다.

#### 수신 처리

`Receive` 는 `recv_mutex_` 아래에서 프레임을 읽어 다음처럼 처리한다.

| 수신 프레임 | 처리 |
|---|---|
| DATA | 큐에 넣고 첫 메시지를 호출자 버퍼로 복사 (`SG_MessageInfo` 에 request_id, flags) |
| PING | 즉시 PONG 으로 응답(같은 opaque 값). 애플리케이션에 전달하지 않음 |
| PONG | 형식만 검증하고 버림 |
| CLOSE | `SESSION_EXPIRED` → `SG_SESSION_EXPIRED`(EXPIRED), `AUTH_FAILED` → `SG_SERVER_REJECTED`, 그 밖 → `SG_CLOSED` |
| REAUTH_CHALLENGE / REAUTH_RESULT | 재인증이 기다리는 바로 그 메시지만 허용, 아니면 `SG_PROTOCOL_ERROR` |

- 버퍼가 작으면 `SG_BUFFER_TOO_SMALL` 과 필요한 크기를 돌려주고 메시지는 큐에 남는다.
- 큐 총량이 64 MiB 를 넘으면 `SG_LIMIT_EXCEEDED` 로 연결을 끊는다(읽지 않는 애플리케이션에 대한 메모리 상한).
- 수신 타임아웃(`SG_TIMEOUT`)은 치명적이지 않다. 그 밖의 수신 오류는 그 세대의 연결을 끊는다.

#### 재인증과 자동 재인증

- `Refresh` 는 `control_mutex_` 와 `recv_mutex_` 를 잡고 REAUTH 교환을 수행한다. 교환 중 도착한 DATA 는 큐에
  쌓여 이후 Receive 로 전달된다. 송신은 계속 가능하다(`REFRESHING`).
- 키 전환 순서: REAUTH_RESULT(OK) 처리 직후 수신 키를 epoch+1 로, `send_mutex_` 안에서 송신 키를 epoch+1 로
  바꾸고 TLS 1.3 KeyUpdate 를 요청한다. 한 프레임이 두 epoch 에 걸쳐 봉인되는 일은 없다.
- `SG_CLIENT_FLAG_AUTO_REFRESH` 는 **별도 스레드 없이** Send/Receive 진입 시 수명의 80% 가 지났는지 확인한다.
  자동 재인증은 `recv_mutex_` 를 `try_lock` 으로만 잡는다. 다른 스레드가 Receive 에서 대기 중이면 기다리지 않고
  다음 호출에서 다시 시도한다. 반면 **수동 `SG_Client_Refresh` 는 `recv_mutex_` 를 기다리므로**, 다른 스레드가
  무한 대기 Receive 중이면 그 호출이 반환될 때까지 블록된다.
- 따라서 `SG_WAIT_INFINITE` 로 막힌 수신 스레드가 있으면 자동 재인증도 수동 재인증도 진행되지 못하고, 그 수신 스레드도
  메시지가 올 때까지 재진입하지 않으므로 세션은 만료된다. 수신 스레드는 재인증 창(수명의 마지막 20%)보다 짧은 유한한
  타임아웃으로 Receive 를 반복해야 한다([INTEGRATION.md §6](INTEGRATION.md#6-blocking-과-타임아웃)).

#### Disconnect

1. `link_mutex_` 아래에서 Link 를 떼어내고 세대를 올린 뒤 상태를 `CLOSED` 로 바꾼다
   (`DISCONNECTED`, `EXPIRED` 는 유지).
2. 연결 중인 transport 를 shutdown 한다(진행 중인 connect 중단).
3. `ACTIVE` / `REFRESHING` 이었다면 CLOSE(NORMAL) 를 **best effort** 로 보낸다. 다른 스레드가 송신 중이면 생략하고,
   네트워크 쓰기는 200 ms 로 제한한다. 이어 close_notify(200 ms 제한)와 transport shutdown.
4. 깨어난 작업이 빠져나가도록 `recv_mutex_` / `send_mutex_` 를 잡은 뒤 수신 큐를 비운다.

Disconnect 는 멱등이며 상대가 읽지 않아도 오래 막히지 않는다.

### 2.3 ClientHandshake (`src/auth/`)

sans-IO 객체다. 호출자(ClientSession)가 TLS 로 프레임을 옮기고 자기 TLS 연결의 채널 바인딩 값을 넘긴다.

```text
Start(channel_binding, enrollment?)  -> CLIENT_HELLO 프레임 (seq 1, session_id 0)
OnServerHello(frame)                 -> CLIENT_PROOF 프레임 (seq 2, TH1 서명 [+ enrollment proof])
OnAuthResult(frame)                  -> OK / SG_SERVER_REJECTED / SG_VERSION_MISMATCH /
                                        SG_INVALID_SIGNATURE / SG_PROTOCOL_ERROR
```

채널 바인딩, TH1, `K_tok` 은 소멸자에서, `K_tok` 은 CLIENT_PROOF 를 만든 직후에도 지운다.
검증 항목은 [PROTOCOL.md](PROTOCOL.md) 참고.

### 2.4 TlsChannel (`src/tls/`)

- `Handshake(timeout)`: OpenSSL 엔진을 구동하며 체인·hostname/IP·유효기간 검증과 SPKI pin 검사를 수행한다.
  결과는 `SG_CERTIFICATE_ERROR` / `SG_PINNING_ERROR` / `SG_TLS_ERROR` / `SG_TIMEOUT`.
- `Send` / `Receive` 는 서로 다른 스레드에서 동시에 실행될 수 있다. `ExportKeyingMaterial`, `ChannelBinding`,
  `RequestKeyUpdate` 는 `tls_mutex_` 아래에서 실행된다.
- `Shutdown(timeout)`: close_notify 를 best effort 로 보낸 뒤 transport shutdown. `Abort()`: 아무것도 보내지 않고 깨우기만.

TLS 정책(OpenSSL 설정)은 SockGate_Common `tls/openssl_tls.cpp` 에 있다: TLS 1.3 기본, TLS 1.2 는 옵션이며 EMS 필수,
압축·재협상·세션 티켓·세션 캐시 비활성, 부분 wildcard 금지, pin 은 `SSL_get0_verified_chain` 에만 비교.

### 2.5 Transport 와 proxy (`src/transport/`)

- `TcpTransport`: 소켓은 내부적으로 non-blocking 이고, 대기는 최대 200 ms 조각으로 나눠 매 조각마다 shutdown 플래그를
  확인한다. 연결 deadline 은 이름 해석 **전에** 시작하고(858b162), 해석된 주소를 차례로 시도하며 각 시도는 남은 시간만
  받는다.
  `TCP_NODELAY`, `SO_KEEPALIVE` 를 설정한다. `Shutdown()` 은 어느 스레드에서나 호출할 수 있고 대기 중인 작업을 깨운다.
- `transport_factory`: proxy 정책을 적용한다.
  - `DIRECT`(기본, `proxy == NULL` 포함): 시스템 설정과 `http_proxy` / `https_proxy` / `ALL_PROXY` 를 **읽지 않는다**.
  - `SYSTEM`: Windows 는 `WinHttpGetIEProxyConfigForCurrentUser` 의 정적 proxy 와 bypass 목록(PAC/WPAD 미지원),
    Linux 는 `NO_PROXY`/`no_proxy` 를 적용한 뒤 `ALL_PROXY`/`all_proxy`, 없으면 `HTTPS_PROXY`/`https_proxy`.
    적용할 proxy 가 없으면 직접 연결한다.
  - `EXPLICIT`: `SG_ProxyConfig` 의 proxy.
  - proxy 연결 실패는 `SG_TIMEOUT` / `SG_CLOSED` 가 아니면 `SG_PROXY_ERROR` 로 보고된다.
- **Connect 의 시간 예산**: `ClientSession::Connect` 는 설정 검증 뒤 `connect_timeout_ms` 짜리 deadline 하나를 시작하고,
  시스템 proxy 조회·이름 해석·TCP 연결·proxy 협상·TLS 핸드셰이크가 모두 그 예산을 나눠 쓴다(bad2b3a, 858b162).
  `transport_factory` 도 시스템 proxy 조회 전에 deadline 을 시작해 TCP 연결에는 남은 시간만 넘긴다. transport 단계가
  끝났을 때 예산이 이미 소진되었으면 TLS 를 시도하지 않고 `SG_TIMEOUT`(로그 `event=connect_failed ... err=SG_TIMEOUT`),
  아니면 핸드셰이크는 **남은 시간**만 받는다. 한 번의 resolver 호출(`getaddrinfo`)은 중단할 수 없으므로 그 동안은 반환하지
  않지만, 걸린 시간은 예산에서 빠지고 그 뒤 예산이 없으면 TCP 연결을 시작하지 않는다.
- 첫 Connect 에서 프로세스당 한 번, OpenSSL 을 함께 배포하는 빌드(Windows, 또는 정적 링크)가 업스트림 3.0.7 미만의
  OpenSSL 로 실행 중이면 `SG_LOG_WARN` 수준 `event=config_warning` 을 남긴다(WARN 로그를 받는 첫 클라이언트에게).
  배포판 OpenSSL 은 보안 패치가 백포트되므로 실행 시에는 판단하지 않는다([BUILD.md §1](BUILD.md#1-요구-사항)).
- `proxy`: HTTP/1.1 CONNECT(선택적 Basic 인증, 응답 헤더는 1 바이트씩 최대 8 KiB 읽어 터널 바이트를 소비하지 않음,
  2xx 만 성공), SOCKS4a(호스트 이름을 proxy 가 해석), SOCKS5(도메인 주소 타입, no-auth 또는 RFC 1929
  user/password, 제안한 방법과 정확히 일치하는 응답만 허용, 바인드 주소를 끝까지 소비). 대상 호스트 이름은
  영숫자와 `. - : _` 만 허용해 프로토콜 구문 주입을 막는다. 자격 증명은 로그에 남기지 않는다.

### 2.6 Key store (`src/crypto/`, `src/platform/*/`)

Core 는 키를 **이름으로만** 참조하고 저장소에 서명을 요청한다. 개인키 바이트는 Core 에 나타나지 않는다.

```cpp
class IKeyStore {
    KeyStoreKind Kind();            bool HardwareBacked();
    Status GenerateKeyPair(name);   // 배타적 생성: 이미 있으면 SG_ALREADY_EXISTS
    Status GetPublicKey(name, out); // 없으면 SG_NOT_FOUND (그 외 실패는 "없음"이 아니다)
    Status Sign(name, message, out);// ECDSA-P256-SHA256, P1363 r||s 64 bytes
    Status DeleteKey(name);  Status ForceDeleteKey(name);  Status Describe(...);
};
```

| 종류 | 구현 | 저장 위치 | `hardware_backed` |
|---|---|---|---|
| `SG_KEYSTORE_MEMORY` | `MemoryKeyStore` | 프로세스 메모리(영속성 없음) | 0 |
| `SG_KEYSTORE_FILE` | `FileKeyStore` + `platform/*/key_file_*` | `<dir>/<name>.sgkey` | 0 |
| `SG_KEYSTORE_CNG_SOFTWARE` | `CngKeyStore` (Windows) | Microsoft Software KSP, 키 이름 `SockGate-<name>`, non-exportable | 0 |
| `SG_KEYSTORE_CNG_TPM` | `CngKeyStore` (Windows) | Microsoft Platform Crypto Provider(TPM 2.0) | 1 |
| `SG_KEYSTORE_TPM2` | `Tpm2KeyStore` (Linux, `SOCKGATE_WITH_TPM2`) | TPM 이 wrap 한 blob `<dir>/<name>.tpm2key` | 1 |
| `SG_KEYSTORE_AUTO` | `AutoKeyStore` | 아래 참고 | 실제 저장소에 따름 |

- 기본 디렉터리: Windows `%LOCALAPPDATA%\SockGate\keys`, Linux `$XDG_DATA_HOME/sockgate/keys`, 없으면
  `~/.local/share/sockgate/keys`(`secure_getenv`, `HOME` 이 없으면 `getpwuid_r`). `key_store_path` 로 바꿀 수 있다.
- 디렉터리는 없으면 owner-only 로 만들고 **모든 작업마다** 다시 검증한다. Linux: 심볼릭 링크 아님, 소유자 = euid,
  group/other 쓰기 불가, 파일은 디렉터리 fd 기준 `openat` 계열로만 접근. Windows: reparse point 아님,
  소유자/DACL 검사(사용자·SYSTEM·Administrators 외 쓰기 권한 거부), 새 디렉터리에는 보호된 DACL.
- 파일 생성은 배타적·원자적이다(Linux `O_TMPFILE` + `linkat`, 대체 경로 `renameat2(RENAME_NOREPLACE)` / `linkat`;
  Windows 임시 파일 + 덮어쓰기 없는 `MoveFileExW`). 읽기는 일반 파일·링크 수 1·64 KiB 이하·소유자 검사를 한다.
  삭제는 0 으로 덮어쓴 뒤 제거한다(매체 특성상 완전 삭제는 보장하지 않음).
- `.sgkey` 형식과 pairwise 검사, DPAPI entropy 는 [06 §3.1](../docs/design/06-key-lifecycle.md#31-file-key-store-형식) 참고.

#### AUTO 와 locator

`SG_KEYSTORE_AUTO` 는 강한 순서의 저장소 목록이다. **메모리 저장소로는 절대 떨어지지 않는다.**

| 플랫폼 | 순서 | locator 위치 |
|---|---|---|
| Windows | CNG TPM → CNG Software KSP (`SG_Client_Create` 때 어떤 이유로든 provider 를 열 수 없는 저장소는 그 핸들의 목록에서 빠짐) | `%LOCALAPPDATA%\SockGate\keys` (`key_store_path` 무시) |
| Linux | TPM2 (`SOCKGATE_WITH_TPM2` 빌드 시) → FILE | `key_store_path` 또는 기본 디렉터리 |

- 새 키는 생성을 지원하는 첫 저장소에 만든다. `SG_NOT_SUPPORTED` 만 다음 저장소로 넘어가는 이유가 된다.
  TPM 저장소는 확정적인 답(TPM 2.0 없음, TBS 비활성, `/dev/tpmrm0` 접근 불가, owner auth 설정, 알고리즘 미지원)에만
  `SG_NOT_SUPPORTED` 를 쓰고 일시적 오류는 `SG_KEYSTORE_ERROR` 로 보고한다.
- 만든 저장소를 identity 마다 locator `<name>.sgref`(`"SGRF" ‖ u16 version ‖ u8 store kind ‖ u8 0`)에 기록한다.
  이후에는 **기록된 저장소만** 조회한다: 저장소를 쓸 수 없으면 `SG_KEYSTORE_ERROR`, 저장소는 동작하지만 키가 없으면
  `SG_IDENTITY_LOST`. 어느 경우에도 새 identity 를 만들지 않는다. locator 없이 발견된 기존 키는 처음 조회될 때 기록된다.
  "키가 없음" 은 저장소가 `SG_NOT_FOUND` 를 보고할 때다: FILE/TPM2 는 키 파일이 없을 때, CNG 는 `NTE_BAD_KEYSET`/`NTE_NO_KEY`.
  Linux TPM2 는 TPM 이 clear 되어도 blob 파일이 남아 있으므로 조회는 성공하고 **서명**이 `SG_KEYSTORE_ERROR` 로 실패한다.
- TPM 에 닿을 수 있는지는 `SG_Client_Create` 때 정해진다: Linux TPM2 는 그때 TCTI 를 고르고(없으면 그 핸들에서는 생성
  `SG_NOT_SUPPORTED`, 기존 키 서명 `SG_KEYSTORE_ERROR`), Windows 는 그때 열 수 없던 TPM provider 를 목록에서 뺀다(기록된
  CNG TPM identity 는 `SG_KEYSTORE_ERROR`). 같은 핸들로는 회복되지 않으며 Destroy + Create 가 필요하다. Windows 의
  "TPM 2.0 인지" 판정(`Tbsi_GetDeviceInfo`)만은 알 수 없음으로 남았을 때 다음 생성에서 다시 묻는다.
- `DeleteKey` 는 기록된 저장소의 키와 locator 를 지우며, 그 저장소를 쓸 수 없으면 거부한다(`SG_KEYSTORE_ERROR`).
  `ForceDeleteKey`(`SG_IDENTITY_DELETE_FORCE`)는 실패하는 저장소를 건너뛰고 locator 를 항상 지운다.

TPM2 저장소(Linux): owner hierarchy 아래 결정적 템플릿의 ECC P-256 primary 를 필요할 때마다 다시 만들고,
서명 키(`fixedTPM`, `fixedParent`, ECDSA-SHA256)를 그 아래에 만든다. TCTI 는 `SOCKGATE_TPM2_TCTI`
(`device`/`tabrmd`/`swtpm`/`mssim` 만 허용, 그 외 값은 `SG_Client_Create` 에서 `SG_INVALID_ARGUMENT`) 또는
접근 가능한 `/dev/tpmrm0`. ESAPI context 는 mutex 로 직렬화하며, 서명 결과는 공개키로 다시 검증한 뒤 반환한다.

### 2.7 Integrity 수집 (`src/platform/*/integrity_*.cpp`)

`SG_CLIENT_FLAG_INTEGRITY_REPORT` 가 있으면 인증(Authenticate/Enroll)마다 `CollectIntegrityReport()` 로 관측값을
모아 CLIENT_HELLO 에 싣는다. 파일 해시와 (Windows) 서명 판정은 프로세스당 한 번 계산해 **성공한 결과만** 캐시하고,
나머지 관측은 매번 다시 평가한다. 해시에 실패하면 `SG_INTEGRITY_HASH_UNAVAILABLE` 을 세운다(인증을 실패시키지 않음).
재인증(Refresh)은 새 보고를 보내지 않는다.

| 관측 | Windows | Linux |
|---|---|---|
| 실행 파일 / SockGate 모듈 SHA-256 | `GetModuleFileNameW`, `GetModuleHandleExW(FROM_ADDRESS)` | `/proc/self/exe`, `dl_iterate_phdr` 로 찾은 객체(절대 경로의 일반 파일만) |
| Build ID | - | `NT_GNU_BUILD_ID` |
| `UNSIGNED_EXECUTABLE` | `WinVerifyTrust`(embedded Authenticode, 폐기 확인·UI·네트워크 없음) | 설정하지 않음 |
| `DEBUGGER_PRESENT` | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | `TracerPid != 0` |
| `PRELOAD_PRESENT` | - | `LD_PRELOAD`, `LD_AUDIT`, 비어 있지 않은 `/etc/ld.so.preload` |
| `ASLR_DISABLED` | PE `DYNAMIC_BASE` 없음 | `randomize_va_space == 0`, `ADDR_NO_RANDOMIZE`, 비-PIE 실행 파일 |
| `DEP_DISABLED` / `CFG_DISABLED` | 프로세스 mitigation policy (64-bit 는 DEP 항상 켜짐) | - |
| `EXECUTABLE_WRITABLE` | - | 실행 파일이 group/other 쓰기 가능 |
| `UNEXPECTED_MODULES` | 사용자 temp 디렉터리에서 로드된 모듈 | `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/memfd:`, `/proc/` 경로 또는 world-writable 파일에서 온 실행 파일·`.so` |

모든 관측은 우회 가능하다. 서버 정책의 입력일 뿐이다([SECURITY.md §7](SECURITY.md#7-integrity-보고는-주장이다)).

## 3. 공개 API 의 스레드 안전성

라이브러리는 스레드를 만들지 않는다. 모든 호출은 호출한 스레드에서 실행되고 콜백은 로그 콜백뿐이다.

| 호출 | 보장 |
|---|---|
| `SG_Client_Send(Ex)` ↔ `SG_Client_Receive(Ex)` | 서로 다른 스레드에서 **동시에** 호출할 수 있다 |
| 같은 방향의 동시 호출 (Send 2개, Receive 2개) | 내부 mutex 로 직렬화된다. 송신 순서 = sequence 순서 = wire 순서 |
| `SG_Client_Ping` | Send 와 같은 송신 측 잠금을 사용 |
| `SG_Client_Connect` / `Authenticate` / `Enroll` / `Refresh` / `DeleteIdentity(Ex)` | `control_mutex_` 로 한 번에 하나. 상태가 맞지 않으면 `SG_INVALID_STATE` (예: 인증 중 재연결) |
| `SG_Client_Disconnect` | **어느 스레드에서나** 호출 가능. 대기 중인 Connect/TLS/Authenticate/Send/Receive/Refresh 를 깨운다. 진행 중인 Connect 는 어느 단계에서든 `SG_CLOSED`(이미 판정된 인증서/pin 실패 제외), 그 밖의 깨어난 호출은 오류(보통 `SG_CLOSED`)로 반환된다 |
| `SG_Client_EnsureIdentity` / `GetIdentity` | 세션 잠금 없이 key store 에 접근한다. 같은 이름의 동시 생성은 저장소의 배타적 생성으로 하나의 identity 로 수렴한다 |
| `SG_Client_GetState` / `GetSessionInfo` | 언제든 호출 가능(원자 변수 / `info_mutex_`). 값은 호출 시점의 스냅샷 |
| `SG_Client_Destroy` | **같은 핸들의 다른 어떤 호출과도 동시에 호출하면 안 된다**(C API 계약). 내부적으로 Disconnect 를 수행한 뒤 해제한다 |
| 서로 다른 `SG_Client*` | 완전히 독립적이다. key store 이름 공간(파일/CNG 키)은 공유되므로 같은 identity 이름을 쓰면 같은 키를 쓴다 |

로그 콜백은 호출한 API 의 스레드에서, 라이브러리 내부 잠금을 잡은 상태로 호출될 수 있다. 콜백 안에서 같은
`SG_Client*` 의 API 를 호출하지 않는다.

## 4. 비밀값 취급

- 개인키: key store 밖으로 나오지 않는다(FILE 은 서명/조회 동안만 메모리에 로드 후 폐기).
- 세션 키, TLS exporter 값, transcript 해시, `K_tok`, token 문자열, proxy 비밀번호는 사용 후 `SecureZero` 로 지운다.
- 로그에는 키, 서명, token, 비밀번호, payload 를 기록하지 않는다. installation/session ID 는 앞부분만 기록한다.
- `SG_LOG_DEBUG` / `SG_LOG_TRACE` 문장은 Release(`NDEBUG`) 빌드에서 `SOCKGATE_ENABLE_DEBUG_LOG` 없이는 컴파일되지 않는다.
