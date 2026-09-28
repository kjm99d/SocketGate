# 01. Architecture

> 상태: v1 설계 기준 문서. 구현은 이 문서를 따르며, 설계 변경 시 이 문서를 먼저 갱신한다.

## 1. 목적과 범위

SockGate는 C/C++ 애플리케이션에 임베딩되는 **인증 게이트 통신 계층**이다.
단순 소켓 래퍼가 아니라 다음을 하나의 라이브러리로 제공한다.

- TLS 1.3 기반 암호화 채널 (OpenSSL)
- 서버 인증: 인증서 체인 + hostname + 유효기간 + 서명 + (선택) SPKI pinning
- 클라이언트 인증: installation 단위 비대칭 키 + challenge-response
- 채널 바인딩: 클라이언트 서명에 TLS exporter 값을 포함해 TLS 종단 MITM 을 무력화
- 세션 무결성: 모든 인증 후 프레임에 sequence + AEAD tag
- Replay 방어: 1회용 challenge, 엄격한 sequence, 단조 증가 request id
- 서버측 최종 권한 판단: 라이선스/제품/기능/무결성 정책
- Windows / Linux 공통 C ABI

범위 밖(보장하지 않음)은 [13-security-limitations.md](13-security-limitations.md) 를 참고한다.

## 2. 구성 요소

```text
SockGate_Common   (정적 라이브러리, 내부 전용 + 공용 public header)
SockGate_Client   (공유/정적 라이브러리, C ABI: sockgate/client.h)
SockGate_Server   (공유/정적 라이브러리, C ABI: sockgate/server.h)
```

원 요구사항(§23)은 Client/Server 각각에 `tls/`, `crypto/`, `transport/` 디렉터리를 두도록 한다.
보안에 민감한 코드(직렬화, TLS 검증, 암호 프리미티브, 소켓 추상화)를 두 벌 유지하면
한쪽만 수정되는 결함이 생기므로 **공통 구현은 SockGate_Common 에 한 벌만 둔다.**
Client/Server 의 동명 디렉터리에는 역할별 코드만 둔다.

| 영역 | Common | Client | Server |
|---|---|---|---|
| 직렬화 / 프레임 / 메시지 | 전부 | - | - |
| 암호 프리미티브 (SHA-256, HKDF, AES-GCM, ECDSA verify, RNG) | 전부 | - | - |
| TLS 엔진 (memory BIO, sans-IO) | 전부 | 클라이언트 컨텍스트/검증/pinning | 서버 컨텍스트/인증서 로드 |
| 소켓 기본 기능 | 플랫폼별 socket, 주소 해석 | 블로킹+타임아웃 연결, proxy connector | IOCP / epoll IoService, Listener |
| 인증 | transcript, 서명 포맷 | IKeyStore 구현 (CNG, File, TPM2 등) | Authenticator, ClientRegistry |
| 세션 | 채널 보호(AEAD), sequence 검증 | ClientSession 상태 머신 | SessionManager, Connection |
| 정책 | - | Integrity 수집 | Authorizer, License, Integrity 정책 |

## 3. 계층 구조

```text
                         Application
                              |
              +---------------+----------------+
              |  C ABI (opaque handle, struct size/version)  |
              +---------------+----------------+
                              |
     +------------------------+-------------------------+
     |                   SockGate Core                   |
     |  Client: ClientSession                            |
     |  Server: ServerEngine / SessionManager /          |
     |          Authenticator / Authorizer / Dispatcher  |
     +------------+----------------------+---------------+
                  |                      |
        Common Security            Protocol (Common)
        - ICryptoProvider           - FrameHeader codec
        - IKeyStore                 - Message codecs (TLV)
        - ChannelProtector(AEAD)    - Transcript
        - SPKI pin                  - Sequence / RequestId window
                  |                      |
                  +----------+-----------+
                             |
                   TLS Engine (OpenSSL, memory BIO)
                             |
                        Transport
               - ITransport (client, blocking+timeout)
               - IoService  (server, async)
               - ProxyConnector (HTTP CONNECT / SOCKS4a / SOCKS5)
                             |
                       Platform Layer
                 /                         \
            Windows                        Linux
      Winsock2, WSAPoll, IOCP        POSIX socket, poll, epoll
      CNG / NCrypt / DPAPI / TPM     File keystore, keyring, TPM2-TSS
      WinVerifyTrust, PSAPI          /proc, dl_iterate_phdr, ELF
```

### 3.1 공통 코드 규칙

- `src/platform/windows`, `src/platform/linux` (Linux 는 POSIX 공통 부분을 `posix` 로 둔다) 외부에서는
  OS 헤더(`windows.h`, `sys/socket.h`, `sys/epoll.h` 등)를 include 하지 않는다.
- OS 기능은 다음 추상화로만 접근한다.

```cpp
class ITransport;        // 클라이언트 바이트 스트림 (Connect/Send/Receive/Close)
class IIoService;        // 서버 비동기 I/O (IOCP / epoll)
class ITlsProvider;      // TLS 컨텍스트 팩토리 (OpenSSL 구현 1개)
class IKeyStore;         // 비대칭 키 저장/서명 (CNG, File, TPM2 ...)
class ICryptoProvider;   // hash / hkdf / aead / verify / random
class IPlatformSecurity; // integrity 관측, 보안 저장소 가용성
```

## 4. TLS 엔진 설계 (sans-IO)

TLS 는 OpenSSL 의 memory BIO 로 구동한다. 소켓을 OpenSSL 에 직접 넘기지 않는다.

```text
  plaintext  ->  SSL_write  ->  [wbio: outgoing ciphertext]  ->  transport send
  transport recv -> [rbio: incoming ciphertext] -> SSL_read -> plaintext
```

이유:

1. **플랫폼 독립**: Windows `SOCKET`(64bit) 을 OpenSSL `int fd` 로 캐스팅하지 않는다.
2. **IOCP 호환**: completion 기반 I/O 는 readiness 기반 BIO 와 맞지 않는다.
3. **Proxy 터널**: HTTP CONNECT / SOCKS 협상을 raw transport 에서 끝낸 뒤 같은 transport 위에서 TLS 를 시작한다.
4. **테스트 용이성**: 인메모리 transport 쌍으로 TLS + 프로토콜 전체를 소켓 없이 테스트한다.
5. **Client / Server 가 같은 엔진**을 사용해 검증 로직 중복을 없앤다.

## 5. 클라이언트 실행 모델

- 공개 API 는 **동기(blocking) + 타임아웃** 모델이다. 임베딩 대상 애플리케이션이 자체 스레드 모델을 가지므로
  라이브러리가 내부 스레드를 만들지 않는다.
- 소켓은 non-blocking 으로 열고 `WSAPoll` / `poll` 로 타임아웃을 구현한다.
- 동시성 규칙:
  - `Send` 와 `Receive` 는 서로 다른 스레드에서 동시에 호출할 수 있다.
  - 같은 방향의 동시 호출(`Send` 2개)은 내부 mutex 로 직렬화된다.
  - `Disconnect` 는 다른 스레드에서 진행 중인 `Send`/`Receive` 를 깨운다(`shutdown`).
  - `Destroy` 는 다른 호출과 동시에 호출하면 안 된다(C API 계약). 내부적으로는 in-flight 카운터로 방어한다.
- OpenSSL `SSL` 객체는 스레드 안전하지 않으므로 `SSL_*` 호출은 하나의 TLS mutex 아래에서만 수행하고,
  실제 네트워크 I/O 는 TLS mutex 밖에서 수행한다. 송신 레코드 순서는 TLS mutex 안에서 큐에 적재한 순서로 보장된다.

## 6. 서버 실행 모델

```text
Listener (accept)
    ↓
ConnectionManager   ── 연결 수 제한, 핸드셰이크 타임아웃, 연결 ID 발급
    ↓
Connection          ── TLS 엔진 + FrameDecoder + 상태 머신 (연결당 1개, 독립 상태)
    ↓
SessionManager      ── session_id ↔ connection, 만료/idle sweep
    ↓
Authenticator       ── ClientHello/ClientProof 검증, ClientRegistry 조회
    ↓
Authorizer          ── 제품/라이선스/기능/무결성 정책 + 애플리케이션 콜백
    ↓
Dispatcher          ── DATA → on_message, PING/PONG, REAUTH, CLOSE
```

- I/O: Windows **IOCP** (AcceptEx, WSARecv, WSASend overlapped), Linux **epoll** (non-blocking, `EPOLLONESHOT`).
  둘 다 `IIoService` 뒤에 숨긴다. `io_uring` 은 향후 `IIoService` 의 추가 구현으로 붙일 수 있게 한다(현재 미구현).
- 워커 스레드 N 개(기본: 하드웨어 스레드 수, 최대 64).
- 연결당 **읽기 요청은 항상 1개만** 걸려 있다. 수신 데이터 처리와 애플리케이션 콜백이 끝난 뒤 다음 읽기를 건다.
  → 연결별 메시지 순서 보장 + 자연스러운 backpressure.
- 연결 상태는 연결 mutex 로 보호한다. **애플리케이션 콜백은 mutex 를 잡지 않은 상태에서 호출**한다
  (콜백 안에서 `SG_Server_Send` 를 호출해도 교착되지 않게).
- 타이머: 별도 sweeper 스레드가 주기적으로(기본 250ms) 핸드셰이크 타임아웃, challenge 만료, 세션 만료, idle 타임아웃을 검사한다.
- 연결은 `std::shared_ptr` 로 관리되고, I/O 완료 컨텍스트는 연결의 `shared_ptr` 를 보유한다 → 완료 통지 전 해제(UAF) 방지.
- 애플리케이션은 연결을 포인터가 아닌 **재사용되지 않는 64bit `SG_SessionHandle`** 로 참조한다 → 댕글링 핸들 방지.

## 7. 보안 계층 조합

```text
TLS 1.3 (TLS 1.2 는 명시적 옵션)
+ 인증서 체인/hostname/유효기간/서명 검증
+ SPKI pinning (복수 핀, 교체 대비)
+ (선택) 서버 proof 서명 — TLS PKI 와 독립된 서버 인증
+ 클라이언트 비대칭 키 challenge-response
+ TLS exporter 채널 바인딩
+ 1회용 challenge + TTL
+ 세션 수명 / idle 타임아웃 / 재인증(rekey)
+ 방향별 엄격한 sequence + request id 단조 증가
+ 프레임 단위 AES-256-GCM tag (선택적으로 payload 암호화)
+ 서버측 권한 판단 (제품/라이선스/기능/무결성)
+ (선택) OS 보안 키 저장소 (CNG/TPM, TPM2, keyring)
+ (선택) 클라이언트 integrity 보고 — 신뢰 **하향**에만 사용
```

어느 한 계층도 단독으로 안전성을 주장하지 않는다. 특히 proxy 탐지는 보안 수단이 아니다.

## 8. 데이터 흐름 (인증 후 DATA 송신)

```text
App buffer
  → ClientSession::Send
      → FrameHeader{type=DATA, session_id, seq=n+1, request_id, len}
      → ChannelProtector::Seal (AES-256-GCM, AAD=header[+payload], 선택적 payload 암호화)
  → TlsEngine::Write (SSL_write → wbio)
  → Transport::Send
─────────── network ───────────
  → IoService completion → Connection::OnRead
  → TlsEngine::Feed / Read
  → FrameDecoder (헤더 검증, 길이 상한, overflow 검사)
  → SequenceValidator (seq == expected, request id 단조 증가)
  → ChannelProtector::Open (tag 검증 실패 → 즉시 연결 종료)
  → Dispatcher → on_message(App callback)
```

## 9. 에러 처리 원칙

- 내부 함수는 `[[nodiscard]] sg::Status` 를 반환한다. 예외는 경계(C ABI)에서 모두 잡아 `SG_INTERNAL_ERROR` / `SG_OUT_OF_MEMORY` 로 변환한다.
- 프로토콜 위반, tag 검증 실패, sequence 위반은 **복구하지 않고 연결을 종료**한다.
- 네트워크로 되돌려 보내는 사유는 일반화된 코드(REJECTED, UNSUPPORTED_VERSION, RETRY_LATER, PROTOCOL_ERROR 등)만 사용한다.
  상세 사유는 서버 로그(민감값 제외)에만 남긴다.

## 10. 확장 지점

| 확장 | 방법 |
|---|---|
| macOS | `src/platform/macos` + kqueue `IIoService`, Keychain `IKeyStore` |
| io_uring | `IIoService` 추가 구현, CMake 옵션 `SOCKGATE_WITH_IO_URING` |
| mbedTLS | `ITlsProvider` 추가 구현 (현재 OpenSSL 단일) |
| 서명 알고리즘 추가 (Ed25519 등) | `key_algorithm` 값 추가, IKeyStore 기능 플래그 |
| 외부 라이선스 서버 | `on_authorize` 콜백에서 판단 |
| 언어 바인딩 | C ABI 위에 Rust/C#/Python/Go 래퍼 |
