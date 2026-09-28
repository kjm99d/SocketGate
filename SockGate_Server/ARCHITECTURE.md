# SockGate_Server Architecture

서버 라이브러리의 구성 요소와 스레드 모델을 설명한다. 전체 시스템 설계는
[01-architecture.md](../docs/design/01-architecture.md), 세션 상태 머신은
[07-session-lifecycle.md](../docs/design/07-session-lifecycle.md) 를 기준으로 하며, 여기서는 실제 구현 구조를 기술한다.

> 설계 문서 01 §6 의 `ConnectionManager` / `SessionManager` / `Authenticator` / `Dispatcher` 는 구현에서 별도 클래스가
> 아니다. 연결 수 제한과 연결 테이블은 `ServerEngine`, 연결별 상태 머신·세션·메시지 분배는 `Connection`,
> 인증은 `ServerHandshake` 가 맡는다.

## 1. 구성 요소

```text
 Application (C)
     │  sockgate/server.h
     ▼
 server_api.cpp ── 구조체 size/version 검증, 옵션 파싱, 콜백 복사·브리지, 예외 → SG_INTERNAL_ERROR / SG_OUT_OF_MEMORY
     │
     ▼
 ServerEngine ──────────────────────────────────────────────────────────────┐
  ├─ ITlsContext (OpenSSL 서버 컨텍스트, SockGate_Common)                    │
  ├─ IClientRegistry   (메모리 | 파일 "SGRG")                                │
  ├─ ILicenseStore     (메모리 | 파일 "SGLC")                                │
  ├─ BuiltinAuthorizer (라이선스 · integrity · on_authorize hook · 좌석)      │
  ├─ ServerAuthContext (HandshakeConfig, token key, proof key, dummy key)   │
  ├─ IIoService        (IOCP | epoll) ── worker threads × N                  │
  ├─ connections_  : map<SG_SessionHandle, shared_ptr<Connection>>           │
  ├─ closing_      : graceful-close 중인 stream 목록                          │
  ├─ unauthenticated_ : 인증 전 연결 수 (atomic, max_unauthenticated)        │
  ├─ sweeper thread (250 ms)                                                 │
  └─ revocations_  : 폐기 세대 카운터 (atomic)                                │
                                                                            │
 Connection (연결당 1개, shared_ptr) ◀──────────────────────────────────────┘
  ├─ AsyncStream        (I/O 서비스의 소켓 스트림)
  ├─ ITlsEngine         (memory BIO, sans-IO)
  ├─ FrameDecoder       (헤더 단계 상태 검증 hook = CheckHeaderForState)
  ├─ ServerHandshake    (CLIENT_HELLO / CLIENT_PROOF)
  ├─ ProtectedChannel   (인증 후 프레임 seal/open, SockGate_Common)
  └─ 이벤트 큐           (on_session_opened / on_message / on_session_closed 를 lock 밖에서 전달)
```

## 2. I/O 서비스 (`transport/io_service.h`)

`IIoService` / `AsyncStream` 은 completion 스타일 비동기 I/O 추상화이다. 서버 core 코드는 OS 헤더를 포함하지 않는다.

공통 계약 (헤더 주석 기준):

- 핸들러는 I/O 워커 스레드에서, 스트림 내부 lock 을 잡지 않은 상태로 실행된다.
- 스트림당 **읽기는 최대 1개**만 걸린다. `Connection` 은 이전 읽기의 처리(콜백 이벤트 적재 포함)를 마친 뒤 다음 읽기를
  건다 → 연결별 순서 보장과 자연스러운 backpressure.
- 쓰기는 큐에 쌓여 순서대로 완료된다. `PendingWriteBytes()` 로 미전송량을 알 수 있다.
- `CloseAfterWrites()` 는 새 쓰기를 거부하고, 큐가 비면 송신 방향만 닫은(FIN) 뒤 상대가 닫을 때까지 남은 입력을
  버린다 (미수신 데이터가 남은 채 닫아 RST 로 응답이 유실되는 것을 막음). 이 단계의 상한은 소유자(`ServerEngine`)가 건다.
- `Close()` 는 즉시 닫고 대기 중인 작업을 `SG_CLOSED` 로 한 번씩 완료시킨다.
- 워커 수: `worker_threads` (0 = 하드웨어 스레드 수), [1, 64] 로 제한. 스트림당 읽기 버퍼 16 KiB. listen backlog = `SOMAXCONN`.
- `Listen()` 은 `bind_address` 를 해석한 **첫 번째 주소**에만 bind 한다.

| 항목 | Windows (`iocp_io_service.cpp`) | Linux (`epoll_io_service.cpp`) |
|---|---|---|
| 수락 | listener 당 `AcceptEx` 8개를 미리 게시, 완료 시 `SO_UPDATE_ACCEPT_CONTEXT`, 즉시 재게시 | listener fd `EPOLLIN \| EPOLLONESHOT`, 깨어날 때마다 `accept4(SOCK_NONBLOCK \| SOCK_CLOEXEC)` 최대 64회 후 re-arm |
| 소켓 옵션 | listen 소켓 `SO_EXCLUSIVEADDRUSE`, 수락 소켓 `TCP_NODELAY`, `FILE_SKIP_SET_EVENT_ON_HANDLE` | listen 소켓 `SO_REUSEADDR`(TIME_WAIT 재bind 용), 수락 소켓 `TCP_NODELAY` |
| 완료/이벤트 | `GetQueuedCompletionStatus` → `IoOp` 종류(accept/read/write/task)별 처리 | `epoll_wait` (최대 64 이벤트) → 스트림 id 로 조회 후 처리, `EPOLLONESHOT` 으로 한 스트림을 두 워커가 동시에 처리하지 않음 |
| 수명 안전 | 모든 overlapped 작업 객체가 스트림의 `shared_ptr` 을 보유 → 완료 전 해제 불가 | epoll 에는 포인터가 아닌 64bit id 를 등록 → 닫힌 스트림의 늦은 이벤트는 아무것도 찾지 못함. fd 시스템 콜은 스트림 mutex 아래에서만 |
| 작업 게시 | `PostQueuedCompletionStatus` | `eventfd` wake-up + 작업 큐 |
| 송신 | overlapped `WSASend` | non-blocking `send(MSG_NOSIGNAL)` |
| 종료 | listener close → 모든 스트림 `Close()` → 미완료 작업 대기(최대 10 s) → 종료 패킷 게시 → 워커 join | listener 제거·close → 모든 스트림 `Close()` → 워커 join → 남은 작업 실행 |

`Stop()` 은 워커 스레드에서 호출하면 아무것도 하지 않는다 (계약 위반 방어).

## 3. ServerEngine (`core/server_engine.*`)

### 3.1 생성 (`SG_Server_Create`)

1. `server_api.cpp` 가 `SG_ServerOptions` 를 검증·복사한다 (문자열 길이, 알 수 없는 flag → `SG_NOT_SUPPORTED`,
   integrity 마스크, allowlist, `registry_path` 와 `license_path` 가 같은 파일인지 등 — [INTEGRATION.md](INTEGRATION.md) §2).
   콜백 구조체는 필드 단위로 복사하며 `SG_Server` 가 소유한다.
2. TLS 서버 컨텍스트 생성 (인증서 체인 + 개인키 로드와 일치 검사). 이후 메모리의 PEM 개인키 사본을 지운다.
3. registry, license store 생성. 파일 경로가 있으면 이때 저장소 lock 을 잡고 로드한다. 형식 오류는 생성 실패
   (`SG_STORAGE_ERROR`), 다른 프로세스가 lock 을 가진 경우는 `SG_INVALID_STATE` 이다 (§8.3).
4. `BuiltinAuthorizer` 구성 (`on_authorize` 가 있으면 hook 으로 연결).
   allowlist 가 있는데 `SG_INTEGRITY_UNKNOWN_EXECUTABLE` 이 어느 마스크에도 없으면 경고 로그.
5. token key 가 없으면 CSPRNG 로 32 bytes 생성 (이 `SG_Server` 인스턴스에서만 유효한 token).
6. `ServerAuthContext` 생성: 핸드셰이크 설정 검증, 미등록 installation 검증용 **더미 P-256 공개키** 생성.

### 3.2 시작과 수락

- `SG_Server_Start`: I/O 서비스 시작 → listen → sweeper 스레드 시작. 이미 실행 중이거나 콜백 안에서 호출하면 `SG_INVALID_STATE`.
  `SG_Server_Stop` 후 다시 `Start` 할 수 있다. 애플리케이션이 자체 OpenSSL 을 함께 배포하는 빌드(Windows, 정적 링크)에서
  실행 중인 OpenSSL 이 3.0.7 보다 오래되었으면 시작 시 `event=config_warning` 을 WARN 으로 남긴다.
- 수락 시 `OnAccept` 가 TLS 엔진과 `Connection` 을 만들고, **용량 검사와 테이블 삽입을 `connections_mutex_` 아래에서
  한 번에** 수행한다. 다음 중 하나면 소켓을 즉시 닫고 `event=connection_refused reason=…` 을 남긴다:
  종료 중(`stopping`), `connections_.size() + closing_.size() >= max_connections` (`max_connections`),
  인증 전 연결 수 `>= max_unauthenticated` (`max_unauthenticated`). graceful-close 중인 소켓도 descriptor 를 쓰므로 전체 상한에 포함된다.
- 인증 전 연결 수는 atomic 카운터로 센다. 수락 시 1 증가하고, 연결마다 정확히 한 번 감소한다: 세션이 열리는 순간, 또는 인증 전에
  닫힌 연결의 **소켓이 완전히 닫힐 때** (graceful close 가 끝나거나 5 s 후 강제로 닫힐 때), 또는 엔진 종료 시. 쓰레기를 보내고 소켓을
  닫지 않는 피어가 상한을 우회하지 못하게 하기 위함이다. 열린 세션은 이 상한에 포함되지 않으므로 인증 전 연결 폭주가 기존 세션의 자리를
  모두 차지하지 못한다.
- 핸들(`SG_SessionHandle`)은 수락 시점에 1부터 단조 증가하는 64bit 값으로 발급되며 `SG_Server` 수명 동안 재사용되지 않는다.
  애플리케이션에는 세션이 열린 뒤(`on_session_opened`)부터 의미가 있다.

### 3.3 종료 (`SG_Server_Stop` / `SG_Server_Destroy`)

1. `stopping_` 설정 (이후 수락은 즉시 닫힘).
2. 모든 연결에 `Close(SERVER_SHUTDOWN)`: 인증된 세션에는 CLOSE(SERVER_SHUTDOWN) 을 보내고, `on_session_closed(SG_CLOSED)`
   가 보통 **Stop 을 호출한 스레드**에서, 엔진의 lifecycle lock 을 잡은 채로 실행된다. 그 세션의 이벤트를 이미 다른 스레드가 전달하고
   있으면 (§4.3) 그 스레드가 lifecycle lock 없이 `on_session_closed` 를 전달한다.
3. 스트림이 비워지기를 최대 약 500 ms (10 ms × 50) 기다린다.
4. sweeper 정지·join → I/O 서비스 `Stop()` (남은 스트림 강제 종료, 워커 join) → 인증 전 연결 카운터 정리 → 테이블 정리.

콜백 안에서 `SG_Server_Start` / `SG_Server_Stop` / `SG_Server_Destroy` 를 호출하면 `SG_INVALID_STATE` 이다
(thread-local 플래그로 판별). Stop 이 전달하는 콜백은 lifecycle lock 아래에서 실행되므로, 이 거부가 없으면 재진입이 된다.

## 4. Connection (`session/connection.*`)

### 4.1 단계 (phase)

```text
 AwaitClientHello ──CLIENT_HELLO──▶ AwaitClientProof ──CLIENT_PROOF(OK)──▶ Active ◀──REAUTH_RESULT(OK)── Refreshing
        │                                  │                                  │ ──REAUTH_REQUEST──────────────▶ │
        └──────────────────────────────────┴──────────── 오류 / 거부 / 타임아웃 / 폐기 / 종료 ──▶ Closed ◀───────┘
```

TLS 핸드셰이크는 `AwaitClientHello` 이전에 같은 연결 객체 안에서 진행된다. 완료 직후 서버측 채널 바인딩
(`EXPORTER-Channel-Binding`, 32 bytes)을 계산해 둔다. 단계별 허용 프레임은 [PROTOCOL.md](PROTOCOL.md) §2 참고.

### 4.2 Locking

- 연결의 모든 상태(TLS 엔진, decoder, handshake, channel, phase, 타이머, 이벤트 큐)는 **연결 mutex 하나**로 보호된다.
  수신 처리, `SG_Server_Send`, sweeper 의 `Tick`, 관리 API 의 `Close` 가 모두 이 mutex 로 직렬화된다.
- 애플리케이션 코드를 부르는 두 지점 — CLIENT_PROOF 처리(`on_authorize`, `on_enroll`)와 REAUTH_PROOF 의 재인가
  (`on_authorize`) — 은 **mutex 를 풀고** 호출한 뒤 다시 잡고 상태를 재확인한다 (그 사이 타임아웃·`CloseSession`·`Stop`
  으로 닫혔으면 결과를 버린다). 핸드셰이크 객체는 이 읽기 처리 스레드만 만지므로 lock 없이 안전하다.
- Lock 순서: `ServerEngine` 의 `connections_mutex_` 를 잡은 채 연결 mutex 를 잡지 않는다 (연결 목록은 스냅샷을 떠서
  lock 밖에서 순회). 연결 mutex 를 잡은 상태에서는 registry / license store 의 내부 mutex 와 스트림 mutex 만 잡을 수 있으며,
  이들은 다른 lock 을 잡지 않는 leaf lock 이다.

### 4.3 이벤트 전달 (lock 밖, 직렬, 순서 보장)

세션 이벤트(`kOpened`, `kMessage`, `kClosed`, 내부용 `kRemove`)는 mutex 아래에서 큐에 적재되고, 적재한 스레드가 mutex 를
놓은 뒤 `DeliverEvents()` 로 전달한다.

- 한 번에 한 스레드만 전달한다 (`delivering_` 플래그). 다른 스레드가 이벤트를 적재하면 현재 전달 중인 스레드가 이어서
  처리한다 → 큐로 전달되는 콜백(`on_session_opened`, `on_message`, `on_session_closed`)은 **동시에 실행되지 않고 적재 순서대로** 실행된다.
- 예외: 재인증의 `on_authorize` 는 이 큐를 거치지 않고 REAUTH_PROOF 를 처리하는 I/O 스레드에서 (연결 mutex 를 푼 채) 직접 호출된다.
  그래서 같은 세션의 `on_message` (다른 스레드가 전달 중일 때)나 `CloseSession`·폐기·Stop·challenge 만료가 전달하는 `on_session_closed`
  와 **겹칠 수 있다**. `on_authorize` 가 쓰는 세션별 데이터는 동기화해야 하고, `on_authorize` 가 반환할 때까지 해제하면 안 된다
  (`on_session_closed` 가 먼저 끝날 수도 있다).
- 그래서 콜백은 I/O 워커뿐 아니라 세션을 닫은 API 호출 스레드(`SG_Server_CloseSession`, `SG_Server_RevokeClient`,
  `SG_Server_RevokeLicense`, `SG_Server_ReleaseLicenseSeat`, `SG_Server_Stop`, 실패한 `SG_Server_Send`)와 sweeper 스레드
  (만료, idle, 재인증 challenge 만료)에서도 실행될 수 있다. 단, 그 세션의 이벤트를 이미 다른 스레드가 전달하고 있으면 그 스레드가 전달한다.
  연결 mutex 는 어느 경우에도 잡혀 있지 않지만, `SG_Server_Stop` / `SG_Server_Destroy` 가 직접 전달하는 콜백은 엔진의 lifecycle lock
  아래에서 실행된다 (§3.3).
- 콜백이 던진 C++ 예외는 삼킨다. `on_session_closed` 는 `on_session_opened` 가 적재된 세션에 대해서만, 정확히 1회 적재된다.
- `kRemove` 는 연결을 엔진 테이블에서 지운다. 그 후 해당 핸들은 `SG_NOT_FOUND` 이다.

### 4.4 Backpressure 와 상한

| 상수 | 값 | 동작 |
|---|---|---|
| 읽기 일시 정지 watermark | 8 MiB | 전달되지 않은 DATA 바이트가 넘으면 다음 읽기를 걸지 않는다. 전달이 따라잡아 8 MiB 이하가 되면 전달 스레드가 읽기를 재개 |
| 연결당 미전달 이벤트 상한 | 64 MiB | 넘으면 `SG_LIMIT_EXCEEDED` 로 연결 종료 (CLOSE(PROTOCOL_ERROR)) |
| 미전송 출력 상한 | 32 MiB | 수신 처리 후 초과하면 즉시 종료 (`SG_LIMIT_EXCEEDED`, CLOSE 프레임 없음) — 읽지 않으면서 PING/KeyUpdate 로 응답을 쌓는 피어 차단. `SG_Server_Send` 는 초과 시 연결을 닫지 않고 `SG_LIMIT_EXCEEDED` 반환 |
| 인증 전 decoder 버퍼 | 16 KiB | 미파싱 입력 상한 |
| 인증 후 decoder 버퍼 | 48 + `max_payload_size` + 16 + 64 KiB | |

느린 `on_message` 는 그 세션의 읽기를 멈추게 할 뿐 다른 세션에는 영향을 주지 않는다 (워커 스레드를 점유하는 동안은 예외).

### 4.5 종료 경로

| 원인 | 피어에게 보내는 것 | `on_session_closed` reason |
|---|---|---|
| `SG_Server_CloseSession` | CLOSE(NORMAL) | `SG_CLOSED` |
| `SG_Server_Stop` / `Destroy` | CLOSE(SERVER_SHUTDOWN) | `SG_CLOSED` |
| `RevokeClient` / `RevokeLicense` / `ReleaseLicenseSeat` | CLOSE(AUTH_FAILED) | `SG_AUTH_FAILED` |
| 세션 수명 만료 | CLOSE(SESSION_EXPIRED) | `SG_SESSION_EXPIRED` |
| idle 타임아웃 | CLOSE(IDLE_TIMEOUT) | `SG_TIMEOUT` |
| 재인증 중 challenge TTL 초과 | CLOSE(AUTH_FAILED) | `SG_CHALLENGE_EXPIRED` |
| 재인증 거부 | REAUTH_RESULT(REJECTED) | `SG_AUTH_FAILED` |
| 프로토콜 위반 (형식, tag, sequence, 상태, 상한) | CLOSE(PROTOCOL_ERROR) | 해당 오류 (`SG_PROTOCOL_ERROR`, `SG_REPLAY_DETECTED`, `SG_LIMIT_EXCEEDED` …) |
| 피어의 CLOSE 또는 TLS close_notify / EOF | 없음 | `SG_CLOSED` |
| 소켓 오류 | 없음 | `SG_NETWORK_ERROR` |
| 미전송 출력 32 MiB 초과 | 없음 | `SG_LIMIT_EXCEEDED` |

인증 전 연결(핸드셰이크 실패, 거부, 타임아웃)은 세션이 열린 적이 없으므로 콜백이 호출되지 않는다.
종료 시 TLS close_notify 를 보내고 `ProtectedChannel` 을 파기해 세션 키를 지운다. 대부분의 경로는 graceful close
(`CloseAfterWrites`)이며, 핸드셰이크 타임아웃·소켓 오류·출력 상한 초과는 즉시 닫는다.

## 5. ServerHandshake (`auth/server_handshake.*`)

sans-IO 핸드셰이크 객체이다. 입력은 디코딩된 프레임, 출력은 응답 프레임 바이트이다.

- `OnClientHello`: 헤더(`sequence == 1`, `session_id == 0`) 확인, 메시지 디코딩, 버전 협상. 교집합이 없으면
  AUTH_RESULT(UNSUPPORTED_VERSION). 아니면 새 `session_id`(CSPRNG, 0 아님), `server_nonce`, 1회용 `challenge` 를 만들어
  SERVER_HELLO 를 돌려준다. **installation 등록 여부와 무관하게** challenge 를 발급한다.
- `OnClientProof`: 연결당 정확히 한 번. challenge 를 먼저 소비하고, TH1 을 서버측 채널 바인딩으로 계산해
  서명(또는 enrollment)을 검증한 뒤 `IAuthorizer::Authorize` 를 호출하고, 수명을 계산해 AUTH_RESULT 를 만든다.
  proof key 가 있으면 서명을 붙인다.
- 모든 거부는 같은 AUTH_RESULT(REJECTED) 이며 상세 사유는 `failure_reason()` 으로 로그에만 남는다.

검증 순서의 세부는 [PROTOCOL.md](PROTOCOL.md) §3 에 있다.

## 6. 인가: BuiltinAuthorizer + `on_authorize`

`BuiltinAuthorizer` 가 유일한 `IAuthorizer` 구현이며, 최초 인증과 재인증 모두에서 호출된다.

```text
 1. installation 활성 확인; registry 의 product/license 바인딩과 다른 클레임 → 거부
 2. 유효 라이선스 결정: registry 바인딩 > (LICENSE_ACTIVATION 이면) 클레임 > 없음(클레임은 UNKNOWN)
 3. store 조회: 폐기/다른 제품/만료 → 거부, 있으면 VALID + granted = requested & features, 만료 시각 기록
 4. REQUIRE_LICENSE 이고 VALID 아님 → 거부
 5. integrity 조건 계산 → reject_mask 겹침 → 거부 / restrict_mask 겹침 → RESTRICTED
 6. on_authorize(checked request, pre-filled decision)   ← lock 밖, CallbackScope
 7. 허용이면 integrity RESTRICTED 하한 재적용
 8. VALID 라이선스면 좌석 확정(BindSeat), 활성화면 registry 에 바인딩 기록 — 실패 시 거부로 전환
```

`on_authorize` 가 `SG_OK` 가 아닌 값을 돌려주거나 `policy` 를 NORMAL/RESTRICTED 이외로 설정하면 거부로 처리한다.
세부 규칙은 [INTEGRATION.md](INTEGRATION.md) §5–§6 에 있다.

## 7. ProtectedChannel 사용

인증 성공 직후 연결은 `km = TLS-Exporter("EXPORTER-SockGate-v1-keys", context = TH1, 32)` 로 서버 역할의
`ProtectedChannel` 을 초기화한다 (epoch 0, 각 방향 sequence 는 3 부터). 서버에서는 seal(송신)과 open(수신)이
모두 연결 mutex 아래에서 실행된다.

- 수신: `Open()` 이 session id, sequence, `KEY_PHASE`, GCM tag, request id 규칙을 검증하고 `ENCRYPTED` 면 복호화한다.
  실패하면 채널이 poison 되어(수신 키 파기) 이후 모든 동작이 실패하고 연결은 닫힌다.
- 송신: DATA 는 `SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION` 이거나 피어가 한 번이라도 `ENCRYPTED` DATA 를 보냈으면 암호화한다.
  제어 프레임(PONG, REAUTH_*, CLOSE)은 tag 만 붙인다.
- 재인증 성공: REAUTH_RESULT(OK) 를 epoch e 키로 보낸 직후 송신 키를 e+1 로 바꾸고(`SwitchSendKey`), 수신 키 e+1 을
  대기시키며(`StageReceiveKey`), TLS 1.3 이면 KeyUpdate 를 요청한다. 첫 e+1 프레임을 받는 순간 e 키를 지운다.

## 8. 저장소

### 8.1 Client registry

installation 레코드와 사용된 enrollment token ID 를 보관한다.

```text
파일 (big endian):
  u32 magic "SGRG" | u16 version(1) | u32 record_count | records | u32 token_count | tokens
  record: iid[16] | pubkey[65] | u8 alg(1) | u8 status(1 active, 2 revoked)
          | vec16 product(≤64) | vec16 license(≤128) | u64 created_at_ms
  token:  token_id[16] | u64 expires_at_ms
```

- 로드 검증: magic/version, 개수 ≤ 10,000,000, 공개키 곡선 위 검증, `iid == SHA-256("SockGate/v1/iid" ‖ pubkey)[0..16)`,
  알고리즘·상태 값, 문자열 길이, 레코드와 사용된 token ID 모두 중복 없음, 뒤따르는 바이트 없음. 하나라도 어긋나면 파일 전체를 거부한다.
- 등록은 active/revoked 를 막론하고 이미 있는 ID 면 `SG_ALREADY_EXISTS` (폐기된 installation 은 재등록 불가).
- enrollment 는 token ID 소비와 레코드 삽입을 한 번의 원자적·영속적 변경으로 수행한다.
- 파일로 쓸 내용이 512 MiB 를 넘으면 쓰지 않는다 (`SG_LIMIT_EXCEEDED`, 19d1208).
- 사용된 token ID 는 만료 후에도 삭제하지 않는다. 그래서 enrollment 가 매우 많은 registry 는 레코드 수 상한(10,000,000)보다 먼저
  파일 크기 상한에 닿을 수 있다.

### 8.2 License store

```text
파일 (big endian):
  u32 magic "SGLC" | u16 version(1) | u32 count | licenses
  license: vec16 id(1..128) | vec16 product(1..64) | u64 features | u64 expires_at_ms
           | u32 max_installations | u8 status(1 active, 2 revoked) | u32 seat_count | seat_count × iid[16]
```

- 상한: 라이선스 1,000,000 개, 라이선스당 좌석 1,000,000 개. 로드 시 문자열은 protocol string 검증(UTF-8, 제어문자 금지)을 한다.
- 파일로 쓸 내용이 512 MiB 를 넘으면 쓰지 않는다 (`SG_LIMIT_EXCEEDED`) — 로드가 거부할 파일을 만들지 않기 위함.

### 8.3 원자적 쓰기와 읽기 (`storage/atomic_file.h`)

모든 변경은 **파일 전체를 다시 쓴다.**

| | POSIX | Windows |
|---|---|---|
| 쓰기 | `<path>.tmp-<16 hex>` 를 `O_CREAT \| O_EXCL \| O_NOFOLLOW`, mode `0600` 으로 생성 → write → `fsync` → `rename` → 디렉터리 `fsync` (best effort) | 보호된 DACL(현재 사용자, SYSTEM, Administrators 만 full access, 상속 차단)로 `CREATE_NEW` 임시 파일 생성 → `FlushFileBuffers` → `MoveFileExW(MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)` (DACL 은 rename 후에도 유지) |
| 읽기 | `O_NOFOLLOW` (symlink 거부), 일반 파일만, ≤ 512 MiB | ≤ 512 MiB |
| 저장소 lock | `<path>.lock` (`0600`) 에 `flock(LOCK_EX \| LOCK_NB)`, close 로 해제 | `<path>.lock` (위와 같은 DACL) 에 `LockFileEx(EXCLUSIVE \| FAIL_IMMEDIATELY)`, 해제는 `UnlockFileEx` 후 `CloseHandle` (바로 다시 열어도 lock 이 남아 있지 않게) |

읽는 쪽은 이전 내용 또는 새 내용만 본다. 파일이 없으면 빈 저장소로 시작하고 첫 변경 때 만든다.

파일 저장소는 여는 순간(로드 전)부터 닫힐 때까지 `<path>.lock` 의 배타적 advisory lock 을 잡는다. 저장소는 변경마다
파일 전체를 다시 쓰므로 두 프로세스가 같은 파일을 고치면 변경(폐기 포함)이 조용히 사라지기 때문이다. 다른 프로세스
(다른 서버, 실행 중인 서버에 대한 `sg_admin`)가 이미 열고 있으면 `SG_INVALID_STATE` 로 열기에 실패하고, 따라서
`SG_Server_Create` 도 `SG_INVALID_STATE` 로 실패한다. lock 은 `SG_Server_Destroy` 로 저장소가 해제되거나 프로세스가 끝나면 풀린다.

저장 실패 시 동작:

| 변경 | 저장 실패 시 |
|---|---|
| 등록, enrollment, 라이선스 추가/변경, 좌석 확정/반납, 활성화 바인딩 | 메모리 변경을 되돌리고 `SG_STORAGE_ERROR` (크기 상한 초과는 `SG_LIMIT_EXCEEDED`) |
| installation 폐기, 라이선스 폐기 | **메모리에서는 폐기 유지**, 세션도 종료, `SG_STORAGE_ERROR` (I/O 오류가 폐기를 되돌리지 않음). 저장소가 "저장되지 않은 폐기" 를 기억해, 같은 폐기 함수를 다시 부르면 쓰기를 재시도하고 그 저장소의 다른 쓰기가 성공할 때도 함께 저장된다 (19d1208) |

저장소는 단일 프로세스용이다 (위 lock 이 동시 사용을 막는다). 여러 서버 노드가 상태를 공유해야 하면 `on_authorize` /
`on_enroll` 과 외부 저장소를 쓴다.

## 9. Sweeper

별도 스레드가 250 ms 마다 연결 스냅샷을 순회하며 `Connection::Tick()` 을 호출한다.

| 검사 | 조건 | 결과 |
|---|---|---|
| 핸드셰이크 타임아웃 | 인증 전이고 수락 후 `handshake_timeout_ms` 초과 (TLS 핸드셰이크와 인가 콜백 시간 포함) | 즉시 종료, 로그 `event=handshake_timeout` |
| 세션 만료 | `now >= expires_at` | CLOSE(SESSION_EXPIRED) |
| idle | `idle_timeout_ms != 0` 이고 마지막 **검증된 수신 프레임** 이후 초과 | CLOSE(IDLE_TIMEOUT) |
| 재인증 challenge | Refreshing 상태에서 REAUTH_CHALLENGE 이후 `challenge_ttl_ms` 초과 | CLOSE(AUTH_FAILED) |

이어서 graceful-close 중인 스트림 중 닫힌 것은 목록에서 빼고, 5 s 를 넘긴 것은 강제로 닫는다.
모든 시간 비교는 monotonic clock 기준이며, 판정 해상도는 sweep 주기(250 ms)이다.

## 10. 폐기 세대 카운터

폐기 API 는 **열린 세션**만 순회해 닫는다. 인가 콜백이 실행되는 동안(아직 열리지 않은 연결)의 폐기를 놓치지 않도록:

1. 연결은 CLIENT_PROOF 처리 전에 `revocation_generation()` 값을 기록한다.
2. `RevokeClient`, `RevokeLicense`, `ReleaseLicenseSeat` 는 저장소를 바꾼 뒤 카운터를 증가시키고 열린 세션을 닫는다.
3. 연결이 mutex 를 다시 잡은 뒤 값이 바뀌었으면 `IsStillAuthorized()` 로 registry(활성 여부)와 license store(존재·활성·좌석)를
   다시 확인한다. 실패하면 이번 인가가 새로 잡은 좌석을 반납하고 AUTH_RESULT(REJECTED) 로 바꾼다.

세션은 연결 mutex 아래에서 열리므로, 폐기 순회가 보지 못한 연결은 반드시 이 재확인을 거친다.

## 11. 콜백 스레딩 계약

`sockgate/server.h` 의 계약 원문:

```text
Threading: callbacks run without any SockGate lock held (except the ones
SG_Server_Stop / SG_Server_Destroy deliver, under their lifecycle lock),
usually on I/O worker threads, but also on the thread whose call closed a
session (SG_Server_CloseSession, SG_Server_RevokeClient,
SG_Server_RevokeLicense, SG_Server_ReleaseLicenseSeat, SG_Server_Stop, a
failing SG_Server_Send) and on the internal timer thread (expiry, idle
timeout). The log callback is the exception: it may run while internal
locks are held, so it must only record the message and never call a
SockGate function. Callbacks for one session are serialised and ordered,
with one exception: on_authorize for a re-authentication (the client's
SG_Client_Refresh) runs on an I/O thread outside that order and may overlap
the same session's on_message and on_session_closed, so per-session data it
uses must be synchronised and must not be freed while it runs. Callbacks for
different sessions may run concurrently. Every API function except
SG_Server_Start, SG_Server_Stop and SG_Server_Destroy may be called from a
callback, including for the session being processed. A slow on_message
callback applies backpressure: reading from that session pauses until it
returns.
```

보충:

- `on_authorize` / `on_enroll` 은 해당 연결의 읽기 처리 스레드(I/O 워커)에서 핸드셰이크 도중 호출된다. 이 시간은 핸드셰이크
  타임아웃(`handshake_timeout_ms`)에 포함된다. 재인증의 `on_authorize` 도 REAUTH_PROOF 를 처리하는 I/O 스레드에서 이벤트 큐 밖으로
  호출되며 (§4.3), 그 시간은 재인증 challenge TTL (`challenge_ttl_ms`)에 포함된다.
- Stop/Destroy 가 직접 전달하는 `on_session_closed` 는 lifecycle lock 아래에서 실행되므로, 그 안에서 오래 막히면 종료가 그만큼 늦어진다.
  그 세션의 이벤트를 이미 다른 스레드가 전달 중이면 그 스레드가 lifecycle lock 없이 전달한다.
- 로그 콜백(`log_callback`)은 메시지를 기록만 하고 어떤 SockGate 함수도 호출하지 않아야 한다.
