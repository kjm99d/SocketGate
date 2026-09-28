# 07. Session Lifecycle

## 1. 클라이언트 상태 머신

```text
                SG_Client_Connect
 Disconnected ───────────────────▶ Connecting ──(TCP/proxy 성공)──▶ TlsHandshake
      ▲                                │                                 │
      │                                └──실패──▶ Closed                  │ TLS 성공 + 검증 통과
      │                                                                  ▼
      │                                                            TlsEstablished
      │                                                                  │ SG_Client_Authenticate / Enroll
      │                                                                  ▼
      │                                                            Authenticating
      │                                                                  │ AUTH_RESULT(OK)
      │                                                                  ▼
      │                                                            Authenticated
      │                                                                  │ 세션 키 설치
      │                                                                  ▼
      │               REAUTH_RESULT(OK) ◀──────────┐                 Active ◀──┐
      │                     │                      │                    │      │
      │                     ▼                      │   REAUTH_REQUEST   │      │
      │                  Active ────────────▶ Refreshing ───────────────┘      │
      │                                                                        │
      │  SG_Client_Disconnect / 오류 / CLOSE 수신 / 만료                         │
      └──────────── Closed ◀──── Expired ◀─── (session lifetime 초과) ───────────┘
```

| 상태 (`SG_ClientState`) | 허용 API |
|---|---|
| `DISCONNECTED` | Connect, DeleteIdentity |
| `CONNECTING`, `TLS_HANDSHAKE` | (내부) |
| `TLS_ESTABLISHED` | Authenticate, Enroll, Disconnect |
| `AUTHENTICATING` | (내부) |
| `AUTHENTICATED` | (내부, 세션 키 설치 직후 곧바로 `ACTIVE`. 이 상태에서의 호출은 `SG_INVALID_STATE`) |
| `ACTIVE` | Send, Receive, Ping, Refresh, Disconnect |
| `REFRESHING` | Send, Receive, Ping, Disconnect |
| `EXPIRED` | Disconnect, Connect(재연결), DeleteIdentity (Send/Ping/Refresh → `SG_SESSION_EXPIRED`. Receive 는 이미 큐에 들어온 메시지를 먼저 돌려준 뒤 `SG_SESSION_EXPIRED`) |
| `CLOSED` | Disconnect(no-op), Connect(재연결 = 새 TLS + 새 인증), DeleteIdentity |

- 재연결은 항상 새 TCP, 새 TLS, 새 challenge 로 시작한다. 이전 세션 정보는 재사용하지 않는다.
- `EnsureIdentity` / `GetIdentity` 는 상태와 무관하게 호출할 수 있다.
- `AUTHENTICATED` → `ACTIVE` 전환은 세션 키 설치 직후 자동으로 일어난다. 두 상태를 분리한 이유는
  키 설치 실패(내부 오류) 시 `ACTIVE` 에 도달하지 않도록 하기 위함이다.

## 2. 서버 연결/세션 상태 머신

```text
 Accepted ──▶ TlsHandshake ──▶ AwaitHello ──▶ AwaitProof ──▶ Active ◀──▶ Refreshing
    │              │               │               │            │
    └──────────────┴───────────────┴───────────────┴────────────┴──▶ Closing ──▶ Closed
                     (타임아웃 / 프로토콜 오류 / 거부 / 만료 / 서버 종료 / 애플리케이션 요청)
```

서버 세션 레코드:

```text
session_id          bytes16 (CSPRNG, 서버 전역에서 유일)
handle              u64     (애플리케이션용, 재사용 없음)
installation_id     bytes16
state               enum
created_at          monotonic ms
expires_at          monotonic ms (AUTH_RESULT/REAUTH_RESULT 에서 설정)
last_activity       monotonic ms
challenge           bytes32 + issued_at + consumed
recv_sequence       u64 (마지막 수신)
send_sequence       u64 (마지막 송신)
recv_max_request_id u64
send_max_request_id u64
epoch               u32
granted_features    u64
policy              NORMAL / RESTRICTED
product_id, license_id
```

## 3. 시간 기준

- 만료/타임아웃은 **monotonic clock**(`steady_clock`) 으로 계산한다 (시스템 시간 변경에 영향 없음).
- 라이선스 만료, token 만료처럼 절대 시간이 필요한 값은 서버의 `system_clock` (Unix epoch ms) 을 사용한다.
- 클라이언트 시계는 신뢰하지 않는다.

## 4. 만료와 갱신

| 이벤트 | 서버 | 클라이언트 |
|---|---|---|
| `now >= expires_at` | CLOSE(SESSION_EXPIRED) 송신 후 종료 | 수신 시 `EXPIRED` 상태, API 는 `SG_SESSION_EXPIRED` |
| 수명 80% 경과 | - | `SG_CLIENT_FLAG_AUTO_REFRESH` 설정 시 다음 Send/Receive 호출 경로에서 재인증 시작, 또는 `SG_Client_Refresh` 수동 |
| idle 초과 | CLOSE(IDLE_TIMEOUT) | `CLOSED` |
| 재인증 성공 | `expires_at = now + lifetime`, epoch+1 | 동일 |
| installation 폐기 / 라이선스 폐기 / 좌석 반납 | 해당 세션 즉시 CLOSE(AUTH_FAILED) | `CLOSED`, 진행 중인 수신은 `SG_SERVER_REJECTED` |
| 라이선스 조건 변경 | 다음 재인증에서 인가 재평가 (feature 축소, 만료 반영) | 재인증 거부 시 `CLOSED` |

- 세션 수명은 무한일 수 없다 (최대 7일). 장시간 연결은 재인증을 통해 유지한다.
- 세션 만료 시각은 **라이선스 만료 시각을 넘지 않도록** 잘린다 (`expires_at = min(now + lifetime, license_expires_at)`).
- 폐기 처리는 **열린 세션**만 순회한다. 인가 콜백 실행 중(아직 열리지 않은) 연결이 폐기를 놓치지 않도록,
  서버는 폐기 세대 카운터를 인가 전에 기록해 두고, 값이 바뀌었으면 세션을 열기 직전에 registry/license 를
  다시 확인해 거부한다.
- idle 판정의 "활동" 은 **검증을 통과한 수신 프레임** 단위(PING 포함)이다. 바이트 단위 수신은 활동으로 보지 않는다
  (느린 전송으로 idle 타이머를 연장하는 것 방지).

## 5. 종료

- 정상 종료: CLOSE(NORMAL) 송신 → TLS close_notify → 소켓 close.
- 비정상 종료: 즉시 소켓 close. 프로토콜 오류에 대해 상대에게 상세 사유를 보내지 않는다(CLOSE(PROTOCOL_ERROR) 까지만).
- 서버 종료(`SG_Server_Stop`): 새 연결 수락 중지 → 활성 세션에 CLOSE(SERVER_SHUTDOWN) → I/O 완료 대기 → 워커 종료.
- 종료 시 세션 키 cleanse, 콜백 `on_session_closed(handle, reason)` 는 세션마다 정확히 1회 호출된다
  (`on_session_opened` 가 호출된 세션에 한함).

## 6. 동시성 규칙

| 상황 | 처리 |
|---|---|
| Concurrent Send (클라이언트) | send mutex 로 직렬화, sequence 는 TLS mutex 안에서 증가 |
| Concurrent Receive | receive mutex 로 직렬화 |
| Disconnect During Send | closing 플래그 + socket shutdown → Send 는 `SG_CLOSED` 반환, 이후 정리 |
| Disconnect During Connect | 진행 중 단계(proxy 조회, TCP, proxy 협상, TLS)를 중단, Connect 는 `SG_CLOSED` (인증서/pinning 실패는 그대로 보고) (05 §4) |
| Reconnect During Authentication | 상태 검사로 거부 (`SG_INVALID_STATE`) |
| Destroy 중 다른 호출 | API 계약 위반. (v1 미구현: in-flight 카운터 대기 — `Destroy` 는 `Disconnect` 로 진행 중인 Send/Receive 를 깨워 끝나기를 기다린 뒤 해제할 뿐, 이후 들어오는 호출은 막지 못한다. in-flight 카운터는 `TcpTransport` 에만 있다) |
| 서버: 콜백 내 SG_Server_Send | 허용 (lock 미보유 상태에서 콜백) |
| 서버: 종료된 handle 로 Send | `SG_NOT_FOUND` (handle 재사용 없음) |
| 서버: I/O 완료 중 연결 해제 | 완료 컨텍스트가 `shared_ptr<Connection>` 보유 → UAF 없음 |
