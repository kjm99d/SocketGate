# SockGate_Client Protocol View

바이트 레이아웃과 전체 규칙은 [04-protocol-specification.md](../docs/design/04-protocol-specification.md),
서버 측 처리를 포함한 순서는 [05-handshake-sequence.md](../docs/design/05-handshake-sequence.md) 가 기준이다.
이 문서는 **클라이언트가 무엇을 보내고, 무엇을 검증하며, 실패를 어떤 `SG_*` 코드로 돌려주는지**만 다룬다.

## 1. 스택

```text
SockGate frame (48-byte header + payload + [16-byte GCM tag])    wire protocol v1
TLS 1.3  (TLS 1.2 는 SG_CLIENT_FLAG_ALLOW_TLS12 + EMS 필수)       OpenSSL, memory BIO
[proxy 터널: HTTP CONNECT / SOCKS4a / SOCKS5]                      TLS 이전에 raw TCP 위에서 협상
TCP
```

SockGate 프레임은 평문 TCP 로 절대 전송되지 않는다. 모든 정수는 big endian 이다.

## 2. 연결 (SG_Client_Connect)

| 단계 | 클라이언트 상태 | 제한 시간 | 실패 |
|---|---|---|---|
| 설정 검증, TLS 컨텍스트 생성(CA 로드) | 변화 없음 | - | `SG_INVALID_ARGUMENT`, `SG_NOT_SUPPORTED` (모르는 `SG_ServerConfig.flags` 비트, 0 이 아닌 미지 필드), `SG_CERTIFICATE_ERROR` (CA 로드 실패) — 모두 I/O 전 |
| 시스템 proxy 조회, 이름 해석, TCP 연결, proxy 협상 | `CONNECTING` | `connect_timeout_ms` 예산 하나를 여기서 시작 | `SG_NETWORK_ERROR`, `SG_TIMEOUT`, `SG_PROXY_ERROR`, `SG_NOT_SUPPORTED`, `SG_INVALID_ARGUMENT`(proxy 에 넘길 대상 host 문자) → `CLOSED`. 이 단계가 예산을 다 쓰면 TLS 를 시도하지 않고 `SG_TIMEOUT` |
| TLS 핸드셰이크 + 서버 검증 | `TLS_HANDSHAKE` | 같은 예산의 **남은 시간** | 아래 표 → `CLOSED` |
| 완료 | `TLS_ESTABLISHED` | | |

`connect_timeout_ms` 는 시스템 proxy 조회와 이름 해석부터 TLS 핸드셰이크 끝까지 Connect 전체의 예산이다(bad2b3a,
858b162). 각 단계는 남은 시간만 받는다. 한 번의 resolver 호출(`getaddrinfo`)은 중단할 수 없지만 걸린 시간은 예산에서
빠지고, 그 뒤 예산이 없으면 TCP 연결을 시작하지 않는다.

다른 스레드의 `SG_Client_Disconnect` 가 진행 중인 Connect 를 끊으면, 어느 단계였든(시스템 proxy 조회, TCP/proxy, 링크를
게시하기 직전, TLS) Connect 는 `SG_CLOSED` 를 반환하고 `event=connect_aborted` 를 INFO 로 남긴다(991a1b6). proxy 나 TLS
오류로 보고되지 않는다. 단, 이미 판정된 인증서/pin 실패(`SG_CERTIFICATE_ERROR` / `SG_PINNING_ERROR`)는 그대로 보고된다.

TLS 단계에서 클라이언트가 검증하는 것:

1. 체인(신뢰 앵커, 서명, 유효기간) — `SG_CERTIFICATE_ERROR`
2. `server_name`(없으면 `host`)과 인증서 이름. DNS 이름은 `SSL_set1_host` 로 검증하고 SNI 로도 보낸다. IP literal 은
   iPAddress SAN 과 비교한다. 부분 wildcard 는 허용하지 않는다 — `SG_CERTIFICATE_ERROR`
3. 협상 결과: TLS 1.3, 또는 허용된 경우 EMS 가 있는 TLS 1.2 — 아니면 `SG_TLS_ERROR`
4. pin 이 설정되어 있으면 **검증된 체인**의 어느 인증서의 SPKI SHA-256 이 pin 중 하나와 같아야 한다 — `SG_PINNING_ERROR`
   (로그 `event=possible_tls_interception`)
5. 그 밖의 TLS 실패, 핸드셰이크 도중 상대 종료 — `SG_TLS_ERROR`

## 3. 인증 핸드셰이크 (SG_Client_Authenticate / SG_Client_Enroll)

```text
Client (TLS_ESTABLISHED → AUTHENTICATING)                             Server
  | identity 확인 (AUTO_IDENTITY 또는 Enroll 이면 EnsureIdentity, 아니면 GetIdentity)
  | cb = TLS-Exporter("EXPORTER-Channel-Binding", context = 길이 0, 32)       (RFC 9266 tls-exporter)
  |--- CLIENT_HELLO  seq=1 sid=0 flags=0 --------------------------------->|
  |<-- SERVER_HELLO  seq=1 sid=S ------------------------------------------|   (또는 AUTH_RESULT UNSUPPORTED_VERSION)
  | 검증(3.2), TH1 = SHA256("SockGate/v1/transcript" ‖ u16 ver ‖ cb ‖ u32 len(CH) ‖ CH ‖ u32 len(SH) ‖ SH)
  | sig = Sign(installation key, "SockGate/v1/client-proof" ‖ 0 ‖ TH1)
  |--- CLIENT_PROOF  seq=2 sid=S  (sig [, ENROLLMENT_PROOF]) ------------->|
  |<-- AUTH_RESULT   seq=2 sid=S ------------------------------------------|
  | 검증(3.3), [server proof 검증]
  | km = TLS-Exporter("EXPORTER-SockGate-v1-keys", context=TH1, 32)
  | epoch 0 채널 키 설치 → AUTHENTICATED → ACTIVE
```

핸드셰이크 전체(읽기 대기 포함)는 `io_timeout_ms` 하나의 deadline 으로 제한된다(0 이면 무제한).
identity 확인과 token 파싱은 상태를 바꾸기 전에 수행하므로, 여기서 실패하면(`SG_NOT_FOUND`, `SG_KEYSTORE_ERROR`,
`SG_IDENTITY_LOST`, token 형식 오류 `SG_INVALID_ARGUMENT`) 연결은 `TLS_ESTABLISHED` 로 남는다. `AUTHENTICATING` 이후의
모든 실패는 연결을 닫는다(`CLOSED`). 인증 전 프레임은 type 과 무관하게 payload 4 KiB 이하, `flags == 0`,
`request_id == 0`, `auth_length == 0` 이어야 한다.

채널 바인딩은 RFC 9266 tls-exporter(길이 0 context)이다(b95a843). 이전 빌드는 context 없이 export 했는데, TLS 1.3 에서는
같은 값이지만 TLS 1.2 에서는 다르다. 그래서 **TLS 1.2 로 협상된 연결에서는 b95a843 이전 빌드와 이후 빌드가 서로 인증하지
못한다**(서버는 서명을 거부 → `SG_SERVER_REJECTED`). TLS 1.3 연결은 영향이 없다.

### 3.1 CLIENT_HELLO 에 싣는 것

| 필드 / TLV | 값의 출처 |
|---|---|
| `protocol_version_min/max` | 1 / 1 |
| `client_version_*` | `SG_ClientConfig.client_version_major/minor/patch` |
| `client_nonce` | 32 bytes CSPRNG |
| `installation_id` | `SHA-256("SockGate/v1/iid" ‖ public_key)[0..16)` |
| `key_algorithm` | 1 (ECDSA P-256 SHA-256) |
| `auth_mode` | Authenticate = 1, Enroll = 2 |
| TLV `PRODUCT_ID` / `PRODUCT_VERSION` / `LICENSE_ID` | 설정값이 비어 있지 않을 때 (UTF-8, 제어·비가시 문자 금지) |
| TLV `REQUESTED_FEATURES` | `requested_features != 0` 일 때만 |
| TLV `INTEGRITY_REPORT` | `SG_CLIENT_FLAG_INTEGRITY_REPORT` 일 때, 인증마다 새로 수집 |
| TLV `ENROLLMENT_TOKEN_ID`, `PUBLIC_KEY` | Enroll 일 때: token 의 공개 부분(`token_id ‖ claims`)과 SEC1 공개키 |

### 3.2 SERVER_HELLO 검증

| 검사 | 실패 |
|---|---|
| type = SERVER_HELLO, `sequence == 1`, `session_id != 0` | `SG_PROTOCOL_ERROR` |
| 엄격한 디코드: `selected_version != 0`, `challenge_ttl_ms != 0`, 알려진 `server_proof_algorithm`, 알 수 없는 TLV 는 길이 검증 후 무시, trailing data 금지 | `SG_PROTOCOL_ERROR` |
| `selected_protocol_version ∈ [min, max]` | `SG_PROTOCOL_ERROR` |
| `proof_keys` 가 설정되어 있으면 `server_proof_algorithm == 1` (ECDSA P-256) | `SG_INVALID_SIGNATURE` |

SERVER_HELLO 자리에 AUTH_RESULT 가 오면 `result == UNSUPPORTED_VERSION`, `sequence == 1`, `session_id == 0` 인 경우에만
`SG_VERSION_MISMATCH`, 그 밖은 `SG_PROTOCOL_ERROR` 이다.

### 3.3 AUTH_RESULT 검증

| 검사 | 실패 |
|---|---|
| `sequence == 2`, `session_id` 가 SERVER_HELLO 의 값과 같음 | `SG_PROTOCOL_ERROR` |
| 디코드: 알려진 result / policy / proof 알고리즘, 서명 길이가 알고리즘과 일치(0 또는 64), trailing data 금지 | `SG_PROTOCOL_ERROR` |
| OK 이면 `policy != NONE`, `session_lifetime_ms != 0`. OK 가 아니면 나머지 필드가 전부 0 이고 서명 없음 | `SG_PROTOCOL_ERROR` |
| `result`: `REJECTED`, `RETRY_LATER` | `SG_SERVER_REJECTED` (둘은 구분되지 않는다) |
| `result`: `UNSUPPORTED_VERSION` | `SG_VERSION_MISMATCH` |
| `server_proof_algorithm` 이 SERVER_HELLO 의 값과 같음 | `SG_PROTOCOL_ERROR` |
| `proof_keys` 설정 시: 서명이 있고, `"SockGate/v1/server-proof" ‖ 0 ‖ TH2` 에 대해 설정된 키 중 하나로 검증됨 | `SG_INVALID_SIGNATURE` |

`TH2 = SHA-256("SockGate/v1/server-transcript" ‖ TH1 ‖ u32 len ‖ CLIENT_PROOF 프레임 ‖ u32 len ‖ R)`,
R 은 AUTH_RESULT 의 헤더와 payload 중 `server_proof_algorithm` 까지(04 §6.4).

검사 순서상 `result` 판정이 서명 검사보다 먼저다. 거부 결과(REJECTED / RETRY_LATER / UNSUPPORTED_VERSION)는 서명 없이
오므로(부가 필드와 `server_proof_algorithm` 이 0 이어야 함) `proof_keys` 가 있어도 **인증되지 않는다**. proof key 는
`AUTH_RESULT(OK)` 만 보증한다. SERVER_HELLO 자리의 UNSUPPORTED_VERSION 도 마찬가지다.

성공하면 `SG_ClientSessionInfo` 에 `session_id`, `policy`, `granted_features`, `license_expires_at_ms`,
남은 수명(`expires_in_ms`), `epoch = 0` 이 기록된다. 거부 사유의 세부 내용은 네트워크로 오지 않는다.

### 3.4 Enrollment

`SG_Client_Enroll(client, token)`: token 은 `base64url(token_pub ‖ K_tok)` 이다(최대 1024 자). 클라이언트는
`token_pub` 을 CLIENT_HELLO TLV 6 으로, `ENROLLMENT_PROOF = HMAC-SHA256(K_tok, "SockGate/v1/enroll-proof" ‖ 0 ‖ TH1)`
을 CLIENT_PROOF TLV 1 로 보낸다. `K_tok` 은 전송하지 않고 proof 를 만든 즉시 지운다. identity 가 없으면 먼저 만든다.
성공하면 그 연결이 곧바로 인증된 세션이 된다. 서버 측 검증 순서는 05 §2.

## 4. 세션 채널 규칙 (ACTIVE / REFRESHING)

인증 후 모든 프레임은 `auth_length = 16` 이고 `ProtectedChannel` 이 봉인/검증한다.

| 규칙 | 클라이언트 송신 | 클라이언트 수신 시 위반 결과 |
|---|---|---|
| sequence | 방향별로 3 부터(핸드셰이크 프레임 1, 2 다음) 정확히 +1 | 기대값보다 작음: `SG_REPLAY_DETECTED`, 큼: `SG_PROTOCOL_ERROR` |
| session_id | 할당된 값 | 다르면 `SG_PROTOCOL_ERROR` |
| AEAD | AES-256-GCM, 키는 방향·epoch 별, nonce = `u32(0) ‖ u64(sequence)`, AAD = 헤더(+ 비암호화 시 payload) | tag 실패: `SG_PROTOCOL_ERROR` |
| `ENCRYPTED` | `SG_CLIENT_FLAG_APP_ENCRYPTION` 이면 DATA payload 암호화 | 수신은 플래그대로 복호화, `SG_MessageInfo.flags` 에 `SG_MESSAGE_FLAG_ENCRYPTED` |
| `KEY_PHASE` | 송신 epoch & 1 | 현재 수신 epoch 와 다르면 `SG_PROTOCOL_ERROR` |
| 요청 ID | 응답이 아닌 모든 DATA 에 방향별로 단조 증가하는 ID 를 붙인다(`out_request_id`) | 상대 요청 ID 가 이전 이하: `SG_REPLAY_DETECTED` |
| 응답 | `reply_to_request_id` 는 상대가 실제로 보낸 요청 ID 이하여야 한다. 아니면 **로컬에서** `SG_INVALID_ARGUMENT`(전송하지 않음, 연결 유지) | 우리가 할당한 최대 요청 ID 보다 큰 ID 에 대한 응답: `SG_PROTOCOL_ERROR`. 중복 응답은 거부하지 않는다(짝 맞추기는 애플리케이션 몫) |
| `RESPONSE` 플래그 | DATA 에만 | DATA 가 아닌 프레임의 RESPONSE 또는 request_id: `SG_PROTOCOL_ERROR` |
| 크기 | DATA ≤ `max_payload_size`(아니면 로컬 `SG_INVALID_ARGUMENT`), 제어 메시지 ≤ 4 KiB | DATA > `max_payload_size`: `SG_PROTOCOL_ERROR` |

- 첫 위반에서 채널은 poison 되고(수신 키 폐기) 연결은 닫힌다. 수신 오류 후 계속 진행하지 않는다.
- 서버의 `SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION` 이 켜져 있으면 `ENCRYPTED` 없는 DATA 는 서버가 거부한다.
  이 경우 클라이언트는 `SG_CLIENT_FLAG_APP_ENCRYPTION` 을 켜야 한다.

제어 메시지:

| 메시지 | 클라이언트 동작 |
|---|---|
| PING 수신 | 같은 `opaque` 값으로 PONG 을 즉시 보냄 |
| PONG 수신 | 검증 후 버림 |
| `SG_Client_Ping` | PING(`opaque` = monotonic ms) 송신. PONG 을 기다리지 않음 |
| CLOSE 수신 | `SESSION_EXPIRED` → `SG_SESSION_EXPIRED`(`EXPIRED`), `AUTH_FAILED` → `SG_SERVER_REJECTED`, 그 밖(NORMAL, PROTOCOL_ERROR, SERVER_SHUTDOWN, IDLE_TIMEOUT, LIMIT_EXCEEDED) → `SG_CLOSED` |
| `SG_Client_Disconnect` | ACTIVE/REFRESHING 이었다면 CLOSE(NORMAL) 를 best effort(200 ms)로 보낸 뒤 close_notify |

## 5. 재인증과 key phase (SG_Client_Refresh)

`ACTIVE` 에서만 시작한다(`EXPIRED` → `SG_SESSION_EXPIRED`, 그 밖 → `SG_INVALID_STATE`).

```text
Client (ACTIVE → REFRESHING)                                         Server
  |--- REAUTH_REQUEST(client_nonce)              [epoch e] ------------->|
  |<-- REAUTH_CHALLENGE(server_nonce, challenge, ttl) [epoch e] ---------|
  | THr = SHA256("SockGate/v1/reauth" ‖ sid ‖ u32 e ‖ cb ‖ prev_TH ‖ u32 len(F(RQ)) ‖ F(RQ) ‖ u32 len(F(CHL)) ‖ F(CHL))
  |--- REAUTH_PROOF(Sign("SockGate/v1/reauth-proof" ‖ 0 ‖ THr)) [epoch e] ->|
  |<-- REAUTH_RESULT(OK, lifetime, new_epoch)    [epoch e] --------------|
  | new_epoch == e + 1 확인
  | km' = Exporter("EXPORTER-SockGate-v1-keys", context=THr)
  | 수신 키 → e+1, (send lock 안에서) 송신 키 → e+1, TLS 1.3 KeyUpdate 요청
  | REFRESHING → ACTIVE, 수명 재설정
```

- `F(x)` 는 헤더(auth_length=16)와 평문 payload 이다. `cb` 는 최초 인증 때의 채널 바인딩, `prev_TH` 는 직전
  transcript(TH1 또는 이전 THr) 이다.
- 교환 중에도 DATA/PING/PONG 은 epoch e 키로 계속 오간다. 도착한 DATA 는 큐에 쌓인다. 서버는 REAUTH_RESULT 를 보낸 직후
  s2c 를 e+1 로 바꾸므로 클라이언트는 REAUTH_RESULT 처리 직후부터 e+1 만 받는다. c2s 전환 시점은 클라이언트가 정한다
  (04 §7.3).
- 교환 전체는 `io_timeout_ms` 로 제한된다. 기다리던 메시지가 아닌 재인증 메시지는 `SG_PROTOCOL_ERROR`.
- 실패: `REAUTH_RESULT` 가 OK 가 아님 → `SG_SERVER_REJECTED`, `new_epoch != e + 1` → `SG_PROTOCOL_ERROR`,
  서버 CLOSE → 4 절의 매핑. 어느 경우든 연결은 닫힌다.
- 서버는 최초 인증, 또는 직전에 받아들인 REAUTH_REQUEST(challenge 발급 시점) 이후 `min_reauth_interval_ms`(서버 기본
  10 s) 이내의 REAUTH_REQUEST 를 프로토콜 오류로 보고 연결을 닫는다. 인증 직후 곧바로 Refresh 하지 않는다.
- 서버는 REAUTH_CHALLENGE 를 보낸 뒤 `challenge_ttl_ms`(서버 기본 30 s) 안에 REAUTH_PROOF 가 오지 않으면 CLOSE(AUTH_FAILED)
  로 닫는다. 클라이언트는 `SG_SERVER_REJECTED` 를 받는다(느린 TPM 서명 등).
- `SG_CLIENT_FLAG_AUTO_REFRESH`: Send/Receive **진입 시** 마지막 (재)인증 후 수명의 80% 가 지났으면 같은 절차를 수행한다
  (수신 측 잠금을 `try_lock` 으로만 잡으므로 무한 대기 중인 Receive 가 있으면 미뤄진다).
- 재인증은 integrity 보고를 다시 보내지 않는다(서버는 최초 CLIENT_HELLO 의 보고를 사용).

## 6. 오류 코드 매핑

| 단계 | 조건 | `SG_*` | 이후 상태 |
|---|---|---|---|
| Create | 설정 오류, 이름 규칙 위반, 알 수 없는 key store 종류 | `SG_INVALID_ARGUMENT` | 핸들 없음 |
| Create | 알 수 없는 `SG_CLIENT_FLAG_*`, 지원하지 않는 key store, 0 이 아닌 미지 필드 | `SG_NOT_SUPPORTED` | 핸들 없음 |
| Create | key 디렉터리 생성/검증 실패 | `SG_KEYSTORE_ERROR` | 핸들 없음 |
| Connect | 신뢰 설정 누락, pin 없는 OS store, pin/proof key 개수 초과, 잘못된 proof key | `SG_INVALID_ARGUMENT` | 변화 없음 |
| Connect | proxy 에 넘길 대상 host 에 허용되지 않은 문자 (`CONNECTING` 이후 검사) | `SG_INVALID_ARGUMENT` | `CLOSED` |
| Connect | 다른 스레드의 Disconnect (어느 단계든) | `SG_CLOSED` | `CLOSED` (Disconnect 가 설정) |
| Connect | 모르는 `SG_ServerConfig.flags` 비트, 0 이 아닌 미지 필드 | `SG_NOT_SUPPORTED` | 변화 없음 |
| Connect | 이미 연결됨 | `SG_INVALID_STATE` | 변화 없음 |
| Connect | 이름 해석/TCP 실패 | `SG_NETWORK_ERROR` | `CLOSED` |
| Connect | `connect_timeout_ms` 예산 소진 (해석·연결·proxy·TLS 합계) | `SG_TIMEOUT` | `CLOSED` |
| Connect | proxy 거부/형식 오류 | `SG_PROXY_ERROR` | `CLOSED` |
| Connect | 체인/이름/유효기간, CA 로드 실패 | `SG_CERTIFICATE_ERROR` | `CLOSED` (CA 로드 실패는 변화 없음) |
| Connect | pin 불일치 | `SG_PINNING_ERROR` | `CLOSED` |
| Connect | TLS 협상 실패, TLS 1.2 without EMS | `SG_TLS_ERROR` | `CLOSED` |
| Authenticate | identity 없음(AUTO_IDENTITY 아님) | `SG_NOT_FOUND` | `TLS_ESTABLISHED` 유지 |
| Authenticate | key store 사용 불가 / identity 소실 | `SG_KEYSTORE_ERROR` / `SG_IDENTITY_LOST` | 확인 단계면 유지, 서명 단계면 `CLOSED` (clear 된 Linux TPM2 키는 서명 단계의 `SG_KEYSTORE_ERROR`) |
| Enroll | token 형식 오류 | `SG_INVALID_ARGUMENT` | `TLS_ESTABLISHED` 유지 |
| Authenticate/Enroll | REJECTED / RETRY_LATER | `SG_SERVER_REJECTED` | `CLOSED` |
| Authenticate/Enroll | 버전 협상 실패 | `SG_VERSION_MISMATCH` | `CLOSED` |
| Authenticate/Enroll | server proof 누락/불일치 | `SG_INVALID_SIGNATURE` | `CLOSED` |
| Authenticate/Enroll | 형식/순서 위반, 서버가 AUTH_RESULT 없이 CLOSE | `SG_PROTOCOL_ERROR` | `CLOSED` |
| Authenticate/Enroll | 응답 시간 초과 | `SG_TIMEOUT` | `CLOSED` |
| Authenticate/Enroll | 서버가 연결을 끊음 | `SG_CLOSED` / `SG_NETWORK_ERROR` / `SG_TLS_ERROR` | `CLOSED` |
| 세션 | sequence 역행, 중복 요청 | `SG_REPLAY_DETECTED` | `CLOSED` |
| 세션 | sequence 건너뜀, tag 실패, 규칙 위반, 과대 DATA | `SG_PROTOCOL_ERROR` | `CLOSED` |
| 세션 | 수명 만료(로컬) 또는 CLOSE(SESSION_EXPIRED) | `SG_SESSION_EXPIRED` | `EXPIRED` |
| 세션 | CLOSE(AUTH_FAILED): installation/라이선스 폐기, 좌석 반납, 재인증 서명이 서버 `challenge_ttl_ms` 초과(예: 느린 TPM 서명) | `SG_SERVER_REJECTED` | `CLOSED` |
| 세션 | 그 밖의 CLOSE, 상대 종료 | `SG_CLOSED` | `CLOSED` |
| 세션 | 수신 큐 64 MiB 초과 | `SG_LIMIT_EXCEEDED` | `CLOSED` |
| Send | 송신 쓰기 시간 초과 / 네트워크 오류 | `SG_TIMEOUT` / `SG_NETWORK_ERROR` | `CLOSED` |
| Receive | 대기 시간 초과 | `SG_TIMEOUT` | **유지** |
| Receive | 버퍼 부족 | `SG_BUFFER_TOO_SMALL` (`*received` = 필요 크기) | **유지**, 메시지 보존 |
| Refresh | REAUTH_RESULT 거부 | `SG_SERVER_REJECTED` | `CLOSED` |

네트워크로 오가는 거부 사유는 일반화되어 있다(REJECTED 등). 구체적인 `SG_*` 코드와 로그는 로컬 애플리케이션만 본다.
