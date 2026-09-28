# SockGate_Server Protocol View

서버가 SockGate wire protocol v1 을 어떻게 받아들이고 검증하는지 설명한다. 바이트 레이아웃(프레임 헤더, 메시지 필드,
TLV, transcript 입력)은 [04-protocol-specification.md](../docs/design/04-protocol-specification.md), 전체 순서는
[05-handshake-sequence.md](../docs/design/05-handshake-sequence.md) 가 기준이다. 코덱과 규칙 검사는 클라이언트와 공유하는
`SockGate_Common/src/sockgate_common/protocol` 에 있고, 서버 고유 처리는 `ServerHandshake` 와 `Connection` 에 있다.

## 1. 전송 계층

- TLS 1.3 이 기본이다. `SG_SERVER_OPT_ALLOW_TLS12` 가 있으면 TLS 1.2 도 받지만, 핸드셰이크 직후 Extended Master Secret 이
  협상되지 않았으면 연결을 끊는다 (TLS 1.2 에서 exporter 를 채널 바인딩으로 쓰기 위한 RFC 9266 조건).
- 암호군: TLS 1.3 `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`,
  TLS 1.2 는 ECDHE-ECDSA/RSA 의 AES-GCM, CHACHA20-POLY1305 만. 서버 선호 순서 사용. 압축·재협상·세션 재개(ticket, cache) 없음.
- TLS 계층에서 클라이언트 인증서를 요구하지 않는다. 클라이언트는 SockGate 계층에서 인증한다.
- TLS 핸드셰이크가 끝나면 서버는 자기 쪽 연결에서 채널 바인딩을 계산해 둔다:

```text
channel_binding = TLS-Exporter(label = "EXPORTER-Channel-Binding", context = 길이 0 (use_context = 1), length = 32)   // RFC 9266 tls-exporter
```

길이 0 context 는 b95a843 부터이다. TLS 1.3 에서는 "context 없음" 과 같은 값이지만 TLS 1.2 에서는 다르므로, 그 이전에 빌드된 피어와
이후 빌드는 **TLS 1.2 로 협상하면 서로 인증하지 못한다** (TLS 1.3 은 영향 없음). `SG_SERVER_OPT_ALLOW_TLS12` 를 쓰는 배포는 서버와
클라이언트를 함께 올린다.

## 2. 단계별 허용 프레임

모든 수신 프레임은 두 번 검사된다. (1) 48 bytes 헤더가 모이면 구조 검사와 **현재 단계 기준 상태 검사**를 한 뒤에야 본문을
버퍼링한다. (2) 프레임이 완성되면 그 시점의 단계로 상태 검사를 다시 한다.

구조 검사 (단계 무관): `magic == "SGAT"`, `version == 1` (아니면 `SG_VERSION_MISMATCH`), 정의된 `type`, `flags` 예약 비트 0,
`reserved == 0`, `auth_length ∈ {0, 16}`, `payload_length ≤ 16 MiB`. 위반은 모두 연결 종료이다.

상태 검사 (서버가 수신자일 때):

| 단계 | 허용 type | `auth_length` | `flags` | `request_id` | `payload_length` 상한 |
|---|---|---|---|---|---|
| AwaitClientHello | `CLIENT_HELLO`, `CLOSE` | 0 | 0 | 0 | 4096 |
| AwaitClientProof | `CLIENT_PROOF`, `CLOSE` | 0 | 0 | 0 | 4096 |
| Active | `DATA`, `PING`, `PONG`, `REAUTH_REQUEST`, `CLOSE` | 16 | `RESPONSE` 는 DATA 에만, 그때 `request_id != 0` | DATA 외에는 0 | DATA: `max_payload_size`, 그 외 4096 |
| Refreshing | `DATA`, `PING`, `PONG`, `REAUTH_PROOF`, `CLOSE` | 16 | 위와 같음 | 위와 같음 | 위와 같음 |
| Closed | 없음 | | | | |

- 서버는 `SERVER_HELLO`, `AUTH_RESULT`, `REAUTH_CHALLENGE`, `REAUTH_RESULT` 를 어떤 단계에서도 받지 않는다.
- 인증 전 상한은 type 과 무관하게 4096 bytes 이고, 인증 전 decoder 버퍼는 16 KiB 로 제한된다.
- 인증 전의 CLOSE 는 내용을 해석하지 않고 연결을 닫는다. 인증 후 CLOSE 는 `u16 reason` (0–6) 을 엄격히 디코딩한 뒤 닫는다.
- 서버가 보내는 프레임: `SERVER_HELLO`, `AUTH_RESULT`, `DATA`, `PONG`, `REAUTH_CHALLENGE`, `REAUTH_RESULT`, `CLOSE`.
  서버는 PING 이나 재인증을 먼저 시작하지 않는다.

## 3. 핸드셰이크 메시지 검증

### 3.1 CLIENT_HELLO

1. 헤더: `sequence == 1`, `session_id` 가 전부 0.
2. 디코딩 (위반은 `SG_PROTOCOL_ERROR`, 응답 없이 종료):
   - `protocol_version_min ≥ 1`, `min ≤ max`, `key_algorithm == 1` (ECDSA P-256/SHA-256), `auth_mode ∈ {1 AUTHENTICATE, 2 ENROLL}`.
   - TLV: 최대 16개, 중복 type 금지, 길이 합 정확히 일치, 뒤따르는 바이트 금지. 알 수 없는 TLV type 은 무시.
   - `PRODUCT_ID` 1..64, `PRODUCT_VERSION` 1..32, `LICENSE_ID` 1..128 — 모두 protocol string (UTF-8, 제어·비가시·bidi override 문자 금지).
   - `REQUESTED_FEATURES` 정확히 8 bytes. `INTEGRITY_REPORT` ≤ 512 bytes, `report_version == 1`, `platform ∈ 1..3`,
     `SG_INTEGRITY_KNOWN_FLAGS` 밖의 비트 금지, `build_id` ≤ 64.
   - `ENROLLMENT_TOKEN_ID` 1..512, `PUBLIC_KEY` 65 bytes 이고 0x04 로 시작.
   - ENROLL 모드는 `ENROLLMENT_TOKEN_ID` 와 `PUBLIC_KEY` 가 필수, AUTHENTICATE 모드는 둘 다 금지.
3. 버전 협상: `high = min(client_max, 1)`, `low = max(client_min, 1)`. `high < low` 이면 SERVER_HELLO 대신
   `AUTH_RESULT(UNSUPPORTED_VERSION)` (`session_id = 0`, `sequence = 1`, 나머지 0)을 보내고 닫는다.
4. 이 단계에서는 installation 등록 여부, enrollment 허용 여부, 제품·라이선스를 **판단하지 않는다.**
   형식이 맞으면 항상 새 `session_id`(16 bytes CSPRNG, 0 아님), `server_nonce`, 1회용 `challenge`(32 bytes)를 만들어
   `SERVER_HELLO(sequence = 1)` 로 응답한다. `challenge_ttl_ms` 는 설정값, `server_proof_algorithm` 은 proof key 가 있으면 1.

### 3.2 CLIENT_PROOF

1. 헤더: `sequence == 2`, `session_id` == 할당한 값.
2. 디코딩: `signature_algorithm == 1`, `signature` 정확히 64 bytes (P1363 `r‖s`), `ENROLLMENT_PROOF` TLV 는 32 bytes.
   `ENROLLMENT_PROOF` 는 ENROLL 모드에서만, 그리고 반드시 있어야 한다. 위반은 응답 없이 종료.
3. **challenge 소비**: 이 연결의 인증 시도는 이것으로 끝이다. TTL 초과 여부를 기록한다.
4. `TH1` 을 서버측 채널 바인딩으로 계산하고 서명 대상 `"SockGate/v1/client-proof" ‖ 0x00 ‖ TH1` 을 만든다.
5. AUTHENTICATE:
   - registry 조회. 레코드가 활성이고 알고리즘이 일치하면 그 공개키, 아니면 **더미 키**로 서명을 검증한다 (시간 균일화).
   - 결과 판정 순서: 미등록 → 폐기 → 알고리즘 불일치 → 서명 오류 → challenge 만료. 어느 것이든 REJECTED.
6. ENROLL:
   - challenge 만료면 REJECTED.
   - `SG_SERVER_OPT_ALLOW_ENROLLMENT` 가 없으면 REJECTED.
   - `K_tok`: `on_enroll` 이 없으면 token key 와 `token_pub` 로 재계산 (`token_pub` 형식 오류는 REJECTED),
     있으면 콜백이 돌려준 값 (이 경우 `SG_Server_IssueEnrollmentToken` 의 내장 token 은 받지 않는다). 콜백은 아래 검증 전에 호출된다.
   - `enroll_mac = HMAC-SHA256(K_tok, "SockGate/v1/enroll-proof" ‖ 0x00 ‖ TH1)` 를 상수 시간 비교 (서명 검증보다 먼저).
   - 내장 token 만: `now < expires_at_ms`, `issued_at_ms ≤ now + 5 min`, `expires_at_ms - issued_at_ms ≤ 30일`,
     CLIENT_HELLO 의 PRODUCT_ID/LICENSE_ID 는 없거나 claims 와 같아야 함.
   - `PUBLIC_KEY` 가 곡선 위 점이고 `installation_id == SHA-256("SockGate/v1/iid" ‖ PUBLIC_KEY)[0..16)`.
   - `PUBLIC_KEY` 로 서명 검증 (소유 증명).
   - token ID 소비 + installation 등록을 원자적으로 저장 (이미 사용된 token 또는 이미 있는 ID 면 REJECTED). 이는 인가(7) **전**이므로
     인가가 거부되어도 token 은 사용된 것으로 남는다. 1회 사용 기록은 registry 단위이다.
     내장 token 은 claims 의 product/license 를 바인딩으로 기록하고, `on_enroll` 승인은 주장한 product 만 기록한다.
7. 인가 (`BuiltinAuthorizer` → `on_authorize`, [INTEGRATION.md](INTEGRATION.md) §6). 거부 또는 policy 가 NORMAL/RESTRICTED 가 아니면 REJECTED.
   C API 의 `on_authorize` 가 잘못된 policy 를 돌려주면 콜백 실패로 처리되어 `authorization denied: application callback failed` 로 기록된다.
8. 수명: `decision.session_lifetime_ms` (0 이면 `session_lifetime_ms` 설정값), 최대 7일, `license_expires_at_ms` 가 있으면
   `license_expires_at_ms - now` 로 자름. 이미 지났으면 REJECTED. 최소 1 ms.
9. `AUTH_RESULT(OK, sequence = 2)`: `session_policy`, `granted_features`, `session_lifetime_ms`, `license_expires_at_ms`,
   `server_proof_algorithm`, 그리고 proof key 가 있으면 서명:

```text
R   = AUTH_RESULT 헤더(48) ‖ payload 중 server_proof_algorithm 까지
TH2 = SHA-256("SockGate/v1/server-transcript" ‖ TH1 ‖ u32 len ‖ CLIENT_PROOF 프레임 ‖ u32 len ‖ R)
sig = ECDSA-P256(proof_key, "SockGate/v1/server-proof" ‖ 0x00 ‖ TH2)
```

10. 인가 콜백 동안 폐기가 있었다면 세션을 열기 직전 다시 확인하고, 실패하면 AUTH_RESULT(OK) 대신 REJECTED 를 보낸다.

`AUTH_RESULT(REJECTED)` 는 나머지 필드가 모두 0 이며, 보낸 뒤 연결을 닫는다. proof key 서명은 AUTH_RESULT(OK) 에만 붙고,
REJECTED / UNSUPPORTED_VERSION 과 REAUTH_RESULT 에는 붙지 않는다. 이 구현은 `RETRY_LATER` 를 보내지 않는다
(용량 초과 연결은 수락 직후 닫힌다).

## 4. 인증 후 메시지

인증 후 모든 수신 프레임은 먼저 `ProtectedChannel::Open()` 을 통과해야 한다 (§6). 통과한 프레임만 idle 타이머를 갱신한다.

| 수신 | 처리 |
|---|---|
| `DATA` | `SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION` 이면 `ENCRYPTED` 없는 DATA 는 `SG_PROTOCOL_ERROR`. `on_message(session, data, size, info)` 로 전달. `info.request_id`, `info.flags` (`SG_MESSAGE_FLAG_ENCRYPTED`, `SG_MESSAGE_FLAG_RESPONSE`) |
| `PING` | payload 는 정확히 `u64 opaque`. 같은 값으로 `PONG` 응답 |
| `PONG` | 형식만 검사하고 버린다 |
| `CLOSE` | reason 검사 후 연결 종료. `on_session_closed(SG_CLOSED)` |
| `REAUTH_REQUEST` (Active) | 직전 키 전환이 아직 확인되지 않았거나(대기 중인 수신 키 존재) 세션 시작 또는 마지막으로 받아들인 REAUTH_REQUEST (challenge 발급) 후 `min_reauth_interval_ms` 이내면 `SG_PROTOCOL_ERROR` 로 종료. 아니면 payload(`bytes32 client_nonce`) 검사 후 `REAUTH_CHALLENGE(server_nonce, challenge, challenge_ttl_ms)` 를 보내고 Refreshing |
| `REAUTH_PROOF` (Refreshing) | 아래 §4.1 |

### 4.1 재인증

1. `signature_algorithm == 1`, 서명 64 bytes, trailing data 금지.
2. challenge 는 1회용으로 지운다. 발급 후 `challenge_ttl_ms` 이내인지 기록한다.
3. 재인증 transcript:

```text
F(x) = x 프레임 헤더(48, auth_length = 16) ‖ 평문 payload
THr  = SHA-256("SockGate/v1/reauth" ‖ session_id ‖ u32 epoch ‖ channel_binding ‖ prev_TH
               ‖ u32 len ‖ F(REAUTH_REQUEST) ‖ u32 len ‖ F(REAUTH_CHALLENGE))
signed = "SockGate/v1/reauth-proof" ‖ 0x00 ‖ THr
```

4. registry 를 다시 조회해 활성 레코드의 공개키(없으면 더미 키)로 검증한다. 판정 순서: installation 비활성 → 서명 오류 → challenge 만료.
5. 인가를 다시 수행한다 (`SG_AuthRequest.reauthentication = 1`, 클레임과 integrity 보고는 최초 CLIENT_HELLO 의 것).
   라이선스 조건 변경, 만료, 폐기가 여기서 반영된다.
6. 실패하면 `REAUTH_RESULT(REJECTED)` 를 보내고 닫는다 (`on_session_closed(SG_AUTH_FAILED)`).
7. 성공하면 `REAUTH_RESULT(OK, session_lifetime_ms, new_epoch = epoch + 1)` 을 epoch e 키로 보내고, 송신 키를 e+1 로 바꾸고,
   수신 키 e+1 을 대기시키고, TLS 1.3 이면 `SSL_key_update(SSL_KEY_UPDATE_REQUESTED)` 를 요청한다. 세션 만료 시각과 권한은 새 결정으로 바뀐다.

Refreshing 중에도 DATA/PING/PONG 은 계속 처리된다. Refreshing 상태에서 challenge TTL 이 지나도록 REAUTH_PROOF 가 오지 않으면
sweeper 가 CLOSE(AUTH_FAILED) 로 닫는다.

## 5. 네트워크 응답과 로그

네트워크로 나가는 거부는 일반화된 값뿐이다. 상세 사유는 로그 콜백(`log_callback`)으로만 전달된다.

| 상황 | 네트워크 | 로그 (level, event) |
|---|---|---|
| 헤더/메시지 형식 오류, 상태 위반 (인증 전) | 응답 없이 종료 | WARN `event=connection_error ... phase=… err=…` |
| 버전 협상 실패 | AUTH_RESULT(UNSUPPORTED_VERSION) | INFO `event=auth_rejected reason="unsupported protocol version"` |
| 인증·enrollment·인가 실패 | AUTH_RESULT(REJECTED) | WARN `event=auth_rejected peer=… installation=… reason="…"` |
| 재인증 실패 | REAUTH_RESULT(REJECTED) | WARN `event=reauth_rejected session=… reason="…"` |
| 인증 후 tag/sequence/request id 오류 | CLOSE(PROTOCOL_ERROR) | WARN `event=frame_rejected ... err=…` + `event=connection_error` |
| TLS 실패 (EMS 없는 TLS 1.2 포함) | TLS alert 또는 종료 | INFO `event=tls_failed detail="…"` |
| 핸드셰이크 타임아웃 | 종료 | INFO `event=handshake_timeout` |
| 용량 초과 | 수락 직후 종료 | WARN `event=connection_refused reason=max_connections` 또는 `reason=max_unauthenticated` |

`auth_rejected` 의 `reason` 예: `unknown installation`, `installation revoked`, `key algorithm mismatch`, `invalid signature`,
`challenge expired`, `enrollment disabled`, `no enrollment token key configured`, `malformed enrollment token`,
`enrollment rejected by validator`, `enrollment proof mismatch`, `enrollment token expired`, `enrollment token issued in the future`,
`enrollment token lifetime exceeds the maximum`, `enrollment claims mismatch`, `invalid enrollment key`, `token already used or installation exists`, `registry failure`,
`license expired`, `revoked during authentication`, 그리고 `authorization denied: …`
(`product claim contradicts registration`, `license claim contradicts registration`, `license revoked`,
`license is for another product`, `valid license required`, `license claim not bound to installation`,
`integrity policy (conditions 0x…)`, `denied by application`, `application callback failed`,
`license installation limit reached`, `license activation failed` 등).

클라이언트는 이 중 어느 것이 원인인지 구분할 수 없다 (`SG_SERVER_REJECTED`). 로그 메시지에는 키, 서명, transcript, token 문자열,
payload 가 들어가지 않으며, ID 는 앞 8 bytes 의 hex, 라이선스 ID 는 `lic:` + SHA-256 앞 8 bytes 로만 기록된다.

## 6. 키, 채널 바인딩, KEY_PHASE, sequence

### 6.1 키 유도

```text
TH1  = SHA-256("SockGate/v1/transcript" ‖ u16 selected_version ‖ channel_binding
               ‖ u32 len ‖ CLIENT_HELLO 프레임 ‖ u32 len ‖ SERVER_HELLO 프레임)
km   = TLS-Exporter(label = "EXPORTER-SockGate-v1-keys", context = TH1 (재인증 시 THr), length = 32)
k_cs = HKDF-SHA256(ikm = km, salt = session_id, info = "SockGate/v1 c2s" ‖ u32 epoch, L = 32)   // 서버 수신 키
k_sc = HKDF-SHA256(ikm = km, salt = session_id, info = "SockGate/v1 s2c" ‖ u32 epoch, L = 32)   // 서버 송신 키
```

epoch 는 최초 인증 시 0, 재인증마다 +1. 키는 메모리에만 있고 전환·종료 시 지운다.

### 6.2 프레임 보호

- AES-256-GCM, tag 16 bytes, nonce = `u32(0) ‖ u64(sequence)`.
- AAD = `auth_length = 16` 인 헤더 48 bytes. `ENCRYPTED` 가 없으면 payload 도 AAD 에 포함(tag 만), 있으면 payload 를 암호화.
- 헤더(`session_id`, `sequence`, `request_id`, `flags` 의 `KEY_PHASE` 포함)를 변조하면 tag 검증이 실패한다.
- tag 실패는 `SG_PROTOCOL_ERROR` 이며, 첫 실패에서 채널이 poison 되어 수신 키가 파기된다.

### 6.3 Sequence

- 방향별 sequence: 핸드셰이크 프레임이 1 (HELLO), 2 (PROOF / AUTH_RESULT) 이고, 세션 프레임은 **3 부터** 정확히 +1.
- 수신 sequence 가 기대값보다 작으면 `SG_REPLAY_DETECTED`, 크면 `SG_PROTOCOL_ERROR`. 둘 다 연결 종료.
- `2^64 - 1` 에 도달하면 세션을 끝낸다 (`SG_SESSION_EXPIRED`).
- 헤더의 `session_id` 가 세션 값과 다르면 `SG_PROTOCOL_ERROR`.

### 6.4 Request ID

- 클라이언트 요청(`RESPONSE` 없음, `request_id != 0`)은 방향별로 엄격히 증가해야 한다. 아니면 `SG_REPLAY_DETECTED`.
- 클라이언트 응답(`RESPONSE`)의 `request_id` 는 서버가 발급한 최대 요청 ID 이하여야 한다. 아니면 `SG_PROTOCOL_ERROR`.
- `SG_Server_Send` 는 서버측 요청 ID 를 1, 2, … 로 발급한다. `SG_Server_SendEx(..., reply_to_request_id)` 는 `RESPONSE` 프레임을
  보내며, 값이 클라이언트에게서 받은 최대 요청 ID 보다 크면 아무것도 보내지 않고 `SG_INVALID_ARGUMENT` 를 돌려준다
  (피어가 거부하고 세션을 끊을 프레임을 만들지 않음).

### 6.5 KEY_PHASE (방향별 키 전환)

`KEY_PHASE` 비트는 프레임을 보호한 키의 `epoch & 1` 이다.

| 방향 | 서버 동작 |
|---|---|
| s2c (서버 송신) | REAUTH_RESULT(OK) 를 epoch e 로 보낸 **직후**부터 e+1 로 보낸다 |
| c2s (서버 수신) | REAUTH_RESULT 이후 e 와 e+1 키를 모두 보유한다. `KEY_PHASE` 로 키를 고르고, **첫 e+1 프레임을 받는 즉시 e 키를 지운다.** 이후 e 프레임은 `SG_PROTOCOL_ERROR` |

전환이 확인되기 전(e 키 보유 중)에는 새 REAUTH_REQUEST 를 거부한다. 따라서 한 세션에서 동시에 진행되는 재인증은 하나뿐이다.
