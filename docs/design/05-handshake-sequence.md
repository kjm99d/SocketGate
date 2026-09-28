# 05. Handshake Sequence

## 1. 전체 흐름

```text
Client                                   (Proxy, 선택)                           Server
  |                                                                                |
  |--- TCP connect (Direct) ---------------------------------------------------->  |
  |    또는 TCP → proxy, HTTP CONNECT / SOCKS4a / SOCKS5 협상 → 터널                |
  |                                                                                |
  |=== TLS 1.3 handshake (memory BIO) =============================================|
  |    Client: 체인 검증 + hostname + 유효기간 + 서명                              |
  |            + SPKI pinning (설정 시)                                            |
  |                                                                                |
  |  channel_binding_c = Exporter("EXPORTER-Channel-Binding")                      |
  |                                                  channel_binding_s = 동일 계산 |
  |                                                                                |
  |--- CLIENT_HELLO(seq=1, sid=0) ------------------------------------------------>|
  |    versions, client_version, client_nonce, installation_id,                    |
  |    key_alg, auth_mode, [product, version, license, features, integrity]        |
  |                                                     1. 버전 협상               |
  |                                                     2. 형식/상한 검증           |
  |                                                     3. installation 조회       |
  |                                                        (미등록이어도 즉시 거부  |
  |                                                         하지 않고 challenge 발급,|
  |                                                         결과는 Proof 단계에서  |
  |                                                         일괄 REJECTED)          |
  |                                                     4. session_id, challenge,  |
  |                                                        server_nonce 생성        |
  |<-- SERVER_HELLO(seq=1, sid=S) --------------------------------------------------|
  |    server_nonce, challenge, ttl, server_proof_alg                              |
  |                                                                                |
  |  TH1 = SHA256(label || ver || cb_c || CH || SH)                                |
  |  sig = Sign(installation_key, "…client-proof" || 0 || TH1)                     |
  |                                                                                |
  |--- CLIENT_PROOF(seq=2, sid=S) ------------------------------------------------>|
  |                                                     5. challenge 만료/재사용 확인|
  |                                                     6. TH1' = SHA256(… cb_s …) |
  |                                                     7. 공개키로 서명 검증        |
  |                                                     8. installation 상태 확인  |
  |                                                     9. (ENROLL) token 검증/등록 |
  |                                                    10. Authorizer: 제품/라이선스|
  |                                                        /기능/무결성/애플리케이션|
  |                                                    11. 세션 키 유도, Active     |
  |<-- AUTH_RESULT(seq=2, sid=S) ---------------------------------------------------|
  |    OK, policy, granted_features, lifetime, [server proof sig]                  |
  |                                                                                |
  |  (server_proof_keys 설정 시) 서버 서명 검증                                    |
  |  세션 키 유도 → Authenticated → Active                                         |
  |                                                                                |
  |=== DATA / PING / PONG (seq 3.. / 3.., GCM tag) ================================|
```

### 서버 인증서 검증과 pinning 규칙

1. OpenSSL 체인 검증(신뢰 앵커, 서명, 유효기간) + hostname/IP 검증(`SSL_set1_host`, 부분 wildcard 금지)이 **먼저** 성공해야 한다.
2. pin 값은 **DER SubjectPublicKeyInfo 의 SHA-256** 이다.
3. pin 비교 대상은 **검증된 체인**(`SSL_get0_verified_chain`)의 인증서뿐이다. 상대가 보낸 원본 체인
   (`SSL_get_peer_cert_chain`) 과 비교하지 않는다 — 공격자가 위조 leaf 뒤에 진짜 인증서를 덧붙여 pin 을 통과시키는
   공격(CVE-2016-2402 유형)을 막기 위함이다.
4. 검증된 체인의 어느 인증서라도 pin 과 일치하면 통과, 아니면 `SG_PINNING_ERROR`.
5. pinning 해제는 **명시적 플래그**로만 가능하다. 시스템 trust store 를 신뢰하도록 설정했는데 pin 도, 서버 proof key 도 없고
   `SG_SERVER_FLAG_ALLOW_NO_PINNING` 도 없으면 `SG_Client_Connect` 는 `SG_INVALID_ARGUMENT` 를 반환한다.
   애플리케이션이 제공한 사설 CA 만 신뢰하는 경우에는 pin 이 선택 사항이다.

### 미등록 installation 처리

ClientHello 단계에서 미등록 installation 을 즉시 거부하면 공격자가 installation_id 의 등록 여부를
알아낼 수 있다(열거 오라클). 따라서 서버는 형식이 올바르면 항상 challenge 를 발급하고, CLIENT_PROOF 단계에서
미등록·폐기·서명 오류를 모두 동일한 `REJECTED` 로 응답한다.
미등록 installation 에 대해서도 서버 시작 시 생성한 **더미 공개키로 서명 검증을 수행**하여 처리 시간을 맞춘다
(타이밍으로 등록 여부를 구분하지 못하게).

### CLIENT_PROOF 검증 순서 (AUTHENTICATE)

1. challenge 소비 (이미 소비되었거나 TTL 초과면 이후 단계와 무관하게 결과는 REJECTED)
2. registry 조회 → 레코드 없음/폐기 시 더미 키로 검증 수행 후 REJECTED
3. `signature_algorithm` == 레코드의 알고리즘 확인
4. 서버 쪽 channel binding 으로 TH1 계산 → 서명 검증
5. Authorizer (제품, 라이선스, 기능, 무결성, 애플리케이션 콜백)

## 2. Enrollment (auth_mode = ENROLL)

### 핵심 원칙: token 비밀은 전송하지 않는다

enrollment token 을 bearer 비밀로 전송하면, pinning 없이 사용자 설치 CA 로 TLS 를 종단한 MITM 이 token 을 읽어
**자기 키로** 자기 TLS 세션에서 enroll 할 수 있다(채널 바인딩은 공격자 자신의 세션이므로 막지 못함).
따라서 token 은 공개 부분과 비밀 부분으로 나뉘고, 비밀 부분 `K_tok` 는 채널 바인딩이 포함된 TH1 에 대한 MAC 으로만 사용된다.

```text
claims      = u8 token_version(=1) ‖ vec16 product_id ‖ vec16 license_id ‖ u64 issued_at_ms ‖ u64 expires_at_ms
token_pub   = bytes16 token_id ‖ claims                                     (CLIENT_HELLO TLV 6 로 전송)
K_tok       = HMAC-SHA256(server_token_key, "SockGate/v1/enroll-key" ‖ 0x00 ‖ token_pub)   (전송 금지)
token       = base64url( token_pub ‖ K_tok )                                (애플리케이션에 전달되는 문자열)
enroll_mac  = HMAC-SHA256(K_tok, "SockGate/v1/enroll-proof" ‖ 0x00 ‖ TH1)   (CLIENT_PROOF TLV 1)
```

MITM 은 `token_pub` 만 볼 수 있고 `K_tok` 를 모르므로 자기 채널의 TH1 에 대한 `enroll_mac` 을 만들 수 없다.
피해자의 `enroll_mac` 을 중계해도 서버 쪽 TH1(서버 측 채널 바인딩)과 맞지 않는다.

```text
Client                                                                     Server
  |--- CLIENT_HELLO(auth_mode=ENROLL, PUBLIC_KEY, ENROLLMENT_TOKEN_ID) ----->|
  |<-- SERVER_HELLO -----------------------------------------------------------|
  |--- CLIENT_PROOF(signature, ENROLLMENT_PROOF) ----------------------------->|
  |                              1. challenge 소비                            |
  |                              2. token_pub 파싱, K_tok 재계산               |
  |                                 (on_enroll 콜백이 있으면 콜백이 K_tok 제공) |
  |                              3. enroll_mac 검증 (저렴한 검사 먼저)          |
  |                              4. claims 검증: 만료, 제품, hello TLV 일치     |
  |                              5. installation_id == H(PUBLIC_KEY) 확인      |
  |                              6. 서명 검증 (proof-of-possession)            |
  |                              7. [원자적] token_id 소비 + installation 삽입 |
  |                                 (둘 중 하나라도 이미 존재/폐기면 REJECTED,  |
  |                                  token 은 모든 검사 통과 시에만 소비)       |
  |                                 → 저장 완료 후에만 다음 단계               |
  |                              8. Authorizer (AUTHENTICATE 와 동일)          |
  |<-- AUTH_RESULT ------------------------------------------------------------|
```

- Enrollment 성공 시 그 연결은 바로 인증된 세션이 된다.
- 폐기된 installation_id 는 재등록할 수 없다 (ID 가 공개키에서 유도되므로 새 키 = 새 ID).
- `server_token_key` 는 서버 설정으로 로드하거나 `SG_Server_Create` 시 CSPRNG 로 생성한다(바이너리에 포함 금지).
- 내장 token 검증과 1회 사용 추적은 **단일 서버 노드**(레지스트리) 기준이다. 여러 노드가 같은 `server_token_key` 를 공유하면
  노드마다 1회씩 사용될 수 있으므로, 다중 노드 환경에서는 `on_enroll` 콜백으로 중앙 저장소에서 원자적으로 소비해야 한다.
  `on_enroll` 은 검증 전(키 조회 단계)에 호출되므로, 여기서 소비하면 token 의 공개 부분을 본 누구나 token 을 소진시킬 수
  있다 (서비스 거부일 뿐 등록 우회는 아님). 이런 token 은 TTL 을 짧게 준다.
- 서버의 1회 사용 기록과 등록은 증명·키·서명 검증 후, Authorizer 호출 **전**에 원자적으로 저장된다. Authorizer 가 거부한
  enrollment 도 token 은 소진된다.
- 권장: enrollment 시에도 사설 CA 또는 SPKI pinning 을 사용한다 (token 탈취는 막히지만, 가짜 서버가 enrollment 를
  가로채 클라이언트를 속이는 것은 서버 인증으로만 막을 수 있다).

## 3. 재인증 / Rekey (Refreshing)

```text
Client (Active)                                                            Server (Active)
  |--- REAUTH_REQUEST(client_nonce) [epoch e] ------------------------------->|
  |                                                         state=Refreshing |
  |<-- REAUTH_CHALLENGE(server_nonce, challenge, ttl) [epoch e] --------------|
  |  THr = SHA256("…reauth" || sid || e || cb || prev_TH || RQ || CHL)         |
  |--- REAUTH_PROOF(sig) [epoch e] ------------------------------------------->|
  |                                    서명 검증, installation 상태, 재인가     |
  |<-- REAUTH_RESULT(OK, lifetime, e+1) [epoch e] ----------------------------|
  |                          서버: 송신(s2c) 키를 즉시 e+1 로 전환              |
  |                                수신(c2s)은 e, e+1 둘 다 보유 (KEY_PHASE)   |
  |  클라이언트: 수신 키 e+1, 송신 lock 안에서 송신 키 e+1 로 전환             |
  |--- DATA [epoch e+1, KEY_PHASE=1] ----------------------------------------->|
  |                          서버: 첫 e+1 프레임 수신 → e 키 cleanse           |
```

- Refreshing 동안 DATA/PING/PONG 은 계속 송수신 가능하다(epoch e 키).
- 이미 전송 중인 클라이언트 DATA(epoch e)는 서버가 c2s 전환을 확인하기 전까지 정상 처리된다 (04 §7.3).
- 재인증 실패 시 서버는 `REAUTH_RESULT(REJECTED)` 후 연결을 닫는다.
- 재인증 시점에 installation 폐기, 라이선스 만료가 다시 확인된다. 단, 폐기/라이선스 폐기는 재인증을 기다리지 않고
  `SG_Server_RevokeClient` / `SG_Server_RevokeLicense` 호출 즉시 해당 세션을 종료한다 (07 §4).
- 서버는 세션당 재인증 빈도를 제한한다 (최소 간격 10 s).
- 클라이언트는 `session_lifetime` 의 80% 경과 시 자동 재인증을 시도할 수 있다(`SG_ClientConfig.flags` 의 `SG_CLIENT_FLAG_AUTO_REFRESH`).

## 4. 타임아웃

| 항목 | 기본값 | 범위 | 초과 시 |
|---|---|---|---|
| 클라이언트 Connect 전체 (`connect_timeout_ms`: 시스템 proxy 조회 + 이름 해석 + TCP + proxy 협상 + TLS) | 10 s | 100 ms – 120 s | `SG_TIMEOUT` |
| Proxy 협상 | connect 타임아웃에 포함 | | `SG_TIMEOUT` / `SG_PROXY_ERROR` |
| TLS handshake | connect 타임아웃의 남은 시간 | | `SG_TIMEOUT` |
| 클라이언트 Authenticate / Enroll / Refresh (`io_timeout_ms`, 0 = 무한) | 30 s | | `SG_TIMEOUT` |
| 서버: 연결 수락 → AUTH_RESULT | 15 s | 1 – 120 s | 연결 종료 |
| challenge TTL | 30 s | 1 – 300 s | REJECTED |
| 세션 수명 | 1 h | 1 min – 7 d | CLOSE(SESSION_EXPIRED) |
| idle | 5 min | 0(off) – 1 d | CLOSE(IDLE_TIMEOUT) |

(v1 미구현: 범위 검사 — 클라이언트는 범위를 검사하지 않는다 (`connect_timeout_ms` 0 = 기본값). 서버는 세션 수명 ≤ 7 d
(초과 설정은 `SG_INVALID_ARGUMENT`, `on_authorize` 가 준 수명은 7 d 로 자름)와 `max_payload_size` ≤ 16 MiB 만 검사하고,
나머지는 0 을 기본값(idle 은 off)으로 바꿀 뿐이다.)

- 이름 해석과 시스템 proxy 조회에 쓴 시간도 connect 예산에 포함되고, 예산이 다 되면 다음 단계를 시작하지 않는다.
  단, 진행 중인 resolver 호출(`getaddrinfo`) 하나는 중단할 수 없다 (13 §7).
- 다른 스레드의 `SG_Client_Disconnect` 가 진행 중인 Connect 를 중단하면 어느 단계에서든 Connect 는 `SG_CLOSED` 를
  반환한다 (`event=connect_aborted`). 이미 발생한 인증서/pinning 실패는 그대로 `SG_CERTIFICATE_ERROR` / `SG_PINNING_ERROR`.

## 5. 실패 처리 표

| 단계 | 실패 | 서버 동작 | 클라이언트 결과 |
|---|---|---|---|
| TLS | 인증서 체인/hostname/유효기간 | - | `SG_CERTIFICATE_ERROR` |
| TLS | pin 불일치 | - | `SG_PINNING_ERROR` |
| TLS | 프로토콜/버전/암호 협상 | TLS alert | `SG_TLS_ERROR` |
| Hello | 형식 오류 | 즉시 종료 (AUTH_RESULT 없음) | `SG_PROTOCOL_ERROR` / `SG_NETWORK_ERROR` |
| Hello | 버전 불일치 | SERVER_HELLO 대신 AUTH_RESULT(UNSUPPORTED_VERSION, sid=0) | `SG_VERSION_MISMATCH` |
| TLS | TLS 1.2 협상 + EMS 미지원 | 종료 | `SG_TLS_ERROR` |
| Proof | 서명/미등록/폐기/만료 challenge | AUTH_RESULT(REJECTED) | `SG_SERVER_REJECTED` |
| Proof | 권한 거부 | AUTH_RESULT(REJECTED) | `SG_SERVER_REJECTED` |
| Proof | 서버 과부하 | AUTH_RESULT(RETRY_LATER) (v1 미구현: 서버는 보내지 않고, `max_connections` / `max_unauthenticated` 초과 연결을 accept 직후 닫는다) | `SG_SERVER_REJECTED` (재시도 가능. 클라이언트는 REJECTED 와 RETRY_LATER 를 구분하지 않음). accept 직후 닫힌 연결은 `SG_Client_Connect` 가 `SG_TLS_ERROR` / `SG_NETWORK_ERROR` |
| Result | server proof 누락/오류 | - | `SG_INVALID_SIGNATURE` |
| 전체 | 타임아웃 | 종료 | `SG_TIMEOUT` |
