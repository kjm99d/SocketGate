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

### 미등록 installation 처리

ClientHello 단계에서 미등록 installation 을 즉시 거부하면 공격자가 installation_id 의 등록 여부를
알아낼 수 있다(열거 오라클). 따라서 서버는 형식이 올바르면 항상 challenge 를 발급하고, CLIENT_PROOF 단계에서
미등록·폐기·서명 오류를 모두 동일한 `REJECTED` 로 응답한다.
단, 서명 검증 비용을 아끼기 위해 미등록 installation 은 서명 검증을 생략한다(응답 형태는 동일).

## 2. Enrollment (auth_mode = ENROLL)

```text
Client                                                                     Server
  |--- CLIENT_HELLO(auth_mode=ENROLL, PUBLIC_KEY, ENROLLMENT_TOKEN) -------->|
  |<-- SERVER_HELLO -----------------------------------------------------------|
  |--- CLIENT_PROOF (hello 에 실린 PUBLIC_KEY 에 대응하는 private key 서명) --->|
  |                                    1. 서명 검증 (proof-of-possession)      |
  |                                    2. token 검증                           |
  |                                       - on_enroll 콜백이 있으면 콜백이 판단 |
  |                                       - 없으면 내장 HMAC token 검증         |
  |                                         (서명, 만료, 제품, 1회 사용)         |
  |                                    3. installation_id 미사용 확인          |
  |                                    4. registry 에 공개키 등록 (원자적 저장) |
  |                                    5. 이후 AUTHENTICATE 와 동일 (Authorizer)|
  |<-- AUTH_RESULT ------------------------------------------------------------|
```

Enrollment 성공 시 그 연결은 바로 인증된 세션이 된다.

### 내장 enrollment token 포맷

```text
u8       token_version (= 1)
bytes16  token_id                 (CSPRNG, 1회 사용 추적 키)
vec16    product_id
vec16    license_id               (없으면 길이 0)
u64      issued_at_ms
u64      expires_at_ms
bytes32  hmac                     HMAC-SHA256(server_token_key, 위 모든 필드)
```

- `server_token_key` 는 서버 설정으로 로드하거나 서버 시작 시 CSPRNG 로 생성한다(바이너리에 포함 금지).
- 사용된 `token_id` 는 registry 에 기록되어 재사용이 거부된다.
- 애플리케이션에는 base64url 문자열로 제공한다 (`SG_Server_IssueEnrollmentToken`).

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
  |  양쪽: 키 = HKDF(Exporter(ctx=THr), epoch e+1)                             |
  |=== 이후 프레임은 epoch e+1 키 ============================================|
```

- Refreshing 동안 DATA 는 계속 송수신 가능하다(epoch e 키).
- 재인증 실패 시 서버는 `REAUTH_RESULT(REJECTED)` 후 연결을 닫는다.
- 재인증 시점에 installation 폐기, 라이선스 만료가 반영된다.
- 클라이언트는 `session_lifetime` 의 80% 경과 시 자동 재인증을 시도할 수 있다(설정 `auto_refresh`).

## 4. 타임아웃

| 항목 | 기본값 | 범위 | 초과 시 |
|---|---|---|---|
| TCP connect | 10 s | 100 ms – 120 s | `SG_TIMEOUT` |
| Proxy 협상 | connect 타임아웃에 포함 | | `SG_TIMEOUT` / `SG_PROXY_ERROR` |
| TLS handshake | 10 s | | `SG_TIMEOUT` |
| 서버: 연결 수락 → AUTH_RESULT | 15 s | 1 – 120 s | 연결 종료 |
| challenge TTL | 30 s | 1 – 300 s | REJECTED |
| 세션 수명 | 1 h | 1 min – 7 d | CLOSE(SESSION_EXPIRED) |
| idle | 5 min | 0(off) – 1 d | CLOSE(IDLE_TIMEOUT) |

## 5. 실패 처리 표

| 단계 | 실패 | 서버 동작 | 클라이언트 결과 |
|---|---|---|---|
| TLS | 인증서 체인/hostname/유효기간 | - | `SG_CERTIFICATE_ERROR` |
| TLS | pin 불일치 | - | `SG_PINNING_ERROR` |
| TLS | 프로토콜/버전/암호 협상 | TLS alert | `SG_TLS_ERROR` |
| Hello | 형식 오류 | 즉시 종료 (AUTH_RESULT 없음) | `SG_PROTOCOL_ERROR` / `SG_NETWORK_ERROR` |
| Hello | 버전 불일치 | AUTH_RESULT(UNSUPPORTED_VERSION) | `SG_VERSION_MISMATCH` |
| Proof | 서명/미등록/폐기/만료 challenge | AUTH_RESULT(REJECTED) | `SG_SERVER_REJECTED` |
| Proof | 권한 거부 | AUTH_RESULT(REJECTED) | `SG_SERVER_REJECTED` |
| Proof | 서버 과부하 | AUTH_RESULT(RETRY_LATER) | `SG_SERVER_REJECTED` (재시도 가능) |
| Result | server proof 누락/오류 | - | `SG_INVALID_SIGNATURE` |
| 전체 | 타임아웃 | 종료 | `SG_TIMEOUT` |
