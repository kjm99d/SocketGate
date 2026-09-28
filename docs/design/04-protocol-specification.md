# 04. Protocol Specification (SockGate Wire Protocol v1)

## 1. 일반 규칙

- 전송: TLS 1.3 (옵션으로 TLS 1.2) 레코드 위의 바이트 스트림. **평문 TCP 로는 절대 전송하지 않는다.**
- 바이트 순서: 모든 정수는 **Network Byte Order (Big Endian)**.
- 직렬화 구현은 `SockGate_Common/src/serialization` 한 벌만 존재하며 Client/Server 가 공유한다.
- JSON 등 텍스트 포맷은 wire protocol 로 사용하지 않는다.
- 알 수 없는 enum 값, 예약 비트, 예약 필드 ≠ 0 은 모두 **프로토콜 오류**이다 (확장은 TLV 로만).
- 모든 길이 필드는 상한이 정의되어 있으며 상한 초과는 헤더 단계에서 거부한다.

## 2. Frame

### 2.1 Frame Header (고정 48 bytes)

| Offset | Size | Field | 설명 |
|---:|---:|---|---|
| 0 | 4 | `magic` | `0x53 0x47 0x41 0x54` ("SGAT") |
| 4 | 1 | `version` | wire version. v1 = `0x01` |
| 5 | 1 | `type` | Message Type (§3) |
| 6 | 2 | `flags` | §2.2 |
| 8 | 16 | `session_id` | 서버가 ServerHello 에서 할당. 할당 전에는 전부 0 |
| 24 | 8 | `sequence` | 방향별 프레임 번호. 첫 프레임 = 1, 이후 정확히 +1 |
| 32 | 8 | `request_id` | 0 = 없음. 요청은 방향별 단조 증가, 응답은 상대 요청 ID |
| 40 | 4 | `payload_length` | payload 바이트 수 |
| 44 | 2 | `auth_length` | Authentication Data 길이. 0 또는 16 |
| 46 | 2 | `reserved` | 반드시 0 |

그 뒤에 `payload[payload_length]`, `auth_data[auth_length]` 가 이어진다.

```text
+--------+---------+------+-------+------------+----------+------------+-------------+-------------+----------+
| magic  | version | type | flags | session_id | sequence | request_id | payload_len | auth_length | reserved |
|  4     |   1     |  1   |   2   |    16      |    8     |     8      |      4      |      2      |    2     |
+--------+---------+------+-------+------------+----------+------------+-------------+-------------+----------+
| payload (payload_len) ...                                                                                   |
+-------------------------------------------------------------------------------------------------------------+
| auth_data (auth_length) : AES-256-GCM tag                                                                   |
+-------------------------------------------------------------------------------------------------------------+
```

### 2.2 Flags

| Bit | 이름 | 의미 |
|---:|---|---|
| 0 | `ENCRYPTED` | payload 가 application-layer AEAD 로 암호화됨. 인증 후 프레임에서만 허용 |
| 1 | `RESPONSE` | `request_id` 가 상대방 요청에 대한 응답 ID |
| 2 | `KEY_PHASE` | 이 프레임을 보호한 키의 `epoch & 1`. 인증 후 프레임에서만 의미가 있고 AAD(헤더)에 포함된다 (§7.3) |
| 3–15 | reserved | 반드시 0 |

인증 전 프레임은 `flags == 0` 이어야 한다.

### 2.3 길이 상한

| 상수 | 값 | 적용 |
|---|---|---|
| `SG_FRAME_HEADER_SIZE` | 48 | |
| `SG_MAX_HANDSHAKE_PAYLOAD` | 4096 | **인증 완료 전의 모든 프레임**(type 무관), REAUTH_*, PING/PONG/CLOSE |
| `SG_DEFAULT_MAX_PAYLOAD` | 1 MiB | DATA (설정 가능) |
| `SG_ABSOLUTE_MAX_PAYLOAD` | 16 MiB | 설정으로도 넘을 수 없는 컴파일 상수 |
| `SG_AUTH_TAG_SIZE` | 16 | |

총 프레임 크기 = `48 + payload_length + auth_length`. 덧셈 전 `payload_length <= max` 를 먼저 검사하므로
32bit/64bit 모두 overflow 가 발생하지 않는다 (디코더는 `size_t` 가 32bit 인 환경도 가정한다).

### 2.4 헤더 검증 순서 (FrameDecoder)

1. 버퍼에 48 bytes 미만 → 더 기다린다 (Truncated). 핸드셰이크 타임아웃이 상한을 보장한다.
2. `magic` 불일치 → `SG_PROTOCOL_ERROR`
3. `version != 1` → `SG_VERSION_MISMATCH` (연결 종료)
4. `type` 미정의 → `SG_PROTOCOL_ERROR`
5. `flags` 에 예약 비트 → `SG_PROTOCOL_ERROR`
6. `reserved != 0` → `SG_PROTOCOL_ERROR`
7. `auth_length ∉ {0, 16}` → `SG_PROTOCOL_ERROR`
8. **헤더 단계 상태 검증** (본문을 버퍼링하기 전에): 현재 상태·방향에서 허용되는 `type` 인지, `auth_length` 요구 여부
9. `payload_length > 상한` → `SG_PROTOCOL_ERROR`. 상한은 **연결 상태**로 결정한다:
   인증 완료 전에는 type 과 무관하게 `SG_MAX_HANDSHAKE_PAYLOAD`, 인증 후 DATA 는 `max_payload`, 그 외 제어 메시지는 `SG_MAX_HANDSHAKE_PAYLOAD`
10. 전체 프레임이 모일 때까지 대기
11. 상태 머신 검증: session_id, sequence, request_id, `KEY_PHASE`
12. auth tag 검증 (인증 후 프레임)
13. payload 디코드 (메시지별 엄격 파서)

## 3. Message Types

| 값 | 이름 | 방향 | 허용 상태 | auth_length |
|---:|---|---|---|---|
| 0x01 | `CLIENT_HELLO` | C→S | Server: AwaitHello | 0 |
| 0x02 | `SERVER_HELLO` | S→C | Client: AwaitServerHello | 0 |
| 0x03 | `CLIENT_PROOF` | C→S | Server: AwaitProof | 0 |
| 0x04 | `AUTH_RESULT` | S→C | Client: AwaitResult (또는 AwaitServerHello — `UNSUPPORTED_VERSION` 전용, §10) | 0 |
| 0x10 | `DATA` | 양방향 | Active, Refreshing | 16 |
| 0x11 | `PING` | 양방향 | Active, Refreshing | 16 |
| 0x12 | `PONG` | 양방향 | Active, Refreshing | 16 |
| 0x20 | `REAUTH_REQUEST` | C→S | Active | 16 |
| 0x21 | `REAUTH_CHALLENGE` | S→C | Refreshing | 16 |
| 0x22 | `REAUTH_PROOF` | C→S | Refreshing | 16 |
| 0x23 | `REAUTH_RESULT` | S→C | Refreshing | 16 |
| 0x30 | `CLOSE` | 양방향 | 모든 상태 | 인증 전 0, 인증 후 16 |

## 4. 공통 인코딩

- `u8/u16/u32/u64`: big endian 부호 없는 정수
- `bytes[N]`: 고정 길이
- `vec16<T>`: `u16 length` + length bytes. 필드별 최대 길이 존재
- **TLV 확장 영역**: 메시지 고정부 뒤에 `u16 total_length` 후 `{u16 type, u16 length, value}` 반복
  - 같은 type 중복 → 오류
  - TLV 수 최대 16
  - `total_length` 와 개별 길이 합이 정확히 일치해야 함
  - 메시지별로 알 수 없는 TLV type 은 **무시**(forward compatibility), 단 길이 검증은 수행
  - payload 끝에 남는 바이트가 있으면 오류 (trailing data 금지)

## 5. 핸드셰이크 메시지

### 5.1 CLIENT_HELLO (0x01)

```text
u16      protocol_version_min      (= 1)
u16      protocol_version_max      (= 1)
u16      client_version_major
u16      client_version_minor
u16      client_version_patch
bytes32  client_nonce              (CSPRNG)
bytes16  installation_id
u8       key_algorithm             (1 = ECDSA_P256_SHA256)
u8       auth_mode                 (1 = AUTHENTICATE, 2 = ENROLL)
TLV      extensions
```

| TLV type | 이름 | 값 | 제약 |
|---:|---|---|---|
| 1 | `PRODUCT_ID` | UTF-8 (제어문자 금지) | 1..64 |
| 2 | `PRODUCT_VERSION` | UTF-8 | 1..32 |
| 3 | `LICENSE_ID` | UTF-8 | 1..128 |
| 4 | `REQUESTED_FEATURES` | u64 bitmask | 8 |
| 5 | `INTEGRITY_REPORT` | §5.5 | ≤ 512 |
| 6 | `ENROLLMENT_TOKEN_ID` | token 의 **공개 부분** (`token_id ‖ claims`, 05 §2) — token 비밀키는 절대 전송하지 않음 | 1..512, ENROLL 모드에서 필수 |
| 7 | `PUBLIC_KEY` | SEC1 uncompressed P-256 point (0x04‖X‖Y) | 65, ENROLL 모드에서 필수 |

- AUTHENTICATE 모드에서 `ENROLLMENT_TOKEN_ID`, `PUBLIC_KEY` 가 있으면 오류.
- `installation_id` 는 공개키에서 유도된다: `installation_id = SHA-256("SockGate/v1/iid" ‖ PUBLIC_KEY)[0..16)`.
  ENROLL 모드에서 서버는 이 관계를 검증한다 (다른 installation 의 ID 선점 방지).
- ENROLL 모드의 `PRODUCT_ID` / `LICENSE_ID` TLV 는 없거나 token claims 와 정확히 같아야 한다. 권한 판단에는 token claims 가 사용된다.
- 프레임 헤더의 `version` 은 wire 레이아웃 버전이며 CLIENT_HELLO 는 항상 `version = 1` 로 전송한다.
  프로토콜 기능 버전은 CLIENT_HELLO 내부의 `protocol_version_min/max` 로 협상한다.

### 5.2 SERVER_HELLO (0x02)

헤더의 `session_id` 에 새 세션 ID(16 bytes CSPRNG)가 들어간다.

```text
u16      selected_protocol_version
bytes32  server_nonce
bytes32  challenge
u32      challenge_ttl_ms
u8       server_proof_algorithm    (0 = 없음, 1 = ECDSA_P256_SHA256)
TLV      extensions                (v1 정의 없음)
```

### 5.3 CLIENT_PROOF (0x03)

```text
u8       signature_algorithm       (1 = ECDSA_P256_SHA256)
vec16    signature                 (P1363 r‖s, 정확히 64 bytes)
TLV      extensions
```

| TLV type | 이름 | 값 | 제약 |
|---:|---|---|---|
| 1 | `ENROLLMENT_PROOF` | `HMAC-SHA256(K_tok, "SockGate/v1/enroll-proof" ‖ 0x00 ‖ TH1)` | 32, ENROLL 모드에서 필수, AUTHENTICATE 모드에서 금지 |

서버는 **registry 에 저장된 알고리즘**(v1: ECDSA P-256)으로만 검증한다. `signature_algorithm` 이 그와 다르면 거부한다.

### 5.4 AUTH_RESULT (0x04)

```text
u8       result                    (0 OK, 1 REJECTED, 2 RETRY_LATER, 3 UNSUPPORTED_VERSION)
u8       session_policy            (0 NONE, 1 NORMAL, 2 RESTRICTED)
u64      granted_features
u32      session_lifetime_ms
u64      license_expires_at_ms     (Unix epoch ms, 0 = 해당 없음)
u8       server_proof_algorithm
vec16    server_signature          (algorithm=0 이면 길이 0, 1 이면 64)
```

`result != OK` 이면 나머지 필드는 0 이어야 하며 서버는 전송 직후 연결을 닫는다.
네트워크로는 거부 사유의 세부 내용을 보내지 않는다.

### 5.5 INTEGRITY_REPORT (TLV 5)

```text
u8       report_version            (= 1)
u8       platform                  (1 = Windows, 2 = Linux, 3 = macOS)
u32      observation_flags         (bit 정의는 07/10/11 문서 및 sockgate/types.h)
bytes32  executable_sha256
bytes32  library_sha256
vec16    build_id                  (≤ 64)
```

## 6. Transcript 와 서명

### 6.1 채널 바인딩

```text
channel_binding = TLS-Exporter(label = "EXPORTER-Channel-Binding", no context, length = 32)   // RFC 9266
                = SSL_export_keying_material(ssl, out, 32, "EXPORTER-Channel-Binding", 24, NULL, 0, use_context = 0)
```

클라이언트와 서버는 각자 **자기 쪽 TLS 연결**에서 값을 계산한다.
중간자가 TLS 를 두 번 종단하면 양쪽 값이 달라지므로 클라이언트 서명이 서버에서 검증되지 않는다.

TLS 1.2 (호환 옵션) 에서는 RFC 9266 에 따라 **Extended Master Secret 이 협상된 경우에만** exporter 를 채널 바인딩으로
사용할 수 있다. 양쪽 모두 TLS 1.2 로 협상되었는데 `SSL_get_extms_support() != 1` 이면 즉시 연결을 끊는다 (`SG_TLS_ERROR`).

### 6.2 Transcript Hash

```text
TH1 = SHA-256(
    "SockGate/v1/transcript"      (ASCII, NUL 미포함)
 || u16(selected_protocol_version)
 || channel_binding              (32)
 || u32(len(ClientHello frame)) || ClientHello frame  (헤더 포함 전체 바이트)
 || u32(len(ServerHello frame)) || ServerHello frame
)
```

`challenge`, `client_nonce`, `server_nonce`, `installation_id`, `session_id` 는 모두 위 프레임 바이트에 포함된다.

### 6.3 Client Proof 서명

```text
client_signed_data = "SockGate/v1/client-proof" || 0x00 || TH1
signature = ECDSA-P256-SHA256(installation_private_key, client_signed_data)   // P1363 64 bytes
```

### 6.4 Server Proof 서명 (선택)

```text
R   = AUTH_RESULT 프레임의 헤더(48) ‖ payload 중 server_proof_algorithm 필드까지 (마지막 vec16 server_signature 제외)
TH2 = SHA-256( "SockGate/v1/server-transcript" || TH1
               || u32(len(ClientProof frame)) || ClientProof frame
               || u32(len(R)) || R )
server_signed_data = "SockGate/v1/server-proof" || 0x00 || TH2
```

- 헤더의 `payload_length` 는 서명 필드를 포함한 최종 길이이므로 R 은 결정적이다.
- SERVER_HELLO 와 AUTH_RESULT 의 `server_proof_algorithm` 은 같아야 한다.
- 클라이언트에 `server_proof_keys` 가 설정되어 있으면 서버가 무엇을 광고하든 서명을 **요구**한다.
  서명이 없거나 검증 실패 시 `SG_INVALID_SIGNATURE` 로 연결을 끊는다 (알고리즘 필드로 인한 downgrade 불가).

## 7. 세션 키와 프레임 보호

### 7.1 키 유도

```text
km   = TLS-Exporter(label = "EXPORTER-SockGate-v1-keys", context = TH1, length = 32)
k_cs = HKDF-SHA256(ikm = km, salt = session_id, info = "SockGate/v1 c2s" || u32(epoch), L = 32)
k_sc = HKDF-SHA256(ikm = km, salt = session_id, info = "SockGate/v1 s2c" || u32(epoch), L = 32)
```

- `km` 은 `use_context = 1` 로 호출한다 (`SSL_export_keying_material(..., TH1, 32, 1)`).
- `epoch` 는 최초 인증 시 0, 재인증 성공마다 +1. 재인증 시 `TH1` 자리에 재인증 transcript 해시 `THr` 를 사용한다.
- 키는 메모리에만 존재하며 세션 종료/rekey 시 `OPENSSL_cleanse` 로 지운다.
- 재인증 시 TLS 1.3 이면 `SSL_key_update(SSL_KEY_UPDATE_REQUESTED)` 도 함께 수행하여 TLS 트래픽 키도 교체한다.

> 이 채널 보호 키는 TLS exporter 에서 유도되므로 **TLS 를 종단한 MITM 에 대한 추가 방어가 아니다.**
> 목적은 (1) 프레임을 세션 ID·sequence·방향·epoch 에 암호학적으로 결속, (2) TLS 계층 구현 결함에 대한 심층 방어,
> (3) 선택적 애플리케이션 계층 암호화이다. MITM 방어는 인증서 검증·pinning·채널 바인딩·서버 proof 가 담당한다.

### 7.2 AEAD

- 알고리즘: AES-256-GCM, tag 16 bytes.
- nonce (12 bytes) = `u32(0)` || `u64(sequence)` — 키는 방향·epoch 별로 다르고 sequence 는 방향 내에서 반복되지 않으므로 nonce 재사용이 없다.
- 헤더는 `auth_length = 16` 으로 채운 상태의 48 bytes 를 AAD 로 사용한다.
- `ENCRYPTED` 미설정: `AAD = header || payload`, 평문 없음 → tag 만 생성 (GMAC)
- `ENCRYPTED` 설정: `AAD = header`, payload 를 암호화
- 서버 옵션 `require_app_encryption` 이 켜져 있으면 `ENCRYPTED` 없는 DATA 는 거부

### 7.3 방향별 키 전환 (KEY_PHASE)

재인증 중에도 DATA 가 계속 흐르므로 두 방향의 키를 **동시에** 바꾸지 않는다. 각 방향의 송신자가 자기 방향의 전환 시점을 정한다
(TLS 1.3 KeyUpdate 와 같은 모델).

| 방향 | 전환 시점 | 수신측 규칙 |
|---|---|---|
| s2c | 서버가 `REAUTH_RESULT(OK)` 를 **epoch e 키로 보낸 직후**부터 e+1 | 스트림 순서가 보장되므로 클라이언트는 REAUTH_RESULT 처리 직후부터 e+1 만 허용 |
| c2s | 클라이언트가 `REAUTH_RESULT(OK)` 를 처리한 시점(송신 lock 안에서)부터 e+1 | 서버는 REAUTH_RESULT 송신 후 e 와 e+1 두 키를 보유. `KEY_PHASE` 로 키를 선택. **처음으로 e+1 프레임을 받는 즉시 e 키를 cleanse**, 이후 e 프레임은 치명적 오류 |

- `KEY_PHASE` 는 AAD(헤더)에 포함되므로 변조하면 tag 검증이 실패한다.
- 한 번에 하나의 재인증만 진행한다. 서버는 c2s 전환이 확인되기 전(구 키 보유 중)에는 새 REAUTH_REQUEST 를 거부한다.

## 8. 인증 후 메시지

| 메시지 | payload |
|---|---|
| DATA | 애플리케이션 바이트 (0..max_payload) |
| PING / PONG | `u64 opaque` (PONG 은 PING 값을 그대로 반환) |
| REAUTH_REQUEST | `bytes32 client_nonce` |
| REAUTH_CHALLENGE | `bytes32 server_nonce`, `bytes32 challenge`, `u32 challenge_ttl_ms` |
| REAUTH_PROOF | `u8 signature_algorithm`, `vec16 signature` |
| REAUTH_RESULT | `u8 result`, `u32 session_lifetime_ms`, `u32 new_epoch` |
| CLOSE | `u16 reason` (0 NORMAL, 1 PROTOCOL_ERROR, 2 AUTH_FAILED, 3 SESSION_EXPIRED, 4 SERVER_SHUTDOWN, 5 IDLE_TIMEOUT, 6 LIMIT_EXCEEDED) |

재인증 transcript:

```text
F(x) = x 프레임의 헤더(48, auth_length=16 상태) ‖ 평문 payload       (tag 제외, ENCRYPTED 여부와 무관하게 평문)
THr = SHA-256( "SockGate/v1/reauth" || session_id || u32(epoch) || channel_binding || prev_TH
               || u32(len(F(REAUTH_REQUEST))) || F(REAUTH_REQUEST)
               || u32(len(F(REAUTH_CHALLENGE))) || F(REAUTH_CHALLENGE) )
signed = "SockGate/v1/reauth-proof" || 0x00 || THr
```

- `prev_TH` 는 직전 인증의 transcript 해시(TH1 또는 이전 THr).
- REAUTH_RESULT(OK) 는 epoch e 키로 보호되며, 키 전환은 §7.3 규칙을 따른다.
- 클라이언트는 `new_epoch == epoch + 1` 을 확인한다.
- 서버는 세션당 재인증 빈도를 제한한다 (기본: 직전 재인증 후 10 s 이내 요청 거부 → CLOSE(PROTOCOL_ERROR)).

## 9. Sequence / Request ID 규칙

| 규칙 | 위반 시 |
|---|---|
| 방향별 첫 프레임 `sequence = 1`, 이후 정확히 이전 + 1 | 이전 값 이하: `SG_REPLAY_DETECTED`, 건너뜀: `SG_PROTOCOL_ERROR` |
| `sequence == 2^64-1` 도달 | 세션 종료 (실사용상 도달 불가) |
| 요청(`RESPONSE` 미설정, `request_id != 0`)의 `request_id` 는 방향별 단조 증가 | `SG_REPLAY_DETECTED` (Duplicate Request) |
| 응답(`RESPONSE` 설정)은 `request_id != 0` 이며 수신측이 보낸 최대 요청 ID 이하 | `SG_PROTOCOL_ERROR` |
| 인증 전 프레임 session_id: ClientHello 는 0, 이후 모두 할당된 값 | `SG_PROTOCOL_ERROR` |

프로토콜 오류, tag 오류, sequence 오류는 모두 **연결 종료**로 처리한다(오류 후 계속 진행하지 않는다).

## 10. 버전 협상

- 클라이언트는 `[min, max]` 범위를 보낸다. 서버는 지원하는 최고 버전을 고른다.
- 클라이언트는 `selected_protocol_version ∈ [min, max]` 를 확인한다.
- 교집합이 없으면 서버는 SERVER_HELLO 대신 `AUTH_RESULT(UNSUPPORTED_VERSION)` 을 보내고 종료한다.
  이 프레임은 `session_id = 0`, `sequence = 1`, 나머지 필드 0 이다. 클라이언트는 AwaitServerHello 상태에서
  이 형태의 AUTH_RESULT 만 허용하며 `SG_VERSION_MISMATCH` 를 반환한다.
- 프레임 헤더 `version` 은 wire 레이아웃 버전이며 v1 에서 항상 1. 레이아웃이 바뀌는 경우에만 증가한다.
