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
| 2–15 | reserved | 반드시 0 |

### 2.3 길이 상한

| 상수 | 값 | 적용 |
|---|---|---|
| `SG_FRAME_HEADER_SIZE` | 48 | |
| `SG_MAX_HANDSHAKE_PAYLOAD` | 4096 | CLIENT_HELLO ~ AUTH_RESULT, REAUTH_* |
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
8. `payload_length > type 별 상한` → `SG_PROTOCOL_ERROR` (본문을 읽기 전에 거부)
9. 전체 프레임이 모일 때까지 대기
10. 상태 머신 검증: 방향, 상태에서 허용되는 type, session_id, sequence, request_id, auth_length 요구 여부
11. auth tag 검증 (인증 후 프레임)
12. payload 디코드 (메시지별 엄격 파서)

## 3. Message Types

| 값 | 이름 | 방향 | 허용 상태 | auth_length |
|---:|---|---|---|---|
| 0x01 | `CLIENT_HELLO` | C→S | Server: AwaitHello | 0 |
| 0x02 | `SERVER_HELLO` | S→C | Client: AwaitServerHello | 0 |
| 0x03 | `CLIENT_PROOF` | C→S | Server: AwaitProof | 0 |
| 0x04 | `AUTH_RESULT` | S→C | Client: AwaitResult | 0 |
| 0x10 | `DATA` | 양방향 | Active | 16 |
| 0x11 | `PING` | 양방향 | Active | 16 |
| 0x12 | `PONG` | 양방향 | Active | 16 |
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
| 6 | `ENROLLMENT_TOKEN` | opaque | 1..512, ENROLL 모드에서 필수 |
| 7 | `PUBLIC_KEY` | SEC1 uncompressed P-256 point (0x04‖X‖Y) | 65, ENROLL 모드에서 필수 |

AUTHENTICATE 모드에서 `ENROLLMENT_TOKEN`, `PUBLIC_KEY` 가 있으면 오류.

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
TLV      extensions                (v1 정의 없음)
```

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
channel_binding = TLS-Exporter(label = "EXPORTER-Channel-Binding", context = "", length = 32)   // RFC 9266
```

클라이언트와 서버는 각자 **자기 쪽 TLS 연결**에서 값을 계산한다.
중간자가 TLS 를 두 번 종단하면 양쪽 값이 달라지므로 클라이언트 서명이 서버에서 검증되지 않는다.

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
TH2 = SHA-256( TH1 || u32(len(ClientProof frame)) || ClientProof frame || AUTH_RESULT 고정부(서명 필드 제외) )
server_signed_data = "SockGate/v1/server-proof" || 0x00 || TH2
```

클라이언트에 `server_proof_keys` 가 설정되어 있으면 서명이 없거나 검증 실패 시 `SG_INVALID_SIGNATURE` 로 연결을 끊는다.

## 7. 세션 키와 프레임 보호

### 7.1 키 유도

```text
km   = TLS-Exporter(label = "EXPORTER-SockGate-v1-keys", context = TH1, length = 32)
k_cs = HKDF-SHA256(ikm = km, salt = session_id, info = "SockGate/v1 c2s" || u32(epoch), L = 32)
k_sc = HKDF-SHA256(ikm = km, salt = session_id, info = "SockGate/v1 s2c" || u32(epoch), L = 32)
```

- `epoch` 는 최초 인증 시 0, 재인증 성공마다 +1. 재인증 시 `TH1` 자리에 재인증 transcript 해시를 사용한다.
- 키는 메모리에만 존재하며 세션 종료/rekey 시 `OPENSSL_cleanse` 로 지운다.

### 7.2 AEAD

- 알고리즘: AES-256-GCM, tag 16 bytes.
- nonce (12 bytes) = `u32(0)` || `u64(sequence)` — 키는 방향·epoch 별로 다르고 sequence 는 방향 내에서 반복되지 않으므로 nonce 재사용이 없다.
- 헤더는 `auth_length = 16` 으로 채운 상태의 48 bytes 를 AAD 로 사용한다.
- `ENCRYPTED` 미설정: `AAD = header || payload`, 평문 없음 → tag 만 생성 (GMAC)
- `ENCRYPTED` 설정: `AAD = header`, payload 를 암호화
- 서버 옵션 `require_app_encryption` 이 켜져 있으면 `ENCRYPTED` 없는 DATA 는 거부

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
THr = SHA-256( "SockGate/v1/reauth" || session_id || u32(epoch) || channel_binding || prev_TH
               || REAUTH_REQUEST frame || REAUTH_CHALLENGE frame )
signed = "SockGate/v1/reauth-proof" || 0x00 || THr
```

REAUTH_RESULT(OK) 프레임은 **이전 epoch 키**로 보호되고, 그 다음 프레임부터 양방향 모두 새 epoch 키를 사용한다.

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
- 교집합이 없으면 `AUTH_RESULT(UNSUPPORTED_VERSION)` 후 종료. 클라이언트는 `SG_VERSION_MISMATCH` 반환.
- 프레임 헤더 `version` 은 wire 포맷 버전이며 v1 에서 항상 1.
