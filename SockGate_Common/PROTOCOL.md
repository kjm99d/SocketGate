# SockGate Wire Protocol v1 — 구현 요약

> 규범 문서: [04-protocol-specification.md](../docs/design/04-protocol-specification.md),
> [05-handshake-sequence.md](../docs/design/05-handshake-sequence.md).
> 이 문서는 SockGate_Common 의 코드(`protocol/constants.h`, `frame.*`, `rules.*`, `messages.*`, `transcript.*`, `channel.*`,
> `enrollment_token.*`, `serialization/*`)가 **실제로 강제하는** wire format 을 요약한다. 모든 상수는 `constants.h` 와 대조했다.
> 핸드셰이크 순서와 의미 검증(서명, challenge, 권한)은 05 와 Client/Server 코드의 몫이다.

## 1. 일반 규칙

- TLS 1.3 (옵션으로 EMS 가 있는 TLS 1.2) 레코드 위의 바이트 스트림이다. 평문 TCP 로 보내지 않는다.
- 모든 정수는 big endian. wire 코덱의 바이트 순서는 `serialization/byte_order.h` 에 있고, transcript 해시용
  `Sha256Hasher::UpdateU16` / `UpdateU32` (`crypto/openssl_crypto.cpp`) 도 같은 big endian 을 직접 인코딩한다.
- 알 수 없는 enum 값, 예약 비트, 예약 필드 ≠ 0, 남는 바이트는 모두 오류다. 확장은 TLV 로만 한다 (§4).
- 모든 길이 필드는 상한이 있고, 프레임 크기 상한은 헤더 단계에서 검사한다.
- 디코더가 돌려주는 오류는 모두 **연결 종료** 사유다 (오류 후 계속 진행하지 않는다).

## 2. 프레임

### 2.1 헤더 (고정 48 bytes, `kHeaderSize`)

| Offset | Size | Field | 값 / 규칙 |
|---:|---:|---|---|
| 0 | 4 | `magic` | `kMagic` = `0x53474154` ("SGAT") |
| 4 | 1 | `version` | `kWireVersion` = 1 (frame layout 버전) |
| 5 | 1 | `type` | §3 의 12 개 값만 |
| 6 | 2 | `flags` | §2.2 |
| 8 | 16 | `session_id` | 서버가 SERVER_HELLO 에서 할당. 그 전(CLIENT_HELLO)에는 0 |
| 24 | 8 | `sequence` | 방향별 프레임 번호 (§9) |
| 32 | 8 | `request_id` | 0 = 없음 (§9) |
| 40 | 4 | `payload_length` | ≤ `kAbsoluteMaxPayload` (16 MiB) |
| 44 | 2 | `auth_length` | 0 또는 `kAuthTagSize` (16) |
| 46 | 2 | `reserved` | 0 |

헤더 뒤에 `payload[payload_length]`, `auth_data[auth_length]` (AES-256-GCM tag) 가 온다.
프레임 크기 = `48 + payload_length + auth_length`.

### 2.2 Flags

| Bit | 상수 | 의미 |
|---:|---|---|
| 0 | `kFlagEncrypted` | payload 가 애플리케이션 계층 AEAD 로 암호화됨 |
| 1 | `kFlagResponse` | `request_id` 가 상대 요청에 대한 응답 |
| 2 | `kFlagKeyPhase` | 이 프레임을 보호한 키의 `epoch & 1` (§8.4) |
| 3–15 | - | 예약. 설정되면 `SG_PROTOCOL_ERROR` (`kKnownFlags` 밖) |

### 2.3 크기 상한

| 상수 | 값 | 적용 |
|---|---|---|
| `kMaxHandshakePayload` | 4096 | 인증 전 모든 프레임 (type 무관), 인증 후 DATA 가 아닌 모든 프레임 |
| `kDefaultMaxPayload` | 1 MiB (`1u << 20`) | 인증 후 DATA 의 기본 상한 (`FrameLimits::max_data_payload`, Client/Server 의 `max_payload_size` 로 설정) |
| `kAbsoluteMaxPayload` | 16 MiB (`16u << 20`) | 설정으로도 넘을 수 없는 상한. `DecodeHeader` 가 구조 단계에서 강제 |
| `kPreAuthDecoderBuffer` | 16 KiB | 인증 전 `FrameDecoder` 가 쌓아 둘 수 있는 미파싱 입력 상한 |
| `kMaxDecoderBuffer` | 48 + 16 MiB + 16 + 256 KiB | `FrameDecoder` 버퍼 절대 상한. 인증 후 Client/Server 는 `48 + max_payload + 16 + 64 KiB` 로 설정 |

### 2.4 헤더 검증 순서

`FrameDecoder::Next()` 는 48 bytes 가 모이면 다음 순서로 검사하고, **모두 통과해야** 본문을 기다린다.
`Append()` 는 받은 chunk 를 그대로 버퍼에 넣으므로, 헤더 검사 전에 메모리에 올라가는 양의 상한은 48 bytes 가 아니라
`SetMaxBuffered()` 로 정한 값 (인증 전 16 KiB) 이다. 허용되지 않는 헤더는 48 bytes 가 모이는 즉시 거부되고, 그 본문은 기다리지 않는다.

| # | 검사 | 위치 | 실패 |
|---:|---|---|---|
| 1 | 48 bytes 미만 | `FrameDecoder` | 더 기다림 (타임아웃은 Client/Server 가 보장) |
| 2 | `magic` | `DecodeHeader` | `SG_PROTOCOL_ERROR` |
| 3 | `version != 1` | `DecodeHeader` | `SG_VERSION_MISMATCH` |
| 4 | 정의되지 않은 `type` | `DecodeHeader` | `SG_PROTOCOL_ERROR` |
| 5 | 예약 flag 비트 | `DecodeHeader` | `SG_PROTOCOL_ERROR` |
| 6 | `auth_length ∉ {0, 16}` | `DecodeHeader` | `SG_PROTOCOL_ERROR` |
| 7 | `reserved != 0` | `DecodeHeader` | `SG_PROTOCOL_ERROR` |
| 8 | `payload_length > 16 MiB` | `DecodeHeader` | `SG_PROTOCOL_ERROR` |
| 9 | 단계별 규칙 (§3) | `CheckHeaderForState` (HeaderCheck) | `SG_PROTOCOL_ERROR` |
| 10 | 전체 프레임 수신 대기 | `FrameDecoder` | - |
| 11 | session_id / sequence / KEY_PHASE / tag / request id | 인증 후 `ProtectedChannel::Open` (§8, §9), 인증 전 Client/Server 핸드셰이크 | §9 |
| 12 | payload 디코드 | `Decode*` (§5, §6) | `SG_PROTOCOL_ERROR` |

## 3. 메시지 타입과 단계별 규칙 (`CheckHeaderForState`)

`Phase` 는 수신측의 단계다. 표에 없는 조합은 모두 `SG_PROTOCOL_ERROR` 이며, 수신측이 `kClosed` 이면 어떤 프레임도 받지 않는다.

| 값 | 이름 | 수신측 | 허용 Phase | `auth_length` |
|---:|---|---|---|---|
| 0x01 | `CLIENT_HELLO` | 서버 | `kAwaitClientHello` | 0 |
| 0x02 | `SERVER_HELLO` | 클라이언트 | `kAwaitServerHello` | 0 |
| 0x03 | `CLIENT_PROOF` | 서버 | `kAwaitClientProof` | 0 |
| 0x04 | `AUTH_RESULT` | 클라이언트 | `kAwaitAuthResult`, `kAwaitServerHello` (`UNSUPPORTED_VERSION` 전용, §11) | 0 |
| 0x10 | `DATA` | 양쪽 | `kActive`, `kRefreshing` | 16 |
| 0x11 | `PING` | 양쪽 | `kActive`, `kRefreshing` | 16 |
| 0x12 | `PONG` | 양쪽 | `kActive`, `kRefreshing` | 16 |
| 0x20 | `REAUTH_REQUEST` | 서버 | `kActive` | 16 |
| 0x21 | `REAUTH_CHALLENGE` | 클라이언트 | `kRefreshing` | 16 |
| 0x22 | `REAUTH_PROOF` | 서버 | `kRefreshing` | 16 |
| 0x23 | `REAUTH_RESULT` | 클라이언트 | `kRefreshing` | 16 |
| 0x30 | `CLOSE` | 양쪽 | `kClosed` 를 뺀 모든 단계 | 인증 전 0, 인증 후 16 |

추가 규칙 (같은 함수):

- `auth_length` 는 인증된 단계(`kActive`, `kRefreshing`)에서 정확히 16, 그 전에는 정확히 0.
- 인증 전: `flags == 0`, `request_id == 0`.
- 인증 후: `RESPONSE` 는 DATA 에만, 그리고 `request_id != 0` 일 때만. DATA 가 아닌 프레임은 `request_id == 0`.
- 크기 상한은 **연결 단계**로 정한다: 인증 후 DATA 만 `max_data_payload`, 그 밖(인증 전 모든 프레임 포함)은 4096.

## 4. 공통 인코딩과 TLV

| 표기 | 의미 |
|---|---|
| `u8/u16/u32/u64` | big endian 부호 없는 정수 |
| `bytesN` | 정확히 N bytes |
| `vec16` | `u16 length` + length bytes. 필드별 `[min, max]` 를 벗어나면 오류 (`Reader::Vec16`) |
| `TLV` | 확장 영역 (아래) |

TLV 확장 영역 (`serialization/tlv.h`, `TlvSection::Parse`):

```text
u16 total_length
{ u16 type, u16 length, value[length] } *      // 정확히 total_length bytes
```

- 항목들이 `total_length` 를 정확히 채워야 한다 (남거나 모자라면 오류).
- 항목 수 최대 `kMaxTlvCount` = 16. 같은 type 중복은 오류.
- 알 수 없는 type 은 길이 검증만 하고 메시지 디코더가 **무시**한다 (forward compatibility).
- TLV 영역 뒤에 남는 바이트는 오류 (trailing data 금지).
- TLV 영역이 있는 메시지: `CLIENT_HELLO` (type 1–7), `SERVER_HELLO` (v1 정의 없음, 빈 영역), `CLIENT_PROOF` (type 1).
  나머지 메시지는 고정 레이아웃이며 TLV 영역이 없다.
- TLV type 번호 공간은 메시지별이다 (`CLIENT_PROOF` 의 1 과 `CLIENT_HELLO` 의 1 은 다르다).

프로토콜 문자열 (`ser::IsValidProtocolString`): 엄격한 UTF-8 (overlong, surrogate, U+10FFFF 초과 거부) 이며
C0 제어문자·DEL, C1 제어문자, 보이지 않는/서식/양방향 재정의 문자 (U+00AD, U+061C, U+180E, U+FEFF, U+200B–U+200F,
U+2028–U+202E, U+2060–U+206F, U+FFF9–U+FFFB), noncharacter (U+FDD0–U+FDEF, U+xxFFFE/U+xxFFFF) 를 거부한다.

## 5. 핸드셰이크 메시지

### 5.1 CLIENT_HELLO (0x01)

```text
u16      protocol_version_min
u16      protocol_version_max
u16      client_version_major
u16      client_version_minor
u16      client_version_patch
bytes32  client_nonce
bytes16  installation_id
u8       key_algorithm        (1 = ECDSA_P256_SHA256, 그 외 오류)
u8       auth_mode            (1 = AUTHENTICATE, 2 = ENROLL, 그 외 오류)
TLV      extensions
```

- `protocol_version_min != 0` 이고 `min ≤ max` 여야 한다.

| TLV | 상수 (`proto::tlv::`) | 값 | 디코더 제약 |
|---:|---|---|---|
| 1 | `kProductId` | 프로토콜 문자열 | 1..64 (`kMaxProductIdLength`) |
| 2 | `kProductVersion` | 프로토콜 문자열 | 1..32 (`kMaxProductVersionLength`) |
| 3 | `kLicenseId` | 프로토콜 문자열 | 1..128 (`kMaxLicenseIdLength`) |
| 4 | `kRequestedFeatures` | `u64` bitmask | 정확히 8 |
| 5 | `kIntegrityReport` | §5.5 | ≤ 512 (`kMaxIntegrityReportLength`) |
| 6 | `kEnrollmentTokenId` | token 공개 부분 `token_pub` (§10). 비밀 `K_tok` 는 전송하지 않음 | 1..512 (`kMaxEnrollmentTokenIdLength`) |
| 7 | `kPublicKey` | SEC1 uncompressed P-256 point | 정확히 65, 첫 바이트 `0x04` |

- ENROLL 모드는 TLV 6 과 7 이 모두 있어야 하고, AUTHENTICATE 모드에는 둘 다 없어야 한다 (디코더가 검사).
- 공개키의 곡선 위 검증과 `installation_id == H(PUBLIC_KEY)` 확인, token claims 와 TLV 1/3 의 일치 확인은 서버 핸드셰이크가 한다
  ([05 §2](../docs/design/05-handshake-sequence.md)).

### 5.2 SERVER_HELLO (0x02)

```text
u16      selected_protocol_version   (≠ 0)
bytes32  server_nonce
bytes32  challenge
u32      challenge_ttl_ms            (≠ 0)
u8       server_proof_algorithm      (0 = 없음, 1 = ECDSA_P256_SHA256)
TLV      extensions                  (v1 정의 없음; 알 수 없는 항목은 무시)
```

헤더의 `session_id` 가 새 세션 ID 다.

### 5.3 CLIENT_PROOF (0x03)

```text
u8       signature_algorithm         (1 만 허용)
vec16    signature                   (P1363 r‖s, 정확히 64 bytes)
TLV      extensions
```

| TLV | 상수 | 값 | 제약 |
|---:|---|---|---|
| 1 | `kEnrollmentProof` | `HMAC-SHA256(K_tok, "SockGate/v1/enroll-proof" ‖ 0x00 ‖ TH1)` | 정확히 32. 모드별 필수/금지는 서버가 검사 |

### 5.4 AUTH_RESULT (0x04)

```text
u8       result                 (0 OK, 1 REJECTED, 2 RETRY_LATER, 3 UNSUPPORTED_VERSION)
u8       session_policy         (0 NONE, 1 NORMAL, 2 RESTRICTED)
u64      granted_features
u32      session_lifetime_ms
u64      license_expires_at_ms  (Unix epoch ms, 0 = 해당 없음)
u8       server_proof_algorithm (0 또는 1)
vec16    server_signature       (algorithm 0 → 길이 0, 1 → 정확히 64)
```

- `result == OK`: `session_policy != NONE`, `session_lifetime_ms != 0`.
- `result != OK`: policy, features, lifetime, license expiry, proof algorithm 이 모두 0 이어야 한다 (따라서 서명도 없다).
  인코더도 같은 조건을 강제해 거부 응답에 세션 정보가 새지 않게 한다.
- 서버 서명 대상 R 은 헤더(48) + payload 앞 `kAuthResultSignedPayloadPrefix` (= 1+1+8+4+8+1 = 23) bytes 다 (§7.2).

### 5.5 INTEGRITY_REPORT (CLIENT_HELLO TLV 5)

```text
u8       report_version     (= 1)
u8       platform           (1 Windows, 2 Linux, 3 macOS — SG_INTEGRITY_PLATFORM_*)
u32      observation_flags  (SG_INTEGRITY_KNOWN_FLAGS = 0x000001FF 밖의 비트는 오류)
bytes32  executable_sha256
bytes32  library_sha256
vec16    build_id           (0..64, kMaxBuildIdLength)
```

v1 에 정의되지 않은 관측 비트는 디코딩 단계에서 프로토콜 오류다. 새 관측은 새 프로토콜 버전과 함께 추가한다
([09 §5.2](../docs/design/09-public-c-api.md)).

## 6. 인증 후 메시지

모두 `auth_length = 16` 이며 `ProtectedChannel` 로 보호된다 (§8).

| 메시지 | payload | 디코더 제약 |
|---|---|---|
| DATA | 애플리케이션 바이트 | 길이만 (`max_data_payload`) |
| PING / PONG | `u64 opaque` | 정확히 8 bytes. PONG 은 PING 값을 되돌린다 |
| REAUTH_REQUEST | `bytes32 client_nonce` | 정확히 32 |
| REAUTH_CHALLENGE | `bytes32 server_nonce`, `bytes32 challenge`, `u32 challenge_ttl_ms` | ttl ≠ 0 |
| REAUTH_PROOF | `u8 signature_algorithm`, `vec16 signature` | algorithm = 1, 서명 정확히 64 |
| REAUTH_RESULT | `u8 result`, `u32 session_lifetime_ms`, `u32 new_epoch` | result ∈ {0,1,2} (3 금지). OK → lifetime ≠ 0. 그 외 → lifetime = 0, new_epoch = 0 |
| CLOSE | `u16 reason` | 0 NORMAL, 1 PROTOCOL_ERROR, 2 AUTH_FAILED, 3 SESSION_EXPIRED, 4 SERVER_SHUTDOWN, 5 IDLE_TIMEOUT, 6 LIMIT_EXCEEDED (그 밖 오류) |

`new_epoch == epoch + 1` 확인은 클라이언트 세션 코드가 한다.

## 7. Transcript, 서명, 식별자 (`protocol/transcript.h`)

모든 레이블은 ASCII 이며 NUL 없이 해시된다. `u32(len) ‖ x` 는 `Sha256Hasher::UpdateWithLength` 다.

### 7.1 TH1 (`ComputeTranscriptHash`)

```text
TH1 = SHA-256( "SockGate/v1/transcript"
             ‖ u16(selected_protocol_version)
             ‖ channel_binding                          (32, §8.1)
             ‖ u32(len) ‖ CLIENT_HELLO frame            (헤더 포함 전체 wire bytes)
             ‖ u32(len) ‖ SERVER_HELLO frame )
```

### 7.2 TH2 — 서버 proof (`ComputeServerTranscriptHash`)

```text
R   = AUTH_RESULT 프레임의 헤더(48) ‖ payload 앞 23 bytes (server_signature vec16 제외)
TH2 = SHA-256( "SockGate/v1/server-transcript" ‖ TH1
             ‖ u32(len) ‖ CLIENT_PROOF frame ‖ u32(len) ‖ R )
```

### 7.3 THr — 재인증 (`ComputeReauthTranscriptHash`)

```text
F(x) = x 프레임의 헤더(48, auth_length = 16) ‖ 평문 payload      (tag 제외; ProtectedChannel::Open 이 제공)
THr  = SHA-256( "SockGate/v1/reauth" ‖ session_id(16) ‖ u32(epoch) ‖ channel_binding ‖ prev_TH
              ‖ u32(len) ‖ F(REAUTH_REQUEST) ‖ u32(len) ‖ F(REAUTH_CHALLENGE) )
```

`prev_TH` 는 직전 인증의 transcript 해시(TH1 또는 이전 THr) 다.

### 7.4 서명 대상과 도메인 분리

`SignedData(context, hash)` = `context ‖ 0x00 ‖ hash`. 서명은 ECDSA P-256 / SHA-256, P1363 64 bytes.

| 용도 | context (`constants.h`) | hash |
|---|---|---|
| 클라이언트 proof | `kClientProofContext` = `"SockGate/v1/client-proof"` | TH1 |
| 서버 proof | `kServerProofContext` = `"SockGate/v1/server-proof"` | TH2 |
| 재인증 proof | `kReauthProofContext` = `"SockGate/v1/reauth-proof"` | THr |
| enrollment proof (HMAC) | `kEnrollProofContext` = `"SockGate/v1/enroll-proof"` | TH1, 키 `K_tok` |
| `K_tok` 유도 (HMAC) | `kEnrollKeyContext` = `"SockGate/v1/enroll-key"` | `token_pub`, 키 `server_token_key` |

### 7.5 installation_id (`DeriveInstallationId`)

```text
installation_id = SHA-256("SockGate/v1/iid" ‖ SEC1 public key(65))[0..16)
```

## 8. 채널 바인딩, 키 유도, 프레임 보호

### 8.1 채널 바인딩 (`ITlsEngine::ChannelBinding`)

```text
channel_binding = TLS-Exporter(label = "EXPORTER-Channel-Binding", context = 길이 0, length = 32)   // RFC 9266 tls-exporter
                = SSL_export_keying_material(ssl, out, 32, "EXPORTER-Channel-Binding", 24, "", 0, use_context = 1)
```

- context 는 "없음"(`use_context = 0`)이 아니라 **길이 0 의 context** (`use_context = 1`) 다. TLS 1.3 에서는 두 값이 같지만
  TLS 1.2 에서는 다르며, RFC 9266 은 길이 0 context 를 요구한다 (b95a843 에서 수정).
- **업그레이드 주의**: b95a843 이전에 빌드된 peer 는 TLS 1.2 로 협상될 때 다른 채널 바인딩을 계산하므로 새 peer 와 인증에 실패한다.
  TLS 1.3 세션은 영향이 없다.

각 peer 가 **자기 TLS 연결**에서 계산한다. TLS 를 두 번 종단한 중간자는 양쪽 값이 달라 서명이 검증되지 않는다.
TLS 1.2 는 EMS 가 협상된 경우에만 허용된다 (엔진이 핸드셰이크 직후 강제, `SG_TLS_ERROR`).

### 8.2 키 재료와 방향별 키 (`DeriveChannelKeys`)

```text
km   = TLS-Exporter(label = "EXPORTER-SockGate-v1-keys", context = TH1 (재인증 시 THr), use_context = 1, length = 32)
k_cs = HKDF-SHA256(ikm = km, salt = session_id, info = "SockGate/v1 c2s" ‖ u32(epoch), L = 32)
k_sc = HKDF-SHA256(ikm = km, salt = session_id, info = "SockGate/v1 s2c" ‖ u32(epoch), L = 32)
```

- `km` 은 정확히 32 bytes 여야 한다 (아니면 `SG_INVALID_ARGUMENT`).
- epoch 은 최초 인증 0, 재인증 성공마다 +1.
- 이 키는 TLS exporter 에서 유도되므로 TLS 를 종단한 MITM 에 대한 추가 방어가 **아니다**. 목적은 프레임을 세션 ID·sequence·방향·epoch
  에 결속하고 TLS 구현 결함에 대한 심층 방어를 제공하는 것이다 ([04 §7.1](../docs/design/04-protocol-specification.md)).

### 8.3 AEAD

- AES-256-GCM, tag 16 bytes.
- nonce (12 bytes) = `u32(0) ‖ u64(sequence)`. 키가 방향·epoch 별로 다르고 sequence 가 방향 안에서 반복되지 않으므로 nonce 가 재사용되지 않는다.
- AAD 는 `auth_length = 16`, 최종 `flags` (KEY_PHASE 포함) 가 채워진 48-byte 헤더다.
  - `ENCRYPTED` 없음: `AAD = header ‖ payload`, 평문 없음 (GMAC). payload 는 평문으로 전송된다 (TLS 가 암호화).
  - `ENCRYPTED` 있음: `AAD = header`, payload 를 암호화.
- 서버의 "암호화 없는 DATA 거부" 정책(`require_app_encryption`)은 Server 코드의 몫이다.

### 8.4 KEY_PHASE 와 방향별 키 전환

| 방향 | 전환 (`ProtectedChannel`) |
|---|---|
| s2c | 서버는 `REAUTH_RESULT(OK)` 를 epoch e 키로 보낸 뒤 `SwitchSendKey(e+1)`. 클라이언트는 그 결과를 처리하면서 `SwitchReceiveKey(e+1)` |
| c2s | 클라이언트는 송신 lock 안에서 `SwitchSendKey(e+1)`. 서버는 `StageReceiveKey(e+1)` 로 새 키를 대기시키고 `KEY_PHASE` 로 키를 고른다. 새 phase 의 첫 프레임이 검증되면 e 키를 지우며, 이후 e 프레임은 치명적 오류 |

`KEY_PHASE` 는 AAD 에 포함되므로 변조하면 tag 검증이 실패한다. 설계 규칙 전체는 [04 §7.3](../docs/design/04-protocol-specification.md).

## 9. Sequence / Request ID

| 규칙 | 검사 위치 | 위반 시 |
|---|---|---|
| 핸드셰이크: CLIENT_HELLO seq 1, SERVER_HELLO seq 1, CLIENT_PROOF seq 2, AUTH_RESULT seq 2 | Client/Server 핸드셰이크 | `SG_PROTOCOL_ERROR` |
| 인증 후 방향별 첫 프레임 seq = `kFirstSessionSequence` (3), 이후 정확히 +1 | `ProtectedChannel::Open` | 이전 값 이하 `SG_REPLAY_DETECTED`, 건너뜀 `SG_PROTOCOL_ERROR` |
| seq `2^64-1` | `Seal` / `Open` | `SG_SESSION_EXPIRED` |
| session_id: CLIENT_HELLO 는 0, 이후 할당된 값 | 핸드셰이크 / `Open` | `SG_PROTOCOL_ERROR` |
| 요청 (`RESPONSE` 없음, `request_id ≠ 0`) 은 방향별 단조 증가 | `Open` (tag 검증 후) | `SG_REPLAY_DETECTED` |
| 응답 (`RESPONSE`) 은 `request_id ≠ 0` 이고 수신측이 할당한 최대 요청 id 이하 (중복 응답, 할당만 하고 보내지 않은 id 에 대한 응답은 거부하지 않음 — 짝 맞추기는 애플리케이션 몫) | `CheckHeaderForState` + `Open` | `SG_PROTOCOL_ERROR` |
| request id 는 인증 후 DATA 에만 | `CheckHeaderForState` | `SG_PROTOCOL_ERROR` |

`Open()` 의 모든 실패는 채널을 poison 한다 (이후 모든 프레임 거부).

## 10. Enrollment token (`protocol/enrollment_token.h`)

```text
claims    = u8 claims_version(=1) ‖ vec16 product_id(1..64) ‖ vec16 license_id(0..128)
            ‖ u64 issued_at_ms ‖ u64 expires_at_ms                     (expires > issued)
token_pub = bytes16 token_id ‖ claims                                  (CLIENT_HELLO TLV 6, ≤ 512 bytes)
K_tok     = HMAC-SHA256(server_token_key, "SockGate/v1/enroll-key" ‖ 0x00 ‖ token_pub)   (전송 금지)
token     = base64url(token_pub ‖ K_tok)                               (패딩 없음, ≤ 1024 문자)
enroll_mac= HMAC-SHA256(K_tok, "SockGate/v1/enroll-proof" ‖ 0x00 ‖ TH1) (CLIENT_PROOF TLV 1)
```

- `server_token_key` 는 32 bytes 이상이어야 한다.
- 수명 상한 `kMaxEnrollmentTokenLifetimeMs` = 30 일 (`30 × 24 × 3600 × 1000` ms). 코덱은 `expires > issued` 만 검사하고,
  `expires_at_ms - issued_at_ms` 상한은 서버가 발급할 때와 사용(redeem)할 때 모두 강제한다.
- product_id / license_id 는 프로토콜 문자열 규칙(§4)을 따른다.
- base64url 디코더는 패딩, 공백, 알파벳 밖 문자, 불가능한 길이(`len % 4 == 1`), 0 이 아닌 남는 비트를 거부한다 (정규형만 허용).
- `ParseEnrollmentToken` 은 디코딩한 `token_pub` 를 다시 `DecodeTokenPublic` 으로 검증한다. 디코딩 중간값은 `SecureBytes` 로 지워진다.
- token 검증(만료, 1회 사용, claims 일치)은 서버의 몫이다 ([05 §2](../docs/design/05-handshake-sequence.md)).

## 11. 버전 관리

| 값 | 상수 | 의미 |
|---|---|---|
| 헤더 `version` = 1 | `kWireVersion` | frame layout 버전. 레이아웃이 바뀔 때만 증가. 다르면 `DecodeHeader` 가 `SG_VERSION_MISMATCH` |
| 1 | `kProtocolVersion`, `kMinProtocolVersion`, `kMaxProtocolVersion` | CLIENT_HELLO `[min, max]` 로 협상하는 기능 버전. public 헤더의 `SOCKGATE_PROTOCOL_VERSION` 과 같은 값 |

- 서버는 교집합의 최고 버전을 고른다. 교집합이 없으면 SERVER_HELLO 대신 `AUTH_RESULT(UNSUPPORTED_VERSION)` 을
  `session_id = 0`, `sequence = 1`, 나머지 필드 0 으로 보내고 닫는다.
- 클라이언트는 `kAwaitServerHello` 에서 이 형태(`UNSUPPORTED_VERSION`, seq 1, session_id 0)의 AUTH_RESULT 만 받아
  `SG_VERSION_MISMATCH` 를 돌려준다. 다른 AUTH_RESULT 는 `SG_PROTOCOL_ERROR`. 규칙 표는 이 단계의 AUTH_RESULT 를 허용하고,
  형태 검사는 handler 가 한다.
- 클라이언트는 `selected_protocol_version ∈ [min, max]` 를 확인한다.
- 새 message type, 새 integrity 관측 비트, 반드시 이해해야 하는 TLV 는 v1 peer 가 오류로 처리하거나 무시하므로 새 프로토콜 버전과
  함께 도입한다 ([INTEGRATION.md §1.4–1.5](INTEGRATION.md)).

## 12. 상수 요약 (`protocol/constants.h`)

| 상수 | 값 |
|---|---|
| `kMagic` | `0x53474154` |
| `kWireVersion` / `kProtocolVersion` / `kMinProtocolVersion` / `kMaxProtocolVersion` | 1 / 1 / 1 / 1 |
| `kHeaderSize` / `kAuthTagSize` | 48 / 16 |
| `kSessionIdSize` / `kInstallationIdSize` / `kTokenIdSize` | 16 / 16 / 16 |
| `kNonceSize` / `kChallengeSize` | 32 / 32 |
| `kMaxHandshakePayload` / `kDefaultMaxPayload` / `kAbsoluteMaxPayload` | 4096 / 1 MiB / 16 MiB |
| `kKeyAlgorithmEcdsaP256Sha256` / `kProofAlgorithmNone` / `kProofAlgorithmEcdsaP256Sha256` | 1 / 0 / 1 |
| `kMaxProductIdLength` / `kMaxProductVersionLength` / `kMaxLicenseIdLength` | 64 / 32 / 128 |
| `kMaxIntegrityReportLength` / `kMaxEnrollmentTokenIdLength` / `kMaxBuildIdLength` | 512 / 512 / 64 |
| `kKeyExporterLabel` | `"EXPORTER-SockGate-v1-keys"` |
| `kC2SKeyInfo` / `kS2CKeyInfo` | `"SockGate/v1 c2s"` / `"SockGate/v1 s2c"` |
| `kTranscriptLabel` / `kServerTranscriptLabel` / `kReauthTranscriptLabel` | `"SockGate/v1/transcript"` / `"SockGate/v1/server-transcript"` / `"SockGate/v1/reauth"` |
| `kInstallationIdContext` | `"SockGate/v1/iid"` |
| 채널 바인딩 레이블 (`tls/openssl_tls.cpp`) | `"EXPORTER-Channel-Binding"` |
| `kFirstSessionSequence` (`channel.h`) | 3 |
| `kMaxEnrollmentTokenLifetimeMs` (`enrollment_token.h`) | 30 일 (2 592 000 000 ms) |
| `kMaxTlvCount` (`tlv.h`) | 16 |
