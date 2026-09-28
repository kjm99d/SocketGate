# SockGate_Common Threat Model

> 시스템 전체 위협 모델: [02-threat-model.md](../docs/design/02-threat-model.md), 신뢰 경계: [03-trust-boundary.md](../docs/design/03-trust-boundary.md),
> 보장하지 않는 것: [13-security-limitations.md](../docs/design/13-security-limitations.md).
> 이 문서는 그중 **공통 파싱/암호 계층** (SockGate_Common) 이 책임지는 부분만 다룬다.

## 1. 범위와 가정

Common 은 TB1 (network ↔ process) 과 TB2 (TLS 평문 ↔ protocol parser) 경계에서 동작하는 코드를 제공한다.

- 소켓과 TLS 복호화 결과에서 오는 **모든 바이트는 비신뢰**다. 인증된 peer 도 악의적일 수 있으며 (A6 악성 클라이언트, A8 가짜 서버),
  Client 와 Server 는 같은 파서로 상대 입력을 검증한다.
- OpenSSL 과 OS CSPRNG 는 올바르게 동작한다고 가정한다 ([02 §5](../docs/design/02-threat-model.md)).
- 상태 머신, challenge 관리, 권한 판단, 타임아웃은 Client/Server 의 책임이다. Common 은 그들이 쓰는 규칙 표와 검증 부품을 제공한다.

### 보호 대상 (Common 이 다루는 것)

| 자산 | Common 안의 위치 |
|---|---|
| 채널 보호 키 (방향·epoch 별 AES-256-GCM 키) | `ProtectedChannel` |
| 키 재료 `km`, 채널 바인딩, transcript 해시 | `transcript.*`, `ITlsEngine` exporter |
| enrollment `K_tok`, `server_token_key` 파생값 | `enrollment_token.*` |
| 소프트웨어 private key (PKCS#8, EVP_PKEY) | `crypto::SoftwareP256Key` |
| 복호화된 payload, 수신 버퍼 | `FrameDecoder`, `DecodedFrame` |
| 프로세스 가용성 (메모리, CPU) | 파서 상한, 디코더 버퍼 상한 |

## 2. 위협과 대응

### 2.1 잘못된 입력 (malformed / hostile input)

| 위협 | 대응 | 코드 |
|---|---|---|
| 잘린 필드, 과대 길이, 길이 필드 정수 overflow | `Reader` 가 접근 전에 남은 길이를 검사, 실패가 고정(latch)됨. 길이 비교는 뺄셈 형태로 overflow 불가 | `serialization/reader.*` |
| 거대 프레임으로 메모리 소모 | `payload_length` 는 헤더 단계에서 검사: 16 MiB 절대 상한 (`DecodeHeader`), 인증 전·제어 메시지 4096, 인증 후 DATA 는 설정 상한. 헤더 48 bytes 가 모이는 즉시 거부하고 본문을 기다리지 않음. 검사 전에 버퍼에 들어가는 양은 받은 chunk 단위이며 `SetMaxBuffered()` 상한 (인증 전 16 KiB) 이 제한 | `frame.*`, `rules.*` |
| 인증 전 대량 입력 버퍼링 | 인증 전 디코더 버퍼 16 KiB (`kPreAuthDecoderBuffer`), 절대 상한 `kMaxDecoderBuffer` | `FrameDecoder::SetMaxBuffered` |
| 파이프라이닝으로 인한 2차 시간 복잡도 | 조건부 compaction 으로 선형 비용 | `FrameDecoder::Append` |
| 잘못된 단계·방향의 메시지 (인증 전 DATA, 클라이언트가 보낸 SERVER_HELLO 등) | `CheckHeaderForState` 표. 인증 전 `flags == 0`, `request_id == 0` | `rules.cpp` |
| 알 수 없는 type / enum / 예약 비트 / 예약 필드 | 모두 `SG_PROTOCOL_ERROR` | `frame.cpp`, `messages.cpp` |
| TLV 중복·과다·길이 불일치, trailing data | 최대 16 항목, 중복 금지, 정확한 길이, `ExpectEnd()` | `tlv.cpp`, `messages.cpp` |
| 문자열을 통한 로그/관리 화면 스푸핑 | 엄격한 UTF-8, 제어문자·양방향 재정의·보이지 않는 문자 거부 | `IsValidProtocolString` |
| 잘못된 공개키 (invalid curve, 무한원점) | `EVP_PKEY_public_check` 로 곡선 위 검증 | `ValidateP256PublicKey`, `VerifyP256` |
| 비정규 서명/토큰 인코딩 | DER 서명은 뒤따르는 바이트 거부, P1363 은 r/s = 0 거부. base64url 은 정규형만 | `openssl_crypto.cpp`, `base64.cpp` |
| 상태 검사 누락으로 인한 우회 | `HeaderCheck` 없는 `FrameDecoder` 는 모든 호출 실패 (fail closed). 디코더 오류는 고정되고 연결 종료 사유 | `FrameDecoder` |
| 우리 쪽이 잘못된 메시지를 보내 상대가 끊는 상황 | 인코더가 자기 출력을 디코더로 재검증, `EncodeFrame` 은 헤더 재검증 | `SelfCheck`, `EncodeFrame` |

검증 수단: 파서 음성 테스트 (`tests/protocol/*`), libFuzzer 타깃과 CTest 의 결정적 mutation 실행 (`fuzz/*`), ASan/UBSan 프리셋.
상세는 [SECURITY.md §5–6](SECURITY.md).

### 2.2 Downgrade

| 위협 | 대응 |
|---|---|
| TLS 버전 downgrade | 기본 최소 버전 TLS 1.3. TLS 1.2 는 `allow_tls12` 로만 켜지며, 핸드셰이크 직후 Extended Master Secret 이 없으면 `SG_TLS_ERROR` (RFC 9266 채널 바인딩 전제) |
| 약한 cipher | TLS 1.3 suite 명시, TLS 1.2 는 ECDHE + AEAD (AES-GCM, ChaCha20-Poly1305) 만 |
| 재협상 / 압축 / 세션 재개 | `SSL_OP_NO_RENEGOTIATION`, `SSL_OP_NO_COMPRESSION`, `SSL_OP_NO_TICKET`, session cache off, 서버 ticket 0 개 |
| 프로토콜 버전 downgrade | 서버는 교집합의 최고 버전 선택. 선택된 버전이 TH1 에 들어가 서명된다. wire layout `version` 은 1 외 거부 |
| 알고리즘 필드 조작 | `key_algorithm`, `signature_algorithm` 은 1 만 허용. `server_proof_algorithm` 은 {0, 1}, 거부 응답은 0 강제. 서버 proof 요구 여부는 클라이언트 설정이 결정 (Client 코드) |

### 2.3 Replay, 재정렬, 삭제, 주입

| 위협 | 대응 (`ProtectedChannel`) |
|---|---|
| 프레임 재전송 / 중복 | 방향별 sequence 는 정확히 +1. 이전 값 이하 → `SG_REPLAY_DETECTED` |
| 재정렬 / 삭제 | 건너뛴 sequence → `SG_PROTOCOL_ERROR` |
| 중복 요청 | 요청 `request_id` 는 방향별 단조 증가 → `SG_REPLAY_DETECTED` |
| 가짜 응답 | 응답 `request_id` 는 수신측이 할당한 최대값 이하 → 넘으면 `SG_PROTOCOL_ERROR`. 상한만 검사하므로 중복 응답이나 할당만 하고 보내지 않은 id 에 대한 응답은 통과한다: 요청-응답 짝 맞추기는 애플리케이션 몫 |
| 다른 세션 프레임 주입 | `session_id` 불일치 거부, 키 유도 salt 가 `session_id` |
| 반사 (내가 보낸 프레임을 되돌림) | 방향별 키 (`c2s` / `s2c` info 레이블) |
| 이전 epoch 프레임 재사용 | 새 phase 첫 프레임 이후 이전 키 소거, 이후 이전 phase 는 치명적 오류 |
| 실패 후 계속 시도 | 첫 실패에서 poison: 수신 키 소거, 이후 모든 `Seal`/`Open` 거부 |
| 핸드셰이크 재사용 (다른 연결) | TH1 이 연결별 채널 바인딩·nonce·challenge·session_id 를 포함 → 이전 서명/MAC 무효 (challenge 1회 소비는 Server 몫) |

sequence 는 64bit 이며 `2^64-1` 도달 시 세션을 끝낸다 (`SG_SESSION_EXPIRED`).

### 2.4 키 오용과 도메인 분리

- 모든 해시·서명·MAC·KDF 입력에 서로 다른 ASCII 레이블을 붙인다 ([PROTOCOL.md §7.4](PROTOCOL.md)).
  서명/MAC 대상은 `context ‖ 0x00 ‖ hash` 형태라 한 용도의 서명을 다른 용도로 옮길 수 없다.
- 채널 키: `HKDF-SHA256(ikm = km, salt = session_id, info = 방향 레이블 ‖ u32(epoch))`. 방향·epoch·세션마다 다른 키.
- `km` exporter 레이블(`EXPORTER-SockGate-v1-keys`, context = TH1/THr) 과 채널 바인딩 레이블(`EXPORTER-Channel-Binding`, RFC 9266 대로 길이 0 context) 이
  다르다.
- AEAD nonce = `u32(0) ‖ u64(sequence)`: 키가 방향·epoch 별이고 sequence 가 반복되지 않으므로 nonce 재사용이 없다.
- epoch 전환은 정확히 +1 만 허용한다. 대기 키가 있는 동안의 추가 전환은 수신 쪽(`SwitchReceiveKey`, `StageReceiveKey`)만 거부하며,
  `SwitchSendKey` 는 이를 검사하지 않는다 (송신 전환 시점은 Client/Server 의 재인증 흐름이 정한다).
- `KEY_PHASE` 는 AAD 에 포함된다.
- `km` 은 정확히 32 bytes 여야 하며, `server_token_key` 는 32 bytes 이상이어야 한다.
- enrollment token 수명은 공유 상수 `kMaxEnrollmentTokenLifetimeMs` (30 일) 로 제한된다. 서버 키로 다른 곳에서 만든 token 이라도
  서버가 사용 시점에 다시 검사하므로 오래 유효한 token 을 만들 수 없다.

### 2.5 Transcript 결속

- TH1 은 선택된 버전, 채널 바인딩, CLIENT_HELLO·SERVER_HELLO **프레임 전체**(헤더 포함)를 길이 접두와 함께 해시한다.
  nonce, challenge, installation_id, session_id, TLV 확장이 모두 서명 범위에 들어간다.
- TH2 는 TH1, CLIENT_PROOF 프레임, AUTH_RESULT 의 서명 대상 부분(헤더 + 결과 필드)을 묶는다.
- THr 은 session_id, epoch, 채널 바인딩, 직전 transcript, 재인증 요청/challenge 의 평문 프레임을 묶어 재인증을 이전 인증에 체인으로 연결한다.
- 모든 가변 길이 요소는 `u32` 길이 접두를 가져 경계가 모호하지 않다.
- 양쪽이 같은 함수(`transcript.cpp`)로 계산하므로 레이아웃이 어긋날 수 없다.

### 2.6 부채널

- 비밀 비교는 `ConstantTimeEqual` (`CRYPTO_memcmp`) 을 쓴다: SPKI pin 비교(`openssl_tls.cpp`), 서버의 enrollment MAC 비교.
- AEAD tag 검증과 ECDSA 는 OpenSSL 구현에 맡긴다.
- 인증 후 프레임 검증 실패는 모두 연결 종료로 끝나며, AEAD 실패는 `SG_PROTOCOL_ERROR` 로 일반화된다.
  상세 코드는 로컬에만 남는다 ([INTEGRATION.md §2.1](INTEGRATION.md)).

### 2.7 메모리 노출

- 키·비밀과 수신 버퍼(`FrameDecoder`, `DecodedFrame`)는 `SecureBytes` (해제 시 `OPENSSL_cleanse`) 를 쓰고, 고정 크기 키는 사용 후 `SecureZero` 로 지운다.
  복호화된 애플리케이션 데이터 전부가 대상은 아니다: `ProtectedChannel::Open()` 의 선택적 `F(x)` 출력은 일반 `Bytes` 이고
  호출자가 만든 복사본도 zeroing 대상이 아니다 ([ARCHITECTURE.md §4](ARCHITECTURE.md)).
- 실패 경로도 지운다: HKDF 실패 출력, `AesGcmOpen` 실패 시 평문 출력, exporter 실패 출력, 디코더 실패 시 버퍼 전체, poison 시 수신 키.
- 로그에는 키, exporter 값, transcript 해시, 서명, token, payload 를 쓰지 않는다 ([SECURITY.md §4](SECURITY.md)).

## 3. 잔여 위험

| 항목 | 설명 |
|---|---|
| TLS 를 종단한 MITM | 채널 보호 키는 TLS exporter 에서 유도되므로 사용자 CA 로 TLS 를 종단한 공격자에 대한 방어가 아니다. MITM 방어는 인증서 검증, pinning, 채널 바인딩, 서버 proof 가 담당한다 |
| 인증 전 프레임 | SockGate 계층 tag 가 없다. 무결성은 TLS 와 transcript 서명에 의존한다 |
| `ENCRYPTED` 없는 DATA | 애플리케이션 계층에서는 평문 (TLS 로만 암호화) |
| 무시되는 TLV | v1 peer 는 알 수 없는 TLV 를 무시한다. 보안상 반드시 이해해야 하는 확장은 새 프로토콜 버전 없이 추가하면 조용히 무시된다 |
| OpenSSL 의존 | 부채널 저항과 프리미티브 정확성은 OpenSSL 에 의존한다. 코드는 OpenSSL security level 을 명시적으로 설정하지 않는다 (OpenSSL 기본값/설정 파일을 따름). 3.0.7 미만 OpenSSL 은 configure 시 CMake 경고, OpenSSL 을 함께 배포하는 빌드(Windows, 정적 링크)는 실행 시 경고 로그만 남기며 거부하지 않는다. 배포판 OpenSSL 은 실행 시 판단하지 않는다 (백포트된 보안 수정은 버전 번호로 알 수 없음) |
| 메모리 잔존 | `std::string` 으로 전달되는 값(예: token 문자열, 오류 상세)과 `Open()` 의 `F(x)` 출력(복호화된 payload 포함 가능)은 zeroing 대상이 아니다. poison 뒤 송신 키는 소멸자까지 남는다. 스왑·코어 덤프·컴파일러가 만든 임시 복사본은 통제하지 않는다 |
| fuzzing 범위 | CTest 의 mutation driver 는 coverage-guided 가 아니다. 깊은 탐색은 libFuzzer 빌드(fuzz 프리셋)가 필요하다. `sg_fuzz_channel` 은 고정 키로 수신 경로만 다룬다 (tag 검증을 통과할 수 있는 입력은 seed 로 봉인한 프레임과 그 복제·재배열뿐이다) |
| 가용성 | 파서 상한은 메모리를 제한하지만 연결 수, 타임아웃, TLS 핸드셰이크 CPU 비용은 Client/Server 와 배포 환경의 몫이다 ([13 §6](../docs/design/13-security-limitations.md)) |
| 장악된 호스트 | 같은 프로세스/사용자 권한 공격자는 메모리의 키와 평문을 읽을 수 있다 ([13 §1](../docs/design/13-security-limitations.md)) |
