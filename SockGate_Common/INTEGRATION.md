# SockGate_Common Integration Guide

> SockGate_Common 은 **SockGate 내부 라이브러리**다. 애플리케이션은 `SockGate::Client` / `SockGate::Server` 와 그 C API
> ([09-public-c-api.md](../docs/design/09-public-c-api.md)) 만 사용한다. 이 문서의 §1 은 SockGate 개발자용이고,
> §2–3 은 Common 이 제공하는 공용 public 헤더와 ABI 규칙이다.

## 1. SockGate 개발자용

### 1.1 링크와 include

- Client/Server core (`sockgate_client_core`, `sockgate_server_core`), 테스트, fuzz 타깃이 `sockgate_common` 을 링크한다.
  include 경로(`include/`, `src/`)와 OpenSSL/Threads 는 `PUBLIC` 으로 전파된다.
- 내부 헤더: `#include "sockgate_common/protocol/frame.h"`. public 헤더: `#include <sockgate/error.h>`.
- OS 헤더는 `platform/windows`, `platform/linux` 에서만 include 한다. 나머지 코드는 `platform/socket.h` 를 쓴다.

### 1.2 Client/Server 가 Common 을 쓰는 방식

| 단계 | 사용하는 Common API |
|---|---|
| TLS | `tls::DefaultTlsProvider().CreateClientContext/CreateServerContext` → `ITlsContext::CreateEngine` → `FeedIncoming` / `Handshake` / `TakeOutgoing` 루프 |
| 수신 프레임 | `proto::FrameDecoder` + `proto::CheckHeaderForState` (HeaderCheck), `SetMaxBuffered` |
| 핸드셰이크 | `Encode*`/`Decode*`, `EncodeFrame`, `ITlsEngine::ChannelBinding`, `ComputeTranscriptHash`, `SignedData`, `crypto::VerifyP256`, `DeriveInstallationId`, `ComputeEnrollmentProof`, enrollment token 함수 |
| 세션 키 설치 | `ITlsEngine::ExportKeyingMaterial(kKeyExporterLabel, TH1, use_context = true, 32 bytes)` → `ProtectedChannel::Initialize(km, session_id)` |
| 인증 후 송수신 | `ProtectedChannel::Seal` / `Open`, `NextRequestId` |
| 재인증 | `ComputeReauthTranscriptHash` (평문 `F(x)` 는 `Open` 이 제공), THr 로 `km` 재유도, `SwitchSendKey` / `SwitchReceiveKey` / `StageReceiveKey`, `ITlsEngine::RequestKeyUpdate` |
| C ABI 경계 | 반환 직전 `sg::ToPublicStatus`, 입력 구조체에 `sg::CheckUnknownTail`, `SG_ASSERT_NO_TAIL_PADDING` |
| OpenSSL 버전 경고 | `tls::OutdatedBundledOpenSslVersion()` — 서버는 시작 시, 클라이언트는 프로세스당 1회 (WARN 로그가 켜진 첫 클라이언트가 첫 연결 전에) `event=config_warning` 로그 |
| token 수명 상한 | `proto::kMaxEnrollmentTokenLifetimeMs` — 서버의 token 발급·사용 검증과 `sg_admin token issue` 가 공유 |

수신 경로의 기본 형태 (서버 쪽 예, 실제 코드는 `SockGate_Server/src/session/connection.cpp`, `SockGate_Client/src/session/client_session.cpp`):

```cpp
proto::FrameDecoder decoder([this](const proto::FrameHeader& h) {
    return proto::CheckHeaderForState(h, proto::Role::kServer, phase_, limits_);  // 호출 시점의 phase_ 를 읽는다
});
decoder.SetMaxBuffered(proto::kPreAuthDecoderBuffer);  // 인증 후: 48 + max_payload + 16 + 64 KiB

SG_TRY(decoder.Append(plaintext));                    // TLS 로 복호화된 바이트
for (;;) {
    proto::DecodedFrame frame;
    bool ready = false;
    SG_TRY(decoder.Next(&frame, &ready));             // 오류는 모두 연결 종료 사유
    if (!ready) break;
    if (phase_ == proto::Phase::kActive || phase_ == proto::Phase::kRefreshing) {
        SG_TRY(channel.Open(&frame));                 // sequence, KEY_PHASE, tag, request id, 복호화
    }
    // type 별 Decode* 로 payload 해석
}
```

송신:

```cpp
proto::SealOptions options;
options.encrypt = true;                               // 애플리케이션 계층 AEAD
options.request_id = channel.NextRequestId();         // DATA 에만
Bytes frame;
SG_TRY(channel.Seal(proto::MessageType::kData, payload, options, &frame));
SG_TRY(tls->Write(frame));
```

### 1.3 Common 을 수정할 때의 규칙

- 설계 문서를 먼저 고친다 ([docs/README.md](../docs/README.md)). wire format 변경은 [04](../docs/design/04-protocol-specification.md) 와
  [PROTOCOL.md](PROTOCOL.md) 를 함께 갱신한다.
- 실패 가능한 함수는 `sg::Status` 를 반환하고 결과를 무시하지 않는다 (`SG_TRY`, 의도적 무시는 `IgnoreError()`).
- 비밀값은 `SecureBytes` 에 두거나 사용 후 `SecureZero` 로 지운다. 비밀 비교는 `ConstantTimeEqual`.
- 비신뢰 입력은 `ser::Reader` 로만 읽고 마지막에 `ExpectEnd()` 를 호출한다. 인코더는 `SelfCheck` 로 자기 출력을 검증한다.
  인코더가 실패하면 출력 버퍼에 일부 바이트가 남을 수 있으므로 (`SelfCheck` 실패만 되돌림) 실패한 인코딩의 출력은 버린다.
- `FrameDecoder` 를 `HeaderCheck` 없이 쓰지 않는다 (fail closed 로 동작하지 않음).
- 로그 규칙 ([SECURITY.md §4](SECURITY.md)) 을 지킨다.
- 음성 테스트와 fuzz seed 를 함께 추가한다 (§1.6).

### 1.4 메시지 type 추가

알 수 없는 type 은 `DecodeHeader` 가 거부하므로, 새 type 은 v1 peer 와 호환되지 않는다. 새 프로토콜 버전(`kMaxProtocolVersion`) 으로
협상된 연결에서만 보내야 한다. 헤더 `version` (`kWireVersion`) 은 레이아웃이 바뀔 때만 올린다.

1. `protocol/constants.h`: `MessageType` 에 값 추가.
2. `protocol/frame.cpp`: `IsKnownMessageType`, `MessageTypeName` 의 switch 에 추가.
3. `protocol/rules.cpp`: `CheckHeaderForState` 에 수신 역할과 허용 `Phase` 를 추가. auth 길이, flags/request id, 크기 상한 규칙이
   새 type 에 맞는지 확인한다 (인증 후라도 DATA 가 아니면 4096 상한, request id 금지).
4. `protocol/messages.h/.cpp`: 구조체와 `Encode*`/`Decode*`. 디코더는 모든 필드 범위를 검사하고 `ExpectEnd()` 로 끝낸다.
   인코더는 `SelfCheck` 로 끝낸다. 확장 가능성이 필요하면 처음부터 TLV 영역을 둔다.
5. 인증 후 메시지라면 `ProtectedChannel::Seal` 이 DATA 전용 옵션(request id, response)을 거부하는지 확인한다.
6. Client/Server 의 수신 switch 또는 `MessageDispatcher` 에 handler 를 등록한다 (등록되지 않은 type 은 `SG_PROTOCOL_ERROR`).
7. 테스트: `tests/protocol/messages_test.cpp` (round trip, 필드별 음성 케이스, `Rules.PhaseAndDirectionTable`).
8. Fuzz: `fuzz/fuzz_frame_decoder.cpp` 의 `BuildDispatcher()` 와 seed, `fuzz/fuzz_messages.cpp` 의 선택 switch (`selector % 12` 의
   분기 수도 함께 늘림) 와 seed.

### 1.5 TLV 추가

TLV 영역은 `CLIENT_HELLO`, `SERVER_HELLO`, `CLIENT_PROOF` 에만 있다. 다른 메시지는 고정 레이아웃이라 TLV 를 붙일 수 없다.

1. `protocol/constants.h` 의 `proto::tlv` 에 type 번호를 추가한다 (메시지별 번호 공간). 길이 상한 상수도 추가한다.
2. 메시지 구조체에 필드와 존재 여부(`has_*` 또는 빈 값 = 없음)를 추가한다.
3. 인코더: 값이 있을 때만 `TlvWriter::Add*` 로 추가하고, 쓰기 전에 상한과 문자열 규칙(`IsValidProtocolString`)을 검사한다.
4. 디코더: `switch (e.type)` 에 case 를 추가하고 정확한 길이/범위를 검사한다. 문자열은 `ReadString` 으로 읽는다.
5. 제약을 고려한다: 항목 최대 16 개, 중복 금지, 인증 전 메시지는 payload 4096 bytes 이하.
6. **v1 peer 는 알 수 없는 TLV 를 조용히 무시한다.** 무시되면 보안이 약해지는 확장(반드시 이해해야 하는 확장)은 TLV 만으로
   추가하지 말고 새 프로토콜 버전과 함께 도입한다. integrity 관측 비트도 같은 이유로 새 버전이 필요하다.
7. 테스트와 fuzz seed 를 추가한다.

### 1.6 Fuzz seed 추가 위치

seed corpus 파일은 커밋하지 않는다. 각 fuzz 타깃의 `SockGateFuzzSeeds()` 가 코드로 seed 를 만들고, 필요하면
`sg_mutate_<name> --write-seeds=DIR` 로 파일로 내보낸다 ([BUILD.md §5](BUILD.md)).

| 파일 | seed 형식 |
|---|---|
| `fuzz/fuzz_frame_decoder.cpp` | `{mode, chunk}` 2 bytes + `EncodeFrame` 결과. mode 는 `kModes` (역할·단계 8 조합) 인덱스, bit 7 은 DATA 상한 64 bytes |
| `fuzz/fuzz_messages.cpp` | 선택 바이트 1 개 + payload (`Encode*` 결과, token 공개 부분, token 문자열, base64 텍스트) |
| `fuzz/fuzz_channel.cpp` | 고정 `km`/session id 의 클라이언트 `ProtectedChannel::Seal` 로 만든 프레임과 그 연결 스트림 |

새 메시지나 TLV 를 추가하면 적어도 유효한 인코딩 하나를 seed 로 넣어 mutation 이 그 파서까지 도달하게 한다.

### 1.7 public 에러 코드 추가

1. `include/sockgate/error.h` 의 `SG_StatusCode` **끝에** 추가하고 `SG_StatusString()` 에 case 를 추가한다 (값은 바꾸지 않는다).
2. `core/status.h` 의 `ToPublicStatus` 상한(현재 `SG_IDENTITY_LOST`)을 새 마지막 코드로 바꾼다. 바꾸지 않으면 새 코드가 C ABI 에서
   `SG_INTERNAL_ERROR` 로 바뀐다.
3. `tests/unit/core_test.cpp` 의 status 테스트와 [09 §3](../docs/design/09-public-c-api.md) 을 갱신한다.

## 2. 공용 public 헤더

`include/sockgate/` 의 헤더는 C99/C++ 양쪽에서 컴파일되며 STL, C++ 타입, OS 헤더를 포함하지 않는다.

### 2.1 `sockgate/error.h`

`SG_Status` 는 `int32_t` 이다. 값은 ABI 의 일부이며 끝에만 추가한다. `SG_StatusString()` 은 `static inline` 이라 두 공유 라이브러리가
같은 심볼을 export 하지 않으며, 알 수 없는 값에는 `"SG_UNKNOWN_STATUS"` 를 돌려준다.

| 값 | 이름 | 의미 |
|---:|---|---|
| 0 | `SG_OK` | 성공 |
| 1 | `SG_INVALID_ARGUMENT` | 잘못된 인자·설정 (NULL, 크기, 구조체 size/version, 문자열 길이, 인코딩할 수 없는 메시지) |
| 2 | `SG_OUT_OF_MEMORY` | 메모리 부족 (C ABI 경계에서 `std::bad_alloc` 포함) |
| 3 | `SG_NETWORK_ERROR` | 소켓, 연결, 주소 해석 오류 |
| 4 | `SG_TLS_ERROR` | TLS 협상/레코드 오류, EMS 없는 TLS 1.2 |
| 5 | `SG_CERTIFICATE_ERROR` | 인증서 체인·hostname·유효기간 검증 실패, 인증서/CA 로드 실패 |
| 6 | `SG_PINNING_ERROR` | 검증된 체인에 설정된 SPKI pin 과 일치하는 인증서가 없음 |
| 7 | `SG_AUTH_FAILED` | 인증 실패 (로컬 사유) |
| 8 | `SG_INVALID_SIGNATURE` | 서명 검증 실패 (클라이언트: 요구한 서버 proof 누락/오류) |
| 9 | `SG_CHALLENGE_EXPIRED` | challenge 만료 |
| 10 | `SG_REPLAY_DETECTED` | 이전 sequence 재수신, 중복 요청 id |
| 11 | `SG_PROTOCOL_ERROR` | 형식·단계 규칙 위반, 건너뛴 sequence, tag 검증 실패 |
| 12 | `SG_SERVER_REJECTED` | 서버가 거부 (AUTH_RESULT/REAUTH_RESULT 거부, CLOSE(AUTH_FAILED)) |
| 13 | `SG_SESSION_EXPIRED` | 세션 만료 (CLOSE(SESSION_EXPIRED), sequence 소진) |
| 14 | `SG_INTEGRITY_FAILED` | 무결성 분류 코드. 현재 코드는 반환하지 않는다 |
| 15 | `SG_TIMEOUT` | 타임아웃 |
| 16 | `SG_INVALID_STATE` | 현재 상태에서 허용되지 않는 호출 |
| 17 | `SG_BUFFER_TOO_SMALL` | 호출자 버퍼 부족 |
| 18 | `SG_NOT_SUPPORTED` | 지원하지 않는 기능·플랫폼, 이 빌드가 모르는 0 이 아닌 구조체 필드 |
| 19 | `SG_CLOSED` | 연결이 닫힘 (close_notify, EOF, CLOSE) |
| 20 | `SG_KEYSTORE_ERROR` | key store 오류 |
| 21 | `SG_NOT_FOUND` | 대상 없음 |
| 22 | `SG_ALREADY_EXISTS` | 이미 존재 |
| 23 | `SG_LIMIT_EXCEEDED` | 자원 상한 초과 |
| 24 | `SG_PROXY_ERROR` | proxy 협상 실패 |
| 25 | `SG_VERSION_MISMATCH` | wire layout 버전 불일치, 프로토콜 버전 협상 실패 |
| 26 | `SG_CRYPTO_ERROR` | 암호 연산 실패 (OpenSSL), 함수 수준의 AEAD 인증 실패 |
| 27 | `SG_INTERNAL_ERROR` | 내부 오류, 경계에서 잡힌 예외, 공개 범위 밖 내부 코드 |
| 28 | `SG_STORAGE_ERROR` | 서버 저장소 읽기/쓰기 실패 |
| 29 | `SG_IDENTITY_LOST` | identity 를 보관하던 key store 에 키가 더 이상 없음 |

**wire 로 가는 값은 일반화된다.** `SG_Status` 자체는 직렬화되지 않는다. 네트워크에는 다음만 실린다.

| wire 필드 | 값 | 수신측(클라이언트) 결과 |
|---|---|---|
| `AUTH_RESULT.result` | OK / REJECTED / RETRY_LATER / UNSUPPORTED_VERSION | REJECTED, RETRY_LATER → `SG_SERVER_REJECTED`; UNSUPPORTED_VERSION → `SG_VERSION_MISMATCH` |
| `REAUTH_RESULT.result` | OK / REJECTED / RETRY_LATER | OK 가 아니면 `SG_SERVER_REJECTED` |
| `CLOSE.reason` | NORMAL, PROTOCOL_ERROR, AUTH_FAILED, SESSION_EXPIRED, SERVER_SHUTDOWN, IDLE_TIMEOUT, LIMIT_EXCEEDED | SESSION_EXPIRED → `SG_SESSION_EXPIRED`, AUTH_FAILED → `SG_SERVER_REJECTED`, 그 밖 → `SG_CLOSED` |

- 서버의 인증 실패 사유(`SG_AUTH_FAILED`, `SG_INVALID_SIGNATURE`, `SG_CHALLENGE_EXPIRED`, 미등록·폐기, 권한 거부)는 네트워크에서
  모두 REJECTED 로 보인다 ([05 §5](../docs/design/05-handshake-sequence.md)). 상세 코드는 서버 로그와 서버 콜백에만 남는다.
- `SG_REPLAY_DETECTED`, `SG_PROTOCOL_ERROR`, `SG_CRYPTO_ERROR` 같은 수신측 검증 결과도 로컬 전용이다. 상대에게는 연결 종료
  (최대 `CLOSE(PROTOCOL_ERROR)`) 만 보인다.

### 2.2 `sockgate/types.h`

| 상수 / 타입 | 값 |
|---|---|
| `SG_INSTALLATION_ID_SIZE`, `SG_SESSION_ID_SIZE` | 16, 16 |
| `SG_SHA256_SIZE` | 32 |
| `SG_PUBLIC_KEY_SIZE` | 65 (SEC1 uncompressed P-256) |
| `SG_MAX_PINS`, `SG_MAX_PROOF_KEYS` | 8, 4 |
| `SG_InstallationId`, `SG_SessionId`, `SG_Sha256`, `SG_PublicKey` | 위 크기의 `uint8_t bytes[]` 를 감싼 구조체 |
| `SG_SessionHandle`, `SG_INVALID_SESSION_HANDLE` | `uint64_t`, 0. `SG_Server` 수명 동안 재사용되지 않음 |
| `SG_LOG_NONE` … `SG_LOG_TRACE` | 0–5. DEBUG/TRACE 는 release 에서 `SOCKGATE_ENABLE_DEBUG_LOG` 없이는 제거 |
| `SG_LogCallback` | `void (SG_CALL*)(void* user, uint32_t level, const char* message)`. 메시지에 키, token, 서명, payload 없음 |
| `SG_CLIENT_STATE_*` | DISCONNECTED 0, CONNECTING 1, TLS_HANDSHAKE 2, TLS_ESTABLISHED 3, AUTHENTICATING 4, AUTHENTICATED 5, ACTIVE 6, REFRESHING 7, EXPIRED 8, CLOSED 9 |
| `SG_SESSION_POLICY_*` | NONE 0, NORMAL 1, RESTRICTED 2 (AUTH_RESULT `session_policy` 와 같은 값) |
| `SG_INTEGRITY_*` 관측 비트 | DEBUGGER_PRESENT `1<<0`, PRELOAD_PRESENT `1<<1`, UNSIGNED_EXECUTABLE `1<<2`, ASLR_DISABLED `1<<3`, DEP_DISABLED `1<<4`, CFG_DISABLED `1<<5`, EXECUTABLE_WRITABLE `1<<6`, UNEXPECTED_MODULES `1<<7`, HASH_UNAVAILABLE `1<<8` |
| `SG_INTEGRITY_KNOWN_FLAGS` | `0x000001FF` — 이 밖의 비트는 CLIENT_HELLO 디코딩에서 프로토콜 오류 |
| `SG_INTEGRITY_PLATFORM_*` | WINDOWS 1, LINUX 2, MACOS 3 (integrity report `platform`) |
| `SG_MESSAGE_FLAG_ENCRYPTED`, `SG_MESSAGE_FLAG_RESPONSE` | `1<<0`, `1<<1` (wire flag 비트와 같은 위치) |
| `SG_MessageInfo` | `{ size, version, request_id, flags, reserved }`, `SG_MESSAGE_INFO_VERSION` = 1 |

### 2.3 `sockgate/version.h`, `sockgate/export.h`

- `SOCKGATE_VERSION_MAJOR/MINOR/PATCH` = 0/1/0, `SOCKGATE_VERSION_STRING` = `"0.1.0"`,
  `SOCKGATE_MAKE_VERSION(maj, min, pat)` = `(maj << 16) | (min << 8) | pat`, `SOCKGATE_VERSION`.
- `SOCKGATE_API_VERSION` = 1 (호환되지 않는 C ABI 변경 때만 증가), `SOCKGATE_PROTOCOL_VERSION` = 1 (이 빌드가 구현한 최고 wire 프로토콜 버전).
- `SG_CLIENT_API` / `SG_SERVER_API`: 라이브러리 빌드 시 `SOCKGATE_CLIENT_BUILDING` / `SOCKGATE_SERVER_BUILDING` 이면 export,
  정적 라이브러리 소비자는 `SOCKGATE_CLIENT_STATIC` / `SOCKGATE_SERVER_STATIC` (CMake 타깃이 자동 정의), 그 밖은 import.
  Windows 는 `__declspec(dllexport/dllimport)`, GCC/Clang 은 `visibility("default")`.
- `SG_CALL` 은 Windows 에서 `__cdecl`. `SG_EXTERN_C_BEGIN/END` 는 C++ 에서 `extern "C"`.

## 3. ABI 규칙

설계: [09 §1, §6](../docs/design/09-public-c-api.md). Common 은 규칙을 강제하는 보조 코드(`core/abi.h`, `core/status.h`)를 제공한다.

| 규칙 | 구현 |
|---|---|
| C ABI 만 공개, 예외는 경계를 넘지 않음 | Client/Server `Guard()`: `ToPublicStatus`, `bad_alloc` → `SG_OUT_OF_MEMORY`, 그 밖 예외 → `SG_INTERNAL_ERROR` |
| enum 은 `uint32_t` 필드 + `#define` 상수 | public 헤더 전체 |
| 에러 코드는 끝에만 추가 | `error.h`, `ToPublicStatus` 상한 갱신 (§1.7) |
| 설정 구조체는 `{ uint32_t size; uint32_t version; }` 로 시작, `*_Init()` 으로 초기화 | Client/Server 헤더. 라이브러리는 `size` 안의 필드만 읽는다 |
| 필드는 끝에만 추가, 추가 때마다 `*_VERSION` 증가 | 모든 `*_VERSION` 은 1 에서 시작. 0.1.0 이전 추가분은 버전 1 에 포함 |
| **모르는 뒤쪽 필드는 0 이어야 함** | `sg::CheckUnknownTail(object, size, known)`: `size ≤ known` 이면 OK, `size - known > kMaxUnknownTail` (4096) 이면 `SG_INVALID_ARGUMENT`, 뒤쪽에 0 이 아닌 바이트가 하나라도 있으면 `SG_NOT_SUPPORTED`. 새 헤더로 빌드한 애플리케이션이 옛 라이브러리에서 보안 설정을 조용히 잃지 않게 한다 |
| **끝에 암묵적 padding 없음** | `SG_ASSERT_NO_TAIL_PADDING(type, last)`: `sizeof(type) == offsetof(type, last) + sizeof(last)` 를 `static_assert`. padding 이 생기면 명시적 `reserved` 멤버를 둔다 (초기화되지 않은 padding 이 "설정된 모르는 필드" 로 보이지 않게) |
| export 는 `SG_*_API` 함수만 | Linux: `-fvisibility=hidden` + version script `cmake/sockgate_exports.map` (`SG_*` 만 global), Windows: `__declspec(dllexport)`. shared 빌드의 CTest `sg_exports_sockgate_client` / `sg_exports_sockgate_server` 가 export 표를 헤더 선언과 비교 (`tests/tools/check_exports.cmake`, `nm` / `dumpbin` / `llvm-readobj`) |
| **0.x 동안 minor 버전은 ABI 를 깰 수 있음** | 공유 라이브러리 soname 은 0.x 에서 `MAJOR.MINOR` (`libsockgate_client.so.0.1`), 1.0 부터 `MAJOR`. 패키지 버전 호환성은 0.x 에서 `SameMinorVersion`, 1.0 부터 `SameMajorVersion` (최상위 `CMakeLists.txt` 의 `SOCKGATE_SOVERSION`, `cmake/SockGateInstall.cmake`). `SOCKGATE_API_VERSION` 은 호환되지 않는 C ABI 변경 때 올린다 |
| 설치되는 헤더는 public 헤더뿐 | 8 개 (Common 4, Client 3, Server 1). `src/sockgate_common/**` 는 설치하지 않으며 `tests/package` 가 설치된 목록을 검사 |
| 패키지 | `find_package(SockGate)` → `SockGate::Client`, `SockGate::Server`. static 빌드는 `SockGate::ClientCore`, `SockGate::ServerCore`, `SockGate::Common` 도 export 하지만 이는 정적 링크를 위한 의존성일 뿐 공개 API 가 아니다 ([BUILD.md §1](BUILD.md)) |

`CheckUnknownTail` 과 `SG_ASSERT_NO_TAIL_PADDING` 이 적용되는 입력 구조체: `SG_ClientConfig`, `SG_ServerConfig`, `SG_ProxyConfig`
(`client_api.cpp`), `SG_ServerOptions`, `SG_ServerCallbacks`, `SG_ClientRecord`, `SG_EnrollmentTokenRequest`, `SG_LicenseRecord`
(`server_api.cpp`). 새 입력 구조체를 추가하면 두 검사를 모두 붙인다.
