# SockGate_Common

[English](README.md) | **한국어** | [日本語](README.ja.md)

> SockGate 의 공통 구현 계층. **내부 정적 라이브러리**이며 애플리케이션이 직접 링크하는 대상이 아니다.
> 공개 API 는 `SockGate_Client` (`sockgate/client.h`) 와 `SockGate_Server` (`sockgate/server.h`) 의 C ABI 뿐이다.

## 1. 역할

SockGate_Common 은 두 가지를 제공한다.

1. **내부 정적 라이브러리 `sockgate_common`** (CMake alias `SockGate::Common`)
   - 보안에 민감한 코드(직렬화, 프레임/메시지 파서, 암호 프리미티브, TLS 엔진, 소켓 추상화)를 **한 벌만** 둔다.
     Client 와 Server 가 같은 파서·같은 검증 코드를 쓰므로 한쪽만 고쳐지는 결함이 생기지 않는다
     ([01-architecture.md §2](../docs/design/01-architecture.md)).
   - `sockgate_client_core` 와 `sockgate_server_core` 가 `PUBLIC` 으로 링크한다. 테스트와 fuzz 타깃도 직접 링크한다.
   - `src/sockgate_common/**` 헤더는 내부 전용이다. 설치되지 않으며 ABI/API 안정성을 보장하지 않는다.
   - 설치 패키지(`find_package(SockGate)`)에서는 shared 빌드에 포함되지 않고, static 빌드에서만 Client/Server archive 의
     의존성으로 `SockGate::Common` 이 export 된다. 애플리케이션이 직접 링크하는 대상은 아니다 ([BUILD.md §1](BUILD.md)).
2. **공용 public C 헤더** (`include/sockgate/`)
   - Client/Server 양쪽 공개 헤더가 include 하는 공통 정의. Client/Server 패키지와 함께 설치된다
     (설치되는 public 헤더는 이 4 개와 Client 3 개, Server 1 개, 모두 8 개뿐이다).

| 헤더 | 내용 |
|---|---|
| `sockgate/version.h` | `SOCKGATE_VERSION_MAJOR/MINOR/PATCH` (현재 0.1.0), `SOCKGATE_API_VERSION` (1), `SOCKGATE_PROTOCOL_VERSION` (1). 최상위 `CMakeLists.txt` 가 이 파일에서 프로젝트 버전을 읽는다 (버전의 단일 원천) |
| `sockgate/export.h` | `SG_CLIENT_API` / `SG_SERVER_API`, `SG_CALL`, `SG_EXTERN_C_BEGIN/END` |
| `sockgate/error.h` | `SG_Status` (`int32_t`), 에러 코드 0–29, `SG_StatusString()` (`static inline`) |
| `sockgate/types.h` | ID/해시/공개키 구조체, 로그 레벨·콜백, 클라이언트 상태, 세션 정책, integrity 관측 비트, `SG_MessageInfo` |

에러 코드와 ABI 규칙은 [INTEGRATION.md](INTEGRATION.md) 에 정리한다.

## 2. 구성

| 모듈 | 네임스페이스 | 내용 |
|---|---|---|
| `core/` | `sg` | `Status` (`[[nodiscard]]`), `ToPublicStatus`, `SecureBytes`/`SecureZero`/`ConstantTimeEqual`, monotonic clock/`Deadline`, 로그 콜백 `Logger`, ABI 보조(`abi.h`) |
| `serialization/` | `sg::ser` | big-endian `Reader`/`Writer`, 엄격한 TLV 파서, base64url, 프로토콜 문자열(UTF-8) 검증 |
| `protocol/` | `sg::proto` | wire 상수, 48-byte `FrameHeader` 코덱, `FrameDecoder`, 단계별 규칙 `CheckHeaderForState`, 메시지 코덱, transcript/키 유도, enrollment token, 인증 후 프레임 보호 `ProtectedChannel` |
| `crypto/` | `sg::crypto` | OpenSSL 3 EVP 래퍼: SHA-256, HMAC-SHA256, HKDF-SHA256, AES-256-GCM, ECDSA P-256 (P1363), CSPRNG, `SoftwareP256Key` |
| `tls/` | `sg::tls` | sans-IO TLS 엔진 (`ITlsProvider` / `ITlsContext` / `ITlsEngine`, OpenSSL memory BIO), 인증서·hostname 검증, SPKI pinning, exporter / 채널 바인딩, 오래된 번들 OpenSSL 판정 |
| `net/` | `sg::net` | 바이트 스트림 추상화 `ITransport`, `Endpoint` |
| `platform/` | `sg::platform` | Winsock2 / POSIX 소켓 원시 기능, 주소 해석, OS trust store 로드 |

모듈 간 의존 방향과 설계는 [ARCHITECTURE.md](ARCHITECTURE.md), wire format 은 [PROTOCOL.md](PROTOCOL.md) 를 본다.

## 3. 디렉터리

```text
SockGate_Common/
├── CMakeLists.txt                     target: sockgate_common (STATIC), alias SockGate::Common
├── include/sockgate/                  공용 public C 헤더 (C/C++ 양쪽에서 컴파일)
│   ├── error.h  export.h  types.h  version.h
└── src/sockgate_common/               내부 구현 (설치하지 않음)
    ├── core/            status.h  bytes.h/.cpp  clock.h  log.h/.cpp  abi.h
    ├── serialization/   byte_order.h  reader.*  writer.*  tlv.*  base64.*
    ├── protocol/        constants.h  frame.*  rules.*  messages.*  transcript.*
    │                    enrollment_token.*  channel.*
    ├── crypto/          crypto.h  openssl_crypto.cpp
    ├── tls/             tls.h  openssl_tls.cpp
    ├── net/             transport.h
    └── platform/        socket.h  trust_store.h
        ├── windows/     socket_win.cpp  trust_store_win.cpp
        └── linux/       socket_posix.cpp  trust_store_linux.cpp
```

- 내부 include 형태: `#include "sockgate_common/protocol/frame.h"`. public 헤더: `#include <sockgate/types.h>`.
- OS 헤더는 `platform/windows`, `platform/linux` 아래 파일만 include 한다. 해당하지 않는 플랫폼 파일은
  CMake 가 소스 목록에서 뺀다 (`SOCKGATE_PLATFORM`).

## 4. 의존성

- OpenSSL ≥ 3.0 (`OpenSSL::SSL`, `OpenSSL::Crypto`), `Threads::Threads` — `PUBLIC` 링크.
- Windows: `ws2_32`, `crypt32`.
- 그 밖의 외부 라이브러리는 없다. 상세는 [BUILD.md](BUILD.md), [12-dependencies.md](../docs/design/12-dependencies.md).

## 5. 문서

| 문서 | 내용 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 모듈 구조, 에러 모델, 메모리 소거, TLS 엔진, 프레임 디코더, 채널 보호, 플랫폼 추상화 |
| [THREAT_MODEL.md](THREAT_MODEL.md) | 파서/암호 계층에 대한 위협과 대응, 잔여 위험 |
| [PROTOCOL.md](PROTOCOL.md) | wire format 요약 (헤더, 메시지, TLV, 단계 규칙, transcript, 키 유도, token) |
| [SECURITY.md](SECURITY.md) | 암호 선택, TLS 설정, 소거, 상수 시간 비교, 파서 강화, fuzzing, 취약점 보고 |
| [BUILD.md](BUILD.md) | 빌드, OpenSSL 요구사항, 프리셋, fuzzer, 테스트 |
| [INTEGRATION.md](INTEGRATION.md) | SockGate 개발자용: 모듈 사용법, 메시지/TLV 추가, 공용 헤더, ABI 규칙 |
| [CHANGELOG.md](CHANGELOG.md) | 변경 이력 |

설계 기준 문서는 [docs/design](../docs/design/) (01–13) 이다. 특히
[01 Architecture](../docs/design/01-architecture.md), [04 Protocol Specification](../docs/design/04-protocol-specification.md),
[05 Handshake Sequence](../docs/design/05-handshake-sequence.md), [08 Directory Structure](../docs/design/08-directory-structure.md),
[09 Public C API](../docs/design/09-public-c-api.md) 가 이 라이브러리와 직접 관련된다.
