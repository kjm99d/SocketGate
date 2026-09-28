# 08. Directory Structure

```text
SocketGate/
├── CMakeLists.txt                  최상위 (3개 프로젝트 + tests + fuzz + examples + tools)
├── CMakePresets.json               windows-msvc-*, windows-clangcl-*, linux-gcc-*, linux-clang-*, sanitizer/fuzz 프리셋
├── vcpkg.json                      Windows 의존성 (OpenSSL)
├── vcpkg-configuration.json        vcpkg registry baseline 고정
├── cmake/
│   ├── SockGateOptions.cmake       빌드 옵션 (SOCKGATE_BUILD_SHARED, _TESTS, _FUZZ, _WITH_TPM2 ...)
│   ├── SockGateCompilerFlags.cmake 경고 + 플랫폼별 hardening 플래그
│   ├── SockGateSanitizers.cmake    ASan / UBSan / TSan / libFuzzer
│   └── SockGateConfig.cmake.in     find_package(SockGate) 지원
├── docs/
│   └── design/                     01–13 설계 문서 (이 문서 포함)
│
├── SockGate_Common/
│   ├── CMakeLists.txt              target: sockgate_common (static, PIC)
│   ├── include/sockgate/           공용 public C 헤더 (Client/Server 모두 설치)
│   │   ├── export.h                심볼 export 매크로
│   │   ├── types.h                 공용 타입/상수 (ID, 해시, 상태, 플래그)
│   │   ├── error.h                 SG_Status, 에러 코드, SG_StatusString (inline)
│   │   └── version.h               SOCKGATE_API_VERSION, 버전 매크로
│   ├── src/sockgate_common/        내부 구현 (public 아님)
│   │   ├── core/                   Status, SecureBuffer, 시간, 로깅, 스코프 가드
│   │   ├── serialization/          byte order, bounds-checked Reader / Writer, TLV
│   │   ├── protocol/               FrameHeader, FrameDecoder, 메시지 codec, transcript, sequence 검증
│   │   ├── crypto/                 ICryptoProvider(OpenSSL), ECDSA, AES-GCM ChannelProtector, SPKI
│   │   ├── tls/                    TlsEngine (memory BIO), TlsContext 빌더, 인증서 검증/pinning
│   │   ├── net/                    Endpoint, ITransport, 주소 해석
│   │   └── platform/
│   │       ├── windows/            Winsock 초기화, socket 원시 기능, 시간/랜덤 보조
│   │       └── linux/              POSIX socket 원시 기능
│   └── README.md, ARCHITECTURE.md, THREAT_MODEL.md, PROTOCOL.md,
│       SECURITY.md, BUILD.md, INTEGRATION.md, CHANGELOG.md
│
├── SockGate_Client/
│   ├── CMakeLists.txt              target: sockgate_client (shared 기본, static 옵션)
│   ├── include/sockgate/
│   │   ├── sockgate.h              umbrella 헤더
│   │   ├── client.h                클라이언트 C API
│   │   └── config.h                SG_ClientConfig, SG_ServerConfig, SG_ProxyConfig
│   ├── src/
│   │   ├── core/                   C ABI 구현, 핸들 수명 관리
│   │   ├── auth/                   identity 관리, 클라이언트 핸드셰이크
│   │   ├── crypto/                 IKeyStore 인터페이스, Memory/File(OpenSSL) key store
│   │   ├── protocol/               클라이언트 프레임 송수신기
│   │   ├── session/                ClientSession 상태 머신
│   │   ├── tls/                    클라이언트 TLS 설정 (trust store, hostname, pinning)
│   │   ├── transport/              TcpTransport(블로킹+타임아웃), ProxyConnector
│   │   └── platform/
│   │       ├── windows/            CNG/TPM key store, DPAPI, 시스템 proxy 조회, integrity
│   │       └── linux/              file key store 권한 검사, TPM2 key store, integrity
│   └── (8개 문서)
│
├── SockGate_Server/
│   ├── CMakeLists.txt              target: sockgate_server (shared 기본, static 옵션)
│   ├── include/sockgate/
│   │   └── server.h                서버 C API (SG_ServerOptions, 콜백)
│   ├── src/
│   │   ├── core/                   C ABI 구현, ServerEngine
│   │   ├── auth/                   Authenticator, enrollment token
│   │   ├── crypto/                 서버 proof 서명
│   │   ├── protocol/               Dispatcher
│   │   ├── session/                Connection, SessionManager, sweeper
│   │   ├── tls/                    서버 TLS 컨텍스트
│   │   ├── transport/              IIoService 인터페이스, Listener
│   │   ├── storage/                ClientRegistry, LicenseStore (메모리 + 파일)
│   │   └── platform/
│   │       ├── windows/            IOCP IoService
│   │       └── linux/              epoll IoService
│   └── (8개 문서)
│
├── tests/
│   ├── framework/                  의존성 없는 경량 테스트 프레임워크 (CTest 연동)
│   ├── support/                    런타임 테스트 PKI, 인메모리 transport, 테스트 proxy / MITM
│   ├── unit/                       단위 테스트
│   ├── protocol/                   파서 음성(negative) 테스트
│   ├── security/                   인증/네트워크 공격 시나리오
│   └── integration/                Client ↔ Server 종단 테스트
├── fuzz/                           libFuzzer 타깃 + 비-fuzzer 빌드용 재현 드라이버 + seed corpus
├── examples/                       C 예제 (echo client/server)
├── tools/                          sg_admin (토큰 발급, SPKI pin 계산, 클라이언트 등록)
└── .github/workflows/ci.yml        Windows MSVC / clang-cl, Linux GCC / Clang, sanitizer
```

## Include 규칙

| 위치 | include 형태 |
|---|---|
| Public C 헤더 | `#include <sockgate/client.h>` |
| Common 내부 | `#include "sockgate_common/protocol/frame.h"` |
| Client / Server 내부 | `#include "session/client_session.h"` (각 프로젝트 `src/` 기준) |

- Public 헤더는 C99/C++ 양쪽에서 컴파일되어야 하며 C++ 타입, STL, OS 헤더를 포함하지 않는다.
- `platform/` 아래 파일만 OS 헤더를 include 할 수 있다.
- 비-해당 플랫폼 파일은 CMake 가 소스 목록에서 제외한다(`#ifdef` 로 파일 전체를 감싸지 않는다).

## 네임스페이스

| 네임스페이스 | 내용 |
|---|---|
| `sg` | Status, 공통 유틸 |
| `sg::ser` | serialization |
| `sg::proto` | protocol |
| `sg::crypto` | crypto |
| `sg::tls` | TLS |
| `sg::net` | transport / socket |
| `sg::platform` | OS 추상화 |
| `sg::client` | 클라이언트 구현 |
| `sg::server` | 서버 구현 |
