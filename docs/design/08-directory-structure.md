# 08. Directory Structure

```text
SocketGate/
├── CMakeLists.txt                  최상위 (3개 프로젝트 + tests + fuzz + examples + tools)
├── CMakePresets.json               windows-msvc-*, windows-clangcl-*, linux-gcc-*, linux-clang-*, sanitizer/fuzz 프리셋
├── vcpkg.json                      Windows 의존성 (OpenSSL)
├── vcpkg-configuration.json        vcpkg registry baseline 고정
├── cmake/
│   ├── SockGateOptions.cmake       빌드 옵션 (SOCKGATE_BUILD_SHARED, _TESTS, _FUZZERS, _WITH_TPM2 ...)
│   ├── SockGateCompilerFlags.cmake 경고 + 플랫폼별 hardening 플래그
│   ├── SockGateSanitizers.cmake    ASan / UBSan / TSan / libFuzzer
│   ├── SockGateInstall.cmake       install 규칙, CMake 패키지 생성
│   ├── sockgate_exports.map        Linux version script (SG_* 만 global)
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
│   │   ├── core/                   Status, SecureBytes(bytes.h, 해제 시 0 으로 지움), 시간/Deadline, 로깅, 공개 구조체 size/version 보조(abi.h)
│   │   ├── serialization/          byte order, bounds-checked Reader / Writer, TLV, base64url
│   │   ├── protocol/               FrameHeader, FrameDecoder, 메시지 codec, transcript, 상태별 헤더 규칙(rules),
│   │   │                           ProtectedChannel (AES-GCM 채널 보호 + sequence/request id 검증), enrollment token.
│   │   │                           rules.h 의 `MessageDispatcher` 는 tests/fuzz 에서만 쓰인다 (Client/Server 는 자체 분기)
│   │   ├── crypto/                 crypto.h 자유 함수 (OpenSSL 구현: SHA-256, HMAC, HKDF, AES-GCM, ECDSA, RNG)
│   │   ├── tls/                    TlsEngine (memory BIO), TlsContext 빌더, 인증서 검증/pinning, SPKI
│   │   ├── net/                    Endpoint, ITransport
│   │   └── platform/               socket.h (socket 원시 기능, 주소 해석), trust_store.h
│   │       ├── windows/            Winsock 초기화, socket 원시 기능, 시스템 trust store
│   │       └── linux/              POSIX socket 원시 기능, 시스템 trust store (별도 posix/ 없음)
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
│   │   ├── auth/                   클라이언트 핸드셰이크 (ClientHandshake)
│   │   ├── crypto/                 IKeyStore 인터페이스, identity 관리, Memory/File(OpenSSL)/AUTO key store, key store factory
│   │   ├── session/                ClientSession 상태 머신 (프레임 송수신 포함. 별도 protocol/ 없음 — 프레이밍은 Common)
│   │   ├── tls/                    TlsChannel (TLS 엔진 ↔ transport. 설정/검증/pinning 은 Common tls/)
│   │   ├── transport/              TcpTransport(블로킹+타임아웃), proxy 협상, transport factory
│   │   └── platform/               integrity.h, key_file.h (플랫폼별 구현의 공통 선언)
│   │       ├── windows/            CNG/TPM key store, key file(DPAPI), 시스템 proxy 조회, integrity
│   │       └── linux/              key file(디렉터리/권한 검사), TPM2 key store, proxy 환경 변수, integrity
│   └── (8개 문서)
│
├── SockGate_Server/
│   ├── CMakeLists.txt              target: sockgate_server (shared 기본, static 옵션)
│   ├── include/sockgate/
│   │   └── server.h                서버 C API (SG_ServerOptions, 콜백)
│   ├── src/
│   │   ├── core/                   C ABI 구현, ServerEngine (연결 표, 연결 상한, sweeper)
│   │   ├── auth/                   ServerHandshake (인증, enrollment 검증, 서버 proof 서명), IAuthorizer / BuiltinAuthorizer
│   │   ├── session/                Connection (연결별 상태 머신, 메시지 분기)
│   │   ├── transport/              IIoService / AsyncStream 인터페이스
│   │   ├── storage/                ClientRegistry, LicenseStore (메모리 + 파일), 원자적 파일 쓰기 / store lock
│   │   └── platform/
│   │       ├── windows/            IOCP IoService (AcceptEx listener 포함), 파일 쓰기 / lock
│   │       └── linux/              epoll IoService (listener 포함), 파일 쓰기 / lock
│   │   (서버 전용 crypto/, protocol/, tls/ 는 없다: 암호·프레이밍·TLS 컨텍스트는 Common 을 쓴다)
│   └── (8개 문서)
│
├── tests/
│   ├── framework/                  의존성 없는 경량 테스트 프레임워크 (CTest 연동)
│   ├── support/                    런타임 테스트 PKI, 인메모리 transport, 테스트 proxy / MITM
│   ├── unit/                       단위 테스트
│   ├── protocol/                   파서 음성(negative) 테스트
│   ├── security/                   인증/네트워크 공격 시나리오
│   ├── integration/                Client ↔ Server 종단 테스트
│   ├── package/                    설치된 CMake 패키지의 외부 소비자 테스트 (find_package(SockGate), CI)
│   └── tools/                      check_exports.cmake (CTest sg_exports_*: 공개 C ABI 만 export 되는지 검증)
├── fuzz/                           libFuzzer 타깃 (frame_decoder, messages, channel, proxy_config, storage_files)
│                                   + 비-fuzzer 빌드용 결정적 mutation 드라이버 (standalone_main.cpp, CTest sg_mutate_*).
│                                   seed corpus 파일은 없다: seed 는 각 타깃의 SockGateFuzzSeeds() 가 코드로 만들고
│                                   `sg_mutate_<name> --write-seeds=DIR` 로 내보낸다
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
| `sg::client::os` | 클라이언트 플랫폼 보조 (key file 입출력, integrity 수집). CNG/TPM2 key store 와 시스템 proxy 조회는 `sg::client` |
| `sg::server` | 서버 구현 |
