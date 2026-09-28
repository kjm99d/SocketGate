# SockGate_Client

[English](README.md) | **한국어** | [日本語](README.ja.md)

> 버전 0.1.0 (Unreleased) · C ABI 버전 `SOCKGATE_API_VERSION = 1` · wire protocol v1

SockGate_Client 는 C/C++ 애플리케이션에 임베딩하는 **인증 게이트 클라이언트 라이브러리**이다.
단순 소켓 래퍼가 아니라, 서버를 검증한 TLS 채널 위에서 installation 단위 키로 challenge-response 인증을 하고,
인증된 세션의 모든 프레임을 sequence 와 AEAD tag 로 보호한다. 권한(정책, 기능, 수명)은 항상 서버가 결정한다.

설계의 근거는 [docs/design](../docs/design/) 의 01–13 문서이며, 이 디렉터리의 문서는 클라이언트 관점에서
**현재 코드가 실제로 하는 일**을 설명한다.

## 기능

| 영역 | 내용 |
|---|---|
| TLS | OpenSSL 3 기반 TLS 1.3 (TLS 1.2 는 `SG_CLIENT_FLAG_ALLOW_TLS12` 로만, Extended Master Secret 필수). 체인·hostname/IP·유효기간 검증, 부분 wildcard 금지, 세션 재개·압축·재협상 없음 |
| 서버 인증 | 애플리케이션이 준 CA(`ca_file` / `ca_pem`) 또는 OS trust store(`SG_TRUST_SYSTEM_STORE`), 선택적 **SPKI pinning**(최대 8개, 검증된 체인에만 비교), 선택적 **server proof key**(최대 4개, 설정 시 서버 서명 필수) |
| Installation 키 | ECDSA P-256 키를 **TPM**(Windows CNG Platform Crypto Provider / Linux TPM2), **CNG Software KSP**(DPAPI 보호, non-exportable), **FILE**(Windows DPAPI, Linux 0600), **MEMORY** 에 보관. `SG_KEYSTORE_AUTO` 는 가장 강한 저장소를 고르고 locator 파일로 identity 가 저장소 사이를 옮겨 다니지 않게 한다 |
| 인증 | 서버 challenge 와 TLS exporter 채널 바인딩을 포함한 transcript 에 대한 서명(`SG_Client_Authenticate`). 1회용 enrollment token 으로 새 installation 등록(`SG_Client_Enroll`) — token 비밀은 전송하지 않는다 |
| 보호 채널 | 방향별 sequence(정확히 +1), 요청 ID 단조 증가, 프레임마다 AES-256-GCM tag. `SG_CLIENT_FLAG_APP_ENCRYPTION` 으로 DATA payload 를 애플리케이션 계층에서도 암호화 |
| 재인증 | `SG_Client_Refresh` 또는 `SG_CLIENT_FLAG_AUTO_REFRESH`(수명 80% 경과 시): 새 서명, 방향별 키 교체(epoch+1), TLS 1.3 KeyUpdate |
| Proxy | 기본 **DIRECT**(시스템 설정·환경 변수를 읽지 않음). `SG_PROXY_MODE_SYSTEM`(요청 시에만 OS 설정 조회), `SG_PROXY_MODE_EXPLICIT`(HTTP CONNECT / SOCKS4a / SOCKS5). proxy 는 TLS 암호문만 중계한다 |
| Integrity | `SG_CLIENT_FLAG_INTEGRITY_REPORT` 시 실행 파일/라이브러리 SHA-256, 디버거, ASLR 등 관측값을 서버에 보고. **서버가 신뢰를 낮추는 데만** 쓰는 주장(claim)이다 |
| 실행 모델 | 동기(blocking) + 타임아웃 API. 라이브러리는 스레드를 만들지 않는다. Send/Receive 동시 호출, 다른 스레드에서 Disconnect 로 대기 중인 호출을 깨우기 지원 |

## Windows 와 Linux 에서 같은 API

공개 API 는 `#include <sockgate/client.h>` 하나로 충분하다(`config.h`, `types.h`, `error.h`, `export.h`,
`version.h` 를 함께 포함한다). 헤더는 C99/C++ 양쪽에서 컴파일되며 OS 헤더, C++ 타입, STL 을 포함하지 않는다.
함수 이름, 구조체 레이아웃, 에러 코드 값, 동작 계약은 두 플랫폼에서 같다. 플랫폼 차이는 다음뿐이며
모두 **같은 API 의 반환값**으로 드러난다.

- 그 플랫폼에 없는 key store 종류(예: Linux 의 `SG_KEYSTORE_CNG_TPM`, tpm2-tss 없이 빌드한 `SG_KEYSTORE_TPM2`)는 `SG_Client_Create` 에서 `SG_NOT_SUPPORTED`.
- 기본 key 디렉터리, `SG_PROXY_MODE_SYSTEM` 의 설정 출처, integrity 관측 항목이 OS 별로 다르다.

```c
#include <sockgate/client.h>   /* Windows (MSVC, clang-cl) 와 Linux (GCC, Clang) 에서 동일 */
```

## 최소 사용 예

[examples/echo_client.c](../examples/echo_client.c) 를 줄인 것이다(순수 C, 공개 API 만 사용).

```c
#include <sockgate/client.h>
#include <stdio.h>

int echo_once(const char* host, uint16_t port, const char* ca_file, const SG_Sha256* pin)
{
    SG_ClientConfig config;
    SG_ServerConfig server;
    SG_IdentityInfo id;
    SG_MessageInfo info;
    SG_Client* client = NULL;
    char reply[1024];
    size_t received = 0;
    uint64_t request_id = 0;
    SG_Status st;

    SG_ClientConfig_Init(&config);                      /* 기본값 채우기 (size/version 포함) */
    config.identity_name = "com.example.sockgate-echo"; /* reverse-DNS: 사용자 단위로 공유되는 이름 */
    config.key_store_type = SG_KEYSTORE_AUTO;           /* 기본값: TPM 우선 */
    config.product_id = "sockgate-echo";                /* 주장(claim)일 뿐, 서버가 판단 */
    config.flags = SG_CLIENT_FLAG_APP_ENCRYPTION | SG_CLIENT_FLAG_AUTO_REFRESH;
    st = SG_Client_Create(&config, &client);
    if (st != SG_OK) return (int)st;

    SG_IdentityInfo_Init(&id);
    st = SG_Client_EnsureIdentity(client, &id);         /* 없으면 생성, 있으면 로드 */
    if (st == SG_OK) {
        /* id.public_key (65 bytes) 를 서버에 등록하거나 SG_Client_Enroll 을 사용한다. */
        SG_ServerConfig_Init(&server);
        server.host = host;
        server.port = port;
        server.ca_file = ca_file;                       /* 사설 CA */
        server.spki_pins = pin;                         /* 운영 환경에서는 pin 권장 */
        server.spki_pin_count = pin != NULL ? 1u : 0u;

        st = SG_Client_Connect(client, &server);        /* TCP (+proxy) + TLS + 서버 검증 */
        if (st == SG_OK) st = SG_Client_Authenticate(client);
        if (st == SG_OK) st = SG_Client_SendEx(client, "hello", 5, 0, &request_id);
        if (st == SG_OK) {
            SG_MessageInfo_Init(&info);
            st = SG_Client_ReceiveEx(client, reply, sizeof(reply), &received, &info, SG_WAIT_DEFAULT);
        }
        if (st != SG_OK) fprintf(stderr, "sockgate: %s\n", SG_StatusString(st));
    }
    SG_Client_Disconnect(client);
    SG_Client_Destroy(client);
    return (int)st;
}
```

예제 실행 파일 `sg_echo_client` 는 `SOCKGATE_BUILD_EXAMPLES=ON`(기본) 빌드에 포함된다.

```text
sg_echo_client --host HOST --port N --ca FILE [--pin HEX] [--identity NAME]
               [--key-dir DIR] [--product ID] [--enroll-file FILE]
```

- 시작하면 installation ID 와 공개키를 hex 로 출력한다. 등록되지 않은 installation 이면 그 공개키를 서버에 등록하거나
  `--enroll-file FILE` 로 enrollment 한다([INTEGRATION.md §9](INTEGRATION.md#9-installation-등록-out-of-band-vs-enrollment)).
  token 은 프로세스 목록이나 셸 기록에 남지 않도록 명령줄이 아니라 **파일**(한 줄)에서 읽고, 사용 직후 volatile 저장으로
  지운다(`memset` 은 컴파일러가 없앨 수 있다. 애플리케이션도 `SecureZeroMemory` / `explicit_bzero` / volatile 루프로 지워야 한다).
- `--port` 는 1..65535 의 10 진수만 받는다. `--key-dir` 를 주면 FILE key store, 아니면 AUTO.
- 받은 응답은 비신뢰 데이터로 다룬다: `SG_MESSAGE_FLAG_RESPONSE` 가 있고 `request_id` 가 방금 보낸 요청의 ID 인지 확인하며,
  출력할 수 없는 바이트는 `\xNN` 으로 escape 한다.

## 빌드와 링크

```cmake
find_package(SockGate 0.1 REQUIRED)                    # 0.x 동안은 같은 minor 버전만 호환
target_link_libraries(myapp PRIVATE SockGate::Client)
```

설치 패키지에는 공개 헤더 8 개와 라이브러리, CMake 설정만 들어간다. 프리셋, 옵션, 공유/정적 차이, soname 은
[BUILD.md](BUILD.md) 참고.

## 디렉터리 구성

```text
SockGate_Client/
├── CMakeLists.txt                sockgate_client_core (내부 static) + sockgate_client (공개, SockGate::Client)
├── include/sockgate/
│   ├── client.h                  클라이언트 C API
│   ├── config.h                  SG_ClientConfig, SG_ServerConfig, SG_ProxyConfig, 상수
│   └── sockgate.h                umbrella 헤더 (version/error/types/config/client)
├── src/
│   ├── core/client_api.cpp       C ABI: 인자 검증, 구조체 size/version, 예외 → SG_Status
│   ├── session/                  ClientSession: 상태 머신, 연결 세대, 잠금, 재인증
│   ├── auth/                     ClientHandshake: CLIENT_HELLO / CLIENT_PROOF / AUTH_RESULT (sans-IO)
│   ├── tls/                      TlsChannel: ITransport 위의 blocking TLS
│   ├── transport/                TcpTransport, proxy 협상, transport_factory (proxy 정책)
│   ├── crypto/                   IKeyStore, MEMORY / FILE / AUTO key store, factory
│   └── platform/
│       ├── windows/              CNG key store, DPAPI key 파일, 시스템 proxy(WinHTTP), integrity
│       └── linux/                POSIX key 파일, TPM2 key store, 시스템 proxy(환경 변수), integrity
└── *.md                          이 문서들
```

프로토콜 직렬화, 프레임 보호, TLS 엔진, 소켓 원시 기능은 서버와 공유하는
[SockGate_Common](../SockGate_Common/README.ko.md) 에 한 벌만 있다.

## 문서

| 문서 | 내용 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 구성 요소, 상태 머신, 연결 세대와 잠금, key store, 스레드 안전성 |
| [THREAT_MODEL.md](THREAT_MODEL.md) | 클라이언트 측 위협과 대응, 잔여 위험 |
| [PROTOCOL.md](PROTOCOL.md) | 클라이언트가 보는 핸드셰이크/재인증/채널 규칙과 SG_* 코드 매핑 |
| [SECURITY.md](SECURITY.md) | 안전한 설정, key store 선택, 보안 테스트, 취약점 보고 |
| [BUILD.md](BUILD.md) | 요구 사항, 프리셋, 옵션, 테스트, 설치와 `find_package(SockGate)`, CI |
| [INTEGRATION.md](INTEGRATION.md) | 임베딩 단계별 가이드: 설정 필드와 기본값, 호출 순서, 오류 처리, ABI 규칙 |
| [CHANGELOG.md](CHANGELOG.md) | 변경 이력 |

설계 문서: [01 Architecture](../docs/design/01-architecture.md) ·
[02 Threat Model](../docs/design/02-threat-model.md) ·
[04 Protocol](../docs/design/04-protocol-specification.md) ·
[05 Handshake](../docs/design/05-handshake-sequence.md) ·
[06 Key Lifecycle](../docs/design/06-key-lifecycle.md) ·
[07 Session Lifecycle](../docs/design/07-session-lifecycle.md) ·
[09 Public C API](../docs/design/09-public-c-api.md) ·
[13 Security Limitations](../docs/design/13-security-limitations.md)
