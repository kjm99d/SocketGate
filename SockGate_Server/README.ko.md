# SockGate_Server

[English](README.md) | **한국어** | [日本語](README.ja.md)

SockGate 의 **서버 라이브러리**이다. C/C++ 서버 애플리케이션에 임베딩되어, TLS 위에서 클라이언트 installation 을
암호학적으로 인증하고, 라이선스·기능·무결성 정책을 **서버에서** 최종 판단한 뒤, 인증된 세션의 메시지를
애플리케이션 콜백으로 전달한다. 공개 인터페이스는 C ABI 하나(`sockgate/server.h`)뿐이다.

- 버전: 0.1.0 (미릴리스), `SOCKGATE_API_VERSION` 1, wire protocol v1
- 플랫폼: Windows 10/11 x64 (IOCP), Linux x64/ARM64 (epoll)
- 런타임 의존성: OpenSSL ≥ 3.0 ([BUILD.md](BUILD.md))

설계 기준 문서는 [`docs/design`](../docs/design/) 의 01–13 이다. 이 디렉터리의 문서는 서버 라이브러리의 실제 구현을
기준으로 쓴 것이며, 설계와 구현이 다른 부분은 구현을 따른다.

## 기능

| 영역 | 내용 |
|---|---|
| 전송 보안 | TLS 1.3 (기본). `SG_SERVER_OPT_ALLOW_TLS12` 로 TLS 1.2 를 허용하면 ECDHE + AEAD suite 만 쓰고 **Extended Master Secret 이 협상된 연결만** 받는다. 압축·재협상·세션 재개(ticket, session cache) 비활성 |
| 클라이언트 인증 | installation 단위 ECDSA P-256 키 + 1회용 challenge 서명. 서명 대상 transcript 에 TLS exporter 채널 바인딩(RFC 9266) 포함 → TLS 를 종단한 중계자는 인증 세션을 만들 수 없다 |
| 등록 | ① `SG_Server_RegisterClient` 로 공개키 직접 등록, ② `SG_Server_IssueEnrollmentToken` 이 발급한 1회용 enrollment token (token 비밀은 전송되지 않고 채널 결속 HMAC 으로만 증명), ③ 외부 발급 token 을 `on_enroll` 콜백으로 검증 |
| 서버 proof (선택) | `proof_key_file` / `proof_key_pem` 을 설정하면 AUTH_RESULT(OK) 에 서버 서명을 붙인다 (TLS PKI 와 독립된 서버 인증. 거부 응답에는 서명하지 않음) |
| 라이선스 | 서버측 license store (메모리 또는 파일), 내장 인가(`BuiltinAuthorizer`): registry 바인딩 우선, `granted = requested & license.features`, 만료가 세션 수명을 제한, 좌석(`max_installations`), `SG_SERVER_OPT_REQUIRE_LICENSE`, `SG_SERVER_OPT_LICENSE_ACTIVATION` |
| 애플리케이션 인가 | `on_authorize` 콜백이 내장 결정을 보고 거부·축소·확장할 수 있다 |
| Integrity 정책 | 클라이언트 보고(`SG_INTEGRITY_*`)와 서버 판단 조건(보고 없음, allowlist 에 없는 실행 파일)을 `integrity_reject_mask` / `integrity_restrict_mask` 로 평가. **신뢰를 낮추는 데만** 사용 |
| 폐기 | `SG_Server_RevokeClient` / `SG_Server_RevokeLicense` / `SG_Server_ReleaseLicenseSeat` 는 해당 활성 세션을 즉시 종료한다. 인가 중인 연결과의 경합은 폐기 세대 카운터로 다시 확인한다. 저장에 실패한 폐기도 프로세스 안에서는 유효하며, 다시 호출하면 저장을 재시도한다 |
| 세션 보호 | 인증 후 모든 프레임에 방향별 sequence + AES-256-GCM tag, 선택적 payload 암호화(`SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION`), 재인증 시 epoch 별 rekey + TLS KeyUpdate |
| 자원 보호 | `max_connections`, 인증 전 연결 수 상한(`max_unauthenticated`), 핸드셰이크 타임아웃, 인증 전(과 인증 후 DATA 가 아닌) 프레임의 payload 4 KiB 상한, 세션 수명·idle 타임아웃, 재인증 최소 간격, 수신/송신 backpressure 상한 |
| I/O | Windows IOCP (`AcceptEx`/`WSARecv`/`WSASend`), Linux epoll (`EPOLLONESHOT`). 워커 스레드 기본값 = 하드웨어 스레드 수 (지정한 값도 최대 64) |
| 저장소 | client registry / license store 를 파일로 영속화 (소유자 전용 임시 파일 + 원자적 rename, 로드 시 비신뢰 입력으로 검증, 열려 있는 동안 `<path>.lock` 으로 다른 프로세스의 사용 차단) |

보장하지 않는 것은 [THREAT_MODEL.md](THREAT_MODEL.md) 의 잔여 위험과
[13-security-limitations.md](../docs/design/13-security-limitations.md) 를 참고한다.

## 최소 사용 예

[`examples/echo_server.c`](../examples/echo_server.c) 를 줄인 골격이다. 받은 메시지를 요청 ID 에 대한 응답으로 되돌려 보낸다.

```c
#include <sockgate/server.h>
#include <stdio.h>

static SG_Server* g_server = NULL;

static void SG_CALL on_log(void* user, uint32_t level, const char* message)
{
    (void)user;
    fprintf(stderr, "[sockgate:%u] %s\n", (unsigned)level, message);
}

static void SG_CALL on_message(void* user, SG_SessionHandle session, const void* data, size_t size,
                               const SG_MessageInfo* info)
{
    (void)user;
    /* 콜백 안에서 SG_Server_SendEx 를 호출해도 된다 (내부 lock 을 잡지 않은 상태로 호출됨). */
    SG_Status st = SG_Server_SendEx(g_server, session, data, size, info->request_id);
    if (st != SG_OK) fprintf(stderr, "echo failed: %s\n", SG_StatusString(st));
}

static void SG_CALL on_closed(void* user, SG_SessionHandle session, SG_Status reason)
{
    (void)user;
    printf("session %llu closed (%s)\n", (unsigned long long)session, SG_StatusString(reason));
}

int main(void)
{
    SG_ServerCallbacks callbacks;
    SG_ServerOptions options;
    SG_Status st;
    uint16_t port = 0;

    SG_ServerCallbacks_Init(&callbacks);
    callbacks.on_message = on_message;
    callbacks.on_session_closed = on_closed;

    SG_ServerOptions_Init(&options);            /* 모든 기본값 + size/version */
    options.port = 7443;
    options.tls_cert_chain_file = "server.crt"; /* leaf 먼저, 그 뒤 중간 인증서 */
    options.tls_private_key_file = "server.key";
    options.registry_path = "registry.bin";     /* NULL 이면 메모리 registry */
    options.license_path = "licenses.bin";      /* NULL 이면 메모리 license store */
    options.callbacks = &callbacks;             /* SG_Server_Create 에서 복사됨 */
    options.log_callback = on_log;
    options.log_level = SG_LOG_INFO;

    st = SG_Server_Create(&options, &g_server);
    if (st != SG_OK) { fprintf(stderr, "create: %s\n", SG_StatusString(st)); return 1; }
    st = SG_Server_Start(g_server);
    if (st != SG_OK) { fprintf(stderr, "start: %s\n", SG_StatusString(st)); SG_Server_Destroy(g_server); return 1; }
    SG_Server_GetPort(g_server, &port);
    printf("listening on %u, press Enter to stop\n", (unsigned)port);

    (void)getchar();
    SG_Server_Destroy(g_server);                /* Stop 포함: 세션 종료 후 해제 */
    return 0;
}
```

클라이언트를 받으려면 그 installation 을 먼저 등록하거나(`SG_Server_RegisterClient`, `sg_admin client register`),
enrollment 를 허용하고 token 을 발급해야 한다. 단계별 설명은 [INTEGRATION.md](INTEGRATION.md) 에 있다.

빌드된 예제 실행 (개발용 PKI 는 `sg_admin dev-pki` 로 만든다):

```text
sg_admin dev-pki ./pki --host localhost
sg_echo_server --cert ./pki/server.crt --key ./pki/server.key --port 7443 \
               --registry registry.bin --issue-token example-product
(출력된 token 을 token.txt 에 저장)
sg_echo_client --host localhost --port 7443 --ca ./pki/ca.crt --product example-product --enroll-file token.txt
```

- `sg_echo_server` 는 `--bind` 를 주지 않으면 `127.0.0.1` 에서만 listen 한다 (라이브러리 자체의 `bind_address` 기본값은 `0.0.0.0`).
  `--port` 는 0–65535 의 10진수만 받는다 (0 = 빈 포트). `--issue-token PRODUCT [--license ID]` 는 enrollment 를 허용하고 1회용 token 을 출력한다.
  `--token-key FILE` 은 32–256 bytes 파일이어야 한다 (더 길면 오류). 라이선스 ID 는 출력하지 않는다.
- `sg_echo_client` 는 token 을 명령행이 아니라 `--enroll-file` 파일에서 읽는다 (프로세스 목록·셸 기록에 남지 않게).
  `--enroll-file` 이 없으면 이미 등록된 installation 으로 인증하며, out-of-band 등록용 공개키를 출력한다.

## 디렉터리 구성

```text
SockGate_Server/
├── CMakeLists.txt              sockgate_server_core (내부 정적) + sockgate_server (공개, SockGate::Server)
├── include/sockgate/
│   └── server.h                공개 C API (SG_ServerOptions, 콜백, registry/license 관리)
└── src/
    ├── core/
    │   ├── server_api.cpp      C ABI 경계: 인자/구조체 검증, 옵션 파싱, 콜백 브리지, 예외 차단
    │   └── server_engine.*     ServerEngine: accept, 연결 테이블, sweeper, 관리 API, 폐기 세대 카운터
    ├── session/
    │   └── connection.*        Connection: TLS + FrameDecoder + 핸드셰이크 + ProtectedChannel + 재인증 + 이벤트 큐
    ├── auth/
    │   ├── server_handshake.*  CLIENT_HELLO / CLIENT_PROOF 처리, enrollment 검증, AUTH_RESULT
    │   ├── authorizer.h        IAuthorizer, AuthorizationRequest / AuthorizationDecision
    │   └── builtin_authorizer.* 라이선스·integrity 내장 인가 + on_authorize hook + 좌석 확정
    ├── storage/
    │   ├── client_registry.*   installation 레코드 + 사용된 token ID (메모리 / 파일 "SGRG")
    │   ├── license_store.*     라이선스와 좌석 (메모리 / 파일 "SGLC")
    │   └── atomic_file.h       ReadWholeFile / WriteFileAtomically
    ├── transport/
    │   └── io_service.h        IIoService / AsyncStream (completion 스타일 비동기 I/O 추상화)
    └── platform/
        ├── windows/            iocp_io_service.cpp, atomic_file_win.cpp
        └── linux/              epoll_io_service.cpp, atomic_file_posix.cpp
```

프로토콜 codec, TLS 엔진, 암호 프리미티브, 채널 보호(`ProtectedChannel`)는 클라이언트와 공유하는
`SockGate_Common` 에 한 벌만 있다. 관련 도구와 예제는 저장소 루트의 `tools/sg_admin.cpp`,
`examples/echo_server.c` 이다.

## 문서

| 문서 | 내용 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 구성 요소, 스레드 모델, 콜백 스레딩 계약, 저장소 형식, sweeper, 폐기 세대 카운터 |
| [THREAT_MODEL.md](THREAT_MODEL.md) | 서버측 자산, 공격자, 신뢰 경계, 위협별 대응, 잔여 위험 |
| [PROTOCOL.md](PROTOCOL.md) | 서버가 보는 wire protocol: 단계별 허용 프레임, 메시지 검증, 거부 방식, 키/sequence 규칙 |
| [SECURITY.md](SECURITY.md) | 보안 속성, 안전한 배포 지침, hardening, 알려진 한계, 취약점 신고 |
| [BUILD.md](BUILD.md) | 요구 사항, 프리셋, CMake 옵션, 테스트, sanitizer/fuzz, 설치와 `find_package(SockGate)` |
| [INTEGRATION.md](INTEGRATION.md) | 임베딩 단계별 안내: 옵션 기본값, 콜백, 등록/라이선스/integrity, 오류 처리, `sg_admin`, ABI 규칙 |
| [CHANGELOG.md](CHANGELOG.md) | 변경 이력 |
