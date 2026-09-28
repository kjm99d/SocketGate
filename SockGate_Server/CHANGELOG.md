# Changelog

SockGate_Server 에 관련된 변경을 기록한다. 형식은 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) 를 따르고,
버전 번호는 `SockGate_Common/include/sockgate/version.h` (`SOCKGATE_VERSION_*`)가 기준이다.
각 항목의 괄호는 해당 커밋이다 (`git log`).

## [0.1.0] — Unreleased

첫 릴리스. 아래는 구현 단계(phase)별로 묶은 서버 관련 변경이다. 클라이언트 전용 변경은 한 줄로만 적는다.

### Phase 0 — 설계 문서 (4e0492e, b9a27ca)

#### Added

- 설계 문서 01–13: 아키텍처, 위협 모델, 신뢰 경계, wire protocol v1, 핸드셰이크, 키·세션 수명, 디렉터리 구조, 공개 C API,
  Windows/Linux 플랫폼 계층, 의존성, 보안 한계. Windows 용 OpenSSL vcpkg manifest.

#### Changed

- 설계 리뷰 반영: enrollment token 비밀을 전송하지 않고 채널 결속 HMAC 으로 증명, `KEY_PHASE` 기반 방향별 키 전환,
  TLS 1.2 는 EMS 필수, 인증 전 프레임은 type 과 무관하게 4 KiB 상한과 헤더 단계 상태 검사, installation ID 를 공개키에서 유도,
  token 소비와 등록의 원자화, 폐기 시 활성 세션 즉시 종료, 재인증 속도 제한.

### Phase 1 — 전송 계층과 빌드 시스템 (8a66626, bf8174c)

#### Added

- CMake 슈퍼프로젝트와 프리셋 (MSVC, clang-cl, GCC, Clang), 경고·hardening 플래그, sanitizer 옵션.
- 공용 public 헤더: 상태 코드(`error.h`), 공용 타입(`types.h`), export 매크로(`export.h`), 버전(`version.h`).
- 서버 `IIoService` / `AsyncStream`: Windows IOCP (`AcceptEx`/`WSARecv`/`WSASend`), Linux epoll (`EPOLLONESHOT`, id 기반 스트림 조회).
- Windows listen 소켓의 배타적 bind (`SO_EXCLUSIVEADDRUSE`).

#### Fixed

- epoll: 반쯤 닫힌 피어가 워커를 100% 점유하던 문제 (`EPOLLRDHUP` 은 읽기가 걸려 있을 때만), wake fd 처리 순서.
- 두 I/O 서비스 공통: listener 소켓은 listener lock 아래에서만 사용·종료, 실패한 accept 슬롯 재시도, `Stop()` 시작 후 `Post()` 거부와
  조건 변수 기반 drain, `Stop()` 직렬화, 던지는 핸들러가 다른 콜백을 건너뛰지 않게 격리.
- graceful close 가 미수신 데이터가 남은 연결을 RST 로 끊지 않고 half-close 후 입력을 비움.

### Phase 2 — TLS (a0e0354)

#### Added

- OpenSSL 3 EVP 기반 암호 provider (SHA-256, HMAC, HKDF, AES-256-GCM, ECDSA P-256, CSPRNG).
- memory BIO 기반 sans-IO TLS 엔진: TLS 1.3 기본, TLS 1.2 는 opt-in 이며 EMS 필수, 압축·재협상·세션 재개 비활성.
- RFC 9266 채널 바인딩과 RFC 5705 exporter, TLS 1.3 KeyUpdate.
- 런타임 테스트 PKI (저장소에 키를 커밋하지 않음)와 TLS 음성 테스트.

### Phase 3 — 프레임, 코덱, 파서 hardening (8b0984f, 9b7bc60)

#### Added

- bounds-checked Reader/Writer, 엄격한 TLV, base64url, protocol string 검증.
- 48 bytes 프레임 헤더 codec 과 스트리밍 `FrameDecoder` (본문 버퍼링 전 헤더 단계 상태 검사).
- 모든 v1 메시지 codec, enrollment token 공개 부분과 `K_tok` 유도, transcript 해시와 서명 도메인 분리, HKDF 채널 키 유도.
- 단계별 수신 규칙 (방향, auth length, flags, 인증 전 4 KiB 상한).
- frame decoder / message codec libFuzzer 타깃과 CTest 결정적 변이 테스트.

#### Fixed

- decoder 가 header check 없이는 fail closed, 인증 전 버퍼 상한 (인증 전 세션이 약 16 MiB 를 붙잡지 못하게).
- 인증 전 프레임은 `request_id == 0` 필수, 알 수 없는 integrity 관측 비트 거부.
- encoder 자체 검증 (상대가 거부할 메시지를 만들지 않음), 거부된 AUTH_RESULT 는 세션 데이터를 담지 못함.
- protocol string 에서 비가시·bidi override·noncharacter 코드 포인트 거부, 버퍼와 token 처리 중간값 zeroing.

### Phase 4 — challenge-response 인증 (9c6d6da)

#### Added

- `ServerHandshake`: 버전 협상, 새 session id 와 TTL 이 있는 1회용 challenge, 연결당 인증 1회, 미등록·폐기 installation 에 대한 더미 키 검증,
  일반화된 거부, 채널 결속 enrollment (서명 전 MAC, claims·만료·제품 검사, `iid = H(key)`), 원자적 token 소비, 인가 hook,
  라이선스 만료로 잘리는 세션 수명, 선택적 서버 proof 서명.
- Client registry (메모리 / 파일, 원자적 교체, 엄격한 로드 검증).
- 보안 테스트: 사칭, 변조, 만료·재사용 challenge, 새 연결 replay, TLS 종단 중계, 버전 불일치, 인가 거부, proof key downgrade,
  enrollment token 재사용·변조·만료·위조·중계.

### Phase 5 — 세션 보호, 서버 엔진, C API (089f513, e7ffea4)

#### Added

- `ProtectedChannel`: 방향별 엄격한 sequence, 방향·epoch 별 AES-256-GCM tag (헤더 AAD), 선택적 payload 암호화, `KEY_PHASE` 와 대기 수신 키를 이용한
  방향별 키 전환, 단조 증가 request ID 와 응답 검증, 첫 실패 시 poison.
- 공개 C API `sockgate/server.h` (`SG_ServerOptions`, `SG_ServerCallbacks`, 세션·registry·token·통계 API).
- `ServerEngine`: 원자적 용량 검사(graceful-close 소켓 포함)를 하는 accept, IOCP/epoll 위의 연결별 상태 머신, 핸드셰이크·세션·idle·challenge
  타임아웃 sweeper, graceful-close 기한, 폐기 시 활성 세션 종료, 통계.
- 애플리케이션 콜백은 내부 lock 없이 세션별로 직렬·순서대로 호출 (인가·enrollment 검증 동안 연결 lock 해제), 콜백 지연 시 읽기 backpressure,
  PING/KeyUpdate 로 쌓이는 미전송 출력 상한.
- 재인증: 속도 제한, 재인가, 대기 수신 키, TLS KeyUpdate. 응답은 피어가 보낸 요청 ID 만 참조 가능.
- 공개 API 를 통한 종단 테스트 23개.

### Phase 6 — proxy 와 MITM 저항 (c884cb9, 5b5058b)

#### Added

- 실제 중개자를 둔 보안 테스트: 모든 proxy 종류가 암호문만 중계, 사용자 설치 CA 로 TLS 를 종단한 MITM 의 중계가 채널 바인딩으로 거부,
  pinning 으로 조기 차단, proof key 로만 탐지되는 가짜 서버. (proxy 지원 자체는 클라이언트 변경.)
- 종단 테스트 하네스(`tests/support/e2e_harness.h`) 분리, 클라이언트 주장과 registry 바인딩 설정 가능.

### Phase 7 — 라이선스와 서버측 인가 (301a57a, eb1f31e)

#### Added

- License store (메모리 / 파일, 로드 시 비신뢰 입력으로 검증)와 `BuiltinAuthorizer`: registry 바인딩 우선, 바인딩 없는 주장은 권한 없음,
  `SG_SERVER_OPT_LICENSE_ACTIVATION` (first wins 영구 바인딩), `granted = requested & license.features`, 라이선스 만료가 세션 수명 제한,
  `SG_SERVER_OPT_REQUIRE_LICENSE`, 허용된 세션만 잡는 좌석.
- `SG_Server_AddLicense`, `SG_Server_RevokeLicense`, `SG_Server_ReleaseLicenseSeat`, `SG_Server_GetLicense` (영향받는 세션 즉시 종료).
- 폐기 세대 카운터: 폐기와 동시에 인가된 연결이 세션을 열기 전 다시 확인 (`SG_Server_RevokeClient` 의 같은 틈도 해결).
- `SG_AuthRequest.license_status` / `license_features`, `SG_ServerSessionInfo.license_status`.

#### Changed

- installation 폐기 시 좌석 반납. 외부 `on_enroll` 승인은 라이선스 주장을 바인딩으로 바꾸지 않음. 라이선스 ID 는 로그에 해시로만 기록.
- 저장하지 못한 라이선스 폐기도 프로세스 안에서는 유효하며 `SG_STORAGE_ERROR` 반환.

#### Fixed

- registry 쓰기 실패 시 installation 폐기가 active 로 되돌아가고 세션도 닫히지 않던 문제. 이제 메모리에서 폐기를 유지하고 세션을 닫은 뒤
  `SG_STORAGE_ERROR` 를 반환한다 (eb1f31e).

### Phase 8 — 클라이언트 key store (9398bf9, e74031d)

- 클라이언트 전용 (FILE / CNG / TPM2 / AUTO key store, 네임스페이스 이름 변경). 서버 변경 없음.

### Phase 9 — integrity 정책과 export hardening (0474a24)

#### Added

- `integrity_reject_mask` / `integrity_restrict_mask`, 서버 조건 `SG_INTEGRITY_REPORT_MISSING`, `SG_INTEGRITY_UNKNOWN_EXECUTABLE`,
  실행 파일 SHA-256 allowlist (`allowed_executables`). 보고는 신뢰를 낮추기만 하며 RESTRICTED 하한은 `on_authorize` 가 풀 수 없다.
- `SG_AuthRequest.integrity_conditions`.

#### Changed

- ABI: 입력 구조체에서 라이브러리가 모르는 뒤쪽 필드가 0 이 아니면 `SG_NOT_SUPPORTED` (버전 간 조용한 보안 설정 손실 방지),
  입력 구조체의 tail padding 금지를 컴파일 시 검증.

#### Security

- 공유 라이브러리가 `SG_*_API` 함수만 정확히 export (ELF version script), CTest `sg_exports_*` 가 export 표를 헤더 선언과 비교.

### Phase 9 이후 수정 (c1adf40, cfdab25, 8522a02, b94a77f)

#### Security

- Windows 저장소 파일(token key, registry, license store)을 디렉터리 ACL 상속 대신 현재 사용자·SYSTEM·Administrators 전용 보호 DACL 로 생성
  (POSIX 는 이미 `0600`) (c1adf40).
- 파일 저장소가 열려 있는 동안 `<path>.lock` 의 배타적 lock (flock / LockFileEx) 을 잡아, 실행 중인 서버와 `sg_admin` 등 두 번째 프로세스가 같은
  저장소를 고쳐 변경(폐기 포함)이 사라지는 일을 막음. 두 번째 사용자는 `SG_INVALID_STATE` (cfdab25).
- 내장 enrollment token 의 유효 기간 30 일 상한을 발급 시뿐 아니라 사용 시에도 검사 (token key 로 서버 밖에서 만든 token 포함) (8522a02).

#### Fixed

- Windows 저장소 lock 을 `CloseHandle` 전에 `UnlockFileEx` 로 명시적으로 해제. 서버 재시작이나 서버 종료 직후의 `sg_admin` 이 아직 남은 lock 때문에
  `SG_INVALID_STATE` 를 받던 문제 (b94a77f).

### Phase 10 — 예제, 관리 도구, 패키지, fuzz, CI (da67590, b4a6510)

#### Added

- `examples/echo_server.c` (`sg_echo_server`): 공개 API 만 쓰는 C 에코 서버. 기본 bind `127.0.0.1`, 엄격한 `--port` (0 = 빈 포트),
  token key 파일 32–256 bytes (더 길면 오류), 라이선스 ID 는 출력하지 않음 (da67590).
- `examples/echo_client.c` (`sg_echo_client`): enrollment token 을 명령행이 아닌 `--enroll-file` 에서 읽고, 응답을 escape 해 출력하며,
  자기 요청 ID 에 대한 `SG_MESSAGE_FLAG_RESPONSE` 응답인지 확인 (da67590).
- `tools/sg_admin.cpp` (`sg_admin`): SPKI pin, token key 생성, 오프라인 token 발급 (1 ms–30 일, 선택적 `--licenses` 바인딩 검사),
  license store / registry 관리, 개발용 PKI (무작위 일련번호, 검증된 SAN, `O=SockGate DEVELOPMENT ONLY`, CA `pathlen:0`).
  명령별 옵션 allowlist, 중복 옵션 거부, 10진수 / `0x` 16진수만 허용, 기존 key·PKI 파일은 `--force yes` 로만 교체,
  서버가 사용 중인 저장소는 "the store is in use" 로 거부 (da67590).
- 설치 규칙과 CMake 패키지: `find_package(SockGate)`, `SockGate::Client` / `SockGate::Server` (정적 빌드는 `ClientCore` / `ServerCore` / `Common` 포함),
  공개 헤더 8개만 설치, 0.x 동안 `SameMinorVersion` 호환성과 MAJOR.MINOR soname (`libsockgate_server.so.0.1`), `SOCKGATE_INSTALL`
  (최상위 빌드에서만 기본 ON), TPM2 정적 패키지의 의존성 누락 시 `SockGate_FOUND FALSE`. `tests/package` 는 out-of-tree 소비자 (da67590).
- fuzz 타깃 `channel`, `proxy_config`, `storage_files` (서버 registry / license 파일의 로드 → 변경 → 저장 → 재로드). 각각 CTest 변이 테스트로도 실행 (b4a6510).
- GitHub Actions CI: Windows (MSVC, clang-cl, ASan), Linux x64/ARM64 (GCC, Clang, ASan/UBSan, TSan), TPM2 (swtpm), 패키지 소비자,
  Debian 12 / Rocky 9 컨테이너, libFuzzer (push 60 s / nightly 20 min). Action 은 SHA 고정, Dependabot 갱신 (b4a6510).

### Phase 10 이후 (877df61, 404abc3, bad2b3a, 5099896, 583d55f)

#### Added

- OpenSSL 3.0.7 미만 경고: configure 단계 경고, 그리고 자체 OpenSSL 을 배포하는 빌드(Windows, 정적 링크)는 `SG_Server_Start` 때
  `event=config_warning` 로그. 배포판 OpenSSL 은 실행 시 판단하지 않음 (404abc3).

#### Changed

- `server.h` 주석 정정: `on_enroll` 은 검증 전에 호출되는 키 조회이며 1회 사용은 registry 단위(증명·키·서명 검증 후, `on_authorize` 전 소비),
  다중 registry 배포는 `on_enroll` 에서 소비할 수 있으나 token 소진 위험이 있음, `on_enroll` 설정 시 내장 token 거부, `token_key` NULL 은
  `SG_Server_Create` 마다 무작위, `RevokeLicense` / `ReleaseLicenseSeat` 도 호출 스레드에서 세션을 닫음, Stop/Destroy 가 전달하는 콜백은
  lifecycle lock 아래에서 실행, 로그 콜백은 내부 lock 아래에서 호출될 수 있음 (5099896).

#### Fixed

- `SG_Server_Start` 를 콜백 안에서 호출하면 `SG_INVALID_STATE` (Stop/Destroy 와 같음). Stop 이 전달한 `on_session_closed` 에서 Start 를 부르면
  lifecycle 에 재진입하던 문제 (583d55f).
- 클라이언트 전용: 알 수 없는 `SG_ServerConfig.flags` 거부 (877df61), `connect_timeout_ms` 가 TCP + proxy + TLS 전체를 제한 (bad2b3a).

### 인증 전 연결 상한 — feat(server) (6d34c39, 8ae636d)

#### Added

- `SG_ServerOptions.max_unauthenticated` (`reserved1` 자리, 구조체 배치 동일): TLS·인증 단계에 있는 연결 수 상한. 0 = `max_connections / 2`
  (최소 1), `max_connections` 보다 크면 `SG_INVALID_ARGUMENT`. 초과 연결은 수락 직후 닫고 `event=connection_refused reason=max_unauthenticated`
  를 남긴다. 열린 세션은 세지 않으므로 인증 전 연결 폭주가 세션 자리를 차지하지 못한다.
- 인증 전에 실패한 연결은 graceful close 가 끝날 때까지 자리를 유지한다 (쓰레기를 보내고 FIN 을 보내지 않는 방식의 우회 방지).

#### Changed

- `SG_ServerSessionInfo.product_id` 주석: 등록된 product 가 없으면 클라이언트가 주장한 값이다 (8ae636d).

### 리뷰 반영 수정 (86cb919, 19d1208, bd6ca45, 6f4566b, 991a1b6, 858b162, b95a843)

#### Fixed

- 저장에 실패한 폐기의 재시도: 예전에는 `SG_Server_RevokeClient` / `SG_Server_RevokeLicense` 를 다시 불러도 쓰기 없이 `SG_OK` 를 돌려줘
  재시작 시 폐기가 사라질 수 있었다. 이제 저장소가 저장되지 않은 폐기를 기억해, 다시 호출하면 쓰기를 재시도하고 그 저장소의 다른 성공적인
  쓰기도 함께 저장한다. registry 는 사용된 token ID 중복이 있는 파일을 거부하고, 로드가 거부할 크기(512 MiB 초과)의 파일은 쓰지 않는다
  (`SG_LIMIT_EXCEEDED`) (19d1208).
- 예제가 token key 와 enrollment token 을 컴파일러가 없앨 수 있는 `memset` 대신 volatile store 로 지운다 (86cb919).

#### Changed

- `server.h` 스레딩 주석: 재인증의 `on_authorize` 는 세션 이벤트 순서 밖의 I/O 스레드에서 실행되어 같은 세션의 `on_message` /
  `on_session_closed` 와 겹칠 수 있으므로, 쓰는 데이터는 동기화하고 실행 중에 해제하지 않아야 한다 (6f4566b).
- Linux sanitizer 테스트 프리셋이 CI 와 같은 `ASAN_OPTIONS` / `UBSAN_OPTIONS` / `TSAN_OPTIONS` 로 실행된다 (bd6ca45).
- 채널 바인딩이 RFC 9266 tls-exporter (길이 0 context) 가 되었다. TLS 1.3 값은 그대로이지만 **업그레이드 주의**: 이 변경 이전에 빌드된 피어와는
  TLS 1.2 (`SG_SERVER_OPT_ALLOW_TLS12`) 로 협상할 때 인증에 실패하므로 서버와 클라이언트를 함께 올린다 (b95a843, common).
- 클라이언트 전용: Connect 도중의 Disconnect 는 모든 단계에서 `SG_CLOSED` (991a1b6), 이름 해석과 system proxy 조회도
  `connect_timeout_ms` 에 포함 (858b162).
