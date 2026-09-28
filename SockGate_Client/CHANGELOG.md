# Changelog

SockGate_Client 의 주요 변경 사항을 기록한다. 형식은 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) 를
따른다. 버전의 단일 출처는 `SockGate_Common/include/sockgate/version.h` 이다.
아래 항목은 저장소 `git log` 에서 클라이언트와 관련된 변경만 추려 개발 단계(phase)별로 묶은 것이며, 괄호 안은 커밋이다.

## [0.1.0] — Unreleased

첫 릴리스 전이다. 이 버전까지의 구조체 필드 추가는 모두 `*_VERSION = 1` 에 포함된다
([09 §6](../docs/design/09-public-c-api.md#6-abi--버전-정책)).

### 설계 (4e0492e, b9a27ca)

- **Added**: 13 개의 설계 문서(아키텍처, 위협 모델, 신뢰 경계, wire protocol v1, 핸드셰이크, 키/세션 수명, 디렉터리,
  공개 C API, Windows/Linux 플랫폼 계층, 의존성, 보안 한계)와 Windows 용 vcpkg manifest.
- **Changed** (설계 리뷰 반영): enrollment token 비밀을 전송하지 않고 채널 결속 HMAC 으로만 증명, 방향별 키 전환과
  `KEY_PHASE` 플래그, SPKI pin 은 검증된 체인에만 비교하고 pinning 해제는 명시적 플래그로만, TLS 1.2 는 EMS 필수,
  인증 전 프레임 4 KiB 상한과 헤더 단계 type/상태 검사, installation ID 를 공개키에서 유도.

### Phase 1 — 크로스 플랫폼 transport 와 빌드 시스템 (8a66626)

- **Added**: MSVC, clang-cl, GCC, Clang 용 CMake 프리셋, 경고/hardening/sanitizer 옵션. Windows 는 vcpkg OpenSSL,
  Linux 는 시스템 OpenSSL.
- **Added**: 클라이언트와 서버가 공유하는 공개 C 헤더(`error.h` 상태 코드, `types.h`, `export.h`, `version.h`).
- **Added**: Winsock2 / POSIX 소켓 계층(상속되지 않는 소켓, 타임아웃 있는 non-blocking connect, Linux `MSG_NOSIGNAL`).
- **Added**: `TcpTransport` — 타임아웃 있는 blocking API, 대기 중인 작업을 깨우는 스레드 간 `Shutdown`, 안전한 `Close`.

### Phase 2 — TLS 1.3, 인증서 검증, SPKI pinning (a0e0354)

- **Added**: OpenSSL 3 EVP 기반 crypto provider(SHA-256, HMAC, HKDF, AES-256-GCM, ECDSA P-256 P1363/SEC1 곡선 검증, CSPRNG).
- **Added**: memory BIO 기반 sans-IO TLS 엔진. TLS 1.3 기본, TLS 1.2 는 opt-in + EMS, 압축·재협상·재개 없음,
  체인 + hostname/IP + 유효기간 검증, 부분 wildcard 거부.
- **Added**: 검증된 체인에만 비교하는 SPKI pinning(교체용 복수 pin), RFC 9266 채널 바인딩, RFC 5705 exporter, KeyUpdate.
- **Added**: OS trust store 로드(Windows ROOT store, OpenSSL 기본 경로).
- **Added**: 클라이언트 `TlsChannel` — 송수신 동시 실행과 레코드 순서가 보장되는 blocking TLS.

### Hardening — transport 동시성 리뷰 (bf8174c)

- **Fixed**: `TcpTransport` 가 `Close()` 와 경합할 때 실패한 connect 의 소켓을 자기가 소유할 때만 닫는다(이중 close,
  재사용된 핸들 close 방지). 소켓 옵션 설정과 in-flight 등록 순서 수정.
- **Fixed**: Windows 에서 `select()` 예외 집합을 connect 대기에만 사용(TCP urgent data 로 인한 busy wait 제거).

### Phase 3 — 바이너리 프로토콜 프레이밍과 파서 hardening (8b0984f, 9b7bc60)

- **Added**: bounds-checked big-endian Reader/Writer, 엄격한 TLV, base64url 과 프로토콜 문자열 검증.
- **Added**: 48 바이트 프레임 헤더 codec 과 스트리밍 `FrameDecoder`(본문 버퍼링 전 헤더 단계 상태 검사, 산술 전 길이 검증).
- **Added**: 모든 v1 메시지 codec, integrity report, enrollment token 공개 부분과 `K_tok`, transcript 해시,
  서명 도메인 분리, installation ID 유도, HKDF 채널 키 유도.
- **Added**: 프로토콜 음성 테스트와 frame decoder / message codec fuzz 타깃(CTest mutation 테스트로도 실행).
- **Fixed** (파서 보안 리뷰): 인증 전 디코더 버퍼 상한, 인증 전 프레임의 `request_id` 0 강제, 알 수 없는 integrity 관측 비트
  거부, 인코더 자체 검증, 비가시·bidi override·noncharacter 코드 포인트 거부, 디코더 버퍼와 token 처리 중간값 제로화.

### Phase 4 — 클라이언트 키 추상화와 challenge-response 인증 (9c6d6da)

- **Added**: `IKeyStore`(이름으로 서명, Core 에 개인키 바이트 없음), 메모리 key store, key 이름 검증, `EnsureIdentity`.
  installation ID 는 공개키에서 유도.
- **Added**: `ClientHandshake` — CLIENT_HELLO, 채널 결속 transcript 에 대한 ECDSA P-256 proof, `K_tok` enrollment proof,
  proof key 가 설정되면 server proof 검증 필수.
- **Added**: 사칭, 변조, 만료/재사용 challenge, 새 연결 재전송, TLS 종단 중계, 버전 불일치, proof key 다운그레이드,
  token 재사용/변조/만료/위조/중계 보안 테스트.

### Phase 5a — 세션 프레임 보호 (089f513)

- **Added**: `ProtectedChannel` — 방향별 정확히 +1 sequence(replay/중복 → `SG_REPLAY_DETECTED`, 재정렬/삭제 →
  `SG_PROTOCOL_ERROR`), 방향·epoch 별 AES-256-GCM tag, `KEY_PHASE` 기반 방향별 키 전환, 요청 ID 단조 증가와 응답 검증,
  첫 실패 시 poison(키 폐기).

### Phase 5b — 클라이언트 세션과 공개 C API (e7ffea4)

- **Added**: `sockgate/client.h`, `sockgate/config.h` 공개 API.
- **Added**: `ClientSession` 상태 머신 — Connect(TCP + TLS 1.3 + 체인/hostname/pin), Authenticate/Enroll, 요청 ID 가 있는
  보호된 Send/Receive, Ping, Refresh(방향별 rekey + TLS KeyUpdate), 만료와 선택적 자동 재인증, 스레드 간 Disconnect.
- **Added**: 연결 세대(Link) — 오래된 작업이 재연결된 세션을 손상시키지 못하고, 제어 작업이 동시 Disconnect 를 덮어쓰지 않음.
- **Added**: Disconnect 시 시간 제한 있는 best-effort CLOSE / close_notify.
- **Added**: 구조체 size/version 처리, 상한 있는 문자열 복사, 예외 격리를 갖춘 C ABI.
- **Added**: 두 공개 API 를 통한 종단간 시나리오 테스트(pinning, enrollment, 거부, 한도, 만료, idle, 트래픽 중 refresh,
  폐기, 동시성, Disconnect 깨우기, 애플리케이션 계층 암호화 정책, 자동 재인증, server proof key).

### Phase 6 — Proxy 지원과 MITM 저항 테스트 (c884cb9, 5b5058b)

- **Added**: 명시적 proxy 정책. 기본 DIRECT(시스템 설정과 `http_proxy`/`https_proxy`/`ALL_PROXY` 를 암묵적으로 쓰지
  않음), 요청 시에만 SYSTEM(Windows WinHTTP IE 설정 읽기 전용, PAC/WPAD 미지원; Linux `ALL_PROXY`/`HTTPS_PROXY`/`NO_PROXY`),
  EXPLICIT HTTP CONNECT(Basic), SOCKS4a, SOCKS5(user/password).
- **Added**: 엄격하고 상한 있는 proxy 응답 파싱(8 KiB 헤더, 바이트 단위 읽기, 정확한 방법 일치), connect 타임아웃 안의
  협상, 자격 증명 비로깅.
- **Added**: pin 불일치 시 예상 밖 발급자를 보고하고 `possible_tls_interception` 이벤트를 로그.
- **Added**: 실제 중계자를 쓰는 보안 테스트 — 모든 proxy 종류의 터널, proxy 인증, 거부/쓰레기/과대/무응답 proxy,
  사용자 설치 CA 를 쓰는 TLS 종단 MITM(채널 바인딩으로 중계 거부, pinning 으로 더 일찍 차단), proof key 로만 탐지되는
  가짜 서버, proxy URL/bypass 파싱. 종단간 테스트 harness 분리.

### Phase 7 — 서버 라이선스 인가 (301a57a, eb1f31e)

클라이언트 코드 변경은 없으며, 클라이언트가 받는 결과가 바뀌었다.

- **Changed**: 클라이언트의 `product_id` / `license_id` / `requested_features` 는 서버의 registry 바인딩과 license store 로
  판단된다. `granted_features = requested & license.features`, 라이선스 만료가 세션 수명을 제한
  (`SG_ClientSessionInfo.license_expires_at_ms`). 라이선스 폐기·좌석 반납은 해당 세션을 즉시 닫는다
  (클라이언트는 `SG_SERVER_REJECTED`).
- **Fixed** (서버): 저장 실패 시에도 installation 폐기가 효력을 유지하고 활성 세션을 닫는다.

### Phase 8 — 플랫폼 key store 와 TPM 지원 (9398bf9, e74031d)

- **Added**: `SG_KEYSTORE_FILE` — identity 당 `<name>.sgkey`(공개키 + 보호된 PKCS#8, 로드마다 pairwise 검사).
  Windows 는 이름에 결속된 DPAPI 와 보호된 owner-only DACL 디렉터리(매 작업 검증), Linux 는 0600/0700 파일을 검증된
  디렉터리 fd 기준으로 다루고 `O_TMPFILE`(대체: `renameat2` NOREPLACE, `linkat`)로 원자적으로 게시, 링크·다른 소유자·
  느슨한 권한 거부.
- **Added**: `SG_KEYSTORE_CNG_TPM` / `SG_KEYSTORE_CNG_SOFTWARE` — Microsoft Platform Crypto Provider(TPM 2.0) 또는
  non-exportable Software KSP.
- **Added**: `SG_KEYSTORE_TPM2`(Linux, `SOCKGATE_WITH_TPM2`) — owner hierarchy 의 유도된 primary 아래 ESAPI 서명 키,
  TPM 이 wrap 한 blob 을 FILE 과 같은 규칙으로 저장.
- **Added**: `SG_KEYSTORE_AUTO` — 키를 만들 수 있는 가장 강한 저장소. identity 별 locator 가 저장소를 기록해, 사용 불가하거나
  키를 잃은 저장소는 `SG_KEYSTORE_ERROR` / 새 `SG_IDENTITY_LOST` 가 되고 대체 identity 를 조용히 만들지 않는다. 확정적인
  답만 "지원 안 함" 으로 취급.
- **Added**: `SG_Client_DeleteIdentityEx(client, SG_IDENTITY_DELETE_FORCE)` — 명시적 초기화.
- **Changed**: key 이름에서 `.` 으로 시작하는 이름과 Windows 장치 이름을 거부.
- **Added**: 변조, 링크, ACL/권한, 동시 생성, locator 의미, 실제 TPM 키 테스트. `SOCKGATE_REQUIRE_TPM=1` 이면 TPM 없음이 실패.
- **Changed** (리팩터링): 클라이언트 플랫폼 네임스페이스를 `sg::client::os` 로 변경(동작 변화 없음).

### Phase 9 — Integrity 보고와 export hardening (0474a24)

- **Added**: `SG_CLIENT_FLAG_INTEGRITY_REPORT`(이전에는 무시됨) — 인증마다 실행 파일/라이브러리 SHA-256
  (`SG_Client_Create` 에서 해시, 성공한 결과만 캐시), Authenticode 상태, 디버거, ASLR/DEP/CFG, preload, 임시 위치에서
  로드된 모듈을 보고.
- **Changed**: 알 수 없는 `SG_CLIENT_FLAG_*` 를 `SG_NOT_SUPPORTED` 로 거부.
- **Security**: 입력 구조체에서 라이브러리가 모르는 0 이 아닌 필드를 거부(버전 간 조용한 보안 다운그레이드 방지),
  입력 구조체에 끝 padding 이 없음을 검사.
- **Security**: 공유 라이브러리는 정확히 `SG_*_API` 함수만 export(ELF version script, CTest 가 export 테이블과 헤더 선언을 비교).

### Enrollment token 수명 (8522a02)

- **Changed**: token 최대 수명(30 일)을 Common 의 공유 상수 `proto::kMaxEnrollmentTokenLifetimeMs` 로 옮기고, 서버가 발급할 때뿐
  아니라 **사용할 때도** 검사한다. 서버 키로 다른 곳에서 만든 더 긴 token 으로 `SG_Client_Enroll` 하면 `SG_SERVER_REJECTED`.
- 같은 시기의 서버 전용 수정(저장소 파일 owner-only DACL c1adf40, 저장소 잠금 cfdab25 / b94a77f)은 클라이언트 동작을
  바꾸지 않는다. 다만 서버가 실행 중이면 `sg_admin client register` 가 registry 를 열지 못한다("the store is in use").

### Phase 10a — 예제, sg_admin, CMake 패키지 (da67590)

- **Added**: `examples/echo_client.c` — 공개 API 만 쓰는 순수 C 예제. enrollment token 을 명령줄 대신 파일에서 읽고
  (`--enroll-file FILE`, 사용 직후 제로화 — 86cb919 에서 volatile 저장으로 교체), `--port` 를 엄격하게 파싱하며, 응답이 방금 보낸 요청에 대한 것인지
  (`SG_MESSAGE_FLAG_RESPONSE` + `request_id`) 확인하고 출력할 수 없는 바이트를 escape 한다.
- **Added**: `sg_admin` — pin 계산, token 키와 token 발급(수명 1 ms..30 일, 선택적 `--licenses` 바인딩 검사), 클라이언트 등록
  (`--pubkey`, 선택적 `--licenses` 검사), 개발용 PKI. 명령별 옵션 allowlist, 엄격한 숫자 파싱, 기존 키 파일은 `--force yes`
  없이 덮어쓰지 않음.
- **Added**: install 규칙과 `find_package(SockGate)` 패키지 — `SockGate::Client` / `SockGate::Server`(정적 빌드는
  `SockGate::ClientCore` / `ServerCore` / `Common` 도), **공개 헤더 8 개만** 설치, 0.x 동안 `SameMinorVersion` 호환과
  `MAJOR.MINOR` soname(`libsockgate_client.so.0.1`, 이전에는 `.so.0`), 옵션 `SOCKGATE_INSTALL`(최상위 빌드에서만 기본 `ON`).
  정적 TPM2 패키지는 tss2 가 없으면 `SockGate_FOUND FALSE` 와 이유를 알린다.
- **Added**: `tests/package` — 설치본을 쓰는 트리 밖 소비자(Client/Server 링크·실행, 설치된 헤더 목록 검사).

### Phase 10b — fuzz 타깃과 CI (b4a6510)

- **Added**: fuzz 타깃 `channel`(받아들인 프레임은 연속 sequence, poison 된 채널은 회복하지 않음), `proxy_config`(클라이언트
  proxy URL / WinINet 목록 / bypass 파서), `storage_files`(서버). 모두 libFuzzer 타깃이자 CTest mutation 테스트.
- **Added**: GitHub Actions CI — Windows(MSVC, clang-cl, ASan), Linux x64/ARM64(GCC, Clang, ASan/UBSan, TSan),
  swtpm TPM2, 패키지 소비자(Linux/Windows × 공유/정적), Debian 12 / Rocky 9 컨테이너, libFuzzer(push 60 s, nightly 20 분).
  Actions 는 commit SHA 고정 + Dependabot, pull request 실행만 이전 실행을 취소.
- **Changed**: MSVC ASan 에서 STL container annotation 을 유지하고(사전 빌드된 ASan/libFuzzer 런타임과 일치), fuzz 프리셋의
  비-fuzzer 타깃에 sancov 를 링크.

### Phase 10 이후 수정 (877df61, 404abc3, bad2b3a, 5099896)

- **Fixed** (877df61): `SG_ServerConfig.flags` 의 모르는 비트를 조용히 무시하지 않고 `SG_Client_Connect` 가 I/O 전에
  `SG_NOT_SUPPORTED` 로 거부한다(`SG_ClientConfig.flags` 와 같은 규칙).
- **Added** (404abc3): OpenSSL 3.0.7 미만 경고. configure 시 CMake 경고, OpenSSL 을 함께 배포하는 빌드(Windows, 정적 링크)는
  실행 시에도 첫 Connect 에서 프로세스당 한 번 `event=config_warning`. 배포판 OpenSSL 은 실행 시 판단하지 않는다.
- **Fixed** (bad2b3a): `connect_timeout_ms` 가 TCP + proxy + TLS 핸드셰이크 전체의 한 예산이 되었다. 이전에는 TLS 가 새
  예산을 받아 최악의 경우 약 2 배가 걸렸다. TCP/proxy 가 예산을 다 쓰면 TLS 없이 `SG_TIMEOUT`. (이름 해석과 시스템 proxy
  조회가 TCP 단계의 예산까지 줄이도록 한 것은 858b162.)
- **Fixed** (5099896): `config.h` 의 `SG_KEYSTORE_AUTO` 설명을 실제 순서로 정정(Windows: CNG TPM → CNG Software, Linux:
  TPM2(빌드 시) → 보호된 파일).
- 서버 전용: `SG_Server_Start` 를 콜백 안에서 호출하면 `SG_INVALID_STATE` (583d55f).

### 문서 리뷰 후 수정 (991a1b6, 858b162, 86cb919, b95a843, bd6ca45)

- **Fixed** (991a1b6): 다른 스레드의 `SG_Client_Disconnect` 가 진행 중인 `SG_Client_Connect` 를 끊으면 이제 어느 단계에서든
  `SG_CLOSED` 를 반환한다(`event=connect_aborted`). 이전에는 proxy 협상 중이면 `SG_PROXY_ERROR`, TLS 중이면 `SG_TLS_ERROR`
  (TLS 실패로 로그)였고, transport 연결과 링크 게시 사이의 Disconnect 는 놓쳐 `SG_OK` 를 반환했으며, 시스템 proxy 조회 중의
  Disconnect 는 연결이 끝까지 진행된 뒤에야 반영됐다. 이미 판정된 인증서/pin 실패는 그대로 보고된다.
- **Fixed** (858b162): 이름 해석과 시스템 proxy 조회가 `connect_timeout_ms` 에 포함된다. `TcpTransport` 와
  `transport_factory` 의 deadline 이 해석·조회 **전에** 시작하고 TCP 연결은 남은 시간만 받는다. 한 번의 resolver 호출은
  여전히 중단할 수 없다.
- **Fixed** (86cb919): 예제가 token(과 서버 예제의 token 키)을 `memset` 대신 volatile 저장으로 지운다. 이후 읽지 않는 버퍼의
  `memset` 은 최적화로 사라질 수 있다.
- **Fixed** (b95a843, Common): 채널 바인딩이 RFC 9266 tls-exporter(`EXPORTER-Channel-Binding`, **길이 0 context**)가 되었다.
  이전에는 context 없이 export 했다. TLS 1.3 에서는 같은 값이고 TLS 1.2 에서는 이제 표준 값이다.
  **업그레이드 주의**: 이 변경 전에 빌드된 클라이언트/서버는 TLS 1.2(`SG_CLIENT_FLAG_ALLOW_TLS12` /
  `SG_SERVER_OPT_ALLOW_TLS12`)로 협상되면 새 빌드와 인증에 실패한다(`SG_SERVER_REJECTED`). TLS 1.3 세션은 영향이 없다.
  TLS 1.2 를 쓰는 배포는 양쪽을 함께 올린다.
- **Changed** (bd6ca45, 빌드): Linux sanitizer test 프리셋이 CI 와 같은 `ASAN_OPTIONS` / `UBSAN_OPTIONS`(`halt_on_error=1`) /
  `TSAN_OPTIONS` 를 설정한다.
- **Docs** (8cc9e6a): `config.h` — `connect_timeout_ms` 주석에 시스템 proxy 조회와 이름 해석을 포함.
- **Docs** (e6ad350): `client.h` — TPM clear 뒤 Linux TPM2 키는 파일이 남아 `SG_IDENTITY_LOST` 가 아니라 서명에서
  `SG_KEYSTORE_ERROR` 가 된다. 계속되면 `SG_IDENTITY_DELETE_FORCE` 로 지우고 다시 등록한다.
- 서버 전용, 클라이언트가 보는 영향만:
  - 6d34c39: 서버 `max_unauthenticated` — 상한을 넘는 미인증 연결은 accept 직후 닫히므로, 클라이언트에는 Connect 실패
    (TLS 단계의 `SG_TLS_ERROR` / `SG_NETWORK_ERROR` 등)로 보인다.
  - 19d1208: 저장 실패(`SG_STORAGE_ERROR`) 뒤 폐기를 다시 호출하면 쓰기를 재시도하고, 이후의 성공한 쓰기도 폐기를 저장한다.
    폐기된 installation 이 서버 재시작 뒤 다시 인증되는 일이 없어진다.
