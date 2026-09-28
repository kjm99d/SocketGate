# Changelog

SockGate_Common 의 주요 변경 사항을 기록한다. 형식은 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) 를 따르고,
버전은 `include/sockgate/version.h` 의 값이다. 항목은 저장소 `git log` 에서 Common 과 관련된 변경만 추렸으며, 괄호 안은 커밋이다.

## [0.1.0] — Unreleased

### 설계 (4e0492e, b9a27ca)

- **Added** 설계 문서 01–13 (architecture, threat model, trust boundary, protocol specification, handshake, key/session lifecycle,
  directory structure, public C API, platform layers, dependencies, security limitations). 이후 protocol 설계 리뷰 지적 사항을 반영.

### Phase 1 — 빌드 시스템과 transport 기반 (8a66626)

- **Added** CMake superproject 와 프리셋 (MSVC, clang-cl, GCC, Clang, sanitizer), 경고/hardening 플래그, 빌드 옵션.
  OpenSSL 은 Windows 에서 vcpkg, Linux 에서 시스템 패키지.
- **Added** Client/Server 공용 public 헤더: `sockgate/error.h` (status 코드), `types.h`, `export.h`, `version.h`.
- **Added** core: `[[nodiscard]] sg::Status`, zeroing 바이트 컨테이너 (`SecureBytes`), 상수 시간 비교, monotonic `Deadline`, 콜백 로거.
- **Added** Winsock2 / POSIX 소켓 계층: 상속되지 않는 소켓, 타임아웃 있는 non-blocking connect, Windows exclusive bind,
  Linux `MSG_NOSIGNAL`. 바이트 스트림 인터페이스 `net::ITransport`.
- **Added** 의존성 없는 테스트 프레임워크와 core 단위 테스트.

### Phase 2 — TLS 1.3 과 암호 (a0e0354)

- **Added** OpenSSL 3 EVP 기반 암호 계층: SHA-256, HMAC-SHA256, HKDF-SHA256, AES-256-GCM, ECDSA P-256 (P1363 서명, 곡선 위 검증을 하는
  SEC1 공개키), CSPRNG, 실패 경로 소거.
- **Added** `ITlsProvider` / `ITlsContext` / `ITlsEngine` 뒤의 memory BIO sans-IO TLS 엔진: 기본 TLS 1.3, TLS 1.2 는 opt-in 이며 EMS 필수,
  압축·재협상·세션 재개 없음, 체인 + hostname/IP + 유효기간 검증, 부분 wildcard 거부.
- **Added** 검증된 체인에만 비교하는 SPKI pinning (복수 pin), RFC 9266 채널 바인딩과 RFC 5705 exporter, KeyUpdate.
- **Added** OS trust store 로드 (Windows `ROOT`, OpenSSL 기본 경로).
- **Added** 런타임 생성 테스트 PKI, 암호 known-answer 테스트, TLS 음성 테스트 (신뢰되지 않은 CA, hostname, 만료, pin 우회,
  TLS 1.2 downgrade, 변조).

### Transport / I/O 동시성 리뷰 (bf8174c)

- **Fixed** Windows 에서 `select()` 예외 집합을 connect 대기에만 사용: TCP urgent data 로 대기가 즉시 끝나 busy wait 하던 문제.

### Phase 3 — 바이너리 프로토콜 (8b0984f)

- **Added** 실패가 고정되는 bounds-checked big-endian `Reader` / `Writer`, 엄격한 TLV (정확한 길이, 최대 16 항목, 중복 금지),
  엄격한 base64url, 프로토콜 문자열 (UTF-8, 제어문자 금지) 검증.
- **Added** 48-byte 프레임 헤더 코덱과 스트리밍 `FrameDecoder`: 구조 검사 + 본문 버퍼링 전 상태 hook, 산술 전 길이 검증,
  버퍼 상한, 고정되는 실패.
- **Added** v1 전체 메시지 코덱 (hello, proof, auth result, ping/pong, reauth, close) 과 integrity report, enrollment token 공개 부분,
  `K_tok` 유도, token 문자열.
- **Added** 단계별 수신 규칙 (type/방향/auth 길이/flags, 인증 전 4 KiB 상한) 과 message dispatcher.
- **Added** transcript 해시, 서명 대상 도메인 분리, installation id 유도, enrollment proof, HKDF 채널 키 유도.
- **Added** 프로토콜 음성 테스트, frame decoder / message codec libFuzzer 타깃과 CTest 에서 도는 결정적 mutation 테스트.

### Parser 보안 리뷰 (9b7bc60)

- **Security** `FrameDecoder` 는 header check 없이 fail closed, 단계별 버퍼 상한 추가 (인증 전 세션이 ~16 MiB 를 쌓아 두게 할 수 없음),
  compaction 은 남은 부분이 소비한 앞부분보다 크지 않을 때만 이동해 파이프라이닝 입력도 선형.
- **Security** 인증 전 프레임은 `request_id == 0` 이어야 함. 알 수 없는 관측 비트가 있는 integrity report 거부.
- **Security** 인코더가 자기 출력을 디코더로 재검증하고 재검증에 실패하면 출력을 되돌림 (그 전 단계의 오류는 일부 바이트를 남길 수 있음). 거부 AUTH_RESULT 는 세션 데이터를 실을 수 없음.
  `EncodeFrame` 은 잘못된 헤더를 거부.
- **Security** 프로토콜 문자열에서 보이지 않는 문자, 양방향 재정의 문자, noncharacter 거부.
- **Security** 디코더 버퍼와 decoded frame 에 zeroing 저장소 사용, base64 와 token 처리의 모든 경로에서 중간값 소거,
  채널 키 유도는 exporter 출력이 정확히 32 bytes 일 때만.

### Phase 4 — challenge-response 인증 (9c6d6da)

- **Changed** Common 코드 변경 없음. Client/Server 핸드셰이크가 Common 의 transcript, 서명 대상, enrollment proof, token 코드를
  사용하기 시작하고 인증 공격 시나리오 보안 테스트가 추가됨.

### Phase 5a — 인증 후 프레임 보호 (089f513)

- **Added** `ProtectedChannel`: 방향별 sequence (정확히 +1; replay/중복 → `SG_REPLAY_DETECTED`, 재정렬/삭제 → `SG_PROTOCOL_ERROR`),
  방향·epoch 별 AES-256-GCM tag (헤더를 AAD 로, 애플리케이션 암호화가 없으면 payload 도), `KEY_PHASE` 기반 방향별 키 전환과
  대기 수신 키 (재인증 중 in-flight 프레임 허용, 새 phase 첫 프레임 후 이전 키 소거), 단조 증가 request id 와 응답 검증,
  첫 실패 시 poison (키 소거).
- **Added** replay, 중복, 재정렬, 삭제, 헤더 필드/payload/tag 비트 변조, 교차 세션 주입, 반사, 중복 요청, in-flight epoch 전환 테스트.

### Phase 5b — 세션, 서버 엔진, C API (e7ffea4)

- **Added** `ElapsedMs()` (0 에서 포화하는 경과 시간), `ITransport::SendFor()` (호출별 타임아웃).
- **Changed** `ProtectedChannel` 의 `Seal()` 과 `Open()` 이 서로 다른 스레드에서 동시에 돌 수 있도록 poison 플래그와 request id
  최고값을 atomic 으로 변경. poison 은 수신·대기 키만 즉시 지우고, 다른 스레드의 `Seal()` 이 읽고 있을 수 있는 송신 키는
  소멸자에서 지움. 응답은 상대가 보낸 최대 요청 id 이하만 참조할 수 있음 (`Seal` 이 `SG_INVALID_ARGUMENT` 로 거부).

### Phase 6 — proxy 와 MITM 저항 (c884cb9)

- **Added** 플랫폼 소켓 계층의 블로킹 accept 보조 함수 (`AcceptConnection`, 도구/테스트 중계기용).
- **Changed** pin 불일치 시 오류 상세에 예상 밖 발급자를 담아 TLS 가로채기 가능성을 진단할 수 있게 함.

### Phase 8 — 플랫폼 key store (9398bf9, e74031d)

- **Added** public 에러 코드 `SG_IDENTITY_LOST` (29) 와 `ToPublicStatus` 범위 확장.
- **Fixed** Client 의 `sg::client::platform` 네임스페이스가 Common 의 `sg::platform` (소켓) 을 가리던 문제: `sg::client::os` 로 이름 변경.

### Phase 9 — integrity 보고와 export 강화 (0474a24)

- **Added** `SG_INTEGRITY_PLATFORM_WINDOWS/LINUX/MACOS` 상수.
- **Added** `core/abi.h`: 모르는 뒤쪽 필드가 0 이 아니면 거부하는 `CheckUnknownTail` (보안 설정의 조용한 downgrade 방지),
  입력 구조체 끝 padding 을 금지하는 `SG_ASSERT_NO_TAIL_PADDING`.
- **Security** 공유 라이브러리가 `SG_*_API` 함수만 export (ELF version script `cmake/sockgate_exports.map`),
  CTest 가 export 표를 헤더 선언과 비교.

### Enrollment token 수명 상한 (8522a02)

- **Added** 공유 상수 `proto::kMaxEnrollmentTokenLifetimeMs` (30 일, `protocol/enrollment_token.h`).
- **Security** 서버가 발급 때뿐 아니라 token 사용 시점에도 수명 상한을 검사: 다른 곳에서 서버 키로 만든 token 이 상한을 넘어 유효할 수 없음.

### Examples, sg_admin, CMake 패키지 (da67590)

- **Added** 설치 규칙과 CMake 패키지 (`cmake/SockGateInstall.cmake`, `SockGateConfig.cmake.in`): `find_package(SockGate)` →
  `SockGate::Client` / `SockGate::Server`, static 빌드는 내부 archive `SockGate::ClientCore` / `ServerCore` / `Common` 도 export.
  설치 헤더는 public 헤더 8 개뿐이며 `tests/package` out-of-tree 소비자가 이를 검사.
- **Added** 0.x 동안 `SameMinorVersion` 패키지 호환성과 `MAJOR.MINOR` soname (`libsockgate_client.so.0.1`), 옵션 `SOCKGATE_INSTALL`
  (최상위 프로젝트일 때만 기본 ON).
- **Changed** `SockGate_Common/CMakeLists.txt` 가 자체적으로 헤더를 설치하던 규칙을 제거 (패키지 설치 규칙이 담당).
- **Added** `sg_admin` 이 Common 의 `BuildEnrollmentToken`, `ComputeSpkiPinFromPem`, `DeriveInstallationId`,
  `kMaxEnrollmentTokenLifetimeMs` 를 사용 (`token issue --ttl-ms` 는 1 ms..30 일). 예제는 public C API 만 사용.

### Phase 10 — fuzz 타깃과 CI (b4a6510)

- **Added** fuzz 타깃 `channel` (수락된 프레임은 정확히 연속된 sequence, poison 된 채널은 복구되지 않음), `proxy_config` (Client),
  `storage_files` (Server). 모두 libFuzzer 타깃이자 CTest mutation 테스트 `sg_mutate_*`. 타깃별 링크 라이브러리와 반복 수 설정.
- **Changed** MSVC ASan 에서 STL container annotation 유지 (미리 빌드된 ASan/libFuzzer 런타임과 일치), fuzz 프리셋의
  libFuzzer 가 아닌 타깃에 `sancov` 링크.
- **Added** GitHub Actions CI: Windows (MSVC, clang-cl, ASan), Linux x64/ARM64 (GCC, Clang, ASan/UBSan, TSan), swtpm TPM2,
  패키지 소비자, Debian 12 / Rocky 9 container, libFuzzer (push 60 초, nightly 20 분). action 은 SHA 고정, Dependabot.

### OpenSSL 버전 경고 (404abc3)

- **Added** `tls::IsOutdatedOpenSsl()` (업스트림 3.0.7 미만 판정) 와 `tls::OutdatedBundledOpenSslVersion()`
  (OpenSSL 을 함께 배포하는 빌드에서만 오래된 버전 문자열 반환), 컴파일 정의 `SOCKGATE_BUNDLED_OPENSSL`
  (Windows 또는 `OPENSSL_USE_STATIC_LIBS`).
- **Added** configure 시 `OPENSSL_VERSION < 3.0.7` 이면 CMake 경고. Client/Server 는 번들 OpenSSL 이 오래되면 `event=config_warning` 로그.

### Sanitizer test 프리셋 (bd6ca45)

- **Changed** Linux sanitizer test 프리셋(`linux-gcc-asan`, `linux-clang-asan`, `linux-clang-tsan`)이 숨은 `test-sanitizers` 프리셋에서
  CI 와 같은 `ASAN_OPTIONS` / `UBSAN_OPTIONS` (`halt_on_error=1`) / `TSAN_OPTIONS` 를 받음: 복구 가능한 `-fsanitize=integer` 발견이
  로컬에서도 테스트를 실패시킨다.

### RFC 9266 채널 바인딩 (b95a843)

- **Fixed** `ITlsEngine::ChannelBinding()` 이 exporter 를 context 없이(`use_context = 0`) 호출하던 것을 RFC 9266 tls-exporter 대로
  길이 0 context (`use_context = 1`) 로 변경. TLS 1.3 에서는 값이 같고, TLS 1.2 에서 표준 값이 된다.
- **Upgrade note** 이 변경 이전에 빌드된 peer 는 TLS 1.2 (`allow_tls12`) 로 협상될 때 다른 채널 바인딩을 계산하므로 새 peer 와 인증에
  실패한다. TLS 1.3 세션은 영향이 없다. TLS 1.2 를 쓰는 배포는 Client 와 Server 를 함께 갱신한다.
- **Added** 채널 바인딩이 RFC 9266 exporter 값과 같은지, TLS 1.2 에서 길이 0 context 를 쓰는지 확인하는 TLS 테스트.
