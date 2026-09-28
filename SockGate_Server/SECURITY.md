# SockGate_Server Security

서버 라이브러리의 보안 속성, 안전한 배포 지침, 빌드 hardening, 알려진 한계, 취약점 신고 방법을 정리한다.
위협별 분석은 [THREAT_MODEL.md](THREAT_MODEL.md), 시스템 전체의 한계는
[13-security-limitations.md](../docs/design/13-security-limitations.md) 를 참고한다.

## 1. 보안 속성

올바르게 배포된 서버는 다음을 제공한다.

1. **클라이언트 인증**: 세션은 registry 에 등록된 ECDSA P-256 공개키의 소유를 1회용 challenge 로 증명한 installation 에만 열린다.
2. **중계 저항**: 서명 대상에 서버측 TLS 채널 바인딩이 들어가므로, TLS 를 종단한 중계자(사용자 설치 CA 포함)는
   피해자의 인증으로 서버측 세션을 만들 수 없다. enrollment token 비밀도 네트워크에 나가지 않는다.
3. **Replay 저항**: 1회용 challenge + TTL, 연결당 인증 1회, 방향별 엄격한 sequence, 단조 증가 request ID.
4. **서버측 권한 결정**: 제품·라이선스·기능·수명·정책은 서버가 registry, license store, integrity 정책, `on_authorize` 로 결정한다.
   클라이언트 값은 주장으로만 쓰인다.
5. **즉시 폐기**: installation·라이선스 폐기와 좌석 반납은 해당 활성 세션을 즉시 끝내며, 인가 중인 연결과의 경합도 놓치지 않는다.
   저장에 실패해도 프로세스 안에서는 폐기가 유지되고, 다시 호출하면 저장을 재시도한다.
6. **일반화된 거부**: 네트워크로는 REJECTED 등 일반 결과만 보내고, 미등록 installation 도 더미 키로 서명을 검증해 응답을 균일하게 한다.
7. **Fail closed**: 알 수 없는 옵션 비트·integrity 조건·구조체 뒤쪽 필드는 `SG_NOT_SUPPORTED`, 손상된 저장소 파일은 생성 실패,
   프로토콜 위반·tag 오류·sequence 오류는 연결 종료이다.
8. **비밀 최소 노출**: 세션 키·채널 바인딩·challenge 는 종료 시 지우고, TLS 개인키 PEM 사본은 로드 후 지운다.
   로그에는 키·서명·token·payload 를 쓰지 않는다.

## 2. 안전한 배포 지침

### 2.1 TLS 인증서

- `tls_cert_chain_file` 은 leaf 인증서 다음에 중간 인증서 순서의 PEM 이다. 개인키는 **암호화되지 않은 PEM** 이어야 한다
  (passphrase 를 지원하지 않는다). 따라서 키 파일은 서버 계정만 읽을 수 있게 둔다.
- 파일 경로와 메모리 PEM(`tls_*_pem`)이 둘 다 있으면 파일이 우선한다. 메모리 PEM 을 쓰는 경우 `SG_Server_Create` 후
  애플리케이션 쪽 버퍼를 지운다 (라이브러리는 자기 사본만 지운다). 이후 읽지 않는 버퍼의 `memset` 은 컴파일러가 없앨 수 있으므로
  `SecureZeroMemory`, `explicit_bzero` 또는 volatile store 루프(예제의 `wipe()`)를 쓴다.
- 운영 환경에서는 사설 CA + 클라이언트 SPKI pinning 을 권장한다. `sg_admin pin <cert.pem>` 이 SPKI pin(DER
  SubjectPublicKeyInfo 의 SHA-256)을 출력한다. 인증서 교체 전에 클라이언트에 현재 키와 다음 키의 pin 을 함께 배포한다
  (클라이언트는 pin 을 최대 8개 가진다).
- `SG_SERVER_OPT_ALLOW_TLS12` 는 TLS 1.3 을 쓸 수 없는 클라이언트가 있을 때만 켠다. 켜도 EMS 없는 TLS 1.2 연결은 거부된다.
- `sg_admin dev-pki` 가 만드는 CA/인증서는 **개발 전용**이다.

### 2.2 서버 proof key

- `proof_key_file` / `proof_key_pem` 은 ECDSA P-256 PEM 이다. 설정하면 **AUTH_RESULT(OK)** 에 서명한다.
  AUTH_RESULT(REJECTED), AUTH_RESULT(UNSUPPORTED_VERSION), REAUTH_RESULT 에는 서명하지 않는다.
- TLS 키와 다른 키를 쓰고, TLS 키와 같은 수준으로 보호한다. proof 공개키를 가진 클라이언트는 서명 없는 성공 응답을 거부하므로
  TLS PKI 가 뚫려도(시스템 trust store + pinning 없음) 가짜 서버가 세션을 **성공시킬** 수는 없다. 그러나 가짜 서버는 서명 없는
  거부·버전 불일치 응답을 보낼 수 있고, 그 전에 CLIENT_HELLO 의 주장과 integrity 보고를 이미 받는다. 이를 막는 것은 pinning 이다.
- 교체는 클라이언트가 새 proof 공개키를 추가로 보유한 뒤(클라이언트당 최대 4개) 서버 키를 바꾸는 순서로 한다.

### 2.3 Enrollment token key

- `token_key` 는 32–1024 bytes 의 무작위 비밀이다. `sg_admin token-key <file>` 이 32 bytes 를 소유자 전용 파일로 생성한다 (POSIX `0600`, Windows 보호된 DACL).
- 이 키를 가진 사람은 임의의 enrollment token 을 만들 수 있다. TLS 개인키와 같은 수준으로 보호하고, `SG_Server_Create` 후
  애플리케이션 버퍼를 컴파일러가 없애지 못하는 방식으로 지운다 (라이브러리가 복사한다, §2.1).
- 설정하지 않으면 `SG_Server_Create` 마다 새로 생성된다. 한 서버 객체가 발급한 token 은 다른 서버 객체(재시작 포함)에서 무효이다.
- 키를 바꾸면 발급된 token 이 모두 무효가 된다 (의도적 회수 수단으로 쓸 수 있다). `sg_admin token-key` 는 기존 파일을 `--force yes` 없이 덮어쓰지 않는다.
- token 문자열은 비밀이다. 안전한 경로로 전달하고 TTL 을 짧게 준다 (기본 24 h, 최대 30 일). 30 일 상한은 사용 시에도 다시 검사하므로
  token key 로 서버 밖에서 만든 더 긴 token 은 enroll 에서 거부된다.
- enrollment 는 `SG_SERVER_OPT_ALLOW_ENROLLMENT` 가 있을 때만 받는다. 쓰지 않으면 끈다 (기본값: 꺼짐).

**1회 사용과 다중 노드**:

- SockGate 는 token 1회 사용을 **registry 단위**로 보장한다. token 은 채널 결속 token 증명·공개키·서명 검증이 끝난 뒤, `on_authorize`
  **전에** 사용됨으로 (영구) 기록되고 installation 이 등록된다. 따라서 `on_authorize` 가 거부한 enrollment 도 token 을 소모한다.
- 서로 다른 registry 를 쓰는 서버 노드는 이 기록을 공유하지 않는다. 같은 token key 를 공유하면 내장 token 이 노드마다 한 번씩 쓰일 수 있다.
- 노드 간 1회 사용이 필요하면 `on_enroll` 에서 공유 저장소로 token 을 원자적으로 소비하는 것이 지원되는 방법이다. 단 `on_enroll` 은
  **아무것도 검증되기 전에** 호출되는 키 조회이므로, token 공개 부분(`token_pub`)을 본 누구나 그 token 을 소진시킬 수 있다
  (등록은 할 수 없는 서비스 거부). 이런 token 은 수명을 짧게 한다.
- `on_enroll` 을 설정하면 `SG_Server_IssueEnrollmentToken` 의 내장 token 은 거부된다. 모든 token 을 자체 발급자가 만드는 경우에만 설정한다.

### 2.4 Registry / license 파일 권한

파일에는 MAC 이나 서명이 없으므로 **쓰기 권한이 곧 신뢰**이다.

- 서버 계정만 쓸 수 있는 전용 디렉터리에 둔다. 원자적 쓰기가 같은 디렉터리에 임시 파일과 `<path>.lock` 을 만들고 rename 하므로
  **디렉터리 권한**이 중요하다 (디렉터리에 쓸 수 있는 사용자는 파일을 바꿔치기할 수 있다).
  - 라이브러리가 쓰는 파일은 소유자 전용이다: POSIX `0600`, Windows 는 현재 사용자·SYSTEM·Administrators 만 허용하는 보호된
    DACL (디렉터리 ACL 을 상속하지 않음). 이미 있던 파일을 처음 로드할 때는 권한을 검사하지 않으므로 기존 파일의 권한은 직접 확인한다.
  - POSIX 는 저장소 파일이 symlink 면 읽기를 거부한다. 디렉터리는 예: `0700`, 소유자 = 서버 계정.
  - Windows 는 읽기 시 reparse point 검사를 하지 않으므로 디렉터리를 다른 사용자가 쓸 수 없게 한다.
- `registry_path` 와 `license_path` 는 다른 파일이어야 한다 (같으면 `SG_INVALID_ARGUMENT`).
- 저장소는 단일 프로세스용이다. 실행 중인 서버는 열려 있는 동안 `<path>.lock` 의 배타적 lock 을 잡으므로, 다른 프로세스(두 번째 서버,
  서버 실행 중의 `sg_admin`)는 `SG_INVALID_STATE` 로 실패한다 (`sg_admin` 은 "the store is in use" 를 출력). `sg_admin` 의 저장소 명령은
  **서버가 멈춘 동안에만** 쓴다. lock 은 advisory 이므로 파일을 직접 고치는 프로세스는 막지 못한다. 로컬 디스크에 둔다.
- 백업도 같은 수준으로 보호한다 (공개키, 폐기 상태, 라이선스, 좌석, 사용된 token ID 가 들어 있다). 오래된 백업을 복원하면
  그 이후의 폐기가 사라진다.
- 메모리 저장소(`NULL` 경로)는 재시작 시 모든 등록·폐기·라이선스·사용된 token 기록을 잃는다. 운영에서는 파일 경로를 쓴다.
- 폐기 API 가 `SG_STORAGE_ERROR` 를 돌려주면 폐기는 이 프로세스에서만 유효하다. 저장소는 저장되지 않은 폐기를 기억하므로,
  디스크 문제를 고친 뒤 같은 폐기 함수를 다시 호출하면 쓰기를 재시도하고 (`SG_OK` 가 나올 때까지), 그 저장소의 다른 변경이 성공적으로
  저장될 때도 함께 저장된다 (19d1208).

### 2.5 `REQUIRE_LICENSE` 와 `LICENSE_ACTIVATION`

| 설정 | 동작 | 장점 | 주의 |
|---|---|---|---|
| 둘 다 없음 (기본) | 라이선스는 registry 바인딩(등록 레코드·token)으로만 검증된다. 바인딩 없는 세션도 열리며, 검증된 라이선스가 없으면 `granted_features = 0` | 라이선스 없이 인증만 쓰는 배포 | 라이선스가 필요한 기능은 `license_status` / `granted_features` 로 애플리케이션이 확인해야 한다 |
| `SG_SERVER_OPT_REQUIRE_LICENSE` | store 에서 검증된(`VALID`) 라이선스가 없는 세션은 모두 거부. 관리 API 의 라이선스 바인딩도 store 에 있어야 함 | 라이선스 없는 접근이 구조적으로 불가능 | 등록·token 발급 전에 라이선스를 먼저 `AddLicense` 해야 한다 |
| `SG_SERVER_OPT_LICENSE_ACTIVATION` | 바인딩 없는 installation 이 store 의 라이선스 ID 를 주장하면 활성화되어 registry 에 영구 바인딩 (first wins) | 관리자 개입 없는 셀프 활성화 | **라이선스 ID 가 bearer secret** 이 된다. 클라이언트는 결과(AUTH_RESULT 의 기능·만료, `REQUIRE_LICENSE` 면 허용/거부)로 존재하는 ID 와 없는 ID 를 구분할 수 있고, installation 별 시도 횟수 제한도 없다. 추측 불가능한 고엔트로피 무작위 ID 로 발급하고, 좌석 수(`max_installations`)로 피해를 제한한다 |

두 플래그는 함께 쓸 수 있다 (활성화된 라이선스만 허용). 활성화 모드에서도 로그에는 라이선스 ID 의 해시(`lic:…`)만 남는다.
좌석은 동시 접속 수가 아니라 활성화 기록이며, 관리자가 `SG_Server_ReleaseLicenseSeat` 하거나 installation 을 폐기할 때까지 유지된다.

### 2.6 Integrity 정책

- `integrity_reject_mask` / `integrity_restrict_mask` 는 **신뢰를 낮추는 신호**로만 쓴다. 모든 관측은 장악된 클라이언트가 위조할 수 있으며,
  플래그가 없다는 것은 아무것도 증명하지 않는다.
- 권장: 명확히 비정상인 조건만 reject 에, 개발 환경에서도 흔한 조건(`SG_INTEGRITY_DEBUGGER_PRESENT`, `SG_INTEGRITY_UNSIGNED_EXECUTABLE`)은
  restrict 에 둔다. RESTRICTED 의 의미(기능 제한 등)는 애플리케이션이 `policy` 로 구현한다.
- 보고를 요구하려면 `SG_INTEGRITY_REPORT_MISSING` 을 마스크에 넣는다.
- 실행 파일 allowlist(`allowed_executables`, 최대 4096)는 `SG_INTEGRITY_UNKNOWN_EXECUTABLE` 이 어느 마스크에 있을 때만 효과가 있다
  (없으면 경고 로그). 0 으로만 된 항목은 거부된다.
- integrity 판정은 `on_authorize` 이전에 한다. reject 면 콜백이 호출되지 않고, restrict 는 콜백이 풀 수 없다.

### 2.7 로깅

- `log_callback` 이 없으면 아무것도 기록하지 않는다. 기본 level 은 `SG_LOG_WARN` 이다. installation 을 알게 된 뒤의 인증 실패
  (`event=auth_rejected installation=...`)는 WARN, CLIENT_HELLO 단계의 거부(`event=auth_rejected peer=...`)와 세션 열림/닫힘,
  관리 동작은 INFO 이다. 감사 기록이 필요하면 `log_level` 을 `SG_LOG_INFO` 이상으로 둔다.
- 로그에는 키, 세션 키, exporter 값, transcript, 서명, token 문자열, payload 를 쓰지 않는다. session/installation/token ID 는 앞 8 bytes 의 hex,
  라이선스 ID 는 `lic:` + SHA-256 앞 8 bytes(hex) 로만 기록한다.
- 로그에는 peer 주소와 product ID 가 들어간다. 로그 저장소도 접근을 제한한다.
- `SG_LOG_DEBUG` / `SG_LOG_TRACE` 문장은 `NDEBUG` 빌드에서 컴파일되지 않는다 (`SOCKGATE_ENABLE_DEBUG_LOG=ON` 이면 유지).
- 로그 콜백은 동기 호출이며 내부 lock 을 잡은 상태에서도 호출될 수 있다 (`server.h`). 메시지를 기록만 하고 어떤 SockGate 함수도 호출하지 않는다.
- 자체 OpenSSL 을 함께 배포하는 빌드(Windows, 정적 링크)는 실행 중인 OpenSSL 이 3.0.7 보다 오래되면 `SG_Server_Start` 때
  `event=config_warning` 을 WARN 으로 남긴다. 이 경고를 운영 알림에 연결한다.

### 2.8 기타

- `max_connections` 는 프로세스의 파일 descriptor 한도보다 작게 잡는다 (graceful-close 중인 소켓도 포함된다).
- `max_unauthenticated` (기본 `max_connections / 2`)는 TLS·인증 단계에 동시에 머물 수 있는 연결 수이다. 인증 전 연결 폭주가 세션 자리를
  차지하지 못하게 하며, 예상되는 동시 접속(재접속 폭주 포함)을 받을 만큼만 크게 잡는다. 인증 전에 실패한 연결은 소켓이 완전히 닫힐 때까지
  (graceful close, 최대 5 s) 자리를 유지하므로 그 시간도 계산에 넣는다.
- 타임아웃은 기본값에서 크게 늘리지 않는다. 라이브러리는 `session_lifetime_ms` ≤ 7일 외에는 범위를 강제하지 않는다
  ([INTEGRATION.md](INTEGRATION.md) §2).
- 앞단 L4 방어(연결 속도 제한, SYN flood 방어)를 둔다. 서버는 IP 별 제한을 하지 않는다.
- `on_authorize` 는 fail closed 로 작성한다: 외부 시스템 오류 시 `SG_OK` 가 아닌 값을 돌려주면 거부된다.
- 애플리케이션 계층 암호화가 필요하면 `SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION` 을 켠다 (평문 DATA 는 프로토콜 오류).

## 3. 빌드 hardening 과 검증

### 3.1 컴파일러/링커 플래그 (`cmake/SockGateCompilerFlags.cmake`)

SockGate 자체 타깃에만 적용된다. 모든 타깃은 `-fvisibility=hidden` / inline hidden 이다.

| 툴체인 | 항상 | `SOCKGATE_HARDENING=ON` (기본) |
|---|---|---|
| MSVC / clang-cl | `/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /bigobj`, Release·RelWithDebInfo: `/Gy /Zi`, 링크 `/DEBUG /OPT:REF /OPT:ICF` (sanitizer 빌드 제외). PDB 는 설치하지 않는다 | 컴파일 `/GS /sdl /guard:cf`, 링크(DLL/EXE) `/guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT` |
| GCC / Clang | `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wformat=2 -Wcast-qual -Wnull-dereference -Wdouble-promotion -Wimplicit-fallthrough`. 공유 라이브러리는 **항상** `-Wl,--version-script=cmake/sockgate_exports.map` (`SG_*` 만 global) | `-fstack-protector-strong`, `-fstack-clash-protection`, x86_64 `-fcf-protection=full` / ARM64 `-mbranch-protection=standard`, Release 계열 `-D_FORTIFY_SOURCE=3` (GCC ≥ 12, Clang ≥ 16; 그 외 2, sanitizer 빌드 제외), 링크 `-z relro -z now -z noexecstack`, 실행 파일 `-pie`, 공유 라이브러리 `--exclude-libs,ALL` 과 Release/MinSizeRel 에서 `-s` |

Release 프리셋은 `SOCKGATE_WERROR=ON` (`/WX`, `-Werror`)이다.

### 3.2 Export 검사

공유 라이브러리는 `sockgate/server.h` 에 `SG_SERVER_API` 로 선언된 함수만 export 해야 한다. CTest `sg_exports_sockgate_server`
(label `security`)가 `nm` (Linux) 또는 `dumpbin` / `llvm-readobj` (Windows)로 export 표를 읽어 헤더 선언과 정확히 비교한다.
공유 빌드(`SOCKGATE_BUILD_SHARED=ON`)에서만 등록된다.

### 3.3 Sanitizer

| 프리셋 | 도구 |
|---|---|
| `linux-gcc-asan`, `linux-clang-asan` | ASan + UBSan (`-fno-sanitize-recover=undefined`, Clang 은 integer sanitizer 추가) |
| `linux-clang-tsan` | TSan |
| `windows-msvc-asan` | MSVC ASan |

CI 는 이 프리셋 전부에서 전체 테스트를 실행한다 (TSan `halt_on_error=1`, ASan `detect_leaks=1`, UBSan `halt_on_error=1`).
Linux sanitizer 테스트 프리셋도 같은 `ASAN_OPTIONS` / `UBSAN_OPTIONS` / `TSAN_OPTIONS` 를 설정하므로 로컬 `ctest --preset` 도 CI 와 같이 실패한다 (bd6ca45).

### 3.4 Fuzzing

| 타깃 | 대상 |
|---|---|
| `frame_decoder` | 프레임 헤더 codec, 스트리밍 decoder |
| `messages` | 모든 v1 메시지 codec, integrity 보고 |
| `channel` | `ProtectedChannel` open/seal |
| `storage_files` | 서버 registry / license 파일 로더 (로드 → 변경 → 저장 → 재로드 round trip) |
| `proxy_config` | 클라이언트 proxy 설정 (서버와 무관) |

`SOCKGATE_BUILD_FUZZERS=ON` 이면 libFuzzer 실행 파일 `sg_fuzz_<name>` 을, 테스트 빌드에서는 같은 타깃을 결정적 변이 드라이버와 묶은
`sg_mutate_<name>` 을 만들어 CTest (label `fuzz;protocol`)로 실행한다. CI 의 fuzz job 은 타깃마다 push 시 60 s, nightly 20 min 을 돌린다.

### 3.5 서버 보안 테스트

- `sg_security_handshake`: 사칭, 서명 변조, 만료·재사용 challenge, 새 연결 replay, TLS 종단 중계, 버전 협상, 인가 거부, proof key,
  enrollment token 재사용·변조·만료·위조·중계·과도한 수명, enrollment 기본 비활성, 외부 validator, 저장소 손상과 폐기 영속화 실패,
  저장소 lock, Windows 소유자 전용 파일, 채널 공격.
- `sg_security_license`: 라이선스 기능 부여, 바인딩 우선, 활성화, 좌석, `REQUIRE_LICENSE`, integrity 하한.
- `sg_integration_session` / `sg_integration_license` / `sg_integration_integrity`: 공개 API 를 통한 종단 시나리오
  (만료, idle, 재인증 속도 제한, 폐기, 경합 중 폐기, 좌석 반납, 과다·무응답 연결, 콜백 재진입 등).
- `sg_security_proxy_mitm`: 사용자 설치 CA MITM 중계 거부, pinning, proof key 로 가짜 서버 탐지.

## 4. 알려진 한계

1. 저장소 파일에 무결성 보호(MAC/서명)가 없다. 파일·디렉터리 권한과 호스트 보안에 의존한다. 기존 파일을 로드할 때
   소유자·권한을 검사하지 않고, Windows 에서는 reparse point 도 검사하지 않는다.
2. 저장소는 단일 프로세스용이며 변경마다 파일 전체를 다시 쓴다. 대규모 배포(라이선스·좌석 수가 많거나 다중 노드)는
   `on_authorize` / `on_enroll` 과 외부 DB 를 쓴다. 사용된 token ID 기록은 정리되지 않고 계속 쌓인다.
3. 서비스 거부: TLS 핸드셰이크 CPU 비용 방어와 IP 별 제한이 없다. 인증 전 연결 상한(`max_unauthenticated`)이 차면 새 클라이언트는
   `handshake_timeout_ms` 동안 접속하지 못할 수 있다 (기존 세션은 유지). 과부하 시 `RETRY_LATER` 를 보내지 않고 연결을 닫는다.
4. integrity 보고는 우회 가능하며 신뢰를 높이는 데 쓸 수 없다.
5. 좌석은 동시 접속 제한이 아니다. 라이선스 활성화 모드의 라이선스 ID 는 bearer secret 이다.
6. 서버는 클라이언트의 pinning / proof key 요구를 강제할 수 없다.
7. TLS 개인키는 암호화되지 않은 PEM 이어야 하며, HSM/PKCS#11 을 지원하지 않는다.
8. OpenSSL 은 빌드 시 API 수준(≥ 3.0)을 요구하고, 3.0.7 미만이면 configure 단계에서 경고한다. 실행 시 경고는 자체 OpenSSL 을 배포하는
   빌드(Windows, 정적 링크)에서만 하며, 배포판 OpenSSL 은 보안 수정이 버전 번호 변경 없이 백포트되므로 실행 시 판단하지 않는다.
   업스트림 기준 3.0.7 이상(권장 3.5 LTS 이상), 또는 보안 업데이트가 적용된 배포판 패키지를 쓴다 ([12-dependencies.md](../docs/design/12-dependencies.md)).
9. 타임아웃 판정 해상도는 250 ms 이고, 만료 판단은 서버 시계에 의존한다.
10. 저장에 실패한 폐기(`SG_STORAGE_ERROR`)는 재시도나 그 저장소의 다른 성공적인 쓰기로 저장되기 전에 프로세스가 재시작되면 사라진다.
11. 사용된 token ID 기록은 정리되지 않으므로 매우 큰 registry 는 레코드 수 상한보다 먼저 파일 크기 상한(512 MiB)에 닿을 수 있다.
    그러면 registry 쓰기가 `SG_LIMIT_EXCEEDED` 로 거부된다.

## 5. 취약점 신고

보안 취약점은 공개 이슈로 올리지 말고 **메인테이너에게 비공개로** 신고한다.

신고에 포함할 내용:

- 영향받는 버전 또는 커밋, 플랫폼, 빌드 설정(프리셋, 공유/정적, OpenSSL 버전)
- 재현 절차 또는 PoC, 관련 설정(`SG_ServerOptions` flags 등)
- 예상 영향 (인증 우회, 권한 상승, 정보 노출, 서비스 거부 등)

처리 절차: 접수 확인 → 재현과 분석 → 수정 준비 → 신고자와 공개 일정 협의 → 수정 릴리스와 공지.
수정이 공개되기 전에는 취약점 세부 내용을 공개하지 않도록 요청한다.
