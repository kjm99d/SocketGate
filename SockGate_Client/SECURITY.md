# SockGate_Client Security Guide

위협과 한계는 [THREAT_MODEL.md](THREAT_MODEL.md) 와 [13-security-limitations.md](../docs/design/13-security-limitations.md)
에 있다. 이 문서는 **안전하게 설정하는 방법**과 라이브러리가 스스로 보장하는 검증을 정리한다.

## 1. 운영 환경 체크리스트

| 항목 | 권장 설정 |
|---|---|
| 서버 신뢰 | 사설 CA(`ca_file` / `ca_pem`) **그리고** SPKI pin (현재 키 + 다음 키) |
| OS trust store | 사용하지 않는다. 써야 하면 pin 또는 `proof_keys` 와 함께 |
| `SG_SERVER_FLAG_ALLOW_NO_PINNING` | 운영 환경에서 설정하지 않는다 |
| 가짜 서버 방어가 중요하면 | `proof_keys` 설정 (서버의 `proof_key_file` 과 짝) |
| TLS 버전 | 기본(TLS 1.3 전용). `SG_CLIENT_FLAG_ALLOW_TLS12` 는 불가피할 때만 |
| key store | `SG_KEYSTORE_AUTO`(기본). 결과를 `SG_IdentityInfo.key_store_type` / `hardware_backed` 로 기록 |
| identity 이름 | reverse-DNS, 애플리케이션마다 고유 (`com.example.product`) |
| proxy | 기본 DIRECT. 필요한 경우에만 EXPLICIT/SYSTEM |
| 로그 | `log_callback` 으로 수집, 기본 `SG_LOG_WARN`. `event=possible_tls_interception` 을 경보로 취급 |
| token | enrollment token 을 로그나 명령줄 인자로 다루지 않는다(예제는 파일에서 읽는 `--enroll-file`; 파일은 owner 전용으로). `SG_Client_Enroll` 후 애플리케이션 사본을 컴파일러가 없애지 못하는 방법(`SecureZeroMemory`, `explicit_bzero`, volatile 루프 — `memset` 아님)으로 지운다 |
| OpenSSL | 업스트림 3.0.7 이상(3.5 LTS 권장). `event=config_warning` 로그를 무시하지 않는다 |

## 2. 서버 신뢰 설정

### 2.1 신뢰 앵커

`SG_ServerConfig` 에는 `ca_file`, `ca_pem`, `SG_TRUST_SYSTEM_STORE` 중 최소 하나가 필요하다(없으면 `SG_Client_Connect` 가
`SG_INVALID_ARGUMENT`). 여러 개를 주면 합쳐서 신뢰한다.

- **사설 CA 만** 신뢰하는 것이 기본이다. 사용자나 기업 proxy 가 OS store 에 설치한 CA 는 영향을 주지 않는다.
  사설 CA 만 쓰는 경우 pin 은 선택이지만, CA 키가 유출되는 경우에 대비해 pin 을 권장한다.
- `SG_TRUST_SYSTEM_STORE` 는 Windows 에서 `CertOpenSystemStoreW(L"ROOT")` 의 인증서를, Linux 에서 OpenSSL 기본 경로를
  추가한다. 이 경우 **pin 또는 proof key 가 최소 하나 있어야** 한다. 둘 다 없으면 `SG_INVALID_ARGUMENT` 이다.
- `SG_SERVER_FLAG_ALLOW_NO_PINNING` 은 "OS store + pin 없음" 을 **의도적으로** 허용하는 opt-out 이다. 사용자 설치 CA 로
  TLS 를 가로채는 공격자가 클라이언트에게 가짜 서버로 보일 수 있다(서버 쪽 인증 세션은 채널 바인딩 때문에 만들 수 없다).
  개발 환경이나, 가짜 서버에 속아도 되는 데이터만 다루는 경우에 한정한다.
- `SG_ServerConfig.flags` 의 정의되지 않은 비트는 `SG_Client_Connect` 가 I/O 전에 `SG_NOT_SUPPORTED` 로 거부한다
  (`SG_ClientConfig.flags` 와 같은 규칙). 새 헤더의 신뢰 옵션이나 오타가 조용히 무시되지 않는다.

### 2.2 SPKI pinning

- pin 은 DER SubjectPublicKeyInfo 의 SHA-256 이다. `SG_Client_ComputeSpkiPin(pem, size, &pin)` 이나
  `sg_admin pin <cert.pem>` 으로 계산한다.
- 최대 `SG_MAX_PINS`(8)개. 체인 검증과 hostname 검증이 **먼저** 성공해야 하고, pin 은 검증된 체인의 어느 인증서
  (leaf, 중간, 루트)와 일치해도 된다. 서버가 보낸 원본 체인과는 비교하지 않는다.
- 교체: 현재 키와 다음 키의 pin 을 미리 배포 → 서버 인증서 교체 → 구 pin 제거
  ([06 §4](../docs/design/06-key-lifecycle.md#4-서버-키)).
- pin 불일치는 `SG_PINNING_ERROR` 와 `SG_LOG_ERROR` 수준 로그 `event=possible_tls_interception` 을 남긴다. 기업 SSL
  검사 장비나 악성코드의 전형적인 신호이므로 **자동 재시도로 덮지 말고** 사용자/운영자에게 알린다.

### 2.3 Server proof key

`proof_keys`(최대 `SG_MAX_PROOF_KEYS` = 4, SEC1 비압축 P-256, 곡선 위 검증)를 설정하면 서버는 `AUTH_RESULT(OK)` 에
서명해야 하고, 서명이 없거나 틀리면 `SG_INVALID_SIGNATURE` 이다. TLS PKI 와 독립적이므로 CA 가 뚫리거나 pin 없이 OS store 를
쓰는 경우에도 가짜 서버가 **성공한 세션**을 흉내 내는 것을 막는다. 교체를 위해 여러 키를 둘 수 있다.

proof key 가 막지 못하는 것:

- 서명되는 것은 `AUTH_RESULT(OK)` 뿐이다. REJECTED / RETRY_LATER / UNSUPPORTED_VERSION 은 서명 없이 오므로 가짜 서버가
  `SG_SERVER_REJECTED` 나 `SG_VERSION_MISMATCH` 를 일으킬 수 있다. 이 코드만 보고 identity 를 재등록하거나 업그레이드하지 않는다.
- 서명 검사는 AUTH_RESULT 에서야 일어나므로, 가짜 서버는 그 전에 CLIENT_HELLO 의 주장(제품, 라이선스 ID, integrity 보고)을
  이미 받는다. 주장을 가짜 서버에게서 지키는 것은 TLS 단계의 서버 인증(사설 CA + pin)뿐이다.

## 3. 채널 옵션

- `SG_CLIENT_FLAG_ALLOW_TLS12`: TLS 1.2 를 허용하되 ECDHE + AEAD 스위트와 Extended Master Secret 을 요구한다
  (EMS 없으면 `SG_TLS_ERROR`). TLS 1.3 을 쓸 수 없는 환경에서만 켠다. **업그레이드 주의**: 채널 바인딩이 RFC 9266
  tls-exporter(길이 0 context)로 바뀌었다(b95a843). TLS 1.3 에서는 값이 같지만 TLS 1.2 에서는 다르므로, 이 변경 전에
  빌드된 클라이언트나 서버는 TLS 1.2 로 협상되면 새 빌드와 인증에 실패한다. 양쪽을 함께 올린다.
- `SG_CLIENT_FLAG_APP_ENCRYPTION`: DATA payload 를 TLS 안에서 AES-256-GCM 으로 한 번 더 암호화한다. 이 키는 같은 TLS
  세션의 exporter 에서 유도되므로 **TLS 를 종단한 MITM 에 대한 추가 방어가 아니다**. 목적은 TLS 구현 결함에 대한 심층
  방어와 서버 정책(`SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION`) 충족이다. 암호화 여부와 무관하게 모든 인증 후 프레임에는
  GCM tag 가 있다.
- 세션 수명과 재인증: 수명은 서버가 정한다. 긴 연결은 `SG_CLIENT_FLAG_AUTO_REFRESH` 나 `SG_Client_Refresh` 로 유지한다.
  자동 재인증은 Send/Receive 진입 때만 실행되므로 `SG_WAIT_INFINITE` 로 막힌 수신 스레드는 유한한 타임아웃으로 바꿔야 한다
  ([INTEGRATION.md §6](INTEGRATION.md#6-blocking-과-타임아웃)).
  재인증은 새 서명, epoch 키 교체, TLS 1.3 KeyUpdate 를 수행하지만 post-compromise security 를 주장하지 않는다.

## 4. Key store 선택

| 저장소 | 언제 | 보호 수준 |
|---|---|---|
| `SG_KEYSTORE_AUTO` (기본) | 일반적인 경우 | Windows: TPM(PCP) → Software KSP. Linux: TPM2(빌드 시) → FILE. 가장 강한 것을 고르고 identity 를 고정 |
| `SG_KEYSTORE_CNG_TPM` / `SG_KEYSTORE_TPM2` | 하드웨어 키가 **필수**일 때 (없으면 생성 실패) | 키 추출 불가, 서명 오라클은 가능 |
| `SG_KEYSTORE_CNG_SOFTWARE` | Windows, TPM 을 쓰지 않을 때 | non-exportable, 같은 사용자는 사용 가능, 관리자는 추출 가능 |
| `SG_KEYSTORE_FILE` | 디렉터리를 직접 관리해야 할 때 (예제의 `--key-dir`) | Windows DPAPI(사용자 범위), Linux 0600. **TPM 과 동등하지 않다** |
| `SG_KEYSTORE_MEMORY` | 테스트, 일회성 identity | 영속성 없음. 프로세스가 끝나면 identity 가 사라진다 |

### 4.1 `hardware_backed` 의 의미

`SG_IdentityInfo.hardware_backed == 1` 은 "이 라이브러리가 키를 TPM(CNG Platform Crypto Provider 또는 Linux TPM2)에
만들었다" 는 **로컬 사실**이다. 서버에 전송되지 않으며, 전송하더라도 클라이언트의 주장일 뿐 **원격 증명(attestation)이
아니다**. 서버가 하드웨어 키를 요구해야 한다면 SockGate 범위 밖의 attestation 이 필요하다.

AUTO 는 TPM 을 쓸 수 없다고 판단될 때(TPM 2.0 없음, TBS 비활성, `/dev/tpmrm0` 접근 불가, owner auth 설정 등)만
소프트웨어 저장소에 새 키를 만든다. 키를 만드는 중의 일시적 TPM 오류는 `SG_KEYSTORE_ERROR` 로 보고된다. 단, **TPM 에
닿을 수 있는지는 `SG_Client_Create` 때 정해진다**: Linux 는 그때 TCTI 를 고르고(`/dev/tpmrm0` 에 접근할 수 없으면 그 핸들에서는
TPM 없음), Windows 는 그때 TPM provider 를 **어떤 이유로든** 열지 못하면 그 저장소를 목록에서 뺀다. 이런 경우 같은 핸들로
다시 시도해도 회복되지 않으므로 `SG_Client_Destroy` 후 다시 Create 한다. 그 핸들로 **처음** 만드는 identity 는 소프트웨어
저장소(Windows Software KSP, Linux FILE)에 만들어진다. 결과를 확인하려면 `key_store_type` 과 `hardware_backed` 를 기록한다.

### 4.2 Identity 이름

- `[A-Za-z0-9._-]{1,128}`, `.` 으로 시작 불가, Windows 장치 이름(`CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`,
  `LPT0`–`LPT9`, 대소문자·확장자 무관) 불가. 모든 플랫폼에서 같은 규칙이다.
- 이름 공간(CNG 키 `SockGate-<name>`, 사용자 단위 key 디렉터리)은 **같은 OS 사용자의 모든 SockGate 애플리케이션이
  공유**한다. 이름이 겹치면 두 애플리케이션이 같은 키를 쓰게 된다. reverse-DNS 형식으로 전역적으로 고유하게 짓는다.
- 키 교체는 새 이름(예: `name.next`)으로 만들고 enroll 한 뒤 전환한다([06 §2.4](../docs/design/06-key-lifecycle.md#24-교체-rotation)).

### 4.3 `SG_Client_DeleteIdentityEx` 와 FORCE

- `SG_Client_DeleteIdentity` = `DeleteIdentityEx(client, 0)`: 연결되어 있지 않은 상태(`DISCONNECTED` / `CLOSED` /
  `EXPIRED`)에서만 허용된다. AUTO 는 locator 에 기록된 저장소의 키와 locator 를 지운다. 그 저장소를 지금 쓸 수 없으면
  **거부**한다(`SG_KEYSTORE_ERROR`) — 키가 남은 채 identity 를 잊어버리지 않게 하기 위해서다. 다른 저장소의 장애는 일반
  삭제를 막지 않는다.
- `SG_IDENTITY_DELETE_FORCE`: 실패하는 저장소를 건너뛰고 locator 를 **항상** 지운다. 기록된 저장소에 키가 남을 수 있다.
  남은 키(예: 나중에 다시 보이는 TPM 키)는 새 identity 를 만들기 전에 다시 발견되면 기존 identity 로 다시 채택된다.
  확실히 버리려면 그 저장소가 동작할 때 일반 삭제를 한다.
- 정의되지 않은 플래그 비트는 `SG_INVALID_ARGUMENT`. 삭제 후 새 identity 는 서버에 다시 등록/enroll 해야 하고,
  서버에서는 구 installation 을 폐기한다.

### 4.4 `SG_IDENTITY_LOST` 처리

`SG_IDENTITY_LOST` 는 "identity 를 보관하던 저장소는 동작하지만 키가 없다" 는 뜻이다(예: 키 파일이나 TPM 키 blob 파일
삭제, CNG 가 키 없음을 보고). 라이브러리는 **대체 identity 를 조용히 만들지 않는다**. 복구 절차:

1. 사용자/운영자에게 알린다(예기치 않은 키 소실은 보안 사건일 수 있다).
2. `SG_Client_DeleteIdentity` 로 locator 를 지운다.
3. `SG_Client_EnsureIdentity` 로 새 키를 만들고, 공개키를 등록하거나 새 enrollment token 으로 `SG_Client_Enroll`.
4. 서버에서 구 installation 을 폐기하고(좌석을 쓰는 라이선스면 반납) 새 installation 을 관리한다.

`SG_KEYSTORE_ERROR` 는 다르다: 저장소를 지금 쓸 수 없거나(TPM provider/서비스), 파일·디렉터리 검사에 실패한 것이다.
재시도하거나(TPM 도달 여부는 Create 때 정해지므로 필요하면 Destroy + Create) 환경(권한, 소유자, 링크)을 점검한다.
일반적으로는 여기서 identity 를 지우면 안 된다.

**TPM clear/reset 은 대개 `SG_IDENTITY_LOST` 가 아니다.** Linux TPM2 는 키 blob 파일이 남아 있어 공개키 조회(EnsureIdentity)는
성공하고, TPM 이 blob 을 더 이상 로드하지 못해 **서명**(Authenticate/Enroll/Refresh)에서 `SG_KEYSTORE_ERROR` 가 계속된다.
Windows CNG 의 TPM clear 뒤 동작은 검증되지 않았다. TPM 을 clear/reset 한 것이 확실한데 `SG_KEYSTORE_ERROR` 가 계속되면
`SG_Client_DeleteIdentityEx(client, SG_IDENTITY_DELETE_FORCE)` 로 identity 를 지우고 위 3–4 단계대로 다시 등록/enroll 한다.

## 5. Proxy

- 기본 `SG_PROXY_MODE_DIRECT`(`proxy == NULL` 포함)는 시스템 proxy 설정과 `http_proxy` / `https_proxy` / `ALL_PROXY`
  환경 변수를 **읽지 않는다**. 환경 주입으로 트래픽 경로가 바뀌지 않는다.
- `SG_PROXY_MODE_SYSTEM` 은 명시적으로 선택할 때만 OS 설정을 읽는다(Windows WinHTTP IE 설정의 정적 proxy, PAC/WPAD
  미지원; Linux `NO_PROXY`/`ALL_PROXY`/`HTTPS_PROXY`). `https://` proxy URL 은 `SG_NOT_SUPPORTED`.
- proxy 는 TLS 암호문만 본다. 하지만 **proxy 까지의 구간은 평문**이므로 HTTP Basic / SOCKS5 비밀번호는 그 구간에서
  보인다. 신뢰할 수 있는 네트워크 안의 proxy 에만 자격 증명을 쓴다. 자격 증명은 로그에 남지 않는다.
- proxy 사용은 서버 인증과 무관하다. pinning/proof key 설정은 proxy 여부와 상관없이 그대로 적용된다.

## 6. 라이선스와 권한

`product_id`, `product_version`, `license_id`, `requested_features`, integrity 보고는 모두 **주장**이다. 서버가 registry
바인딩과 license store 로 판단해 `granted_features`, `policy`, 수명을 돌려준다. 클라이언트 쪽에서 기능을 막는 것은 사용자
경험을 위한 것이며, 보안 경계는 서버의 판단과 서버 쪽 기능 검사다([INTEGRATION.md §10](INTEGRATION.md#10-라이선스-클라이언트-관점)).

## 7. Integrity 보고는 주장이다

`SG_CLIENT_FLAG_INTEGRITY_REPORT` 는 실행 파일/라이브러리 해시와 디버거·preload·ASLR 등의 관측값을 보낸다
([ARCHITECTURE.md §2.7](ARCHITECTURE.md#27-integrity-수집-srcplatformintegrity_cpp)).

- 모든 관측은 우회 가능하다. 서버는 이 보고를 **신뢰를 낮추는 데만** 쓴다(Normal → Restricted → Fail). 보고로 권한이
  올라가는 일은 없다.
- 플래그가 **없다는 것**은 아무것도 증명하지 않는다. Linux 는 `UNSIGNED_EXECUTABLE` 을 설정하지 않고, Windows 서명
  검사는 embedded Authenticode 만 본다(카탈로그 서명 파일은 unsigned 로 보고). platform 값 자체도 주장이다.
- 개발 환경(디버거, 서명 없는 빌드)에서는 정상적으로도 플래그가 선다. 서버 정책(`integrity_restrict_mask`,
  `integrity_reject_mask`, 실행 파일 allowlist)으로 조정한다.
- 알 수 없는 `SG_CLIENT_FLAG_*` 는 `SG_NOT_SUPPORTED` 로 거부된다. 새 헤더의 플래그가 옛 라이브러리에서 조용히 무시되지 않는다.

## 8. 라이브러리가 보장하는 검증

### 8.1 ABI 와 입력 검증

- 입력 구조체의 모르는 뒤쪽 필드가 0 이 아니면 `SG_NOT_SUPPORTED`, `SG_ClientConfig.flags` / `SG_ServerConfig.flags` 의
  모르는 비트도 `SG_NOT_SUPPORTED`: 새 헤더로 빌드한 애플리케이션이 옛 라이브러리에서 보안 설정을 조용히 잃지 않는다.
  모든 문자열은 상한 길이로 복사한다. 예외는 ABI 경계를 넘지 않는다.
- 설치 패키지는 공개 헤더 8 개만 담는다. 내부 헤더에 의존하는 코드는 설치본으로 빌드되지 않는다(`tests/package` 가 설치된
  헤더 목록을 검사).

### 8.2 Hardening 과 export 검사

- 모든 SockGate 타깃에 hardening 플래그를 적용한다(`SOCKGATE_HARDENING=ON` 기본). MSVC/clang-cl: `/GS /sdl /guard:cf`,
  링크 `/guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT`. GCC/Clang: `-fstack-protector-strong`,
  `-fstack-clash-protection`, `-fcf-protection=full`(x86_64) / `-mbranch-protection=standard`(ARM64),
  Release `_FORTIFY_SOURCE=3`(GCC ≥ 12, Clang ≥ 16, 그 외 2), `-z relro -z now -z noexecstack`, 공유 라이브러리
  `--exclude-libs,ALL` 과 Release `-s`. 상세는 [BUILD.md §6](BUILD.md#6-hardening-과-export).
- 심볼: hidden visibility 가 기본이고, Linux 공유 라이브러리는 version script(`cmake/sockgate_exports.map`, `SG_*` 만
  global)로 C ABI 만 export 한다. CTest `sg_exports_sockgate_client` 가 export 테이블을 `client.h` 의 `SG_CLIENT_API`
  선언과 비교한다(`nm` / `dumpbin` / `llvm-readobj`).
- Windows 는 OpenSSL 을 정적 링크해(vcpkg `x64-windows-static-md`) DLL 하나로 배포할 수 있다.
- OpenSSL 버전: configure 시 `OPENSSL_VERSION` 이 3.0.7 미만이면 CMake 경고(CVE-2022-3602/3786). OpenSSL 을 함께
  배포하는 빌드(Windows, 또는 정적 링크)는 실행 시에도 `OpenSSL_version_num()` 을 확인해, 3.0.7 미만이면 첫 Connect 에서
  프로세스당 한 번 `event=config_warning` 을 WARN 으로 남긴다. 배포판 OpenSSL 은 버전 번호로 패치 여부를 알 수 없으므로
  실행 시에는 경고하지 않는다.

### 8.3 Sanitizer 와 fuzzing

- 프리셋: `linux-gcc-asan`, `linux-clang-asan`(ASan + UBSan), `linux-clang-tsan`(TSan), `windows-msvc-asan`. CI 는 이들로
  전체 테스트를 실행한다. Linux sanitizer test 프리셋은 CI 와 같은 `ASAN_OPTIONS` / `UBSAN_OPTIONS`(`halt_on_error=1`) /
  `TSAN_OPTIONS` 를 설정하므로 로컬 실행도 첫 보고에서 실패한다(bd6ca45).
- Fuzz 타깃(`fuzz/`): `frame_decoder`, `messages`, `channel`(Common 프로토콜 코드 — 클라이언트가 서버 입력을 파싱하는
  바로 그 코드), `proxy_config`(클라이언트 proxy URL / WinINet 목록 / bypass 파서), `storage_files`(서버 저장소).
  `SOCKGATE_BUILD_TESTS=ON` 이면 같은 타깃이 결정적 mutation 테스트(`sg_mutate_*`, CTest 라벨 `fuzz`)로도 돌고,
  seed 는 코드에서 만든다(`sg_mutate_<name> --write-seeds=DIR`). CI 는 그 seed 로 libFuzzer 를 push 마다 타깃당 60 s,
  nightly 20 분 실행하며, 한 타깃이 실패해도 나머지를 모두 돌린 뒤 실패로 보고한다.
- `channel` 타깃의 불변식: 받아들인 프레임은 sequence 가 정확히 연속이고, 한 번 poison 된 채널은 다시 아무것도 받지 않는다.
- 클라이언트 key 파일 파서는 fuzz 타깃이 아니라 보안 테스트(`sg_security_keystore`: 변조, 링크, 권한/ACL, 동시 생성,
  locator 의미, 실제 TPM 키)로 검증한다.
- 보안 시나리오 테스트: 사칭, 서명 변조, 만료/재사용 challenge, 새 연결에서의 재전송, TLS 종단 중계, 버전 실패,
  server proof 다운그레이드, token 재사용/변조/위조/중계(`sg_security_handshake`), 사용자 설치 CA MITM 과 pinning,
  proof key 로만 잡히는 가짜 서버, 적대적 proxy(`sg_security_proxy_mitm`), replay/재정렬/비트 반전(`channel_test`).

## 9. 로그

- `log_callback` 이 NULL 이면 아무것도 기록하지 않는다. 기본 수준은 `SG_LOG_WARN`.
- 키, 서명, token, 비밀번호, exporter 값, transcript, payload 는 기록하지 않는다. installation/session ID 는 앞 8 바이트만.
- 주요 이벤트: `possible_tls_interception`(ERROR), `tls_failed`, `connect_failed`, `auth_failed`, `refresh_failed`,
  `frame_rejected`, `proxy_connect_failed`, `proxy_negotiation_failed`, `config_warning`(WARN), `tls_established`, `authenticated`,
  `refreshed`, `closed_by_server`, `session_expired`, `disconnected`, `identity_created`, `proxy_tunnel_established`(INFO).
- 로컬 로그는 실패 원인을 구체적으로 드러낸다. 로그 저장소의 접근 권한을 관리한다.

## 10. 취약점 보고

보안 취약점은 **공개 이슈로 올리지 말고 maintainer 에게 비공개로** 보고한다(현재 별도의 advisory 채널은 설정되어 있지
않다). 재현 절차, 영향받는 버전/커밋, 플랫폼과 key store 종류, 가능하면 최소 재현 코드를 포함한다. 수정이 배포될 때까지 세부 내용을 공개하지 않는다.
