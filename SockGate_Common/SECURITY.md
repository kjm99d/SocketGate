# SockGate_Common Security

> 관련 설계: [02-threat-model.md](../docs/design/02-threat-model.md), [12-dependencies.md](../docs/design/12-dependencies.md),
> [13-security-limitations.md](../docs/design/13-security-limitations.md). 위협별 정리는 [THREAT_MODEL.md](THREAT_MODEL.md).

## 1. 암호 선택

**원칙: OpenSSL 3 의 EVP 수준, deprecated 가 아닌 API 만 쓴다. 자체 암호 구성은 없다.**
`crypto/crypto.h` 는 검증된 구성만 노출하며 raw block cipher 나 저수준 EC API 를 노출하지 않는다.

| 용도 | 알고리즘 | 구현 (`crypto/openssl_crypto.cpp`) |
|---|---|---|
| 해시 | SHA-256 | `EVP_DigestInit_ex(EVP_sha256())` — `Sha256`, `Sha256Hasher` |
| MAC | HMAC-SHA256 | `EVP_MAC_fetch("HMAC")`, digest `SHA256` |
| KDF | HKDF-SHA256 (RFC 5869) | `EVP_KDF_fetch("HKDF")`. 빈 salt 는 HashLen 개의 0 (RFC 5869 §2.2). 출력 ≤ 255 × 32 |
| AEAD | AES-256-GCM, nonce 12 bytes, tag 16 bytes | `EVP_aes_256_gcm()`. tag 불일치는 `SG_CRYPTO_ERROR` 이며 출력 평문을 지운다 |
| 서명 | ECDSA P-256 + SHA-256 | `EVP_DigestSign` / `EVP_DigestVerify`. wire 형식은 IEEE P1363 `r‖s` (64 bytes), OpenSSL 과는 DER 로 변환 |
| 공개키 | SEC1 uncompressed P-256 (65 bytes, `0x04‖X‖Y`) | `EVP_PKEY_fromdata` + `EVP_PKEY_public_check` (곡선 위, 무한원점 아님) |
| 키 생성 | P-256 | `EVP_PKEY_Q_keygen(..., "EC", "P-256")` |
| 난수 | OpenSSL DRBG (OS CSPRNG 로 seed) | `RAND_bytes` — `RandomBytes`, `RandomArray` |

- 서명 검증은 길이 64 가 아닌 서명, `r = 0` 또는 `s = 0`, 잘못된 공개키를 모두 `SG_INVALID_SIGNATURE` 로 거부한다.
  DER → P1363 변환은 뒤따르는 바이트가 있거나 스칼라가 32 bytes 를 넘으면 거부한다.
- 소프트웨어 private key (`SoftwareP256Key`) 는 PKCS#8 DER (뒤따르는 바이트 거부) 또는 PEM 에서 읽으며 P-256 만 허용한다.
  PEM 비밀번호 프롬프트는 절대 띄우지 않는다 (콘솔 대기 방지). PKCS#8 내보내기는 `SecureBytes` 로 돌려준다.
- 모든 진입점은 종료 시 스레드의 OpenSSL 에러 큐를 비운다.
- 알고리즘 사용처: 프로토콜 레이블과 조합은 [PROTOCOL.md §7–8](PROTOCOL.md).

## 2. TLS 설정

`tls/openssl_tls.cpp` 의 `ApplyCommonPolicy` 와 컨텍스트 생성 코드가 강제하는 값이다.

| 항목 | 값 |
|---|---|
| 프로토콜 버전 | 최소 TLS 1.3. `allow_tls12 = true` 일 때만 최소 TLS 1.2. 최대 TLS 1.3 |
| TLS 1.2 조건 | 핸드셰이크 직후 Extended Master Secret 확인 (`SSL_get_extms_support`), 없으면 `SG_TLS_ERROR` (RFC 9266) |
| TLS 1.3 suites | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256` |
| TLS 1.2 cipher | `ECDHE-{ECDSA,RSA}-AES256-GCM-SHA384`, `ECDHE-{ECDSA,RSA}-CHACHA20-POLY1305`, `ECDHE-{ECDSA,RSA}-AES128-GCM-SHA256` 만 |
| 옵션 | `SSL_OP_NO_COMPRESSION`, `SSL_OP_NO_RENEGOTIATION`, `SSL_OP_NO_TICKET`, session cache off (재개 없음: 모든 연결이 전체 핸드셰이크와 새 SockGate 인증) |
| 서버 | `SSL_OP_CIPHER_SERVER_PREFERENCE`, session ticket 0 개, `SSL_VERIFY_NONE` (클라이언트 인증은 SockGate 계층), 암호화되지 않은 PEM 키만, `SSL_CTX_check_private_key` |
| 클라이언트 검증 | `SSL_VERIFY_PEER` + 체인/유효기간/서명. DNS 이름은 `SSL_set1_host` + SNI, IP literal 은 `X509_VERIFY_PARAM_set1_ip_asc` (iPAddress SAN). 부분 wildcard 금지 (`X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`) |
| server_name | 비어 있거나 253 bytes 초과, NUL 포함이면 `SG_INVALID_ARGUMENT` |
| 신뢰 앵커 | `ca_file`, `ca_pem`, `trust_system_store` 중 최소 하나. 없으면 `SG_INVALID_ARGUMENT`. OS 저장소: Windows `ROOT`, Linux OpenSSL 기본 경로 |
| SPKI pinning | pin = DER SubjectPublicKeyInfo 의 SHA-256. 체인·hostname 검증이 성공한 뒤 **`SSL_get0_verified_chain`** 과만 비교 (상대가 보낸 원본 체인과 비교하지 않음: 위조 leaf 뒤에 진짜 인증서를 붙이는 CVE-2016-2402 유형 차단). 비교는 상수 시간. 복수 pin 지원 (교체 대비) |
| 채널 바인딩 | RFC 9266 tls-exporter: 레이블 `EXPORTER-Channel-Binding`, 길이 0 context (`use_context = 1`), 32 bytes. TLS 1.3 과 TLS 1.2 모두 표준 값 (b95a843 이전 빌드는 TLS 1.2 에서 context 없이 계산했으므로 TLS 1.2 로는 새 빌드와 인증되지 않는다) |
| KeyUpdate | `RequestKeyUpdate()` (TLS 1.3). Client/Server 는 재인증 때 호출한다 |

- **OpenSSL security level**: 코드는 `SSL_CTX_set_security_level` 을 호출하지 않는다. 키 크기·서명 알고리즘의 하한은 OpenSSL 빌드와
  설정 파일(`openssl.cnf`)의 기본 security level 을 따른다. 배포 환경에서 이를 낮추지 않아야 한다.
- **OpenSSL 버전 경고** ([12 §1](../docs/design/12-dependencies.md)): configure 시 `OPENSSL_VERSION < 3.0.7` 이면 CMake 경고
  (CVE-2022-3602/3786). OpenSSL 을 함께 배포하는 빌드(`SOCKGATE_BUNDLED_OPENSSL` = Windows 또는 `OPENSSL_USE_STATIC_LIBS`)는
  실행 시 `tls::OutdatedBundledOpenSslVersion()` 으로 `OpenSSL_version_num() < 0x30000070` 을 확인해 `event=config_warning` 을 남긴다
  (서버는 시작 시, 클라이언트는 프로세스당 1회 — WARN 로그가 켜진 첫 클라이언트가 첫 연결 전에). 배포판 OpenSSL 은 실행 시 보고하지 않는다. 경고일 뿐 연결을 거부하지 않는다.
- 시스템 trust store 를 pin 이나 서버 proof key 없이 신뢰하는 것은 Client 가 명시적 플래그 없이는 거부한다
  ([05 §1](../docs/design/05-handshake-sequence.md)). Common 엔진은 설정된 pin 을 검사할 뿐 이 정책을 강제하지 않는다.

## 3. 비밀값 소거와 상수 시간 비교

- `SecureZero` = `OPENSSL_cleanse` (최적화로 제거되지 않음). `SecureBytes` 는 해제·재할당 때마다 지운다.
- 소거하는 곳: 채널 키 (소멸자, poison, 키 전환 임시값), HKDF/exporter/AEAD 실패 출력, 디코더 버퍼와 `DecodedFrame`,
  enrollment `K_tok` 임시값, base64 디코더 누산기와 출력(`SecureBytes`). 목록은 [ARCHITECTURE.md §4](ARCHITECTURE.md).
- `ConstantTimeEqual` = 길이 비교 후 `CRYPTO_memcmp`. SPKI pin 과 enrollment MAC 비교에 쓴다. 비밀값을 `memcmp`/`==` 로 비교하지 않는다.
- AEAD tag 와 ECDSA 검증은 OpenSSL 내부 구현을 쓴다.

## 4. 로깅 규칙

`core/log.h` 의 규칙이며 리뷰로 강제한다.

- 키 재료, 세션 키, exporter 값, transcript 해시, 서명, token, 비밀번호, payload 바이트를 **절대** 기록하지 않는다.
- 식별자(세션 ID·installation ID 앞부분, `ShortId()` 로 8 bytes hex)는 허용한다.
- `SG_LOGD` / `SG_LOGT` 는 `NDEBUG` 빌드에서 제거된다. `SOCKGATE_ENABLE_DEBUG_LOG` (CMake 옵션) 로만 유지할 수 있다.
- 로그 콜백이 던진 예외는 삼킨다 (라이브러리가 죽지 않게). TLS 엔진의 `ErrorDetail()` 도 비밀값을 담지 않는다.

## 5. 파서 강화

- 헤더를 끝까지 검증한 뒤에만 본문을 기다린다 (구조 검사 + 상태 검사, 헤더 48 bytes 가 모이는 즉시 거부). 검사 전 버퍼 사용량은
  `SetMaxBuffered()` (인증 전 16 KiB) 가 제한한다.
- 크기 상한: 인증 전 4096 bytes / 디코더 버퍼 16 KiB, 인증 후 DATA 는 설정 상한 (최대 16 MiB), 절대 버퍼 상한 존재. 덧셈 전에 상한 검사.
- `Reader` 는 접근 전 길이 검사와 실패 고정(latch), `ExpectEnd()` 로 trailing data 거부.
- TLV: 정확한 길이, 16 항목, 중복 금지. 문자열: 엄격한 UTF-8 + 제어/서식/양방향 문자 거부.
- 디코더는 fail closed (`HeaderCheck` 없으면 동작 안 함), 오류는 고정되고 연결 종료로 이어진다.
- 인코더는 자기 출력을 디코더로 재검증한다.
- 규칙 전체: [PROTOCOL.md](PROTOCOL.md).

## 6. Fuzzing 과 sanitizer

### 6.1 Fuzz 타깃 (`fuzz/`)

각 타깃은 `LLVMFuzzerTestOneInput` 과 `SockGateFuzzSeeds()` (코드로 생성하는 seed) 를 정의한다.

| 타깃 | 대상 라이브러리 | 내용 / 불변식 |
|---|---|---|
| `frame_decoder` | `sockgate_common` | byte 0 = 수신 역할·단계(8 조합)와 DATA 상한, byte 1 = chunk 패턴. 수락된 프레임은 크기 일치, 16 MiB 이하, `CheckHeaderForState` 통과여야 하며 모든 payload 디코더로 dispatch |
| `messages` | `sockgate_common` | byte 0 = 디코더 선택 (CLIENT_HELLO, SERVER_HELLO, CLIENT_PROOF, AUTH_RESULT, REAUTH_CHALLENGE/PROOF/RESULT, CLOSE, integrity report, token 공개 부분, token 문자열, base64url). 디코딩 성공 시 재인코딩→재디코딩→재인코딩 결과가 같아야 함 |
| `channel` | `sockgate_common` | 고정 키의 `ProtectedChannel` 수신 경로 (디코딩 + sequence/KEY_PHASE/tag). 수락된 프레임은 `kFirstSessionSequence` 부터 정확히 연속된 sequence 여야 하고 (replay·재정렬·gap 불가), 한 번 거부된 뒤에는 어떤 프레임도 수락되지 않아야 함 (poison 불변식) |
| `proxy_config` | `sockgate_client_core` | proxy URL / 목록 / bypass 파서 |
| `storage_files` | `sockgate_server_core` | registry / license 파일 로더 |

- `SOCKGATE_BUILD_FUZZERS=ON` (Clang 또는 MSVC): libFuzzer 실행 파일 `sg_fuzz_<name>`. 모든 코드가 coverage 계측된다.
- `SOCKGATE_BUILD_TESTS=ON`: 같은 타깃을 결정적 mutation driver (`fuzz/standalone_main.cpp`) 와 링크한 `sg_mutate_<name>` 이
  CTest 에 등록된다 (label `fuzz;protocol`, timeout 600 s). 기본 `--iterations` 는 `SG_MUTATION_ITERATIONS` (20000),
  `storage_files` 는 2000. 모든 seed 와 빈 입력을 먼저 실행한 뒤 고정 seed 의 PRNG 로 bit flip, 바이트 치환·삽입·삭제, 잘라내기,
  길이 필드용 16/32bit 경계값, 구간 복제, ±1 변형을 적용한다.
- 같은 실행 파일로 crash 입력 재현(`sg_mutate_<name> <file>...`)과 seed 추출(`--write-seeds=DIR`)을 한다. 실행 방법은 [BUILD.md §5](BUILD.md).
- libFuzzer 없이도 AFL++ 같은 도구가 같은 `LLVMFuzzerTestOneInput` 을 쓸 수 있다 ([12 §3](../docs/design/12-dependencies.md)).
- CI (`.github/workflows/ci.yml` 의 fuzz job) 는 `linux-clang-fuzz` 로 빌드한 뒤 타깃마다 `--write-seeds` 로 corpus 를 만들고
  libFuzzer 를 push 때 60 초, nightly 에 20 분 돌린다. crash 입력은 artifact 로 올린다. Windows / Linux / TPM2 / container job 은 `sg_mutate_*` 를 포함한
  CTest 전체를 각 프리셋(ASan, UBSan, TSan 프리셋 포함)에서 실행한다.

### 6.2 Sanitizer

`SOCKGATE_SANITIZER` = `address`, `undefined`, `address+undefined`, `thread` (`cmake/SockGateSanitizers.cmake`, 프로젝트 전체 적용).

- GCC/Clang: `-fsanitize=address`, `-fsanitize=undefined -fno-sanitize-recover=undefined` (Clang 은 `-fsanitize=integer` 도,
  단 unsigned overflow/shift 제외), `-fsanitize=thread`.
- MSVC: address 만 (`/fsanitize=address`).
- 프리셋: `linux-gcc-asan`, `linux-clang-asan` (ASan+UBSan), `linux-clang-tsan`, `windows-msvc-asan`, fuzz 프리셋 `linux-clang-fuzz`
  (libFuzzer + ASan + UBSan), `windows-msvc-fuzz` (libFuzzer + ASan).
- Linux sanitizer test 프리셋(`linux-gcc-asan`, `linux-clang-asan`, `linux-clang-tsan`)은 숨은 `test-sanitizers` 프리셋에서 CI 와 같은
  환경을 받는다: `ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1`,
  `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1` (복구 가능한 `-fsanitize=integer` 발견도 실패로 처리),
  `TSAN_OPTIONS=halt_on_error=1 second_deadlock_stack=1`. 로컬 `ctest --preset` 에서도 CI 처럼 sanitizer 보고가 테스트를 실패시킨다.
- hardening 컴파일 플래그(`/GS /sdl /guard:cf`, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE`, CET/BTI 등)는 `sockgate_configure_target` 으로
  Common 에도 적용된다. 링크 단계 플래그는 최종 바이너리(Client/Server 공유 라이브러리)에 적용된다 ([10 §4](../docs/design/10-windows-platform-layer.md), [11 §5](../docs/design/11-linux-platform-layer.md)).

## 7. 취약점 보고

- SockGate_Common 을 포함한 SockGate 의 취약점은 **메인테이너에게 비공개로** 보고한다. 현재 저장소에 별도의 보안 advisory
  채널은 설정되어 있지 않다.
- 공개 issue, pull request, 공개 토론에 취약점 세부 내용을 올리지 않는다.
- 보고에 포함하면 좋은 것: 영향받는 커밋/버전, 재현 절차 또는 입력 파일 (fuzz 입력은 `sg_mutate_<name> <file>` 로 재현 가능),
  영향 (어떤 경계 — 네트워크, 인증된 peer, 로컬 — 에서 가능한지), 가능하면 sanitizer 출력.
- 설계상 보장하지 않는 항목([13-security-limitations.md](../docs/design/13-security-limitations.md))은 그 자체로는 취약점이 아니다.
