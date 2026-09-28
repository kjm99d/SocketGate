# Building SockGate_Common

> 관련 설계: [12-dependencies.md](../docs/design/12-dependencies.md), [08-directory-structure.md](../docs/design/08-directory-structure.md).

## 1. 빌드 방식

- SockGate_Common 은 **전체 프로젝트의 일부로만** 빌드된다. `SockGate_Common/CMakeLists.txt` 에는 `project()` 가 없고,
  최상위 `CMakeLists.txt` 가 정하는 값(`SOCKGATE_PLATFORM`, `sockgate_configure_target()`, `find_package(OpenSSL)`, C++17 설정)에
  의존한다. 저장소 루트에서 configure 한다.
- 결과물은 정적 라이브러리 `sockgate_common` (alias `SockGate::Common`) 이다. 최상위에서 `CMAKE_POSITION_INDEPENDENT_CODE ON` 이므로
  공유 라이브러리(`sockgate_client`, `sockgate_server`) 안에 링크될 수 있다.
- Common 만 빌드하려면 타깃을 지정한다: `cmake --build --preset <preset> --target sockgate_common`.
- 플랫폼은 Windows, Linux 뿐이다 (그 밖은 configure 단계 `FATAL_ERROR`). 플랫폼별 소스(`platform/windows/*`, `platform/linux/*`)는
  CMake 가 고른다.

### 설치와 CMake 패키지

`cmake/SockGateInstall.cmake` 가 설치 규칙과 패키지(`find_package(SockGate)`)를 만든다. Common 은 자체 설치 규칙이 없다.
설치 규칙은 `SOCKGATE_INSTALL` 이 ON 일 때만 생성된다 (기본값 = 최상위 프로젝트일 때 ON, `add_subdirectory`/FetchContent 로
포함되면 OFF).

| 빌드 | 설치되는 것 |
|---|---|
| shared (`SOCKGATE_BUILD_SHARED=ON`, 기본) | `sockgate_client`, `sockgate_server` (`SockGate::Client` / `SockGate::Server`) 와 public 헤더. **`sockgate_common` 은 설치하지 않는다** (공유 라이브러리 안에 들어 있다) |
| static (`SOCKGATE_BUILD_SHARED=OFF`) | 위 + 내부 archive `sockgate_client_core`, `sockgate_server_core`, `sockgate_common` (`SockGate::ClientCore` / `SockGate::ServerCore` / `SockGate::Common`). 패키지 설정이 `find_dependency(Threads)`, `find_dependency(OpenSSL 3.0)` 을 수행한다 |

- 설치되는 헤더는 public 헤더 8 개뿐이다: Common 의 `error.h`, `export.h`, `types.h`, `version.h` 와 Client 의 `client.h`,
  `config.h`, `sockgate.h`, Server 의 `server.h`. `src/sockgate_common/**` 내부 헤더는 설치하지 않는다.
  out-of-tree 소비자 `tests/package` 가 설치된 헤더 목록이 정확히 이 8 개인지 검사한다.
- 버전 호환: 0.x 동안은 minor 버전마다 ABI 가 바뀔 수 있으므로 패키지는 `SameMinorVersion`, 공유 라이브러리 soname 은
  `MAJOR.MINOR` (`libsockgate_client.so.0.1`) 이다. 1.0 부터는 `SameMajorVersion`, soname `MAJOR` 가 된다 (`SOCKGATE_SOVERSION`).
- static TPM2 빌드(`SOCKGATE_WITH_TPM2=ON`)의 패키지는 `tss2-esys`, `tss2-mu`, `tss2-tctildr` 를 찾지 못하면
  `SockGate_FOUND = FALSE` 와 메시지로 실패한다.

```cmake
find_package(SockGate 0.1 REQUIRED)
target_link_libraries(app PRIVATE SockGate::Client)   # 또는 SockGate::Server
```

## 2. 요구사항

| 항목 | 요구 |
|---|---|
| CMake | ≥ 3.21 (presets v3) |
| Generator | Ninja (프리셋 기본) |
| 컴파일러 | C++17 / C11. MSVC (VS 2022), clang-cl, GCC, Clang |
| OpenSSL | ≥ 3.0 (`find_package(OpenSSL 3.0 REQUIRED)`). `OpenSSL::SSL`, `OpenSSL::Crypto` 를 `PUBLIC` 링크 |
| 기타 | `Threads::Threads`. Windows 는 `ws2_32`, `crypt32` |

OpenSSL:

- Windows: vcpkg manifest (`vcpkg.json`, baseline 은 `vcpkg-configuration.json` 에 고정). 프리셋이 `$env{VCPKG_ROOT}` 의 toolchain,
  triplet `x64-windows-static-md`, `OPENSSL_USE_STATIC_LIBS=ON` 을 쓰므로 OpenSSL 이 정적 링크된다. `VCPKG_ROOT` 환경 변수가 필요하다.
- Linux: 배포판 패키지 (`libssl-dev` / `openssl-devel`), 시스템 OpenSSL 에 동적 링크.
- CMake 는 API 수준의 최소 버전(3.0)만 강제한다. 보안상 알려진 취약점이 패치된 OpenSSL 을 쓰고 3.5 LTS 이상을 권장한다
  ([12 §1](../docs/design/12-dependencies.md)).
- `OPENSSL_VERSION < 3.0.7` 이면 configure 시 경고한다 (CVE-2022-3602/3786; 배포판 빌드는 백포트 여부를 버전으로 알 수 없어 경고만).
- OpenSSL 을 함께 배포하는 빌드(Windows, 또는 `OPENSSL_USE_STATIC_LIBS`)에서는 `sockgate_common` 이
  `SOCKGATE_BUNDLED_OPENSSL=1` 로 컴파일되어, 실행 시 오래된 OpenSSL 이면 Client/Server 가 `event=config_warning` 로그를 남긴다
  ([SECURITY.md §2](SECURITY.md)). 그 밖의 빌드는 `SOCKGATE_BUNDLED_OPENSSL=0`.
- configure 출력의 `OpenSSL=<version>` 으로 찾은 버전을 확인한다.

## 3. 옵션

`cmake/SockGateOptions.cmake` 중 Common 에 영향을 주는 것 (`SG_MUTATION_ITERATIONS` 만 `fuzz/CMakeLists.txt` 에 정의).

| 옵션 | 기본 | 영향 |
|---|---|---|
| `SOCKGATE_BUILD_SHARED` | ON | Client/Server 를 공유 라이브러리로. Common 설치 여부 결정 (§1) |
| `SOCKGATE_INSTALL` | 최상위 프로젝트면 ON | 설치 규칙과 CMake 패키지 생성 (§1) |
| `SOCKGATE_BUILD_TESTS` | ON | 테스트와 `sg_mutate_*` mutation 테스트 |
| `SOCKGATE_BUILD_FUZZERS` | OFF | libFuzzer 타깃 `sg_fuzz_*` (Clang 또는 MSVC), 전체 coverage 계측 |
| `SOCKGATE_SANITIZER` | "" | `address`, `undefined`, `address+undefined`, `thread` |
| `SOCKGATE_HARDENING` | ON | hardening 컴파일/링크 플래그 |
| `SOCKGATE_WERROR` | OFF | 경고를 오류로 (release 프리셋은 ON) |
| `SOCKGATE_ENABLE_DEBUG_LOG` | OFF | release 빌드에서도 `SG_LOGD`/`SG_LOGT` 유지 |
| `SG_MUTATION_ITERATIONS` | 20000 | CTest mutation 테스트 반복 수 (fuzz/CMakeLists.txt 캐시 변수) |

단일 구성 generator 에서 `CMAKE_BUILD_TYPE` 이 없으면 `Debug` 가 된다. 실행 파일은 `<build>/bin`, 라이브러리는 `<build>/lib` 에 모인다.

## 4. 프리셋

`CMakePresets.json` — build 디렉터리는 `out/build/<preset>`. base 프리셋이 `SOCKGATE_BUILD_TESTS=ON` 을 켠다.

| 플랫폼 | configure/build/test 프리셋 |
|---|---|
| Windows | `windows-msvc-debug`, `windows-msvc-release`, `windows-clangcl-debug`, `windows-clangcl-release`, `windows-msvc-asan` |
| Linux | `linux-gcc-debug`, `linux-gcc-release`, `linux-clang-debug`, `linux-clang-release`, `linux-gcc-asan`, `linux-clang-asan`, `linux-clang-tsan` |
| Fuzz (configure/build 만) | `windows-msvc-fuzz`, `linux-clang-fuzz` |

```sh
cmake --preset linux-gcc-debug
cmake --build --preset linux-gcc-debug
ctest --preset linux-gcc-debug
```

- Windows 프리셋은 architecture 를 외부에서 정하므로 (`strategy: external`) x64 Developer Command Prompt (또는 동등한 환경)에서 실행한다.
- `*-asan` 프리셋: Linux 는 ASan+UBSan, Windows 는 ASan. `linux-clang-tsan` 은 TSan.
- Linux sanitizer test 프리셋은 숨은 `test-sanitizers` 프리셋을 상속해 CI 와 같은 `ASAN_OPTIONS` / `UBSAN_OPTIONS`
  (`halt_on_error=1`) / `TSAN_OPTIONS` 로 실행된다 ([SECURITY.md §6.2](SECURITY.md)).

## 5. Fuzzer

fuzz 프리셋은 `Debug` + `SOCKGATE_BUILD_FUZZERS=ON` + sanitizer (`linux-clang-fuzz`: ASan+UBSan, `windows-msvc-fuzz`: ASan) +
`SOCKGATE_BUILD_SHARED=OFF` 이다. 테스트도 켜져 있으므로 `sg_fuzz_<name>` (libFuzzer) 과 `sg_mutate_<name>` (standalone driver) 가
함께 만들어진다. 타깃: `frame_decoder`, `messages`, `channel` (Common), `proxy_config` (Client), `storage_files` (Server).

```sh
cmake --preset linux-clang-fuzz
cmake --build --preset linux-clang-fuzz
cd out/build/linux-clang-fuzz/bin

# seed corpus: driver 가 코드에서 seed 를 만들어 파일로 쓴다 (디렉터리는 미리 만든다)
mkdir -p corpus/frame_decoder
./sg_mutate_frame_decoder --write-seeds=corpus/frame_decoder

# libFuzzer 실행 (옵션은 libFuzzer 표준 옵션)
./sg_fuzz_frame_decoder corpus/frame_decoder -max_total_time=600 -artifact_prefix=artifacts-frame_decoder-

# crash 재현: 두 실행 파일 모두 입력 파일을 받는다
./sg_mutate_frame_decoder artifacts-frame_decoder-crash-<hash>
```

standalone driver (`fuzz/standalone_main.cpp`) 사용법:

| 인자 | 동작 |
|---|---|
| (없음) `[--iterations=N] [--seed=S]` | 모든 seed + 빈 입력 실행 후 N 회 결정적 mutation (기본 N = 20000, 고정 seed) |
| `file...` | 파일 입력을 그대로 실행 (재현) |
| `--write-seeds=DIR` | seed 를 `DIR/seed-<i>` 로 저장 |

- libFuzzer 없는 일반 빌드에서도 `sg_mutate_*` 는 CTest (`label fuzz;protocol`) 로 매번 실행된다: `ctest --preset <preset> -L fuzz`.
- fuzz 프리셋에는 test 프리셋이 없다. 필요하면 `ctest --test-dir out/build/linux-clang-fuzz` 를 쓴다.
- CI 의 fuzz job 이 위 절차를 모든 `sg_fuzz_*` 에 대해 수행한다 (push 때 타깃당 60 초, nightly 20 분, crash 는 artifact).
- MSVC fuzz 빌드는 ASan 에서 STL container annotation 을 켠 채로 두고 (미리 빌드된 ASan/libFuzzer 런타임과 맞춰야 함),
  libFuzzer 실행 파일이 아닌 타깃에는 `sancov` 런타임을 링크한다 (`cmake/SockGateSanitizers.cmake`).

## 6. Common 을 다루는 테스트

테스트 프레임워크는 의존성 없는 `tests/framework` 이며, 모든 바이너리가 CTest 에 label 과 함께 등록된다.
각 바이너리는 `--filter=<substring>`, `--list` 를 받는다. TLS 테스트용 CA/서버 키는 실행 시 생성한다 (`tests/support/test_pki.cpp`, 커밋된 키 없음).

| CTest | label | 소스 | 다루는 Common 코드 |
|---|---|---|---|
| `sg_unit_common` | unit | `tests/unit/core_test.cpp`, `crypto_test.cpp` | `Status`/`ToPublicStatus`, bytes/소거/상수 시간 비교, `Deadline`, `Logger`; SHA-256, HMAC (RFC 4231), HKDF (RFC 5869), AES-GCM 벡터·변조 탐지·GMAC, ECDSA, 잘못된 공개키, 서명 인코딩, PKCS#8/PEM, RNG |
| `sg_unit_tls` | unit | `tests/unit/tls_test.cpp` | 핸드셰이크, 채널 바인딩, 신뢰되지 않은 CA, hostname, 부분 wildcard, IP SAN, 만료, leaf(CA:FALSE) 인증서를 발급자로 쓰는 체인 거부, SPKI pinning 과 인증서 덧붙이기 우회, 컨텍스트 검증, 쓰레기 입력, close_notify/KeyUpdate, 변조 레코드, TLS 1.2 거부/EMS 요구, RFC 9266 채널 바인딩 (TLS 1.3 / TLS 1.2 에서 길이 0 context), 오래된 OpenSSL 판정 (`IsOutdatedOpenSsl`, `OutdatedBundledOpenSslVersion`) |
| `sg_protocol` | protocol | `tests/protocol/serialization_test.cpp`, `frame_test.cpp`, `messages_test.cpp` | byte order, `Reader`/`Writer`, overflow, TLV, base64url, 문자열 검증; 헤더 코덱, 잘못된/과대/잘린 헤더, 본문 전 헤더 검사, fail closed, 버퍼 상한, 선형 시간; 메시지 round trip·필드 검증·인코더 거부, 단계/방향 표, dispatcher, enrollment token, transcript 도메인 분리 |
| `sg_security_handshake` | security | `tests/security/handshake_test.cpp`, `channel_test.cpp` | `ProtectedChannel`: replay/중복, 재정렬/삭제, 모든 필드 변조, 교차 세션/반사, request id, in-flight epoch 전환, 이전 epoch 거부, 전환 전제 조건, 재인증 transcript 용 평문 view (+ Client/Server 핸드셰이크) |
| `sg_mutate_frame_decoder`, `sg_mutate_messages`, `sg_mutate_channel` | fuzz; protocol | `fuzz/*.cpp` | §5 |

통합/보안 테스트 (`sg_integration_*`, `sg_security_proxy_mitm` 등)도 Common 을 거쳐 동작한다.

```sh
ctest --preset linux-gcc-debug -L protocol
ctest --preset linux-gcc-debug -R "sg_unit_|sg_protocol|sg_mutate_"
out/build/linux-gcc-debug/bin/sg_protocol --filter=Frame
```

설치 패키지 검사: `tests/package` 는 설치된 SockGate 를 `find_package(SockGate 0.1)` 로 쓰는 out-of-tree 소비자이며,
설치된 헤더가 public 헤더 8 개와 정확히 같은지 확인한다.

```sh
cmake --install out/build/linux-gcc-release --prefix /tmp/sockgate
cmake -S tests/package -B build-consumer -DCMAKE_PREFIX_PATH=/tmp/sockgate
cmake --build build-consumer
```

## 7. CI

`.github/workflows/ci.yml` (action 은 commit SHA 로 고정, Dependabot 으로 갱신):

| job | 내용 |
|---|---|
| windows | `windows-msvc-debug/release`, `windows-clangcl-debug/release`, `windows-msvc-asan` 빌드 + CTest |
| linux | GCC/Clang debug/release, `linux-gcc-asan`, `linux-clang-asan`, `linux-clang-tsan` (Ubuntu 24.04 x64), ARM64 과 Ubuntu 22.04 추가 조합 |
| linux-tpm2 | swtpm 과 `SOCKGATE_WITH_TPM2=ON` |
| package | Linux/Windows × shared ON/OFF: 설치 후 `tests/package` 소비자 빌드·실행 |
| containers | Debian 12, Rocky 9 |
| fuzz | `linux-clang-fuzz`, libFuzzer (§5) |
