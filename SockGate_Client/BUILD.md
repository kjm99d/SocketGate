# Building SockGate_Client

SockGate_Client 는 저장소 최상위 CMake 프로젝트의 일부로 빌드된다(`SockGate_Common`, `SockGate_Server`, 테스트,
fuzz, 예제, 도구와 함께). 의존성의 근거와 최소 버전은 [12-dependencies.md](../docs/design/12-dependencies.md) 참고.

## 1. 요구 사항

| 항목 | 요구 | 비고 |
|---|---|---|
| CMake | ≥ 3.21 | presets v3 |
| Ninja | 프리셋의 generator | |
| C++ 컴파일러 | C++17 (C 예제/소비자는 C11) | Windows: MSVC (VS 2022) 또는 clang-cl. Linux: GCC ≥ 9 또는 Clang ≥ 10 |
| OpenSSL | ≥ 3.0 (`find_package(OpenSSL 3.0 REQUIRED)`) | Windows: vcpkg manifest(`vcpkg.json`, baseline 고정)가 설치, `x64-windows-static-md` 로 정적 링크. Linux: 배포판 패키지(`libssl-dev` / `openssl-devel`), 동적 링크. 보안 패치된 버전을 쓴다(업스트림 3.0.7 미만 금지, 3.5 LTS 이상 권장) |
| Threads | 시스템 | |
| tpm2-tss | 선택 (`SOCKGATE_WITH_TPM2=ON`, Linux 전용) | pkg-config 모듈 `tss2-esys`, `tss2-mu`, `tss2-tctildr` (Debian/Ubuntu `libtss2-dev`, `pkg-config`) |
| Windows SDK | Windows | 클라이언트가 링크하는 시스템 라이브러리: `ws2_32`, `crypt32`, `winhttp`, `ncrypt`, `tbs`, `advapi32`, `shell32`, `ole32`, `wintrust`, `psapi` |

지원 플랫폼은 Windows 와 Linux 뿐이다. 그 밖의 `CMAKE_SYSTEM_NAME` 은 configure 단계에서 오류다.

OpenSSL 이 3.0.7 미만이면(CVE-2022-3602/3786) configure 가 CMake 경고를 낸다. 배포판 OpenSSL 은 버전 번호와 무관하게
보안 패치가 백포트되므로 경고만 하고 빌드는 계속된다. OpenSSL 을 함께 배포하는 빌드(Windows, 또는 `OPENSSL_USE_STATIC_LIBS`
정적 링크)는 실행 시에도 확인해, 첫 Connect 에서 프로세스당 한 번 `event=config_warning` 을 로그로 남긴다.

### Windows 준비

- 환경 변수 `VCPKG_ROOT` 가 vcpkg 루트를 가리켜야 한다(프리셋이 `$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake`
  를 toolchain 으로 쓴다). OpenSSL 은 manifest mode 로 `vcpkg_installed/` 에 설치된다.
- Ninja generator 이므로 x64 개발자 명령 프롬프트(또는 동등한 환경)에서 실행한다.

### Linux 준비 (Ubuntu 예)

```sh
sudo apt-get install -y ninja-build cmake g++ clang libssl-dev
# TPM2 key store 를 빌드하려면
sudo apt-get install -y libtss2-dev pkg-config
```

## 2. 프리셋

모든 configure 프리셋은 Ninja, `out/build/<preset>` 빌드 디렉터리, `out/install/<preset>` 설치 디렉터리,
`SOCKGATE_BUILD_TESTS=ON` 을 쓴다. Release 프리셋은 `SOCKGATE_WERROR=ON` 이다.

| 프리셋 | 플랫폼 | 내용 |
|---|---|---|
| `windows-msvc-debug` / `windows-msvc-release` | Windows | MSVC |
| `windows-clangcl-debug` / `windows-clangcl-release` | Windows | clang-cl |
| `windows-msvc-asan` | Windows | MSVC AddressSanitizer (Debug) |
| `windows-msvc-fuzz` | Windows | MSVC libFuzzer + ASan, 정적 라이브러리 |
| `linux-gcc-debug` / `linux-gcc-release` | Linux | GCC |
| `linux-clang-debug` / `linux-clang-release` | Linux | Clang |
| `linux-gcc-asan` / `linux-clang-asan` | Linux | ASan + UBSan (Debug) |
| `linux-clang-tsan` | Linux | ThreadSanitizer (Debug) |
| `linux-clang-fuzz` | Linux | libFuzzer + ASan + UBSan, 정적 라이브러리 |

build 프리셋은 configure 프리셋과 같은 이름이다. test 프리셋은 fuzz 프리셋을 제외한 모든 프리셋에 있다
(실패 시 출력, 테스트가 없으면 오류, 테스트당 300 s). `linux-gcc-asan`, `linux-clang-asan`, `linux-clang-tsan` test 프리셋은
CI 와 같은 `ASAN_OPTIONS`(`detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1`),
`UBSAN_OPTIONS`(`halt_on_error=1:print_stacktrace=1`), `TSAN_OPTIONS`(`halt_on_error=1 second_deadlock_stack=1`)를 설정하므로,
복구 가능한 `-fsanitize=integer` 보고도 로컬에서 실패로 처리된다(bd6ca45).

```sh
cmake --preset linux-gcc-release
cmake --build --preset linux-gcc-release
ctest --preset linux-gcc-release
```

```bat
cmake --preset windows-msvc-release
cmake --build --preset windows-msvc-release
ctest --preset windows-msvc-release
```

## 3. 빌드 옵션

`SG_MUTATION_ITERATIONS` 는 `fuzz/CMakeLists.txt` 의 cache 변수이고, 나머지는 `cmake/SockGateOptions.cmake` 에 정의된
옵션이다. `-D<옵션>=<값>` 으로 프리셋 위에 덮어쓴다.

| 옵션 | 기본값 | 의미 |
|---|---|---|
| `SOCKGATE_BUILD_SHARED` | `ON` | Client/Server 를 공유 라이브러리로. `OFF` 면 정적 라이브러리(4 절) |
| `SOCKGATE_BUILD_TESTS` | `ON` | 단위/프로토콜/보안/통합 테스트와 mutation 테스트 |
| `SOCKGATE_BUILD_FUZZERS` | `OFF` | libFuzzer 실행 파일 `sg_fuzz_*` (Clang 또는 MSVC `/fsanitize=fuzzer`) |
| `SOCKGATE_BUILD_EXAMPLES` | `ON` | `sg_echo_client`, `sg_echo_server` |
| `SOCKGATE_BUILD_TOOLS` | `ON` | `sg_admin` (pin 계산, token 발급, 클라이언트 등록 등) |
| `SOCKGATE_INSTALL` | 최상위 빌드면 `ON`, 하위 프로젝트(`add_subdirectory` / FetchContent)면 `OFF` (`PROJECT_IS_TOP_LEVEL`) | install 규칙과 `SockGate` CMake 패키지 생성 |
| `SOCKGATE_WERROR` | `OFF` | 경고를 오류로 |
| `SOCKGATE_HARDENING` | `ON` | 플랫폼 hardening 컴파일/링크 플래그 |
| `SOCKGATE_WITH_TPM2` | `OFF` | Linux TPM2 key store (tpm2-tss 필요). Windows 에서 켜면 configure 오류(Windows 는 CNG 사용) |
| `SOCKGATE_ENABLE_DEBUG_LOG` | `OFF` | Release 빌드에서도 debug/trace 로그 문장을 유지 |
| `SOCKGATE_SANITIZER` | `""` | `address`, `undefined`, `address+undefined`, `thread`. MSVC 는 `address` 만 |
| `SG_MUTATION_ITERATIONS` (`fuzz/CMakeLists.txt`) | `20000` | CTest mutation 테스트의 타깃당 반복 수 |

빌드 타입을 주지 않으면 단일 구성 generator 에서 `Debug` 가 기본이다.

### 3.1 TPM2 key store 빌드와 테스트

```sh
cmake --preset linux-gcc-debug -DSOCKGATE_WITH_TPM2=ON
cmake --build --preset linux-gcc-debug
```

실제 TPM 없이 swtpm 으로 실행할 수 있다(CI 의 `linux-tpm2` job 과 같은 방법).

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm \
      --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
      --flags not-need-init,startup-clear --daemon
SOCKGATE_TPM2_TCTI=swtpm:host=127.0.0.1,port=2321 SOCKGATE_REQUIRE_TPM=1 \
      ctest --preset linux-gcc-debug
```

| 환경 변수 | 읽는 곳 | 의미 |
|---|---|---|
| `SOCKGATE_TPM2_TCTI` | **라이브러리**(TPM2 / AUTO key store 생성 시, `secure_getenv`) | TCTI 설정. `device`, `tabrmd`, `swtpm`, `mssim` 만 허용(라이브러리 경로 불가, 그 외 값은 `SG_Client_Create` 가 `SG_INVALID_ARGUMENT`). 시뮬레이터는 테스트 용도. 없으면 접근 가능한 `device:/dev/tpmrm0` |
| `SOCKGATE_REQUIRE_TPM` | 테스트 (`sg_security_keystore`) | `1` 이면 "TPM 없음" 을 건너뛰지 않고 실패로 처리 (Windows CNG TPM 테스트에도 적용) |
| `SG_TEST_LOG` | 테스트 (end-to-end harness) | 설정하면 테스트 중 서버 로그 출력 |

`/dev/tpmrm0` 을 쓰려면 사용자가 보통 `tss` 그룹에 속해야 한다. 공유되지 않는 raw `/dev/tpm0` 은 쓰지 않는다.

## 4. 공유 vs 정적 라이브러리

| | `SOCKGATE_BUILD_SHARED=ON` (기본) | `SOCKGATE_BUILD_SHARED=OFF` |
|---|---|---|
| 산출물 | Windows `sockgate_client.dll` + import library, Linux `libsockgate_client.so.0.1.0` 과 soname `libsockgate_client.so.0.1` | 정적 `sockgate_client` + 내부 `sockgate_client_core`, `sockgate_common` |
| export | `SG_CLIENT_API` 함수만 (`sg_exports_sockgate_client` 가 검증) | 해당 없음 |
| 매크로 | 라이브러리 빌드 시 `SOCKGATE_CLIENT_BUILDING` (내부) | 소비자에 `SOCKGATE_CLIENT_STATIC` 필요 |
| 의존성 | OpenSSL 은 Windows 에서 DLL 안에 정적 링크, Linux 에서 시스템 `libssl`/`libcrypto` 동적 링크 | 애플리케이션이 OpenSSL, Threads(, TSS2)와 Windows 시스템 라이브러리를 링크 |

`SOCKGATE_CLIENT_STATIC` 은 `export.h` 의 `SG_CLIENT_API` 를 비워 `__declspec(dllimport)` 를 없앤다. CMake 타깃
`SockGate::Client` 는 정적 빌드에서 이 정의를 PUBLIC 으로 전파하므로 CMake 소비자는 따로 정의할 필요가 없다.
CMake 를 쓰지 않는 빌드 시스템은 정적 라이브러리를 쓸 때 직접 정의하고 의존 라이브러리를 링크해야 한다.

**soname 과 호환성**: 0.x 동안은 어느 minor 버전이든 ABI 를 깰 수 있으므로 soname 에 `MAJOR.MINOR` 를 넣는다
(`libsockgate_client.so.0.1`). 1.0 부터는 `MAJOR` 만 넣는다. 같은 규칙으로 CMake 패키지의 버전 호환성은 0.x 동안
`SameMinorVersion`, 1.0 부터 `SameMajorVersion` 이다. 실행 중에는 `SG_Client_GetApiVersion()` 과
`SOCKGATE_API_VERSION` 을 비교할 수 있다.

## 5. 설치와 `find_package(SockGate)`

```sh
cmake --install out/build/linux-gcc-release --prefix /opt/sockgate
```

install 규칙은 `SOCKGATE_INSTALL=ON`(최상위 빌드의 기본값)일 때만 생성된다. 설치되는 것:

- 공개 헤더 **8 개만**: `sockgate/client.h`, `config.h`, `sockgate.h`(Client), `error.h`, `export.h`, `types.h`,
  `version.h`(Common), `server.h`(Server). 내부 헤더는 설치되지 않는다.
- 라이브러리(`bin/` 또는 `lib/`). 공유 빌드는 공개 라이브러리만, 정적 빌드는 내부 아카이브도 함께 설치한다. PDB 는 설치하지 않는다.
- `lib/cmake/SockGate/`: `SockGateConfig.cmake`, `SockGateConfigVersion.cmake`, `SockGateTargets*.cmake`.

| 가져오는 타깃 | 빌드 |
|---|---|
| `SockGate::Client`, `SockGate::Server` | 항상 |
| `SockGate::ClientCore`, `SockGate::ServerCore`, `SockGate::Common` | 정적 빌드(공개 타깃이 링크하는 내부 아카이브) |

소비자 CMake (저장소의 [tests/package](../tests/package/CMakeLists.txt) 와 같은 형태):

```cmake
cmake_minimum_required(VERSION 3.21)
project(MyApp LANGUAGES C CXX)
find_package(SockGate 0.1 REQUIRED)          # 0.x: SameMinorVersion (0.1.x 만 일치)
add_executable(myapp main.c)
target_link_libraries(myapp PRIVATE SockGate::Client)
```

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH=/opt/sockgate
```

- 정적 패키지이면 `SockGateConfig.cmake` 가 `find_dependency(Threads)`, `find_dependency(OpenSSL 3.0)` 를 수행하므로
  소비자 환경에서도 이 의존성을 찾을 수 있어야 한다. Windows 에서는 vcpkg toolchain 과 같은 triplet
  (`x64-windows-static-md`)을 지정한다(CI 의 `package` job 참고).
- 정적 + TPM2 패키지이면 pkg-config 로 `tss2-esys`, `tss2-mu`, `tss2-tctildr` 도 찾는다. 없으면 오류로 멈추지 않고
  `SockGate_FOUND` 를 FALSE 로 두고 이유("SockGate was built with TPM 2.0 support: ... are required")를 알린다.
  소비자가 이미 만든 `PkgConfig::TSS2` 가 있으면 그것을 쓴다.
- Windows 공유 빌드는 실행 시 `sockgate_client.dll` 을 찾을 수 있어야 한다(설치 prefix 의 `bin` 을 `PATH` 에).
- 소스 트리 안에서는 `add_subdirectory` 후 `SockGate::Client` 별칭을 그대로 쓸 수 있다. 이때 `SOCKGATE_INSTALL` 은
  기본 `OFF` 라 상위 프로젝트의 install 에 SockGate 가 섞이지 않는다.
- `tests/package` 는 설치본을 쓰는 트리 밖 소비자다: `SockGate::Client` 와 `SockGate::Server` 를 링크해 실행하고,
  설치된 헤더 목록이 위 8 개와 정확히 같은지 검사한다.

## 6. Hardening 과 export

`sockgate_configure_target()`(`cmake/SockGateCompilerFlags.cmake`)이 SockGate 자신의 타깃에만 적용한다.

| | MSVC / clang-cl | GCC / Clang |
|---|---|---|
| 경고 | `/W4 /permissive- /utf-8` (+ `/WX` if WERROR) | `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wformat=2 ...` (+ `-Werror`) |
| 컴파일 hardening | `/GS /sdl /guard:cf` | `-fstack-protector-strong`, `-fstack-clash-protection`, `-fcf-protection=full`(x86_64) / `-mbranch-protection=standard`(ARM64), Release 계열 `_FORTIFY_SOURCE=3`(GCC ≥ 12 / Clang ≥ 16, 그 외 2; sanitizer 빌드 제외) |
| 링크 hardening | `/guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT` | `-z relro -z now -z noexecstack`, 실행 파일 `-pie`, 공유 라이브러리 `--exclude-libs,ALL` |
| Release | `/Gy /Zi`, 링크 `/DEBUG /OPT:REF /OPT:ICF` (PDB 는 배포하지 않음) | 공유 라이브러리 `-s` |
| 심볼 | hidden visibility, `__declspec(dllexport)` 는 `SG_CLIENT_API` 뿐 | hidden visibility + version script `cmake/sockgate_exports.map` (`SG_*` 만 global) |

## 7. 테스트

CTest 라벨로 부분 실행할 수 있다: `ctest --preset <p> -L security`.

| 테스트 | 라벨 | 클라이언트 관련 내용 |
|---|---|---|
| `sg_unit_common`, `sg_unit_tls` | unit | crypto known-answer, TLS 검증·pin·다운그레이드 음성 테스트 |
| `sg_protocol` | protocol | 직렬화, 프레임, 메시지 codec 음성 테스트 |
| `sg_security_handshake` | security | 핸드셰이크·enrollment 공격 시나리오, 채널 replay/변조 |
| `sg_security_keystore` | security | FILE/AUTO/CNG/TPM2 key store: 변조, 링크, 권한, 동시 생성, locator |
| `sg_security_integrity` | security | integrity 관측 (temp 에서 로드한 probe 모듈 포함) |
| `sg_security_proxy_mitm` | security | 실제 proxy 경유, 적대적 proxy, 사용자 CA MITM, 가짜 서버 |
| `sg_integration_session` | integration | 공개 C API 종단간: 인증, enrollment, pinning, 만료, idle, refresh, 폐기, 동시성, Disconnect 깨우기 |
| `sg_integration_integrity`, `sg_integration_license` | integration | integrity 정책, 라이선스 인가 종단간 |
| `sg_integration_transport` | integration | TCP/TLS transport |
| `sg_exports_sockgate_client` | security | 공유 빌드에서 export 테이블 = `client.h` 의 `SG_CLIENT_API` 선언 |
| `sg_mutate_*` | fuzz; protocol | fuzz 타깃(`frame_decoder`, `messages`, `channel`, `proxy_config`, `storage_files`)의 결정적 mutation 실행. 타깃당 `SG_MUTATION_ITERATIONS` 회(파일을 쓰는 `storage_files` 는 10 분의 1) |

테스트 PKI 와 키는 실행 시 생성한다. 저장소에 키 자료는 없다. fuzz seed 도 코드에서 만든다
(`sg_mutate_<name> --write-seeds=DIR`).

## 8. CI 개요 (`.github/workflows/ci.yml`)

push(main, develop), pull request, nightly schedule(03:17 UTC), 수동 실행에서 동작한다. 권한은 `contents: read` 뿐이다.
사용하는 GitHub Actions 는 commit SHA 로 고정되어 있고 Dependabot(`.github/dependabot.yml`, 매주)이 갱신한다.
이벤트 종류별로 concurrency group 이 나뉘며, **pull request 실행만** 같은 PR 의 새 push 가 오면 이전 실행을 취소한다
(branch push, nightly, 수동 실행은 취소되지 않는다).

| Job | 내용 |
|---|---|
| `windows` | windows-2022: `windows-msvc-debug/release`, `windows-clangcl-debug/release`, `windows-msvc-asan` — configure, build, ctest. vcpkg 설치물 캐시 |
| `linux` | ubuntu-24.04: GCC/Clang debug/release, `linux-gcc-asan`, `linux-clang-asan`, `linux-clang-tsan`. 추가로 ubuntu-24.04-arm(`linux-gcc-release`, `linux-clang-asan`), ubuntu-22.04(`linux-gcc-debug`). TSan/ASan/UBSan 은 첫 오류에서 실패 |
| `linux-tpm2` | swtpm 을 띄우고 `-DSOCKGATE_WITH_TPM2=ON`, `SOCKGATE_TPM2_TCTI` + `SOCKGATE_REQUIRE_TPM=1` 로 테스트 (TPM 없음은 실패) |
| `package` | Linux/Windows × shared ON/OFF: Release 프리셋을 테스트 없이 빌드·설치한 뒤 `tests/package` 를 `find_package(SockGate)` 로 빌드·실행(설치 헤더 목록 검사 포함) |
| `containers` | `debian:12`, `rockylinux:9`(CRB 저장소 활성화) 에서 `linux-gcc-debug` 빌드·테스트 |
| `fuzz` | `linux-clang-fuzz`: 각 `sg_fuzz_*` 를 코드에서 만든 seed corpus 로 push 마다 60 s, nightly 1200 s. 모든 sanitizer 보고를 crash 로 기록하고, 한 타깃이 실패해도 나머지를 끝까지 돌린 뒤 실패 처리. 실패 시 crash artifact 업로드 |
