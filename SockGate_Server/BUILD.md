# Building SockGate_Server

SockGate_Server 는 저장소 루트의 CMake 슈퍼프로젝트(Common + Client + Server + tests + fuzz + examples + tools)의 일부로 빌드한다.
서버만 따로 configure 하는 경로는 없으며, 필요하면 타깃을 골라 빌드한다. 의존성 기준은
[12-dependencies.md](../docs/design/12-dependencies.md) 이다.

## 1. 요구 사항

| 항목 | 요구 | 비고 |
|---|---|---|
| CMake | ≥ 3.21 | `cmake_minimum_required(VERSION 3.21)`, presets v3 |
| Ninja | 프리셋의 generator | |
| 컴파일러 | C11 / C++17 | Windows: MSVC (VS 2022) 또는 clang-cl, Linux: GCC 또는 Clang. 설계 문서 12 의 최소 버전: MSVC 19.30, clang-cl 13, GCC 9, Clang 10 |
| OpenSSL | ≥ 3.0 (`find_package(OpenSSL 3.0 REQUIRED)`) | Windows: vcpkg manifest (`vcpkg.json`, baseline 은 `vcpkg-configuration.json` 에 고정), triplet `x64-windows-static-md` 로 **정적 링크**. Linux: 시스템 패키지 (`libssl-dev` / `openssl-devel`)에 동적 링크 |
| tpm2-tss (선택) | `tss2-esys tss2-mu tss2-tctildr` (pkg-config) | `SOCKGATE_WITH_TPM2=ON` 일 때 **클라이언트** TPM2 key store 용. 서버는 사용하지 않는다 |
| Threads | `find_package(Threads REQUIRED)` | |

보안상 OpenSSL 은 업스트림 3.0.7 이상(권장 3.5 LTS 이상) 또는 보안 업데이트가 적용된 배포판 패키지를 쓴다.
찾은 OpenSSL 이 3.0.7 보다 오래되면 configure 단계에서 경고한다 (배포판 빌드라면 보안 수정이 백포트되었는지 확인). 자체 OpenSSL 을
함께 배포하는 빌드(Windows, 또는 `OPENSSL_USE_STATIC_LIBS`)는 실행 시에도 확인해 `SG_Server_Start` 때 `event=config_warning` 을 남긴다.

Windows 준비:

```text
set VCPKG_ROOT=C:\vcpkg                  (vcpkg 설치 위치; 프리셋의 toolchainFile 이 참조)
"Developer Command Prompt for VS 2022" (x64) 에서 cl / clang-cl / ninja 를 찾을 수 있어야 한다
```

vcpkg 는 manifest 모드로 `vcpkg_installed/` 에 OpenSSL 을 설치한다. Linux 예 (Ubuntu/Debian):

```text
sudo apt-get install -y ninja-build cmake g++ clang libssl-dev
```

지원 플랫폼은 Windows 와 Linux 이며, 그 외 `CMAKE_SYSTEM_NAME` 은 configure 단계에서 실패한다.

## 2. 프리셋

`CMakePresets.json` 의 configure / build / test 프리셋은 같은 이름을 쓴다. 빌드 디렉터리는 `out/build/<preset>`, 설치 디렉터리
기본값은 `out/install/<preset>` 이다. 모든 프리셋은 `SOCKGATE_BUILD_TESTS=ON` 이다.

| 프리셋 | 호스트 | 컴파일러 | 설정 |
|---|---|---|---|
| `windows-msvc-debug` / `-release` | Windows | cl | Debug / Release (+ `SOCKGATE_WERROR=ON`) |
| `windows-clangcl-debug` / `-release` | Windows | clang-cl | Debug / Release (+ `SOCKGATE_WERROR=ON`) |
| `windows-msvc-asan` | Windows | cl | Debug, `SOCKGATE_SANITIZER=address` |
| `windows-msvc-fuzz` | Windows | cl | Debug, ASan, `SOCKGATE_BUILD_FUZZERS=ON`, `SOCKGATE_BUILD_SHARED=OFF` |
| `linux-gcc-debug` / `-release` | Linux | gcc | Debug / Release (+ `SOCKGATE_WERROR=ON`) |
| `linux-clang-debug` / `-release` | Linux | clang | Debug / Release (+ `SOCKGATE_WERROR=ON`) |
| `linux-gcc-asan`, `linux-clang-asan` | Linux | gcc / clang | Debug, `SOCKGATE_SANITIZER=address+undefined` |
| `linux-clang-tsan` | Linux | clang | Debug, `SOCKGATE_SANITIZER=thread` |
| `linux-clang-fuzz` | Linux | clang | Debug, ASan + UBSan, `SOCKGATE_BUILD_FUZZERS=ON`, `SOCKGATE_BUILD_SHARED=OFF` |

Windows 프리셋은 vcpkg toolchain(`$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake`), `VCPKG_TARGET_TRIPLET=x64-windows-static-md`,
`OPENSSL_USE_STATIC_LIBS=ON`, `OPENSSL_MSVC_STATIC_RT=OFF` 를 설정한다. 테스트 프리셋은 실패 시 출력, 테스트가 없으면 오류,
테스트당 300 s 제한이며, fuzz 프리셋에는 테스트 프리셋이 없다.

```text
cmake --preset linux-gcc-release
cmake --build --preset linux-gcc-release                             # 전체
cmake --build --preset linux-gcc-release --target sockgate_server    # 서버 라이브러리만
ctest --preset linux-gcc-release
```

## 3. CMake 옵션 (`cmake/SockGateOptions.cmake`)

| 옵션 | 기본값 | 의미 |
|---|---|---|
| `SOCKGATE_BUILD_SHARED` | `ON` | `sockgate_client` / `sockgate_server` 를 공유 라이브러리로 (OFF = 정적) |
| `SOCKGATE_BUILD_TESTS` | `ON` | 단위/프로토콜/보안/통합 테스트와 변이(`sg_mutate_*`) 테스트 |
| `SOCKGATE_BUILD_FUZZERS` | `OFF` | libFuzzer 타깃 `sg_fuzz_*` (Clang 또는 MSVC `/fsanitize=fuzzer`). 모든 코드에 coverage 계측 추가 |
| `SOCKGATE_BUILD_EXAMPLES` | `ON` | `sg_echo_server`, `sg_echo_client` |
| `SOCKGATE_BUILD_TOOLS` | `ON` | `sg_admin` |
| `SOCKGATE_INSTALL` | 최상위 프로젝트일 때만 `ON` | install 규칙과 CMake 패키지 생성. `add_subdirectory` / FetchContent 로 포함하면 기본 `OFF` |
| `SOCKGATE_WERROR` | `OFF` | 경고를 오류로 (`/WX`, `-Werror`) |
| `SOCKGATE_HARDENING` | `ON` | 플랫폼 hardening 플래그 ([SECURITY.md](SECURITY.md) §3.1) |
| `SOCKGATE_WITH_TPM2` | `OFF` | Linux TPM2 key store (클라이언트, tpm2-tss 필요) |
| `SOCKGATE_ENABLE_DEBUG_LOG` | `OFF` | Release 빌드에서도 debug/trace 로그 문장을 유지 |
| `SOCKGATE_SANITIZER` | `""` | `address`, `undefined`, `address+undefined`, `thread` 중 하나. MSVC 는 `address` 만 지원 (나머지는 경고 후 무시) |

`CMAKE_BUILD_TYPE` 을 주지 않으면 Debug 이다. `compile_commands.json` 을 생성한다.

## 4. 빌드 결과물

| 타깃 | 종류 | 설명 |
|---|---|---|
| `sockgate_server_core` | 정적 (내부) | 서버 구현 전체. 테스트, 변이/fuzz 타깃, `sg_admin` 이 직접 링크 |
| `sockgate_server` (`SockGate::Server`) | 공유 또는 정적 | 공개 라이브러리. `src/core/server_api.cpp` (C ABI) 만 담고 core 를 private 로 링크 |
| `sockgate_common` | 정적 (내부, PIC) | 프로토콜, 암호, TLS, 소켓 (클라이언트와 공유) |
| `sg_echo_server` | 실행 파일 | `examples/echo_server.c` (`SockGate::Server` 만 사용) |
| `sg_admin` | 실행 파일 | `tools/sg_admin.cpp` (서버 core 에 직접 링크) |

실행 파일과 DLL 은 `<build>/bin`, 라이브러리는 `<build>/lib` 에 모인다.

## 5. 공유 vs 정적

| | 공유 (`SOCKGATE_BUILD_SHARED=ON`, 기본) | 정적 (`OFF`) |
|---|---|---|
| 산출물 | Windows `sockgate_server.dll` + import lib, Linux `libsockgate_server.so.0.1.0` (SONAME `libsockgate_server.so.0.1` — 0.x 동안은 MAJOR.MINOR, 1.0 부터 MAJOR) | `sockgate_server` 정적 라이브러리 + 내부 `sockgate_server_core`, `sockgate_common` |
| 매크로 | 빌드 시 `SOCKGATE_SERVER_BUILDING` (export), 사용자는 import | `SOCKGATE_SERVER_STATIC` 이 타깃의 PUBLIC 정의로 사용자에게 전파된다. CMake 밖에서 링크하면 직접 정의해야 한다 |
| Export | `SG_SERVER_API` 함수만 (ELF version script, Windows `__declspec(dllexport)`). 정적으로 들어간 의존성 심볼은 재노출하지 않음 (`--exclude-libs,ALL`) | 해당 없음 |
| OpenSSL | Windows: DLL 안에 정적 링크. Linux: 시스템 OpenSSL 에 동적 링크 | 애플리케이션이 OpenSSL 과 Threads 를 링크해야 한다 (패키지 config 가 `find_dependency` 로 찾음) |
| 설치 | 공개 라이브러리만 | 공개 + 내부 정적 라이브러리 (`SockGate::ServerCore`, `SockGate::Common`) |

fuzz 프리셋은 정적 빌드를 강제한다. export 검사 테스트(`sg_exports_*`)는 공유 빌드에서만 등록된다.

## 6. 테스트

모든 테스트는 CTest 에 등록되고 label 이 붙는다.

| label | 서버 관련 테스트 |
|---|---|
| `unit` | `sg_unit_common`, `sg_unit_tls` (공통 코드) |
| `protocol` | `sg_protocol` (직렬화, 프레임, 메시지 음성 테스트), `sg_mutate_*` |
| `security` | `sg_security_handshake` (핸드셰이크, enrollment, registry, 채널), `sg_security_license` (license store, 내장 인가), `sg_security_proxy_mitm`, `sg_exports_sockgate_server` |
| `integration` | `sg_integration_session`, `sg_integration_license`, `sg_integration_integrity`, `sg_integration_transport` (IOCP/epoll 전송) |
| `fuzz` | `sg_mutate_frame_decoder`, `sg_mutate_messages`, `sg_mutate_channel`, `sg_mutate_storage_files`, `sg_mutate_proxy_config` |

```text
ctest --preset linux-gcc-debug                  # 전체
ctest --preset linux-gcc-debug -L security      # label 선택
ctest --preset linux-gcc-debug -R sg_integration_license
```

테스트용 CA·서버·클라이언트 키는 실행 시 생성하며 저장소에 커밋된 키는 없다. 변이 테스트 반복 횟수는 `fuzz/CMakeLists.txt` 의
캐시 변수 `SG_MUTATION_ITERATIONS` (기본 20000)로 조정한다. 파일 기반인 `storage_files` 는 그 1/10 (기본 2000 회)이다.

## 7. Sanitizer 와 fuzzing

Sanitizer 는 프리셋(§2)으로 켜거나 `-DSOCKGATE_SANITIZER=...` 로 지정한다. 테스트 전체가 같은 계측으로 빌드된다.
Linux sanitizer 테스트 프리셋(`linux-gcc-asan`, `linux-clang-asan`, `linux-clang-tsan`)은 CI 와 같은 런타임 옵션을 환경 변수로 설정하므로
(bd6ca45) 로컬 `ctest --preset` 도 CI 와 같이 첫 오류에서 실패한다. 프리셋 밖에서 실행할 때는 직접 설정한다:

```text
TSAN_OPTIONS=halt_on_error=1 second_deadlock_stack=1
ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
```

Fuzzing (Linux 예, CI 의 fuzz job 과 같은 절차):

```text
cmake --preset linux-clang-fuzz
cmake --build --preset linux-clang-fuzz
cd out/build/linux-clang-fuzz/bin
./sg_mutate_storage_files --write-seeds=corpus/sg_fuzz_storage_files
./sg_fuzz_storage_files corpus/sg_fuzz_storage_files -max_total_time=60 -artifact_prefix=artifacts-storage-
```

타깃 목록과 대상은 [SECURITY.md](SECURITY.md) §3.4 에 있다.

## 8. 설치와 `find_package(SockGate)`

```text
cmake --install out/build/linux-gcc-release --prefix /opt/sockgate
```

install 규칙은 `SOCKGATE_INSTALL=ON` 일 때만 생성된다 (최상위 빌드의 기본값).

설치 내용:

- 헤더: `include/sockgate/` 의 공개 헤더 8개뿐 (`types.h`, `error.h`, `export.h`, `version.h`, `server.h`, `client.h`, `config.h`, `sockgate.h`).
  내부 헤더는 설치되지 않는다.
- 라이브러리: `SockGate::Client`, `SockGate::Server`. 정적 빌드는 내부 archive `SockGate::ClientCore`, `SockGate::ServerCore`,
  `SockGate::Common` 도 설치한다. PDB 는 설치하지 않는다.
- 패키지: `lib/cmake/SockGate/` 의 `SockGateConfig.cmake`, `SockGateConfigVersion.cmake`, `SockGateTargets.cmake`.
  버전 호환성은 0.x 동안 `SameMinorVersion` (0.x 는 minor 버전 사이에서도 ABI 가 바뀔 수 있음), 1.0 이후 `SameMajorVersion` 이다.

사용하는 쪽:

```cmake
cmake_minimum_required(VERSION 3.21)
project(my_server LANGUAGES C)
find_package(SockGate 0.1 REQUIRED)
add_executable(my_server main.c)
target_link_libraries(my_server PRIVATE SockGate::Server)
```

```text
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=/opt/sockgate
```

정적 패키지는 `find_dependency(Threads)`, `find_dependency(OpenSSL 3.0)` 를 수행하므로 소비자 환경에서도 OpenSSL 을 찾을 수 있어야 한다.
TPM2 로 빌드한 정적 패키지는 pkg-config 로 `tss2-esys`, `tss2-mu`, `tss2-tctildr` 를 찾고, 없으면 오류로 중단하지 않고
`SockGate_FOUND FALSE` 와 이유 메시지를 남긴다. Windows 에서는 vcpkg toolchain 과 `VCPKG_TARGET_TRIPLET=x64-windows-static-md` 를 함께 준다.
공유 빌드를 Windows 에서 실행할 때는 설치된 `bin/` 의 DLL 이 `PATH` 에 있어야 한다. 저장소의 `tests/package` 가 이 절차의 예제이며
(out-of-tree 소비자), 설치된 헤더 집합(공개 헤더만)도 확인한다.

## 9. CI (`.github/workflows/ci.yml`)

push (`main`, `develop`), pull request, nightly 스케줄, 수동 실행에서 돈다. 새 push 가 이전 실행을 취소하는 것은 pull request
실행뿐이다 (branch push, nightly, 수동 실행은 취소되지 않음). Action 은 commit SHA 로 고정하고 Dependabot (`.github/dependabot.yml`)이 매주 갱신한다.

| job | 내용 |
|---|---|
| `windows` | windows-2022: `windows-msvc-debug`, `windows-msvc-release`, `windows-clangcl-debug`, `windows-clangcl-release`, `windows-msvc-asan` — configure, build, ctest |
| `linux` | ubuntu-24.04: gcc/clang debug·release, `linux-gcc-asan`, `linux-clang-asan`, `linux-clang-tsan`; ubuntu-24.04-arm: `linux-gcc-release`, `linux-clang-asan`; ubuntu-22.04: `linux-gcc-debug` |
| `linux-tpm2` | swtpm 으로 `SOCKGATE_WITH_TPM2=ON` 빌드, `SOCKGATE_REQUIRE_TPM=1` 로 TPM 테스트 필수 실행 |
| `package` | Ubuntu / Windows × 공유 / 정적: 설치 후 `tests/package` 를 `find_package(SockGate)` 로 빌드·실행 |
| `containers` | `debian:12`, `rockylinux:9` (ninja-build 를 위해 CRB 활성화) 컨테이너에서 `linux-gcc-debug` |
| `fuzz` | `linux-clang-fuzz`: 타깃마다 seed 생성 후 push 60 s / nightly 20 min fuzzing, 실패 시 crash artifact 업로드 |
