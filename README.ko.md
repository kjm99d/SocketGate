# SockGate

[English](README.md) | **한국어** | [日本語](README.ja.md)

애플리케이션에 임베드하는 **네트워크 인증 게이트** C/C++ 라이브러리 (0.1.0, 미릴리스).
클라이언트 설치본마다 고유한 비대칭 키로 서버에 자신을 증명하고, 서버는 인증·라이선스·정책을
모두 서버 쪽에서 결정한다. 이후 트래픽은 TLS 1.3 위에서 프레임마다 순서 번호와 AES-256-GCM 인증 태그로 보호되며, 페이로드 암호화(AEAD)는 선택이다.

```c
#include <sockgate/client.h>   /* Windows 와 Linux 에서 같은 API */
```

## 구성

| 프로젝트 | 역할 | 문서 |
|---|---|---|
| [SockGate_Client](SockGate_Client/README.ko.md) | 애플리케이션에 넣는 클라이언트 라이브러리 (`SockGate::Client`) | README, ARCHITECTURE, THREAT_MODEL, PROTOCOL, SECURITY, BUILD, INTEGRATION, CHANGELOG |
| [SockGate_Server](SockGate_Server/README.ko.md) | 인증 게이트 서버 라이브러리 (`SockGate::Server`) | 〃 |
| [SockGate_Common](SockGate_Common/README.ko.md) | 두 라이브러리가 공유하는 프로토콜·암호·TLS·직렬화 계층과 공용 헤더 | 〃 |

설계 문서: [docs/design](docs/README.ko.md) — 아키텍처, 위협 모델, 신뢰 경계, 프로토콜, 핸드셰이크,
키·세션 수명주기, 공개 C API, 플랫폼 계층, 의존성, **보장하지 않는 것**.

## 보안 요약

- **TLS 1.3 기본**, TLS 1.2 는 명시적으로 허용할 때만 (EMS 필수). 인증서 체인·호스트명·유효기간 검증,
  선택적 다중 SPKI pinning, 선택적 서버 proof key 서명.
- **설치본별 키**: TPM(Windows CNG Platform Crypto Provider / Linux TPM2), CNG Software KSP(non-exportable),
  DPAPI·0600 파일 저장소. 바이너리에 비밀 없음. installation id 는 공개키에서 유도.
- **Challenge-response**: 1회용 challenge, TLS channel binding 과 transcript 에 대한 서명 — 릴레이·재전송 방지.
- **서버가 결정**: 클라이언트가 보내는 product·license·feature·integrity 는 모두 *주장*이다.
  granted = requested ∩ license, 라이선스 만료가 세션 수명 상한, 폐기는 즉시 세션 종료.
- **엄격한 파서**: big-endian 바이너리 프로토콜, 단계별 헤더 규칙, 인증 전 크기 상한, fuzzing.
- **DoS 완화**: 연결 수 상한과 별도의 인증 전 연결 수 상한, 핸드셰이크·idle 타임아웃, 재인증 최소 간격.
- **프록시 탐지에 의존하지 않음**: MITM 은 인증서 검증·pinning·channel binding 으로 막는다.
- 하지 않는 것: 자체 암호 알고리즘, 하드코딩된 master secret, 바이너리 내 private key, 클라이언트 boolean 기반 판단.
  자세한 한계는 [docs/design/13-security-limitations.md](docs/design/13-security-limitations.md).

## 빠른 시작

```sh
# Windows (Developer PowerShell, VCPKG_ROOT 설정)          # Linux (libssl-dev, ninja, cmake)
cmake --preset windows-msvc-release                          cmake --preset linux-gcc-release
cmake --build --preset windows-msvc-release                  cmake --build --preset linux-gcc-release
ctest --preset windows-msvc-release                          ctest --preset linux-gcc-release
```

개발용 인증서로 예제를 돌려 보기 (`out/build/<preset>/bin`):

```sh
sg_admin dev-pki ./dev                        # 개발 전용 CA + localhost 서버 인증서, SPKI pin 출력
sg_admin token-key ./dev/token.key
sg_echo_server --cert dev/server.crt --key dev/server.key --port 7443 \
               --registry dev/registry.bin --token-key dev/token.key --issue-token sockgate-echo
# 서버가 출력한 1회용 enrollment token 을 dev/token.txt 에 저장한 뒤 (명령줄에는 넣지 않는다):
sg_echo_client --host localhost --port 7443 --ca dev/ca.crt --pin <SPKI pin> \
               --key-dir dev/keys --enroll-file dev/token.txt
```

서버는 실행 중 registry·license 파일을 잠근다(`<path>.lock`). `sg_admin` 으로 이 파일을 고칠 때는 서버를 멈춘다.

설치 후 다른 CMake 프로젝트에서:

```cmake
find_package(SockGate 0.1 REQUIRED)
target_link_libraries(app PRIVATE SockGate::Client)   # 또는 SockGate::Server
```

API 레퍼런스(모든 헤더의 Doxygen 주석): 저장소 루트에서 `doxygen Doxyfile`, 또는 CMake 가 Doxygen 을 찾았다면 `cmake --build --preset <preset> --target docs`. 결과는 `out/doxygen/html/index.html` 이다.

## 저장소 구조

```text
SockGate_Common/   공용 헤더(error/types/version/export) + 내부 공용 라이브러리
SockGate_Client/   클라이언트 라이브러리 (C API: include/sockgate/client.h, config.h)
SockGate_Server/   서버 라이브러리 (C API: include/sockgate/server.h)
examples/          C 예제: sg_echo_server, sg_echo_client
tools/             sg_admin: 오프라인 관리 (pin, 토큰, 라이선스, 클라이언트, dev PKI)
tests/             unit / protocol / security / integration 테스트 (CTest 라벨), 패키지 소비자
fuzz/              libFuzzer 대상 + CTest 용 결정적 mutation 드라이버
cmake/             옵션, 컴파일러 hardening, sanitizer, 설치/패키지
docs/design/       설계 문서 01–13
.github/workflows/ CI (Windows/Linux/ARM64, sanitizer, TPM2(swtpm), 패키지, 컨테이너, fuzz)
```

## 상태

0.1.0 은 첫 릴리스 전이며 ABI 기준선이다. 0.x 동안은 minor 버전마다 ABI 가 바뀔 수 있다
(soname `libsockgate_*.so.0.1`, CMake 패키지 호환성 SameMinorVersion). 변경 이력은 각 프로젝트의 CHANGELOG.md 를 본다.
취약점은 공개 이슈가 아니라 메인테이너에게 비공개로 보고한다.

## 라이선스

SockGate 는 [GNU AGPL v3.0](LICENSE)(`AGPL-3.0-only`)과, AGPL 의무 없이 쓰기 위한(예: 소스를 공개하지 않는 애플리케이션)
상용 라이선스의 이중 라이선스이다. 자세한 내용은 [LICENSING.md](LICENSING.md), 제3자 구성 요소는
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 를 본다.
