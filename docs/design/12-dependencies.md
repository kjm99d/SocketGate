# 12. Dependency List

외부 의존성은 최소화한다. 런타임 필수 의존성은 **OpenSSL 하나**이다.

## 1. 런타임

| 의존성 | 필수 | 최소 버전 | 권장 | 용도 | 획득 |
|---|---|---|---|---|---|
| OpenSSL (libssl, libcrypto) | 예 | **3.0.0** | 3.5 LTS 이상 | TLS 1.3, SHA-256, HKDF, AES-GCM, ECDSA, RNG | Windows: vcpkg (`x64-windows-static-md`), Linux: 배포판 패키지 |
| tpm2-tss (`tss2-esys`, `tss2-mu`, `tss2-rc`, `tss2-tctildr`) | 아니오 | 3.0 | 4.x | Linux TPM2 key store | `libtss2-dev` / `tpm2-tss-devel` |
| Windows SDK (ws2_32, ncrypt, bcrypt, crypt32, wintrust, psapi, winhttp) | Windows | 10.0.19041 | 최신 | 소켓, CNG, DPAPI, 서명 검증 | VS 설치 |

- OpenSSL 1.1.x 는 지원하지 않는다 (EOL, `EVP_PKEY_fromdata`/`OSSL_PARAM` API 사용).
- CMake 에서 `find_package(OpenSSL 3.0 REQUIRED)` 로 **API 수준** 최소 버전을 강제한다.
- **보안 최소 요구**: 알려진 취약점이 패치된 OpenSSL. 업스트림 기준 3.0.7 미만(CVE-2022-3602/3786, X.509 검증 중 overflow)은
  사용 금지. 업스트림 3.0 계열은 2026-09-07 EOL 이므로 **3.5 LTS 이상을 권장**한다.
  배포판 패키지(예: Ubuntu 22.04 의 3.0.2)는 버전 번호와 무관하게 보안 패치가 백포트되므로 배포판 보안 업데이트를 적용한 상태를 전제로 한다.
  배포판 OpenSSL 은 버전 번호로 패치 여부를 알 수 없으므로 configure 시 `OPENSSL_VERSION < 3.0.7` 이면 CMake 경고만 낸다.
  OpenSSL 을 함께 배포하는 빌드(Windows, 또는 정적 링크)는 실행 시 `OpenSSL_version_num() < 3.0.7` 이면
  `event=config_warning` 경고를 남긴다 (서버는 시작 시, 클라이언트는 프로세스당 첫 Connect 시 1회).
- Windows 는 OpenSSL 을 **정적 링크**하여 `sockgate_client.dll` 하나로 배포할 수 있게 한다 (DLL hijacking 표면 축소).
  Linux 는 기본적으로 시스템 OpenSSL 에 동적 링크한다 (보안 업데이트를 배포판이 제공).
- 배포판별 OpenSSL: Ubuntu 22.04 = 3.0.2, Ubuntu 24.04 = 3.0.13, Debian 12 = 3.0.x, Rocky 9 = 3.0.x/3.2.x → 모두 지원.

## 2. 빌드

| 도구 | 최소 버전 | 비고 |
|---|---|---|
| CMake | 3.21 | presets v3 |
| Ninja | 1.10 | 프리셋 기본 generator |
| MSVC | 19.30 (VS 2022) | C++17 |
| clang-cl | 13 | |
| GCC | 9 | C++17 |
| Clang | 10 | |
| vcpkg | 2024 이후 | Windows, manifest mode, baseline 고정 |

## 3. 테스트 / 검증

| 도구 | 용도 | 비고 |
|---|---|---|
| 내장 테스트 프레임워크 (`tests/framework`) | 단위/보안/통합 테스트 | 외부 의존성 없음, CTest 등록 |
| CTest | 테스트 실행 | CMake 포함 |
| libFuzzer | fuzzing | Clang `-fsanitize=fuzzer`, MSVC `/fsanitize=fuzzer` |
| AFL++ | fuzzing (선택) | 같은 `LLVMFuzzerTestOneInput` 타깃 재사용 |
| ASan / UBSan / TSan | 런타임 검증 | Linux Clang/GCC, Windows ASan |

## 4. 의도적으로 사용하지 않는 것

| 후보 | 사용하지 않는 이유 |
|---|---|
| Boost.Asio | 의존성 규모. IOCP/epoll 을 직접 얇게 구현 |
| libsodium | OpenSSL 로 필요한 AEAD/서명/KDF 모두 충족. 필요 시 `crypto/crypto.h` 의 다른 구현(현재 `openssl_crypto.cpp`)으로 추가 가능 |
| mbedTLS | 1차 범위는 OpenSSL 단일 backend. `ITlsProvider` 로 확장 가능 |
| GoogleTest | 테스트 의존성 최소화 |
| JSON 라이브러리 | wire format 은 바이너리 |
| WinHTTP / WinINet (transport 용도) | 시스템 proxy 에 암묵 종속 방지 (System proxy 모드의 설정 **조회**에만 WinHTTP 사용) |

## 5. 버전 차이 대응

- OpenSSL 3.0 에서 사용 불가한 API 는 사용하지 않는다 (예: 3.2+ 전용 API 사용 시 `OPENSSL_VERSION_NUMBER` 분기).
- TLS 1.3 cipher suite 는 OpenSSL 기본값(`TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`)을 명시적으로 설정.
- TLS 1.2 옵션 사용 시 `ECDHE-ECDSA/RSA-AES-GCM`, `ECDHE-*-CHACHA20-POLY1305` 만 허용, 재협상/압축 비활성.
- OpenSSL security level 은 설정하지 않는다 (`SSL_CTX_set_security_level` 호출 없음). 사용하는 OpenSSL 의 기본값
  (버전과 빌드/배포판 설정에 따름)이 적용된다. 허용 프로토콜·cipher suite 는 위 목록으로 고정된다.
