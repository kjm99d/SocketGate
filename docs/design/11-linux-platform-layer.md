# 11. Linux Platform Layer

대상: Linux x64 / ARM64 (glibc 2.28+). 배포판: Ubuntu LTS, Debian, Rocky/AlmaLinux 계열. 툴체인: GCC ≥ 9, Clang ≥ 10.

## 1. 네트워크

### 1.1 클라이언트 소켓

| 항목 | 구현 |
|---|---|
| 생성 | `socket(..., SOCK_STREAM \| SOCK_NONBLOCK \| SOCK_CLOEXEC, IPPROTO_TCP)` |
| 연결 | non-blocking `connect` → `EINPROGRESS` → `poll(POLLOUT)` + `SO_ERROR` |
| 송수신 | `poll` 대기 후 `send(MSG_NOSIGNAL)` / `recv`, `EINTR` 재시도 |
| SIGPIPE | `MSG_NOSIGNAL` 로 방지 (프로세스 시그널 핸들러를 건드리지 않음) |
| 주소 해석 | `getaddrinfo` (`AI_ADDRCONFIG`) |
| 취소 | `shutdown(SHUT_RDWR)` → 대기 중 `poll` 깨움 → in-flight 종료 후 `close` |

### 1.2 Proxy 환경 변수

`http_proxy`, `https_proxy`, `ALL_PROXY`, `no_proxy` 는 **기본적으로 읽지 않는다.**
`ProxyMode::System` 을 명시한 경우에만 `ALL_PROXY` → `https_proxy` 순으로 읽고 `no_proxy` 를 적용한다.

### 1.3 서버 I/O — epoll

```text
epoll_create1(EPOLL_CLOEXEC)
 ├─ listen fd   : EPOLLIN (level-triggered), accept4(SOCK_NONBLOCK | SOCK_CLOEXEC) 루프
 ├─ conn fd     : EPOLLIN | EPOLLOUT | EPOLLONESHOT | EPOLLRDHUP  (필요 시 re-arm)
 └─ eventfd     : Post() 작업 / 종료 wake-up

Worker thread × N: epoll_wait → 준비된 fd 의 read/write 수행 → completion 핸들러 호출
```

- `EPOLLONESHOT` 로 한 연결의 이벤트가 동시에 두 워커에서 처리되지 않게 한다.
- IOCP 와 같은 completion 스타일 인터페이스(`AsyncRead`, `AsyncWrite`)로 감싸 공통 서버 코드가 플랫폼을 모르게 한다.
- `io_uring` 은 `IIoService` 의 선택적 구현으로 설계만 포함한다 (`SOCKGATE_WITH_IO_URING`, 현재 미구현).

## 2. TLS / 암호

- 시스템 OpenSSL (`libssl-dev` / `openssl-devel`) ≥ 3.0.
- `SG_TRUST_SYSTEM_STORE` 설정 시 `SSL_CTX_set_default_verify_paths`.

## 3. 키 저장

### 3.1 File Key Store (fallback, 기본)

| 항목 | 구현 |
|---|---|
| 위치 | `key_store_path` 또는 `$XDG_DATA_HOME/sockgate` → `~/.local/share/sockgate` |
| 디렉터리 | `0700`, 소유자 = 현재 euid 확인, symlink 거부 |
| 파일 | `open(O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_CLOEXEC, 0600)`, PKCS#8 DER |
| 로드 검증 | `fstat` 으로 소유자 = euid, mode & 077 == 0, 일반 파일 확인. 위반 시 `SG_KEYSTORE_ERROR` |
| 쓰기 | 임시 파일 → `fsync` → `rename` → 디렉터리 `fsync` |
| 삭제 | 0 으로 덮어쓰기 → `unlink` (SSD/저널링 FS 에서 완전 삭제 보장 불가) |

**TPM-backed key 와 동등한 보안성을 제공하지 않는다.** 같은 사용자 또는 root 권한 공격자는 키를 읽을 수 있다.

### 3.2 TPM2 Key Store (`SOCKGATE_WITH_TPM2=ON`, tpm2-tss ESAPI)

```text
1. Esys_Initialize (기본 TCTI: device:/dev/tpmrm0 또는 tabrmd)
2. Owner hierarchy 아래 ECC P-256 storage primary 생성 (결정적 템플릿 → 매번 동일 primary)
3. 서명 키: Esys_Create(ECC P-256, sign, fixedTPM, fixedParent, userWithAuth, ECDSA-SHA256)
4. 결과 TPM2B_PUBLIC / TPM2B_PRIVATE(wrapped blob) 를 파일로 저장 (0600)
5. 서명 시: primary 재생성 → Esys_Load(blob) → Esys_Sign(digest) → FlushContext
```

- private 부분은 TPM 의 storage key 로 wrap 되어 TPM 밖에서는 사용 불가.
- tpm2-tss 가 없는 빌드/환경에서는 `SG_NOT_SUPPORTED`, AUTO 는 File 로 폴백한다.

### 3.3 Linux Keyring

- 커널 keyring 은 재부팅 시 소멸하고 사용자 세션 범위라 **영속 키 저장소로 사용하지 않는다.**
- 향후: File key store 의 복호화된 키 캐시 용도로만 검토 (현재 미구현, 문서화된 제한).

## 4. Integrity (`LinuxPlatformSecurity`)

| 관측 | 방법 | flag |
|---|---|---|
| 실행 파일 해시 | `/proc/self/exe` SHA-256 | (값 전송) |
| SockGate .so 해시 | `dladdr` → 경로 → SHA-256 | (값 전송) |
| Build ID | `dl_iterate_phdr` → `PT_NOTE` → `NT_GNU_BUILD_ID` | (값 전송) |
| LD_PRELOAD / LD_AUDIT | `getenv` + `/etc/ld.so.preload` 존재 | `PRELOAD_PRESENT` |
| Tracer | `/proc/self/status` 의 `TracerPid != 0` | `DEBUGGER_PRESENT` |
| ASLR | `/proc/sys/kernel/randomize_va_space < 2` | `ASLR_DISABLED` |
| 실행 파일 권한 | group/other 쓰기 가능 | `EXECUTABLE_WRITABLE` |
| 로드된 .so | `dl_iterate_phdr` 로 목록, 쓰기 가능 경로 / `/tmp` 경로 탐지 | `UNEXPECTED_MODULES` |

## 5. 빌드 Hardening (GCC / Clang)

| 플래그 | 목적 |
|---|---|
| `-fstack-protector-strong` | stack canary |
| `-D_FORTIFY_SOURCE=3` (Release, `-O2` 이상; GCC < 12 는 2) | libc 경계 검사 |
| `-fPIC` / `-fPIE -pie` | ASLR |
| `-Wl,-z,relro,-z,now` | Full RELRO |
| `-Wl,-z,noexecstack` | NX stack |
| `-fcf-protection=full` (x86_64) / `-mbranch-protection=standard` (ARM64) | CET / BTI+PAC |
| `-fstack-clash-protection` | stack clash |
| `-fvisibility=hidden -fvisibility-inlines-hidden` | export 최소화 |
| `-Wl,--exclude-libs,ALL` | 정적 링크한 OpenSSL 심볼 비노출 |
| Release: `-s` 또는 `strip --strip-unneeded` | 심볼 제거 |
| `-Wall -Wextra -Wconversion -Wshadow -Wformat=2` | 경고 |

## 6. 런타임 검증

- `linux-*-asan` (ASan + UBSan), `linux-clang-tsan` (TSan), `linux-clang-fuzz` (libFuzzer + ASan) 프리셋.
- 컨테이너 CI: Ubuntu 22.04/24.04, Debian 12, Rocky 9 (`.github/workflows/ci.yml`).
