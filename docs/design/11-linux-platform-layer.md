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
| 위치 | `key_store_path` 또는 `$XDG_DATA_HOME/sockgate/keys` → `~/.local/share/sockgate/keys` (`secure_getenv`, 없으면 `getpwuid_r`) |
| 디렉터리 | 없는 구성요소는 `0700` 으로 생성. 최종 디렉터리는 `O_DIRECTORY\|O_NOFOLLOW` 로 열어 소유자 = euid, group/other 쓰기 불가 확인 |
| 파일 접근 | 모두 검증된 디렉터리 fd 기준 `openat`/`linkat`/`unlinkat` (경로 재해석 없음) |
| 쓰기 | ① `O_TMPFILE`(0600) 에 쓰고 `fsync` → `/proc/self/fd/N` 을 `linkat(AT_SYMLINK_FOLLOW)` 으로 게시 후 inode 일치 확인: 키가 임시 이름으로 존재하는 순간이 없다. ② 불가하면 임시 파일(`O_EXCL\|O_NOFOLLOW`) → `renameat2(RENAME_NOREPLACE)` (raw syscall, musl 호환), 파일 시스템이 지원하지 않으면 `linkat`. 모두 이미 있으면 `EEXIST` = 배타적 생성. 디렉터리 `fsync` 실패는 오류. SockGate 형식의 임시 파일(`.<name>.<sgkey\|sgref\|tpm2key>.<16 hex>.tmp`)만, 자기 소유이고 10분 넘은 것을 디렉터리 준비 시 제거 |
| 로드 검증 | `fstat`: 일반 파일, 소유자 = euid, `mode & 077 == 0`, 링크 수 1, 64 KiB 이하. 위반 시 `SG_KEYSTORE_ERROR` |
| 삭제 | 0 으로 덮어쓰기 → `unlinkat` (SSD/저널링 FS 에서 완전 삭제 보장 불가) |
| 형식 | 06 §3.1 (Linux 는 보호 계층 없이 파일 권한에 의존) |

**TPM-backed key 와 동등한 보안성을 제공하지 않는다.** 같은 사용자 또는 root 권한 공격자는 키를 읽을 수 있다.

### 3.2 TPM2 Key Store (`SOCKGATE_WITH_TPM2=ON`, tpm2-tss ESAPI)

```text
1. Esys_Initialize (TCTI: `SOCKGATE_TPM2_TCTI` 환경변수 — `device`/`tabrmd`/`swtpm`/`mssim` 만 허용, 라이브러리
   경로 불가, 시뮬레이터는 테스트 용도 — 없으면 접근 가능한 `device:/dev/tpmrm0`. 공유되지 않는 raw `/dev/tpm0` 은
   쓰지 않는다. 연결은 처음 필요할 때 열고, 전송(TCTI) 오류 뒤에는 다시 연다)
2. Owner hierarchy 아래 ECC P-256 storage primary 생성 (결정적 템플릿 → 매번 동일 primary)
3. 서명 키: Esys_Create(ECC P-256, sign, fixedTPM, fixedParent, userWithAuth, ECDSA-SHA256)
4. 결과 TPM2B_PUBLIC / TPM2B_PRIVATE(wrapped blob) 를 "<name>.tpm2key" 로 저장 (File 과 같은 규칙, 0600)
   형식: "SGT2" ‖ u16 version ‖ vec16 TPM2B_PUBLIC ‖ vec16 TPM2B_PRIVATE (Tss2_MU marshal)
5. 서명 시: primary 재생성 → Esys_Load(blob) → Esys_Sign(digest) → FlushContext → 공개키로 서명 검증(fault check)
```

- private 부분은 TPM 의 storage key 로 wrap 되어 TPM 밖에서는 사용 불가. ESAPI context 는 mutex 로 직렬화.
- tpm2-tss 없이 빌드하면 `SG_KEYSTORE_TPM2` 는 `SG_NOT_SUPPORTED`.
- 새 키 생성의 `SG_NOT_SUPPORTED` 는 확정적인 경우뿐이다: `/dev/tpmrm0` 를 쓸 수 없음 (TPM 없음, TPM 1.2,
  커널 4.12 미만, tss 그룹 아님 — 모두 지속되는 상태), owner hierarchy 에 auth 설정(`TPM2_RC_BAD_AUTH`/`AUTH_FAIL`)
  또는 비활성(`TPM2_RC_HIERARCHY`), 곡선/scheme/알고리즘 미지원. 그 밖은 `SG_KEYSTORE_ERROR`. 부팅 초기에 TPM
  드라이버가 아직 없을 때 처음 만든 identity 는 File 에 생성될 수 있다 (13 참고). TCTI 와 tabrmd resource manager 계층 오류 뒤에는 연결을 다시 연다. 기존 TPM 키
  서명은 TPM 이 없으면 `SG_KEYSTORE_ERROR`. 기존 identity 는 locator 로 보호된다 (06 §3).
- 빌드: `-DSOCKGATE_WITH_TPM2=ON` (pkg-config `tss2-esys tss2-mu tss2-tctildr`). swtpm 으로 실행할 수 있다
  (`SOCKGATE_TPM2_TCTI=swtpm:host=127.0.0.1,port=2321`). `SOCKGATE_REQUIRE_TPM=1` 이면 TPM 테스트가 "TPM 없음" 을
  실패로 처리한다 (TPM 이 있어야 하는 CI 에서 조용히 건너뛰지 않도록).

### 3.3 Linux Keyring

- 커널 keyring 은 재부팅 시 소멸하고 사용자 세션 범위라 **영속 키 저장소로 사용하지 않는다.**
- 향후: File key store 의 복호화된 키 캐시 용도로만 검토 (현재 미구현, 문서화된 제한).

## 4. Integrity (`LinuxPlatformSecurity`)

| 관측 | 방법 | flag |
|---|---|---|
| 실행 파일 해시 | `/proc/self/exe` SHA-256 | (값 전송) |
| SockGate .so 해시 | 로더의 세그먼트 맵(`dl_iterate_phdr`)에서 SockGate 코드가 든 객체 → 절대 경로의 일반 파일만 SHA-256 (실행 파일에 정적 링크되면 실행 파일 해시) | (값 전송) |
| Build ID | `dl_iterate_phdr` → `PT_NOTE` → `NT_GNU_BUILD_ID` | (값 전송) |
| LD_PRELOAD / LD_AUDIT | `getenv` + `/etc/ld.so.preload` 존재 | `PRELOAD_PRESENT` |
| Tracer | `/proc/self/status` 의 `TracerPid != 0` | `DEBUGGER_PRESENT` |
| ASLR | `randomize_va_space == 0`, `personality()` 의 `ADDR_NO_RANDOMIZE` (`setarch -R`, 디버거), 또는 실행 파일이 PIE 아님 (ELF `ET_EXEC`) | `ASLR_DISABLED` |
| 실행 파일 권한 | group/other 쓰기 가능 | `EXECUTABLE_WRITABLE` |
| 로드된 코드 | 실행 파일과 `.so` 목록(`dl_iterate_phdr`, 로더 lock 밖에서 검사): `/tmp/`·`/var/tmp/`·`/dev/shm/`·`/memfd:` 또는 world-writable 파일 | `UNEXPECTED_MODULES` |
| 해시 실패 | 파일을 읽지 못함 | `HASH_UNAVAILABLE` |

파일 해시는 프로세스당 1회 계산해 캐시하고, 나머지 관측은 인증마다 다시 평가한다. 모든 관측은 우회 가능하며
서버 정책의 입력일 뿐이다 (09 §5.2).

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
| `-Wl,--version-script=cmake/sockgate_exports.map` (`SG_*` 만 global) | 약한 C++ 템플릿 심볼까지 비노출. CTest `sg_exports_*` 가 `nm -D` 로 검증 |
| `-Wl,--exclude-libs,ALL` | 정적 링크한 OpenSSL 심볼 비노출 |
| Release: `-s` 또는 `strip --strip-unneeded` | 심볼 제거 |
| `-Wall -Wextra -Wconversion -Wshadow -Wformat=2` | 경고 |

## 6. 런타임 검증

- `linux-*-asan` (ASan + UBSan), `linux-clang-tsan` (TSan), `linux-clang-fuzz` (libFuzzer + ASan) 프리셋.
- 컨테이너 CI: Ubuntu 22.04/24.04, Debian 12, Rocky 9 (`.github/workflows/ci.yml`).
