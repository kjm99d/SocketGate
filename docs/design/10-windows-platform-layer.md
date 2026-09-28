# 10. Windows Platform Layer

대상: Windows 10 / 11 x64. 툴체인: MSVC (VS 2022 17.x 이상), clang-cl.

## 1. 네트워크

### 1.1 Winsock 초기화

- `WSAStartup(2.2)` 는 프로세스 전역 참조 카운트로 관리한다 (`WinsockInit` RAII, 첫 Create 에서 시작, 마지막 Destroy 에서 `WSACleanup`).
- 애플리케이션이 이미 `WSAStartup` 을 호출했어도 참조 카운트 방식이라 충돌하지 않는다.

### 1.2 클라이언트 소켓 (TcpTransport)

| 항목 | 구현 |
|---|---|
| 생성 | `WSASocketW(AF_INET/AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED \| WSA_FLAG_NO_HANDLE_INHERIT)` |
| 비동기 연결 | `ioctlsocket(FIONBIO)` → `connect` → `WSAPoll(POLLWRNORM)` + `SO_ERROR` 확인 |
| 송수신 타임아웃 | `WSAPoll` 로 대기 후 `send`/`recv` |
| 주소 해석 | `GetAddrInfoW` (UTF-8 → UTF-16 변환), 결과 순회 |
| 옵션 | `TCP_NODELAY`, `SO_KEEPALIVE`, `SO_EXCLUSIVEADDRUSE`(서버) |
| 취소 | `shutdown(SD_BOTH)` 로 대기 중 `WSAPoll` 을 깨운 뒤, in-flight 종료 후 `closesocket` |

WinHTTP / WinINet 은 **사용하지 않는다**. 따라서 시스템 proxy 설정(IE/WinHTTP)이 transport 에 자동 적용되지 않는다.
`ProxyMode::System` 을 명시적으로 선택한 경우에만 `WinHttpGetIEProxyConfigForCurrentUser` 로 설정을 **읽어**
SockGate 자체 proxy connector 에 전달한다 (PAC 스크립트는 지원하지 않음 — 제한사항).

### 1.3 서버 I/O — IOCP

```text
CreateIoCompletionPort ─┬─ Listen socket (AcceptEx 사전 게시 N개)
                        ├─ Connection sockets (WSARecv / WSASend overlapped)
                        └─ PostQueuedCompletionStatus (작업 게시, 종료 신호)

Worker thread × N: GetQueuedCompletionStatusEx → IoOperation* → 핸들러
```

- `AcceptEx` / `GetAcceptExSockaddrs` 는 `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` 로 획득.
- 수락 후 `setsockopt(SO_UPDATE_ACCEPT_CONTEXT)`.
- `SetFileCompletionNotificationModes(FILE_SKIP_SET_EVENT_ON_HANDLE)` 사용. 즉시 완료 시에도 completion 은 큐잉되도록
  `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` 는 사용하지 않는다 (코드 경로 단순화).
- 각 overlapped 작업 구조체는 `std::shared_ptr<Connection>` 을 보유 → 완료 통지 전 연결 해제 방지.
- 종료: listen 소켓 close → 연결 소켓 `CancelIoEx` + close → 모든 pending 작업 완료 대기 → 워커 수만큼 종료 패킷 게시.

## 2. 암호 / 키 저장

### 2.1 CNG Key Store (`CngKeyStore`)

| 항목 | 구현 |
|---|---|
| Provider | TPM: `MS_PLATFORM_CRYPTO_PROVIDER`, Software: `MS_KEY_STORAGE_PROVIDER` |
| 키 | `NCRYPT_ECDSA_P256_ALGORITHM`, 영속 키 (이름: `SockGate/<identity_name>`) |
| export 정책 | `NCRYPT_EXPORT_POLICY_PROPERTY = 0` (non-exportable) |
| 범위 | 기본 사용자 범위. `SG_KEYSTORE_FLAG_MACHINE` 이면 `NCRYPT_MACHINE_KEY_FLAG` |
| 서명 | SHA-256 (BCrypt) → `NCryptSignHash` → P1363 64 bytes |
| 공개키 | `NCryptExportKey(BCRYPT_ECCPUBLIC_BLOB)` → SEC1 `0x04‖X‖Y` 변환 |
| 메타데이터 | 없음. installation_id 는 공개키에서 유도 (06 §2.1) |
| 삭제 | `NCryptDeleteKey` |
| AUTO | TPM provider 열기 성공 + 키 생성 성공 시 TPM, 아니면 Software KSP |

Software KSP 의 키는 Windows 가 DPAPI 로 보호하는 사용자 프로필 영역에 저장된다.

### 2.2 DPAPI

- File key store 를 Windows 에서 사용할 경우 PKCS#8 private key 를 `CryptProtectData`(사용자 범위,
  `CRYPTPROTECT_UI_FORBIDDEN`, entropy = identity 이름 기반 도메인 분리 문자열)로 암호화해 저장한다.
- DPAPI 는 같은 사용자 권한으로 실행되는 코드로부터 키를 보호하지 못한다 (제한사항).

### 2.3 인증서 저장소

- `SG_TRUST_SYSTEM_STORE` 가 설정되면 `CertOpenSystemStoreW(L"ROOT")` 의 인증서를 OpenSSL `X509_STORE` 에 추가한다.
- 기본값은 애플리케이션이 제공한 CA (사설 PKI) 만 신뢰 + pinning 권장.

## 3. Integrity (`WindowsPlatformSecurity`)

| 관측 | 방법 | flag |
|---|---|---|
| 실행 파일 해시 | `GetModuleFileNameW(NULL)` → SHA-256 | (값 전송) |
| SockGate DLL 해시 | `GetModuleHandleExW(FROM_ADDRESS)` → 파일 SHA-256 | (값 전송) |
| 코드 서명 | `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` (네트워크 revocation 조회 없음) | `UNSIGNED_EXECUTABLE` |
| 디버거 | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | `DEBUGGER_PRESENT` |
| ASLR / DEP / CFG | `GetProcessMitigationPolicy` | `ASLR_DISABLED`, `DEP_DISABLED`, `CFG_DISABLED` |
| 로드 모듈 | `EnumProcessModules` + 서명 여부(선택, 비용 큼) | `UNEXPECTED_MODULES` |

모든 관측은 **우회 가능**하며 서버 정책의 입력일 뿐이다.

## 4. 빌드 Hardening (MSVC / clang-cl)

| 플래그 | 목적 |
|---|---|
| `/GS` | stack buffer security check |
| `/sdl` | 추가 보안 검사 |
| `/guard:cf` (컴파일 + 링크) | Control Flow Guard |
| `/CETCOMPAT` | CET shadow stack 호환 |
| `/DYNAMICBASE /HIGHENTROPYVA` | ASLR |
| `/NXCOMPAT` | DEP |
| `/Qspectre` (옵션) | Spectre 완화 |
| `/W4 /permissive- /utf-8` | 경고, 표준 준수 |
| Release: `/O2 /Gy /GL`, 링크 `/OPT:REF /OPT:ICF /LTCG` | 최적화, 미사용 코드 제거 |
| Release: PDB 는 별도 보관, 배포물에 포함하지 않음 (`/DEBUG` 는 PDB 생성용, 배포 시 제외) | 심볼 제거 |
| export | `__declspec(dllexport)` 가 붙은 `SG_*` 함수만 |

## 5. 런타임 검증

- Debug: `/RTC1`, CRT debug heap.
- `windows-msvc-asan` 프리셋: `/fsanitize=address`.
- `windows-msvc-fuzz` 프리셋: `/fsanitize=fuzzer,address` (MSVC libFuzzer).
