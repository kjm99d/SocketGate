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
| 키 | `BCRYPT_ECDSA_P256_ALGORITHM`, 영속 키 (이름: `SockGate-<identity_name>`), 용도 `NCRYPT_ALLOW_SIGNING_FLAG` |
| export 정책 | Software KSP: `NCRYPT_EXPORT_POLICY_PROPERTY = 0` (non-exportable). TPM: 키가 칩 밖으로 나오지 않음 |
| 범위 | 사용자 범위 (machine key 미지원) |
| UI | 생성·열기·서명에 `NCRYPT_SILENT_FLAG` (UI 금지). 삭제는 PCP 가 이 플래그를 거부하므로 0 |
| 서명 | SHA-256 (OpenSSL) → `NCryptSignHash` → P1363 64 bytes |
| 공개키 | `NCryptExportKey(BCRYPT_ECCPUBLIC_BLOB)` → SEC1 `0x04‖X‖Y` 변환 후 곡선 위 검증 |
| 메타데이터 | 없음. installation_id 는 공개키에서 유도 (06 §2.1) |
| 삭제 | `NCryptDeleteKey` |
| TPM 판정 | provider 를 열 수 있으면 store 생성. **새 키 생성**: `Tbsi_GetDeviceInfo` 가 TPM 2.0 → 허용, TPM 1.2 / `TBS_E_TPM_NOT_FOUND` / `TBS_E_SERVICE_DISABLED` → `SG_NOT_SUPPORTED`, 그 밖(서비스 시작 중 등) → `SG_KEYSTORE_ERROR` 이며 다음 생성 시 다시 묻는다. 생성 실패는 `NTE_NOT_SUPPORTED`/`NTE_BAD_ALGID` 와 TPM 2.0 `ASYMMETRIC`/`HASH`/`HIERARCHY`/`KEY_SIZE`/`SCHEME`/`CURVE` 만 `SG_NOT_SUPPORTED` |
| 오류 | `NTE_BAD_KEYSET`/`NTE_NO_KEY` 만 "키 없음". 그 밖의 오류는 `SG_KEYSTORE_ERROR` — TPM 이 일시적으로 안 될 때 AUTO 가 더 약한 저장소에 새 identity 를 만들지 않게 한다 |
| AUTO | TPM(PCP) → Software KSP 순으로 조회. 새 키는 생성 가능한 첫 저장소에 만든다 |

Software KSP 의 키는 Windows 가 DPAPI 로 보호하는 사용자 프로필 영역에 저장된다.

### 2.2 DPAPI

- File key store 를 Windows 에서 사용할 경우 PKCS#8 private key 를 `CryptProtectData`(사용자 범위,
  `CRYPTPROTECT_UI_FORBIDDEN`, entropy = `"SockGate/v1/file-key/" ‖ identity 이름`)로 암호화해 저장한다.
  entropy 가 이름을 묶으므로 다른 이름의 키 파일로 바꿔치기할 수 없다.
- 위치: `key_store_path` 또는 `%LOCALAPPDATA%\SockGate\keys`. SockGate 가 만드는 디렉터리에는 보호된 DACL
  (`D:P(A;OICI;FA;;;<user SID>)(A;OICI;FA;;;SY)`)을 설정해 부모 ACL 상속을 끊는다.
- 디렉터리는 **모든 작업마다** 다시 검증한다: reparse point 가 아니고, 소유자가 사용자/SYSTEM/Administrators 이며,
  DACL(상속 전용 ACE 포함)이 그 외 주체에게 쓰기/삭제/권한 변경을 허용하지 않아야 한다. NULL DACL, 평가하지
  않는 허용 ACE 종류(조건부/object ACE) 거부. FAT 등 ACL 없는 볼륨은 거부된다 (fail closed).
- 읽은 파일의 소유자도 사용자/SYSTEM/Administrators 여야 한다 (다른 계정이 심은 파일 거부).
- 읽기는 공유 모드 READ|DELETE 로 연다 (방금 게시된 파일의 rename 핸들과 충돌하지 않도록). 백신 검사 등으로
  생기는 일시적 sharing violation 은 최대 250 ms 재시도한다.
- 파일: 임시 파일(`CREATE_NEW`, write-through) → `MoveFileExW`(덮어쓰기 없음) 로 배타적·원자적 생성.
  읽기/삭제는 `FILE_FLAG_OPEN_REPARSE_POINT` 로 열고 reparse point, 디렉터리, hard link(링크 수 ≠ 1)를 거부한다.
  삭제는 0 으로 덮어쓴 뒤 delete-on-close.
- 파일 형식과 무결성 검사는 06 §3.1 참고.
- DPAPI 는 같은 사용자 권한으로 실행되는 코드로부터 키를 보호하지 못한다 (제한사항).

### 2.3 인증서 저장소

- `SG_TRUST_SYSTEM_STORE` 가 설정되면 `CertOpenSystemStoreW(L"ROOT")` 의 인증서를 OpenSSL `X509_STORE` 에 추가한다.
- 기본값은 애플리케이션이 제공한 CA (사설 PKI) 만 신뢰 + pinning 권장.

## 3. Integrity (`WindowsPlatformSecurity`)

| 관측 | 방법 | flag |
|---|---|---|
| 실행 파일 해시 | `GetModuleFileNameW(NULL)` → SHA-256 (프로세스당 1회, 캐시) | (값 전송) |
| SockGate DLL 해시 | `GetModuleHandleExW(FROM_ADDRESS)` → 파일 SHA-256 (정적 링크면 실행 파일 해시 재사용). 해시는 성공한 것만 캐시 | (값 전송) |
| 코드 서명 | `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)`, `WTD_REVOKE_NONE`, `WTD_CACHE_ONLY_URL_RETRIEVAL`, UI 없음. 확정 결과(서명됨 / FACILITY_CERT 판정)만 캐시 | `UNSIGNED_EXECUTABLE` |
| 디버거 | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | `DEBUGGER_PRESENT` |
| ASLR | 실행 파일 PE 헤더의 `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` | `ASLR_DISABLED` |
| DEP / CFG | `GetProcessMitigationPolicy(ProcessDEPPolicy / ProcessControlFlowGuardPolicy)` (64-bit 는 DEP 항상 켜짐) | `DEP_DISABLED`, `CFG_DISABLED` |
| 로드 모듈 | `EnumProcessModules`, 사용자 temp 디렉터리에서 로드된 모듈 (8.3 짧은 경로는 `GetLongPathNameW` 로 정규화해 비교) | `UNEXPECTED_MODULES` |
| 해시 실패 | 파일을 읽지 못함 | `HASH_UNAVAILABLE` |

`SG_CLIENT_FLAG_INTEGRITY_REPORT` 가 있으면 인증(Authenticate/Enroll)마다 수집해 CLIENT_HELLO 에 싣는다.
모든 관측은 **우회 가능**하며 서버 정책의 입력일 뿐이다 (09 §5.2).

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
