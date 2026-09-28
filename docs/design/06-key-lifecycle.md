# 06. Key Lifecycle

## 1. 키 목록

| 키 | 소유 | 알고리즘 | 저장 | 수명 |
|---|---|---|---|---|
| Installation key | 클라이언트 | ECDSA P-256 | IKeyStore (CNG/TPM, TPM2, file) | installation 수명, 교체 가능 |
| Installation ID | 클라이언트 | `SHA-256("SockGate/v1/iid" ‖ SEC1 공개키)[0..16)` | 공개키에서 매번 유도 | 키 수명 |
| 서버 TLS 키 / 인증서 | 서버 | ECDSA/RSA (TLS 정책) | PEM 파일 (배포 환경 보호) | 인증서 유효기간 |
| 서버 proof key (선택) | 서버 | ECDSA P-256 | PEM 파일 | 운영 정책 |
| Enrollment token key | 서버 | HMAC-SHA256 32 bytes | 설정 파일 또는 시작 시 생성 | 운영 정책 |
| Session channel keys | 양쪽 | AES-256-GCM (방향별) | 메모리 | 세션/epoch |
| TLS traffic keys | 양쪽 | OpenSSL 관리 | 메모리 | TLS 연결 |
| Challenge / nonce | 양쪽 | 32 bytes CSPRNG | 메모리 | 1회 사용, TTL |

**하드코딩된 master secret, 바이너리에 포함된 private key 는 존재하지 않는다.**
테스트에서 사용하는 CA/서버/클라이언트 키도 테스트 실행 시 런타임에 생성한다.

## 2. Installation key

### 2.1 생성

```text
SG_Client_EnsureIdentity(client, &info)
   ├─ key store 에 identity(name) 존재? ── yes → 로드, installation_id 반환
   └─ no → GenerateKeyPair(ECDSA P-256, non-exportable if supported)
           installation_id = SHA-256("SockGate/v1/iid" ‖ public_key)[0..16)
```

installation_id 를 공개키에서 유도하므로 (1) 별도 메타데이터 저장이 필요 없고, (2) 다른 installation 의 ID 를
선점(squatting)할 수 없으며, (3) 서버가 enrollment 시 ID 와 키의 관계를 검증할 수 있다.

- identity 이름: `SG_ClientConfig.identity_name` (애플리케이션별로 구분, 예: `"com.example.product"`).
  key store 의 이름 공간(CNG `SockGate-<name>`, key 디렉터리)은 사용자 단위로 모든 SockGate 애플리케이션이
  공유하므로 이름은 reverse-DNS 형식으로 전역적으로 고유해야 한다. `.` 으로 시작하는 이름과 Windows 장치 이름
  (`CON`, `NUL`, `COM1` …)은 모든 플랫폼에서 거부한다.
- 같은 이름에 대해 동시 생성 경쟁은 key store 수준의 배타적 생성(CNG: `NCRYPT_OVERWRITE_KEY_FLAG` 미사용,
  file: `O_EXCL`)으로 막는다.

### 2.2 등록 (서버에 공개키 알리기)

1. **Enrollment token** (권장): 서버가 발급한 1회용 token 으로 `SG_Client_Enroll()` → 서버가 공개키 등록.
2. **Out-of-band**: `SG_Client_EnsureIdentity()` / `SG_Client_GetIdentity()` 가 채우는 `SG_IdentityInfo.public_key`
   (SEC1 공개키)를 관리자가 `SG_Server_RegisterClient()` 로 등록. (별도 `SG_Client_ExportPublicKey()` 는 두지 않았다.)

private key 는 어떤 경로로도 서버에 전송되지 않는다.

### 2.3 사용

- Core 는 `IKeyStore::Sign(handle, data)` 만 호출한다. 해시는 key store 구현이 수행하거나(CNG 는 해시 값 입력),
  Core 가 SHA-256 을 계산해 전달한다. 인터페이스는 **메시지(서명 대상 전체)** 를 받는다.
- 서명 포맷: P1363 `r‖s` 64 bytes (DER 이 필요한 백엔드는 내부 변환).

### 2.4 교체 (rotation)

```text
1. 새 identity 이름(예: name + ".next")으로 생성
2. 새 키 enroll
3. 성공 후 identity 이름 전환, 구 키 DeleteIdentity
4. 서버에서 구 installation revoke
```

### 2.5 폐기 (revocation)

- 서버: `SG_Server_RevokeClient(installation_id)` → registry 상태 `REVOKED`, 즉시 저장.
- 해당 installation 의 **활성 세션은 즉시 종료**된다 (CLOSE(AUTH_FAILED)). 재인증을 기다리지 않는다.
- `SG_Server_RevokeLicense(license_id)` 도 해당 라이선스로 인가된 세션을 즉시 종료한다 (폐기는 영구).
- `SG_Server_ReleaseLicenseSeat(license_id, installation_id)` 는 좌석을 반납하고 그 installation 의 해당
  라이선스 세션을 종료한다. 재설치로 installation 키가 바뀐 경우 구 installation 의 좌석을 이렇게 회수한다.
- 인가가 진행 중인 연결과 폐기가 경합해도 세션이 열리기 전에 다시 확인된다 (07 §4).

### 2.6 삭제

- `SG_Client_DeleteIdentity()` → key store 에서 키와 메타데이터 삭제.
- File key store 는 파일을 덮어쓰기 후 삭제한다(저장 매체 특성상 완전 삭제는 보장 불가 — 제한사항 문서 참고).

## 3. Key store 종류와 보안 수준

| 종류 | 플랫폼 | private key 노출 | 비고 |
|---|---|---|---|
| `SG_KEYSTORE_CNG_TPM` | Windows | TPM 밖으로 나오지 않음 | Microsoft Platform Crypto Provider |
| `SG_KEYSTORE_CNG_SOFTWARE` | Windows | 사용자 프로필에 DPAPI 로 보호되어 저장, non-exportable | Microsoft Software KSP |
| `SG_KEYSTORE_TPM2` | Linux | TPM 밖으로 나오지 않음 (key blob 은 TPM 으로 wrap) | tpm2-tss ESAPI, 빌드 옵션 |
| `SG_KEYSTORE_FILE` | 공통 | 파일(0600 / Windows 는 DPAPI 암호화) | fallback, TPM 과 동등하지 않음 |
| `SG_KEYSTORE_MEMORY` | 공통 | 프로세스 메모리 | 테스트/임시용, 영속성 없음 |
| `SG_KEYSTORE_AUTO` | 공통 | 사용 가능한 가장 강한 것 | Windows: TPM → Software KSP, Linux: TPM2(빌드 시) → File |

AUTO 규칙:

- 기존 키는 **어느 저장소에 있든** 그대로 사용한다 (identity 가 저장소 사이를 옮겨 다니지 않음).
- 새 키는 생성을 지원하는 첫(가장 강한) 저장소에 만든다. `SG_NOT_SUPPORTED` 만 다음 저장소로 넘어가는 이유가 된다.
  TPM 저장소는 **확정적인** 답(TPM 2.0 없음, TBS 비활성, owner auth 설정, 곡선/알고리즘 미지원)에만
  `SG_NOT_SUPPORTED` 를 쓰고, 일시적 오류(서비스 시작 중, lockout, 전송 오류)는 `SG_KEYSTORE_ERROR` 로 보고한다.
  새 identity 가 일시적 장애 때문에 영구히 소프트웨어 저장소로 내려가지 않게 하기 위함이다. 결과는
  `SG_IdentityInfo.hardware_backed` 로 확인한다.
- **조회** 중 `SG_NOT_FOUND` 가 아닌 결과(`SG_NOT_SUPPORTED` 포함)는 그대로 반환한다.
- identity 마다 locator 파일 `<name>.sgref` (owner-only: `"SGRF" ‖ u16 version ‖ u8 store kind ‖ u8 0`)
  에 키를 만든 저장소를 기록한다. 위치: Linux 는 key 디렉터리, Windows 는 CNG 키처럼 사용자 단위이므로
  `key_store_path` 와 무관하게 `%LOCALAPPDATA%\SockGate\keys`. 기록 후에는 **그 저장소만** 조회한다:
  - 저장소를 쓸 수 없음 (TPM provider 를 열 수 없음, fTPM 비활성) → `SG_KEYSTORE_ERROR` (나중에 재시도)
  - 저장소는 동작하지만 키가 없음 (키 파일·CNG 키 삭제 등) → `SG_IDENTITY_LOST`
  - 저장소에 키는 있지만 쓸 수 없음 (예: TPM clear 뒤의 Linux TPM2 키 — blob 파일은 남는다) → 서명에서 `SG_KEYSTORE_ERROR`.
    TPM clear/reset 뒤 계속되면 `SG_IDENTITY_DELETE_FORCE` 로 지우고 다시 등록한다.
  - 어느 경우에도 **새 identity 를 만들지 않는다**. 다른 저장소의 장애는 기록된 identity 에 영향을 주지 않는다.
- locator 이전에 만든 키는 처음 조회될 때 기록된다.
- 초기화: `SG_Client_DeleteIdentity` 는 키와 locator 를 지운다. 기록된 저장소를 쓸 수 없으면 키가 남을 수
  있으므로 거부(`SG_KEYSTORE_ERROR`)하고, `SG_Client_DeleteIdentityEx(client, SG_IDENTITY_DELETE_FORCE)` 로만
  강제로 잊을 수 있다. 일반 삭제는 기록된 저장소만 건드리므로 다른 저장소의 장애가 삭제를 막지 않는다. 강제 삭제는
  실패하는 저장소를 건너뛰고 locator 를 항상 지운다. 새 identity 는 서버에 다시 등록/enroll 해야 한다.
- 강제 삭제 후 살아남은 키(예: 나중에 다시 보이는 TPM 키)는 새 identity 를 만들기 전에 다시 조회되면 기존
  identity 로 다시 채택된다. 확실히 버리려면 해당 저장소가 동작할 때 일반 삭제를 한다.
- AUTO 는 프로세스 메모리 저장소로 절대 떨어지지 않는다.

### 3.1 File key store 형식

```text
"<name>.sgkey":
u32 magic "SGKY" ‖ u16 version(1) ‖ u8 protection(1 = owner-only file, 2 = DPAPI user) ‖ u8 reserved(0)
‖ public key[65] ‖ u32 len ‖ 보호된 PKCS#8 (ECDSA P-256)
```

- protection 값은 해당 플랫폼 값과 같아야 한다 (다른 플랫폼 파일 거부).
- 로드 시 (1) OpenSSL 이 보고하는 공개키 = 저장된 공개키, (2) 고정 메시지를 서명해 저장된 공개키로 검증하는
  pairwise 검사를 한다. DPAPI 처럼 자체 무결성이 있는 보호가 없는 Linux 에서도 손상된 키가 **다른 키**로
  조용히 로드되지 않는다. private key 는 서명/조회 동안만 메모리에 있다.

Linux keyring 은 재부팅 시 소멸하므로 영속 저장소로 사용하지 않는다. File key store 는 로드한 private key 를
프로세스 메모리에 오래 두지 않도록, 가능하면 서명 시에만 로드 후 즉시 해제한다(선택적으로 kernel keyring 캐시 — 향후).

## 4. 서버 키

- TLS 인증서/키: `SG_ServerOptions.tls_cert_chain_file`, `tls_private_key_file` (또는 메모리 PEM).
- 인증서 교체: 클라이언트 pin 에 **현재 키 + 다음 키**의 SPKI 해시를 미리 배포 → 서버 인증서 교체 → 구 pin 제거.
  (`PinnedKey[0..7]`)
- 서버 proof key: 설정 시 AUTH_RESULT(OK) 에 서명 (REJECTED / RETRY_LATER / UNSUPPORTED_VERSION 과 REAUTH_RESULT 는 서명하지
  않는다). 클라이언트는 여러 개의 proof 공개키를 보유할 수 있다(교체 대비).

## 5. 세션 키

```text
생성: 인증 성공 직후 (7.1 유도식)
사용: 방향별 AES-256-GCM
교체: 재인증 성공 시 epoch+1
파기: 세션 종료, 재인증 후 이전 epoch 키, 객체 소멸 시 OPENSSL_cleanse
```

세션 키, TLS exporter 값, transcript 해시는 로그에 기록하지 않는다.

## 6. Challenge / nonce

- 32 bytes CSPRNG (OpenSSL `RAND_bytes`, OS CSPRNG 기반).
- challenge 는 발급 시각을 저장하고, 검증 시 `now - issued > ttl` 이면 거부.
- 검증 시도 시 **먼저 소비(consumed=true)** 하고 검증한다 → 동일 challenge 재시도 불가.
- 연결당 최초 인증은 1회만 허용.

## 7. Enrollment token

| 값 | 위치 | 비밀 여부 |
|---|---|---|
| `server_token_key` (32 bytes) | 서버 설정 또는 시작 시 생성 | 비밀 |
| `token_pub` (token_id + claims) | CLIENT_HELLO 로 전송 | 공개 |
| `K_tok = HMAC(server_token_key, …token_pub)` | token 문자열 안, 클라이언트 메모리 | 비밀, **전송 금지** |
| `enroll_mac = HMAC(K_tok, …TH1)` | CLIENT_PROOF | 채널 결속된 증명 |

- 사용된 `token_id` 는 만료 시각과 함께 registry 에 영구 기록된다 (만료 후에도 유지). (v1 미구현: 만료 후 정리 — 기록은
  삭제되지 않는다. 기록은 enrollment 로 등록된 installation 과 1:1 이고 installation 도 삭제되지 않으므로(폐기만)
  기록 수는 등록된 installation 수를 넘지 않는다.)
- token 문자열은 로그에 기록하지 않는다. 클라이언트는 enroll 후 token 문자열을 즉시 cleanse 한다.
