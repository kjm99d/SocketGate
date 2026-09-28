# SockGate_Client Threat Model

시스템 전체의 자산·공격자·STRIDE 분석은 [02-threat-model.md](../docs/design/02-threat-model.md),
신뢰 경계는 [03-trust-boundary.md](../docs/design/03-trust-boundary.md), 보장하지 않는 것은
[13-security-limitations.md](../docs/design/13-security-limitations.md) 에 있다. 이 문서는 **클라이언트 라이브러리가
막는 것과 막지 못하는 것**을 코드 기준으로 정리한다.

## 1. 목표와 비목표

**목표**: 네트워크 공격자, proxy, TLS 를 종단하는 중간자가 정상 인증 세션을 위조하거나 중계하지 못하게 하고,
설정이 올바르면 클라이언트가 가짜 서버에 속지 않게 하며, installation 키를 가능한 한 복제할 수 없는 곳에 두는 것.

**비목표**: 장악된 클라이언트 호스트(관리자/root 또는 같은 사용자 권한의 코드)로부터 클라이언트 로직, 평문,
키 **사용**을 보호하는 것. 이 경우는 서버 정책(폐기, 라이선스, 이상 탐지)으로 대응한다.

## 2. 클라이언트 측 자산

| 자산 | 위치 | 유출/변조 시 |
|---|---|---|
| Installation 개인키 | key store (TPM / CNG / FILE / MEMORY) | 그 installation 사칭 |
| Identity 기록 (locator `<name>.sgref`, key 파일) | 사용자 단위 key 디렉터리 | 조용한 identity 교체, 서비스 거부 |
| 세션 채널 키, TLS 트래픽 키, exporter 값 | 프로세스 메모리 | 그 세션의 위조/복호화 |
| Enrollment token 문자열 (`K_tok` 포함) | 애플리케이션 → `SG_Client_Enroll` | 공격자 키 등록 시도 (아래 5) |
| 서버 신뢰 설정 (CA, pin, proof key) | 애플리케이션 설정 | 가짜 서버 수용 |
| Proxy 자격 증명 | `SG_ProxyConfig` / 환경 | proxy 계정 도용 |
| 애플리케이션 payload | Send/Receive 버퍼 | 기밀성/무결성 |

## 3. 공격자

02 문서의 공격자 중 클라이언트와 관련된 것: A1 수동 관찰자, A2 능동 네트워크 공격자, A3 proxy 운영자,
A4 TLS MITM(사용자 설치 CA 포함), A7 클라이언트 호스트 관리자, A8 가짜 서버. 여기에 **같은 사용자 권한의 로컬
프로세스**(A7 의 약한 형태)를 따로 다룬다.

## 4. 위협과 대응

### 4.1 MITM / TLS 가로채기 (A2, A3, A4)

| 대응 | 코드 동작 |
|---|---|
| 체인 + hostname/IP + 유효기간 검증 | OpenSSL `SSL_VERIFY_PEER`, `SSL_set1_host`(부분 wildcard 금지), IP literal 은 iPAddress SAN. 실패 → `SG_CERTIFICATE_ERROR` |
| 신뢰 앵커 최소화 | 기본은 애플리케이션이 준 CA(`ca_file` / `ca_pem`)만 신뢰. OS store 는 `SG_TRUST_SYSTEM_STORE` 를 명시할 때만 |
| SPKI pinning | 체인 검증 **후** `SSL_get0_verified_chain` 의 인증서에만 비교(위조 leaf 뒤에 진짜 인증서를 덧붙이는 공격 차단). 불일치 → `SG_PINNING_ERROR` |
| 가로채기 신호 | pin 불일치 시 `SG_LOG_ERROR` 수준의 `event=possible_tls_interception host=...` 로그와, WARN 수준 `event=tls_failed ... detail="... (issuer: ...; possible TLS interception)"` 로그(예상 밖 체인의 발급자 포함) |
| pin 없는 OS store 금지 | `SG_TRUST_SYSTEM_STORE` 인데 pin 도 proof key 도 없으면 `SG_SERVER_FLAG_ALLOW_NO_PINNING` 없이는 `SG_Client_Connect` 가 `SG_INVALID_ARGUMENT` |
| 채널 바인딩 | 클라이언트 서명은 자기 TLS 연결의 RFC 9266 tls-exporter 값(`EXPORTER-Channel-Binding`, 길이 0 context, 32 bytes; TLS 1.3/1.2 모두 표준 값, b95a843)을 포함한 transcript 에 대한 것이다. TLS 를 두 번 종단하는 중계자는 서버 쪽 값과 달라 **인증 세션을 만들 수 없다** |
| 다운그레이드 방지 | TLS 1.3 만 허용(TLS 1.2 는 명시적 플래그 + EMS 필수), 압축·재협상·세션 재개 없음 |
| 설정 다운그레이드 방지 | `SG_ServerConfig.flags` 나 `SG_ClientConfig.flags` 의 모르는 비트, 입력 구조체의 모르는 0 이 아닌 필드는 `SG_NOT_SUPPORTED` — 새 헤더의 신뢰 옵션이 옛 라이브러리에서 조용히 사라지지 않는다 |
| 취약한 OpenSSL | configure 시 3.0.7 미만이면 CMake 경고. OpenSSL 을 함께 배포하는 빌드(Windows, 정적 링크)는 실행 시에도 프로세스당 한 번 `event=config_warning` |

잔여 위험: pin 도 proof key 도 없이 OS store 를 신뢰하면(명시적 opt-out), 사용자 설치 CA 를 가진 공격자는
클라이언트에게 **가짜 서버로 보일 수 있다**(가짜 AUTH_RESULT, 가짜 데이터). 서버 쪽 인증 세션은 여전히 만들 수 없다.

### 4.2 악의적인 서버 / 가짜 서버 (A8)

- **Server proof key**: `SG_ServerConfig.proof_keys` 가 있으면 서버는 AUTH_RESULT 에 TLS PKI 와 독립된 ECDSA 서명을
  **반드시** 붙여야 한다. SERVER_HELLO 가 proof 알고리즘을 광고하지 않거나, 서명이 없거나, 어느 키로도 검증되지 않으면
  `SG_INVALID_SIGNATURE`. 알고리즘 필드를 바꿔 요구를 피할 수 없다(설정이 요구를 결정). 서명은 TH1, CLIENT_PROOF 프레임,
  AUTH_RESULT 헤더와 결과 필드를 덮으므로 다른 세션의 서명을 재사용할 수 없다.
- **proof key 의 한계**: 서명되는 것은 `AUTH_RESULT(OK)` 뿐이다. REJECTED / RETRY_LATER / UNSUPPORTED_VERSION 은 서명이
  없으므로(거부 결과는 부가 필드가 모두 0 이어야 함), pin 없이 연결된 가짜 서버(예: 사용자 설치 CA)는 클라이언트에
  `SG_SERVER_REJECTED` / `SG_VERSION_MISMATCH` 를 일으킬 수 있다(서비스 거부, 잘못된 재등록·업그레이드 유도). 또 서명 검사
  전에 CLIENT_HELLO 가 먼저 가므로 그 서버는 제품·라이선스 ID 주장과 integrity 보고를 이미 받는다. 주장을 가짜 서버에게서
  지키는 것은 TLS 단계의 서버 인증(사설 CA + pinning)이다.
- 인증된 서버도 비신뢰 입력을 보낸다고 가정한다: 모든 프레임은 FrameDecoder(헤더 단계 상태 검증, 인증 전 4 KiB 상한,
  DATA 는 `max_payload_size` 상한), 엄격한 메시지 디코더(예약 값, trailing data 금지, 거부 결과에 부가 정보 금지)를
  통과해야 하고, 위반은 연결 종료다. 수신 큐는 64 MiB 로 제한된다(`SG_LIMIT_EXCEEDED`).
- 서버가 요청하지 않은 재인증 메시지, 클라이언트가 할당한 최대 요청 ID 보다 큰 ID 에 대한 응답은 `SG_PROTOCOL_ERROR`.
  같은 요청에 대한 중복 응답은 거부되지 않으므로 요청-응답 짝 맞추기는 애플리케이션이 한다.
- `granted_features`, `policy`, `license_expires_at_ms` 는 서버가 한 말이다. 그 값의 신뢰도는 서버 인증(4.1, 4.2)의
  강도와 같다.

### 4.3 Proxy 악용 (A3)

| 위협 | 대응 |
|---|---|
| 의도하지 않은 proxy 경유 (환경 변수, 시스템 설정 주입) | 기본 `SG_PROXY_MODE_DIRECT` 는 `http_proxy`/`https_proxy`/`ALL_PROXY` 와 WinHTTP/IE 설정을 **읽지 않는다**. SYSTEM 모드는 명시적 선택 |
| proxy 의 트래픽 열람/변조 | proxy 는 TLS 암호문만 본다. 서버 신원은 종단간 TLS 검증/pinning/proof 로, 클라이언트 인증은 종단간 채널 바인딩으로 확정 |
| 악의적 proxy 응답 (거대/형식 오류/무응답) | HTTP 응답 헤더 8 KiB 상한, 1 바이트씩 읽어 터널 바이트 비소비, 2xx 만 성공, SOCKS 응답 버전/상태/방법 정확 일치, TCP·proxy 협상·TLS 핸드셰이크가 하나의 `connect_timeout_ms` 예산을 공유(느린 proxy 뒤에 멈춘 서버도 예산을 늘리지 못함). 실패 → `SG_PROXY_ERROR` / `SG_TIMEOUT` |
| 요청 구문 주입 | 대상 호스트는 영숫자와 `. - : _` 만 허용, 사용자 이름에 제어 문자 금지 |
| 자격 증명 노출 | 로그에 남기지 않고 사용 후 지운다. **단, proxy 까지의 구간은 평문 TCP 이므로** HTTP Basic / SOCKS5 비밀번호는 그 구간의 관찰자에게 보인다. `https://` proxy(TLS to proxy)는 지원하지 않는다 |
| DNS | SOCKS4a/SOCKS5 는 호스트 이름을 proxy 에 넘겨 proxy 가 해석한다. 해석 결과를 신뢰하지 않는다 — 신원은 인증서 검증으로만 확정 |

proxy 탐지·차단은 보안 목표가 아니다. proxy 사용 자체는 인증 실패 사유가 아니다.

### 4.4 키 탈취

| 저장소 | 개인키 추출 | 같은 사용자 권한 코드 | 관리자/root | 비고 |
|---|---|---|---|---|
| `SG_KEYSTORE_CNG_TPM` | 불가 (TPM 밖으로 안 나옴) | 서명 요청 가능(서명 오라클) | 서명 요청 가능 | `hardware_backed = 1` |
| `SG_KEYSTORE_TPM2` | 불가 (blob 은 이 TPM 으로만 사용) | blob 파일은 owner-only, TPM 사용 가능하면 서명 가능 | 서명 가능 | owner hierarchy auth 가 비어 있다고 가정. TPM 명령은 salted 세션 없이 전송 |
| `SG_KEYSTORE_CNG_SOFTWARE` | non-exportable 정책 | 서명 요청 가능 | 키 추출 도구로 추출 가능 | DPAPI 로 보호되는 사용자 프로필 |
| `SG_KEYSTORE_FILE` (Windows) | DPAPI(사용자 범위) 복호화 필요 | **복호화 가능** | 가능 | entropy 가 identity 이름에 결속 |
| `SG_KEYSTORE_FILE` (Linux) | 파일 권한(0600)만 | **읽기 가능** | 가능 | TPM 과 동등하지 않음 |
| `SG_KEYSTORE_MEMORY` | 프로세스 메모리 | 디버깅 권한 있으면 가능 | 가능 | 영속성 없음, 테스트용 |

TPM 이라도 **키 복제는 막지만 사용은 막지 못한다**. `hardware_backed` 는 클라이언트가 스스로 보고하는 값이며 원격
증명(attestation)이 아니다. 키가 유출되면 서버에서 installation 을 폐기하고 새 키로 다시 등록한다.

### 4.5 Replay

| 공격 | 대응 | 결과 |
|---|---|---|
| 이전 인증 메시지 재전송 | 새 연결마다 새 challenge, 새 서버 nonce, 새 TLS exporter → 이전 서명은 무효 | 서버: REJECTED → 클라이언트 `SG_SERVER_REJECTED` |
| 세션 프레임 재전송/중복 | 방향별 sequence 가 정확히 이전 + 1 | 이하: `SG_REPLAY_DETECTED`, 건너뜀: `SG_PROTOCOL_ERROR` |
| 중복 요청 (같은 request_id) | 요청 ID 방향별 단조 증가 | `SG_REPLAY_DETECTED` |
| 다른 세션/방향의 프레임 주입, 반사 | AEAD 키가 세션·방향·epoch 별, session_id 가 AAD 에 포함 | `SG_PROTOCOL_ERROR` |
| 재인증 메시지 재사용 | 재인증 transcript 가 session_id, epoch, 채널 바인딩, 직전 transcript 를 포함 | 서버 거부 |

모든 경우 첫 위반에서 채널이 "poison" 되고(수신 키 폐기) 연결이 끊긴다. 오류 후 계속 진행하지 않는다.

### 4.6 로컬 공격자

| 공격자 | 할 수 있는 것 | SockGate 의 대응 / 한계 |
|---|---|---|
| 다른 사용자 (비관리자) | key 디렉터리 조작 시도, 파일 심기 | 디렉터리 소유자·권한(DACL) 검사, 링크/reparse point/링크 수 ≠ 1 거부, 다른 소유자의 파일 거부, Windows 는 DPAPI(다른 사용자는 복호화 불가). 위반은 `SG_KEYSTORE_ERROR` (fail closed) |
| 같은 사용자 권한의 프로세스 | FILE 키 읽기/복호화, CNG/TPM 키로 서명 요청, locator 삭제, 메모리 읽기, API hooking | 막지 못한다. TPM 은 키 **복제**만 막는다. 서버 측 폐기·정책으로 대응 |
| 관리자 / root | 위 전부 + 디버거, DLL injection, `LD_PRELOAD`, 바이너리 패치, pin 설정 변경 | 막지 못한다(13 §1). integrity 보고는 비용을 높이는 신호일 뿐 우회 가능 |

Linux 에서 key 디렉터리 환경 변수(`XDG_DATA_HOME`, `HOME`)와 `SOCKGATE_TPM2_TCTI` 는 `secure_getenv` 로 읽으므로
setuid/setgid 프로세스에서는 무시된다.

### 4.7 Identity 교체 (AUTO locator)

위협: TPM 이 일시적으로 보이지 않을 때(서비스 시작 중, fTPM 비활성, 드라이버 미로딩) 라이브러리가 "키 없음"으로
판단해 더 약한 저장소에 **새 identity 를 조용히 만들면**, 등록된 TPM identity 가 파일 키로 바뀌어 버린다.

대응:

- key store 는 "없음"(`SG_NOT_FOUND`)과 "지금 알 수 없음"(`SG_KEYSTORE_ERROR`)을 구분한다. CNG 는
  `NTE_BAD_KEYSET`/`NTE_NO_KEY` 만 "없음"으로 본다.
- 생성은 확정적인 `SG_NOT_SUPPORTED` 일 때만 다음 저장소로 넘어간다. 일시적 오류는 오류로 보고된다.
- 만든 저장소를 locator 에 기록하고 이후 그 저장소만 조회한다. 저장소 불가 → `SG_KEYSTORE_ERROR`, 키 소실 →
  `SG_IDENTITY_LOST`. **새 identity 를 만들지 않는다.** 다른 저장소의 장애는 기록된 identity 에 영향이 없다.
  (Linux TPM2 는 TPM 이 clear 되어도 blob 파일이 남아 조회는 성공하고, 서명이 `SG_KEYSTORE_ERROR` 로 실패한다.)
- TPM 에 닿을 수 있는지는 `SG_Client_Create` 때 정해진다(Linux TCTI 선택, Windows 는 열 수 없는 TPM provider 를 어떤
  이유로든 목록에서 제외). 그 핸들에서 기록된 TPM identity 는 `SG_KEYSTORE_ERROR` 로 남고 교체되지 않으며, 회복하려면
  Destroy + Create 한다.
- 동시 생성은 배타적 생성(`SG_ALREADY_EXISTS` → 승자의 키를 다시 읽음)과 locator 의 일치 검사로 하나로 수렴한다.
- 초기화는 명시적이어야 한다: `SG_Client_DeleteIdentity` 는 기록된 저장소를 쓸 수 없으면 거부하고,
  `SG_Client_DeleteIdentityEx(..., SG_IDENTITY_DELETE_FORCE)` 만 locator 를 강제로 지운다.

잔여 위험: 같은 사용자 권한의 공격자는 locator 와 키 파일을 지울 수 있다. 그 뒤 새로 만든 identity 는 서버에
등록되어 있지 않으므로 인증되지 않는다(서비스 거부이지 사칭은 아니다). `SG_Client_Create` 시점에 TPM 에 닿을 수
없었던 핸들로 **처음** 만든 identity 는 소프트웨어 저장소에 만들어진다: Linux 는 TPM 드라이버 로드 전(부팅 초기) 등
`/dev/tpmrm0` 에 접근할 수 없을 때 FILE, Windows 는 Platform Crypto Provider 를 (일시적인 이유로라도) 열 수 없었을 때
Software KSP. 이후에는 locator 가 그 저장소에 고정한다.

### 4.8 변조된 key 파일

| 파일 | 검사 | 실패 |
|---|---|---|
| `<name>.sgkey` | magic `SGKY`, version 1, 이 플랫폼의 protection 값(다른 플랫폼 파일 거부), reserved 0, 길이 정확히 일치, DPAPI 복호화(Windows, entropy = `"SockGate/v1/file-key/" ‖ name` → 다른 이름의 파일로 바꿔치기 불가), OpenSSL 이 보고하는 공개키 = 저장된 공개키, 고정 메시지 서명의 pairwise 검증 | `SG_KEYSTORE_ERROR` |
| `<name>.tpm2key` | magic `SGT2`, version 1, `Tss2_MU` unmarshal 이 길이를 정확히 소비, 공개 영역이 ECC P-256/ECDSA/sign/fixedTPM, 서명 결과를 공개키로 재검증 | `SG_KEYSTORE_ERROR` |
| `<name>.sgref` | magic `SGRF`, version 1, 알려진 store kind, reserved 0, 정확한 길이 | `SG_KEYSTORE_ERROR` |
| 공통 | 일반 파일, 링크 수 1, 64 KiB 이하, 소유자(Linux: euid, 모드 `& 077 == 0`; Windows: 사용자/SYSTEM/Administrators) | `SG_KEYSTORE_ERROR` |

손상된 키가 **다른 키로 조용히 로드되는 일은 없다**. 공개키 파생 installation_id 는 서버 등록과 비교되므로 교체된
키는 인증되지 않는다. DPAPI envelope 의 일부 헤더 바이트는 MAC 범위 밖이지만 키 자체는 바뀌지 않는다(13 §4).

### 4.9 Enrollment token

- token 의 비밀 부분 `K_tok` 은 전송하지 않는다. CLIENT_HELLO 에는 공개 부분만, CLIENT_PROOF 에는 채널 바인딩이
  포함된 TH1 에 대한 HMAC 만 보낸다. TLS 를 종단한 MITM 은 token 을 훔쳐 자기 키로 등록할 수 없다.
- 라이브러리는 token 복사본과 `K_tok` 을 사용 직후 지운다. **애플리케이션이 가진 token 문자열은 애플리케이션 책임이다.**
  클라이언트 호스트에서 token 문자열이 유출되면(로그, 명령줄 인자, 파일) 그 token 으로 다른 키를 등록할 수 있다.
- token 은 1회용이고 만료가 있다. 서버는 발급할 때와 사용할 때 모두 수명을 최대 30 일로 제한한다
  (서버 키로 다른 곳에서 만든 token 도 그보다 오래 유효할 수 없다).
- 예제 `sg_echo_client` 는 token 을 명령줄 인자가 아니라 파일(`--enroll-file`)에서 읽어, 프로세스 목록과 셸 기록에
  남지 않게 하고 사용 직후 버퍼를 volatile 저장으로 지운다(`memset` 은 컴파일러가 없앨 수 있다). 임베딩 애플리케이션도
  같은 방식(`SecureZeroMemory`, `explicit_bzero`, volatile 루프)을 권장한다.

## 5. 잔여 위험 요약

설계 문서 [02](../docs/design/02-threat-model.md) §3, [13](../docs/design/13-security-limitations.md) 에서 클라이언트에 해당하는 것.

1. 장악된 클라이언트 호스트: 메모리 조작, hooking, 디버거, 바이너리 패치, 평문 가로채기, 서명 오라클, pin 설정 변경.
2. pin/proof key 없이 OS store 를 신뢰하면(명시적 opt-out) 사용자 설치 CA 로 가짜 서버가 가능하다.
3. 프레임 GCM tag 와 재인증 rekey 는 TLS 를 종단한 MITM 에 대한 추가 방어가 아니다(같은 TLS 세션에서 유도).
   post-compromise security 를 주장하지 않는다.
4. integrity 관측은 모두 우회 가능하다. `platform` 값 자체도 주장이다.
5. FILE / Software KSP 키는 같은 사용자(또는 관리자)가 사용·추출할 수 있다. 파일 기반 키의 완전 삭제는 보장되지 않는다.
6. `hardware_backed` 는 attestation 이 아니다. Linux TPM2 는 빈 owner auth 와 버스 무결성을 가정한다.
7. 한 번의 DNS resolver 호출(`getaddrinfo`)은 중단할 수 없다(걸린 시간은 `connect_timeout_ms` 예산에서 빠지고 그 뒤
   예산이 없으면 TCP 연결을 시작하지 않지만, 호출이 끝날 때까지 Connect 는 반환하지 않는다). PAC/WPAD 는 지원하지 않는다.
8. server proof key 는 `AUTH_RESULT(OK)` 만 인증한다. pin 없는 구성에서는 가짜 서버가 거부/버전 불일치를 꾸며 내고
   CLIENT_HELLO 의 주장을 볼 수 있다(4.2).
9. 로컬 오류 코드와 로그는 구체적이다. 로그를 볼 수 있는 공격자는 실패 원인을 알 수 있다(네트워크로는 일반화된
   결과만 오간다).
10. 부채널 방어는 OpenSSL 수준에 의존한다. SockGate 자체 비교(pin 등)는 상수 시간이다.
