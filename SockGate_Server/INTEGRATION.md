# Integrating SockGate_Server

서버 애플리케이션에 SockGate_Server 를 임베딩하는 단계별 안내이다. API 원칙은
[09-public-c-api.md](../docs/design/09-public-c-api.md) 를, 내부 동작은 [ARCHITECTURE.md](ARCHITECTURE.md) 를 참고한다.
모든 내용은 `sockgate/server.h` 와 `src/core/server_api.cpp` 의 실제 동작 기준이다.

## 1. 준비

```c
#include <sockgate/server.h>   /* types.h, error.h, export.h, version.h 를 포함 */
```

- CMake: `find_package(SockGate 0.1 REQUIRED)` 후 `target_link_libraries(app PRIVATE SockGate::Server)` ([BUILD.md](BUILD.md) §8).
- 정적 라이브러리를 CMake 밖에서 링크하면 `SOCKGATE_SERVER_STATIC` 을 정의한다.
- 실행 시 `SG_Server_GetApiVersion() == SOCKGATE_API_VERSION` 인지 확인하면 헤더와 라이브러리의 ABI 불일치를 잡을 수 있다.
- 콜백은 `SG_CALL` 호출 규약으로 선언한다 (Windows `__cdecl`).

전체 흐름:

```text
SG_ServerOptions_Init → 필드 설정 → SG_Server_Create
  → (선택) SG_Server_AddLicense / SG_Server_RegisterClient / SG_Server_IssueEnrollmentToken
  → SG_Server_Start → … 콜백으로 세션 처리 … → SG_Server_Stop → SG_Server_Destroy
```

registry·license·token 관리 API 는 `SG_Server_Create` 직후부터(`Start` 전에도) 쓸 수 있다.

## 2. `SG_ServerOptions`

반드시 `SG_ServerOptions_Init()` 으로 초기화한 뒤 필요한 필드만 바꾼다. `Init` 은 구조체 전체를 0 으로 채우고 아래 기본값을 넣는다.
숫자 필드에서 0 은 대부분 "기본값 사용"이다 (예외: `idle_timeout_ms`).

| 필드 | `Init` 값 | 0 / NULL 의 의미 | 제약 |
|---|---|---|---|
| `size`, `version` | `sizeof`, `SG_SERVER_OPTIONS_VERSION` (1) | | §13 |
| `bind_address` | NULL | `"0.0.0.0"` | ≤ 253 bytes. 해석된 **첫 주소**에만 bind |
| `port` | 0 | 임시 포트 (`SG_Server_GetPort` 로 확인) | |
| `tls_cert_chain_file` | NULL | PEM 메모리 값 사용 | ≤ 4096 bytes. leaf 먼저, 그 뒤 중간 인증서 |
| `tls_private_key_file` | NULL | PEM 메모리 값 사용 | ≤ 4096 bytes. 암호화되지 않은 PEM |
| `tls_cert_chain_pem`, `_size` | NULL, 0 | `_size` 0 = NUL 종료 문자열 | ≤ 16 MiB. 파일 경로가 있으면 무시 |
| `tls_private_key_pem`, `_size` | NULL, 0 | 위와 같음 | 위와 같음. 체인과 키는 필수 (없으면 `SG_INVALID_ARGUMENT`) |
| `proof_key_file` / `proof_key_pem`, `_size` | NULL | 서버 proof 서명 없음 | ECDSA P-256 PEM. 파일이 우선 |
| `token_key`, `token_key_size` | NULL, 0 | `SG_Server_Create` 마다 무작위 32 bytes — 한 서버 객체가 발급한 token 은 다른 서버 객체(재시작 포함)에서 무효 | 32–1024 bytes (벗어나면 `SG_INVALID_ARGUMENT`). 라이브러리가 복사 |
| `registry_path` | NULL | 메모리 registry | ≤ 4096 bytes |
| `worker_threads` | 0 | 하드웨어 스레드 수 | 최대 64 로 제한 |
| `max_connections` | 10000 | 10000 | 핸드셰이크 중 + 세션 + graceful-close 중인 소켓 합계 |
| `max_unauthenticated` | 0 | `max_connections / 2` (최소 1) | TLS·인증 단계에 있는 연결 수 상한. 초과 연결은 수락 직후 닫힘 (`event=connection_refused reason=max_unauthenticated`). 열린 세션은 세지 않음. 인증 전에 실패한 연결은 소켓이 완전히 닫힐 때까지 (graceful close, 최대 5 s) 자리를 유지하므로 크기를 정할 때 포함한다. `max_connections` 보다 크면 `SG_INVALID_ARGUMENT` |
| `handshake_timeout_ms` | 15000 | 15000 | 수락부터 AUTH_RESULT 까지 (TLS, 콜백 시간 포함) |
| `challenge_ttl_ms` | 30000 | 30000 | 최초 인증과 재인증 challenge 모두 |
| `session_lifetime_ms` | 3600000 | 3600000 | 7일 초과는 `SG_INVALID_ARGUMENT`. `on_authorize` 가 수명을 정하지 않을 때의 값 |
| `idle_timeout_ms` | 300000 | **idle 타임아웃 없음** | 검증된 수신 프레임(PING 포함) 기준 |
| `max_payload_size` | 1048576 | 1 MiB | ≤ 16 MiB. DATA 송수신 모두에 적용 |
| `min_reauth_interval_ms` | 10000 | 10000 (끌 수 없음) | 세션 시작 또는 마지막으로 받아들인 REAUTH_REQUEST (challenge 발급) 이후 이 시간 안의 REAUTH_REQUEST 는 연결 종료 |
| `flags` | 0 | | `SG_SERVER_OPT_*` 조합. 알 수 없는 비트는 `SG_NOT_SUPPORTED` |
| `callbacks` | NULL | 콜백 없음 | `SG_Server_Create` 에서 복사 (§3) |
| `log_callback`, `log_user` | NULL | 로그 없음 | |
| `log_level` | `SG_LOG_WARN` | `SG_LOG_NONE` 과 같음 | `SG_LOG_*` |
| `license_path` | NULL | 메모리 license store | ≤ 4096 bytes. `registry_path` 와 같은 파일이면 `SG_INVALID_ARGUMENT` |
| `integrity_restrict_mask` | 0 | 제한 없음 | `SG_INTEGRITY_KNOWN_FLAGS \| SG_INTEGRITY_REPORT_MISSING \| SG_INTEGRITY_UNKNOWN_EXECUTABLE` 밖의 비트는 `SG_NOT_SUPPORTED` |
| `integrity_reject_mask` | 0 | 거부 없음 | 위와 같음 |
| `allowed_executables`, `allowed_executable_count` | NULL, 0 | allowlist 없음 | 최대 4096, count > 0 이면 NULL 불가, 0 으로만 된 항목 불가 |
| `reserved0`, `reserved2` | 0 | | 0 으로 둔다 |

`max_unauthenticated` 는 예전 `reserved1` 자리이며 구조체 배치는 같다. 0 으로 둔(= `Init` 을 쓴) 기존 코드는 기본값을 얻는다.

`flags`:

| flag | 의미 |
|---|---|
| `SG_SERVER_OPT_ALLOW_TLS12` | TLS 1.2 허용 (EMS 필수) |
| `SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION` | 애플리케이션 계층 AEAD 가 없는 DATA 를 프로토콜 오류로 처리, 서버 DATA 도 항상 암호화 |
| `SG_SERVER_OPT_ALLOW_ENROLLMENT` | ENROLL 핸드셰이크 허용 (없으면 enrollment 는 모두 REJECTED) |
| `SG_SERVER_OPT_REQUIRE_LICENSE` | store 에서 검증된 라이선스가 없는 세션 거부 |
| `SG_SERVER_OPT_LICENSE_ACTIVATION` | 바인딩 없는 installation 이 라이선스 ID 주장으로 활성화 가능 (ID 가 bearer secret 이 됨) |

라이브러리는 `session_lifetime_ms` ≤ 7일, `max_payload_size` ≤ 16 MiB 외의 범위를 강제하지 않는다. 설계 문서
[05 §4](../docs/design/05-handshake-sequence.md) 의 권장 범위(핸드셰이크 1–120 s, challenge TTL 1–300 s, 세션 1 min–7 d, idle 0–1 d)
안에서 설정한다.

`SG_Server_Create` 가 끝나면 옵션 구조체와 그것이 가리키는 문자열·버퍼는 해제해도 된다 (모두 복사됨). 메모리로 넘긴 개인키 PEM 과
token key 는 애플리케이션 쪽 사본을 지운다. 이후 읽지 않는 버퍼의 `memset` 은 컴파일러가 없앨 수 있으므로 `SecureZeroMemory`,
`explicit_bzero` 또는 volatile store 루프를 쓴다 (`examples/echo_server.c` 의 `wipe()`).

## 3. 콜백과 스레딩

```c
SG_ServerCallbacks callbacks;
SG_ServerCallbacks_Init(&callbacks);
callbacks.user              = app;             /* 모든 콜백의 첫 인자 */
callbacks.on_authorize      = on_authorize;    /* 선택 */
callbacks.on_enroll         = NULL;            /* NULL = 내장 enrollment token */
callbacks.on_session_opened = on_opened;
callbacks.on_message        = on_message;
callbacks.on_session_closed = on_closed;
options.callbacks = &callbacks;                /* Create 에서 필드 단위로 복사 */
```

스레딩 계약 (`server.h`):

- 콜백은 SockGate 내부 lock 을 잡지 않은 상태로 호출된다. 예외는 `SG_Server_Stop` / `SG_Server_Destroy` 가 전달하는 콜백으로,
  이들은 서버의 lifecycle lock 아래에서 실행된다 (그 세션의 이벤트를 이미 다른 스레드가 전달 중이면 그 스레드가 lock 없이 전달한다). 보통 I/O 워커 스레드이지만, 세션을 닫은 API 를 호출한 스레드
  (`SG_Server_CloseSession`, `SG_Server_RevokeClient`, `SG_Server_RevokeLicense`, `SG_Server_ReleaseLicenseSeat`, `SG_Server_Stop`,
  실패한 `SG_Server_Send`)와 내부 타이머 스레드(만료, idle)에서도 호출된다.
- 한 세션의 콜백은 직렬화되고 순서가 보장된다 (`on_session_opened` → `on_message`… → `on_session_closed`). 다른 세션의 콜백은 동시에 실행될 수 있다.
- **예외**: 재인증(클라이언트의 `SG_Client_Refresh`)의 `on_authorize` 는 이 순서 밖에서 I/O 스레드가 직접 호출하므로, 같은 세션의
  `on_message` 나 `on_session_closed` (`CloseSession`, 폐기, Stop, challenge 만료가 전달)와 **겹칠 수 있다**. `on_authorize` 가 쓰는
  세션별 데이터는 동기화하고, `on_session_closed` 가 반환했더라도 실행 중인 `on_authorize` 가 끝날 때까지 해제하지 않는다.
- `SG_Server_Start`, `SG_Server_Stop`, `SG_Server_Destroy` 를 제외한 모든 API 를, 처리 중인 세션에 대해서도 콜백에서 호출할 수 있다.
  콜백에서 이 셋을 부르면 `SG_INVALID_STATE` 이다.
- 느린 `on_message` 는 그 세션의 읽기를 멈추게 한다 (backpressure). 미전달 데이터가 8 MiB 를 넘으면 읽기를 멈추고, 64 MiB 를 넘으면 연결을 닫는다.
- 콜백에 전달된 포인터(`request`, `info`, `data`)는 호출 동안만 유효하다. 콜백에서 C++ 예외를 던지지 않는다 (라이브러리가 삼킨다).

| 콜백 | 호출 시점 | 비고 |
|---|---|---|
| `on_authorize(user, request, decision)` | 내장 인가가 **허용**한 뒤, 세션이 열리기 전 (최초 인증과 재인증) | §6.3 |
| `on_enroll(user, request, token_key_out)` | ENROLL 핸드셰이크에서 `K_tok` 가 필요할 때 | §5.3 |
| `on_session_opened(user, info)` | AUTH_RESULT(OK) 를 보낸 뒤 | `info` 는 `SG_ServerSessionInfo` |
| `on_message(user, session, data, size, info)` | 검증된 DATA 수신 | `size` 는 0 일 수 있고 `max_payload_size` 이하. `info->request_id`, `info->flags` |
| `on_session_closed(user, session, reason)` | 열린 세션이 닫힐 때 **정확히 1회** | reason 은 [ARCHITECTURE.md](ARCHITECTURE.md) §4.5. 이후 핸들은 무효 |

인증 전에 끝난 연결(거부, 타임아웃, 프로토콜 오류)에는 어떤 세션 콜백도 호출되지 않는다.
최초 인증에서 `on_authorize` / `on_enroll` 에 쓴 시간은 `handshake_timeout_ms` 에 포함되며, 초과하면 연결이 닫히고 결과는 버려진다.
재인증의 `on_authorize` 시간은 재인증 challenge TTL (`challenge_ttl_ms`)에 포함된다.

로그 콜백 `log_callback(user, level, message)` 는 예외이다 (`server.h`): 어느 스레드에서나, 내부 lock 을 잡은 상태에서도 동기 호출되므로
메시지를 기록만 하고 어떤 SockGate 함수도 호출하지 않는다. 메시지는 `ts=<Unix ms> event=… key=value …` 형식이다.

## 4. 시작

```c
SG_Server* server = NULL;
SG_Status st = SG_Server_Create(&options, &server);
if (st == SG_OK) st = SG_Server_Start(server);
uint16_t port = 0;
if (st == SG_OK) SG_Server_GetPort(server, &port);   /* port = 0 으로 설정했을 때 */
```

- `SG_Server_Create` 는 TLS 인증서·키를 로드하고, 파일 저장소를 열어(lock 획득) 검증하고, token key 를 준비한다. 네트워크는 아직 열지 않는다.
- `SG_Server_Start` 는 워커 스레드, listen 소켓, sweeper 를 시작한다. 이미 실행 중이거나 콜백 안에서 호출하면 `SG_INVALID_STATE`.
  `Stop` 후 다시 `Start` 할 수 있다. 자체 OpenSSL 을 배포하는 빌드(Windows, 정적 링크)에서 OpenSSL 이 3.0.7 보다 오래되면
  시작 시 `event=config_warning` (WARN) 을 로그로 남긴다.
- `SG_Server_GetPort` 는 한 번도 시작하지 않았으면 `SG_INVALID_STATE` 이다.

## 5. 클라이언트 등록

세 가지 방법이 있다. 어느 경우든 installation ID 는 공개키에서 유도되며(`SHA-256("SockGate/v1/iid" ‖ key)[0..16)`), 폐기된 ID 는 다시 등록할 수 없다.

### 5.1 공개키 직접 등록

클라이언트가 `SG_Client_EnsureIdentity` / `SG_Client_GetIdentity` 로 얻은 `SG_IdentityInfo.public_key` (65 bytes SEC1 `0x04‖X‖Y`)를
안전한 경로로 받아 등록한다.

```c
SG_ClientRecord record;
SG_ClientRecord_Init(&record);
memcpy(record.public_key.bytes, public_key, SG_PUBLIC_KEY_SIZE);
record.product_id = "example-product";   /* 선택: 제품 바인딩 (≤ 64 bytes) */
record.license_id = "LIC-...";           /* 선택: 라이선스 바인딩 (≤ 128 bytes) */
st = SG_Server_RegisterClient(server, &record);
```

- 공개키는 P-256 곡선 위의 점이어야 한다 (`SG_INVALID_ARGUMENT`). 이미 있는 ID(활성·폐기 무관)는 `SG_ALREADY_EXISTS`.
- 라이선스 바인딩이 있으면 store 가 아는 라이선스는 활성(`SG_INVALID_STATE`)·같은 제품(`SG_INVALID_ARGUMENT`)이어야 하고,
  `SG_SERVER_OPT_REQUIRE_LICENSE` 면 store 에 있어야 한다 (`SG_NOT_FOUND`).
- 라이선스를 바인딩할 때는 `product_id` 도 함께 지정한다. 제품 바인딩이 없으면 인가 시 클라이언트가 주장한 제품으로 라이선스 제품을 비교하므로,
  제품을 주장하지 않는 클라이언트는 "license is for another product" 로 거부된다.
- 저장 실패 시 등록은 취소되고 `SG_STORAGE_ERROR`.

### 5.2 내장 enrollment token

1. `SG_SERVER_OPT_ALLOW_ENROLLMENT` 를 켜고, 재시작 후에도 token 이 유효해야 하면 `token_key` 를 설정한다 (`sg_admin token-key`).
2. token 을 발급한다.

```c
SG_EnrollmentTokenRequest request;
char token[1024];
size_t written = 0;
SG_EnrollmentTokenRequest_Init(&request);
request.product_id = "example-product";  /* 필수, 1..64 bytes */
request.license_id = "LIC-...";          /* 선택, ≤ 128 bytes */
request.ttl_ms     = 0;                  /* 0 = 24 h, 최대 30 일 */
st = SG_Server_IssueEnrollmentToken(server, &request, token, sizeof(token), &written);
/* 전달 후 token 버퍼를 지운다 */
```

   - `*written` 은 NUL 을 포함한 길이이다. 버퍼가 작거나 `token == NULL` 이면 `SG_BUFFER_TOO_SMALL` 과 필요한 크기를 돌려준다.
     이때 만들어진 token 은 버려지며, 다시 호출하면 새 token 이 발급된다.
   - 라이선스 바인딩 검사는 §5.1 과 같다. TTL 이 30 일을 넘으면 `SG_INVALID_ARGUMENT`.
3. token 문자열(base64url)을 안전한 경로로 클라이언트에 전달하고, 클라이언트는 `SG_Client_Enroll(client, token)` 을 호출한다.
4. 서버는 채널 결속 MAC, 만료, `issued_at` (5 min 이상 미래 거부), 유효 기간 ≤ 30 일, 제품·라이선스 주장 일치, 공개키와 ID 의 관계,
   소유 증명 서명을 확인한 뒤 **token 소비와 installation 등록을 원자적으로** 수행한다. claims 의 product/license 가 registry 바인딩이 된다.
5. 이어서 일반 인가(§6)가 진행되고, 성공하면 그 연결이 바로 세션이 된다. token 소비는 `on_authorize` **전**이므로 인가가 거부되어도
   등록과 token 소비는 유지된다.

token 은 1회용이며 그 보장은 **registry 단위**이다. 사용된 token ID 는 registry 에 영구 기록되므로 메모리 registry 는 재시작 후 재사용을
막지 못하고 (token 만료로만 제한), registry 가 다른 서버 노드끼리는 기록을 공유하지 않는다 (§5.3).
`on_enroll` 을 설정하면 내장 token 은 거부된다 (§5.3).

### 5.3 외부 token: `on_enroll`

다른 시스템이 발급한 token 을 검증할 때 쓴다. 콜백은 token 의 공개 부분을 검증하고 그 token 의 32-byte 키 `K_tok` 를 돌려준다.
SockGate 는 `K_tok` 로 채널 결속 `enroll_mac` 을 검증한다.

```c
static SG_Status SG_CALL on_enroll(void* user, const SG_EnrollRequest* req, uint8_t token_key_out[32])
{
    /* req->token_pub / token_pub_size : 클라이언트가 보낸 token 공개 부분 (1..512 bytes)
       req->installation_id, req->public_key, req->product_id, req->license_id : 핸드셰이크의 주장
       req->peer_address */
    if (!lookup_and_check(user, req->token_pub, req->token_pub_size)) return SG_AUTH_FAILED;
    derive_k_tok(user, req->token_pub, req->token_pub_size, token_key_out);
    return SG_OK;
}
```

- `SG_OK` 가 아닌 값은 거부이다. 라이브러리는 `token_key_out` 을 복사한 뒤 지운다.
- `on_enroll` 을 설정하면 `SG_Server_IssueEnrollmentToken` 의 내장 token 은 거부된다. 모든 token 을 자체 발급자가 만드는 경우에만 설정한다.
- **키 조회일 뿐이며, 아무것도 검증되기 전에 호출된다** (challenge 유효성 확인 직후, MAC·공개키/ID 관계·서명 검증 이전).
  `req` (`token_pub` 포함)는 인증되지 않은 값이고, token 공개 부분을 본 누구에게서나 올 수 있다. 콜백이 `SG_OK` 를 돌려줘도 이후 검사가
  실패하면 등록되지 않는다. 등록 완료 통지는 따로 없으며, 성공 여부는 `on_session_opened` (`info->enrolled == 1`)나 인가 콜백으로 알 수 있다.
- 만료, 제품 확인 등 token 내용 검사는 콜백 책임이다 (내장 token 의 claims 검사와 30 일 상한은 적용되지 않는다).
- 승인되면 installation 은 **주장한 product** 로 등록되고, 주장한 license 는 바인딩되지 않는다 (일반 라이선스 주장으로 취급).
- 1회 사용: SockGate 는 채널 결속 token 증명·공개키·서명이 검증된 뒤, `on_authorize` 전에 `SHA-256(token_pub)` 앞 16 bytes 를 사용된
  token ID 로 registry 에 영구 기록하고 installation 을 등록한다. 따라서 같은 registry 에서는 같은 `token_pub` 가 다시 쓰일 수 없고,
  `on_authorize` 가 거부한 enrollment 도 token 을 소모한다.
- registry 가 다른 서버들 사이에서 1회 사용을 지키려면 이 콜백에서 공유 저장소로 token 을 원자적으로 소비한다. 이 경우 `token_pub` 를 본
  누구나 token 을 소진시킬 수 있으므로 (등록은 불가능한 서비스 거부) 이런 token 은 수명을 짧게 한다.

### 5.4 폐기

```c
st = SG_Server_RevokeClient(server, &installation_id);
```

registry 상태를 REVOKED 로 바꾸고(영구), 그 installation 의 열린 세션을 즉시 닫고(CLOSE(AUTH_FAILED), `on_session_closed(SG_AUTH_FAILED)`),
바인딩된 라이선스 좌석을 반납한다. 모르는 ID 는 `SG_NOT_FOUND`. `SG_STORAGE_ERROR` 는 "이 프로세스에서는 폐기됨, 디스크에는 저장 안 됨"
이다. registry 는 저장되지 않은 폐기를 기억하므로, 원인을 고친 뒤 다시 호출하면 쓰기를 재시도하고 `SG_OK` 가 나오면 저장된 것이다.
그 사이 registry 의 다른 변경(등록, enrollment 등)이 성공적으로 저장되어도 함께 저장된다 (19d1208). 이미 폐기되어 저장까지 끝난 경우는 `SG_OK`.

## 6. 라이선스와 인가

### 6.1 라이선스 관리

```c
SG_LicenseRecord lic;
SG_LicenseRecord_Init(&lic);
lic.license_id        = "LIC-7f3a...";     /* 필수, 1..128 bytes */
lic.product_id        = "example-product"; /* 필수, 1..64 bytes */
lic.features          = 0x7;               /* 이 라이선스가 허용하는 feature bit */
lic.expires_at_ms     = 0;                 /* Unix ms, 0 = 무기한 */
lic.max_installations = 5;                 /* 좌석 수, 0 = 무제한 */
st = SG_Server_AddLicense(server, &lic);
```

| API | 동작 | 주요 오류 |
|---|---|---|
| `SG_Server_AddLicense` | 추가 또는 조건 변경 (기존 좌석 유지). 변경은 새 세션과 각 세션의 **다음 재인증**부터 적용 | `SG_INVALID_ARGUMENT` (길이, UTF-8/제어문자), `SG_INVALID_STATE` (폐기된 라이선스), `SG_LIMIT_EXCEEDED` (100만 개 초과), `SG_STORAGE_ERROR` (변경 취소) |
| `SG_Server_RevokeLicense` | 영구 폐기, 그 라이선스로 인가된 열린 세션 즉시 종료 | `SG_NOT_FOUND`, `SG_STORAGE_ERROR` (프로세스 내에서는 폐기됨. 다시 호출하거나 license store 의 다른 쓰기가 성공하면 저장됨, §5.4) |
| `SG_Server_ReleaseLicenseSeat` | installation 의 좌석 반납, 그 installation 의 해당 라이선스 세션 종료 | `SG_NOT_FOUND` (라이선스 없음 또는 좌석 없음), `SG_STORAGE_ERROR` (**반납 취소**, 세션 유지) |
| `SG_Server_GetLicense` | `SG_LicenseInfo`: `product_id`, `features`, `expires_at_ms`, `max_installations`, `installations` (사용 중 좌석), `revoked` | `SG_NOT_FOUND` |

라이선스 ID·제품 ID 는 protocol string (UTF-8, 제어·비가시 문자 금지)이어야 한다. 즉시 차단이 필요하면 조건 변경이 아니라 `RevokeLicense` 를 쓴다.

좌석 의미:

- 좌석은 **활성화 기록**이지 동시 접속 수가 아니다. 최종적으로 허용된 세션만 좌석을 잡는다 (`on_authorize` 이후).
- installation 은 `SG_Server_ReleaseLicenseSeat` 또는 `SG_Server_RevokeClient` 전까지 좌석을 유지한다. 인가 후 세션이 다른 이유로 열리지 못해도 좌석은 남는다.
- `max_installations` 를 줄여도 기존 좌석은 유지되고 새 좌석만 막힌다.
- 좌석을 반납해도 아직 등록된 installation 은 다음 인가 때 빈 좌석이 있으면 다시 잡는다. 영구 차단은 installation 폐기로 한다.
- 재설치로 키가 바뀐 경우 구 installation 의 좌석을 `ReleaseLicenseSeat` 로 회수한다.

### 6.2 내장 인가 순서

1. installation 이 등록·활성이어야 한다.
2. registry 의 product/license 바인딩이 우선하며, 그와 **다른** 클라이언트 주장은 거부한다.
3. 유효 라이선스 = registry 바인딩. 바인딩이 없는 installation 의 라이선스 주장은 검증되지 않은 주장(`SG_LICENSE_STATUS_UNKNOWN`)이다.
   단 `SG_SERVER_OPT_LICENSE_ACTIVATION` 이면 store 에 있는 주장 라이선스로 활성화를 시도한다.
4. store 의 라이선스는 활성, 같은 제품, 미만료여야 한다 (아니면 거부). 그러면 `SG_LICENSE_STATUS_VALID`,
   `granted_features = requested_features & license.features` (요청이 없으면 `license.features` 전체), 만료 시각이 세션 수명을 자른다.
   store 에 없는 라이선스는 `UNKNOWN` 이고 권한이 없다.
5. `SG_SERVER_OPT_REQUIRE_LICENSE` 이면 `VALID` 가 아닌 세션을 거부한다.
6. integrity 판정 (§7): reject → 거부, restrict → RESTRICTED.
7. `on_authorize` 가 결정을 조정한다.
8. 허용이면 integrity RESTRICTED 하한을 다시 적용하고, `VALID` 라이선스는 좌석을 잡는다 (활성화면 registry 에 영구 바인딩, first wins).
   좌석이 없으면(`max_installations`) 거부로 바뀐다.

1–6 에서 거부되면 `on_authorize` 는 호출되지 않는다.

### 6.3 `on_authorize`

```c
static SG_Status SG_CALL on_authorize(void* user, const SG_AuthRequest* req, SG_AuthDecision* d)
{
    if (req->license_status != SG_LICENSE_STATUS_VALID && needs_license(user, req)) {
        d->allow = 0;                       /* 클라이언트는 일반 REJECTED 를 받는다 */
        return SG_OK;
    }
    d->granted_features &= app_policy_mask(user, req->installation_id);
    return SG_OK;                           /* SG_OK 가 아니면 거부 */
}
```

`SG_AuthRequest` (클라이언트에서 온 값은 **주장**):

| 필드 | 출처 |
|---|---|
| `session` | 이 연결의 핸들 (세션은 아직 열리지 않음) |
| `installation_id` | 검증됨 (키 소유 증명) |
| `auth_mode`, `reauthentication` | `SG_AUTH_MODE_AUTHENTICATE` / `SG_AUTH_MODE_ENROLL`, 재인증이면 1 |
| `product_id`, `product_version`, `license_id` | 주장 (없으면 `""`) |
| `requested_features` | 주장 (없으면 0) |
| `client_version_major/minor/patch` | 주장 |
| `integrity_present`, `integrity_flags`, `integrity_platform`, `executable_sha256` | 주장 (보고가 없으면 0 / NULL) |
| `peer_address` | 소켓의 상대 주소 |
| `registered_product_id`, `registered_license_id` | 서버 registry (없으면 `""`) |
| `license_status`, `license_features` | 서버 검증 결과 (`license_features` 는 VALID 일 때만) |
| `integrity_conditions` | 보고된 관측 + 서버 조건 (`SG_INTEGRITY_REPORT_MISSING`, `SG_INTEGRITY_UNKNOWN_EXECUTABLE`) |

`SG_AuthDecision` 은 내장 결정으로 채워져 있다: `allow = 1`, `policy` (NORMAL 또는 integrity 에 의한 RESTRICTED), `granted_features`,
`session_lifetime_ms = 0`, `license_expires_at_ms` (검증된 라이선스의 만료, 없으면 0).

- `allow = 0` 이면 거부. `policy` 는 `SG_SESSION_POLICY_NORMAL` / `_RESTRICTED` 만 가능하며 그 외 값은 콜백 실패와 같은 거부로 처리된다
  (로그: `authorization denied: application callback failed`).
- 애플리케이션은 신뢰 주체이므로 라이선스에 없는 feature 를 부여할 수도 있다.
- `session_lifetime_ms`: 0 = `SG_ServerOptions.session_lifetime_ms`, 최대 7일로 잘림.
- `license_expires_at_ms`: 세션 수명의 상한. 이미 지난 시각이면 거부된다.
- integrity 로 RESTRICTED 가 된 세션은 콜백이 NORMAL 로 바꿔도 RESTRICTED 로 남는다.
- 재인증 때도 호출되며(`reauthentication = 1`), 클레임과 integrity 보고는 최초 CLIENT_HELLO 의 값이다. 라이선스 조건 변경이 여기서 반영된다.
- RESTRICTED 의 의미는 애플리케이션이 정한다. SockGate 는 정책 값을 세션 정보로 전달할 뿐이다.

## 7. Integrity 정책

클라이언트가 `SG_CLIENT_FLAG_INTEGRITY_REPORT` 로 보내는 관측(`SG_INTEGRITY_DEBUGGER_PRESENT`, `_PRELOAD_PRESENT`, `_UNSIGNED_EXECUTABLE`,
`_ASLR_DISABLED`, `_DEP_DISABLED`, `_CFG_DISABLED`, `_EXECUTABLE_WRITABLE`, `_UNEXPECTED_MODULES`, `_HASH_UNAVAILABLE`)과 서버 조건을 합친 값이
`integrity_conditions` 이다.

```c
static const SG_Sha256 allowed[] = { { { /* 32 bytes */ } } };
options.integrity_reject_mask   = SG_INTEGRITY_UNKNOWN_EXECUTABLE;
options.integrity_restrict_mask = SG_INTEGRITY_DEBUGGER_PRESENT | SG_INTEGRITY_REPORT_MISSING;
options.allowed_executables      = allowed;
options.allowed_executable_count = 1;
```

- 조건이 `integrity_reject_mask` 와 겹치면 거부(`on_authorize` 미호출), `integrity_restrict_mask` 와 겹치면 RESTRICTED. reject 가 우선한다.
- 보고가 없으면 `SG_INTEGRITY_REPORT_MISSING`, allowlist 가 있으면 누락도 `SG_INTEGRITY_UNKNOWN_EXECUTABLE` 이다.
- allowlist 는 `SG_INTEGRITY_UNKNOWN_EXECUTABLE` 이 어느 마스크에 있어야 효과가 있다 (없으면 경고 로그).
- 모든 관측은 위조할 수 있다. 신뢰를 **낮추는** 신호로만 쓴다 ([SECURITY.md](SECURITY.md) §2.6).

## 8. 메시지 송신

```c
/* 서버가 시작하는 요청: 요청 ID 는 라이브러리가 발급 (1, 2, …, 반환되지 않음) */
st = SG_Server_Send(server, session, data, size);

/* 클라이언트 요청에 대한 응답: on_message 의 info->request_id 를 그대로 */
st = SG_Server_SendEx(server, session, data, size, info->request_id);
```

- 1 호출 = 1 DATA 프레임. `size ≤ max_payload_size` (초과 `SG_INVALID_ARGUMENT`), `size == 0` 허용, `data == NULL && size != 0` 은 `SG_INVALID_ARGUMENT`.
- `reply_to_request_id` 가 0 이 아니면 `RESPONSE` 프레임이 된다. 클라이언트가 보낸 최대 요청 ID 보다 크면 아무것도 보내지 않고 `SG_INVALID_ARGUMENT`.
  `info->request_id == 0` (요청 ID 없는 메시지)이면 `SendEx(..., 0)` 은 `Send` 와 같다.
- 수신 메시지의 `info->flags`: `SG_MESSAGE_FLAG_RESPONSE` 면 `request_id` 는 서버가 보낸 요청의 ID, `SG_MESSAGE_FLAG_ENCRYPTED` 면 애플리케이션 계층 AEAD 사용.
- 송신 DATA 는 `SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION` 이거나 그 클라이언트가 한 번이라도 암호화된 DATA 를 보냈으면 암호화된다.
- 어느 스레드에서나 호출할 수 있고, 같은 세션의 호출은 직렬화된다. 반환은 데이터를 송신 큐에 넣은 시점이다.
- 미전송 데이터가 32 MiB 를 넘으면 `SG_LIMIT_EXCEEDED` (연결은 유지 — 나중에 다시 시도).
- `SG_NOT_FOUND`: 모르는 핸들 또는 이미 정리된 세션. `SG_CLOSED`: 닫히는 중이거나, 송신 실패로 연결이 닫힘 (이때 `on_session_closed` 가 호출 스레드에서 실행될 수 있다).
- 클라이언트의 `max_payload_size` 가 서버보다 작으면 클라이언트가 큰 DATA 를 프로토콜 오류로 거부하므로 양쪽 값을 맞춘다.

`SG_Server_CloseSession(server, session)` 은 CLOSE(NORMAL) 을 보내고 세션을 닫는다 (`on_session_closed(SG_CLOSED)`).

## 9. 세션 정보와 통계

```c
SG_ServerSessionInfo info;
SG_ServerSessionInfo_Init(&info);
st = SG_Server_GetSessionInfo(server, session, &info);
```

| 필드 | 의미 |
|---|---|
| `session`, `session_id`, `installation_id` | 핸들, wire session id, 검증된 installation |
| `policy` | `SG_SESSION_POLICY_NORMAL` / `_RESTRICTED` |
| `epoch` | 재인증 횟수 (키 epoch) |
| `granted_features` | 서버가 부여한 feature |
| `license_expires_at_ms` | 세션을 제한하는 라이선스 만료 (0 = 없음) |
| `expires_in_ms` | 세션 만료까지 남은 시간 (32bit 로 포화) |
| `enrolled` | 이 연결에서 enrollment 로 등록했으면 1 |
| `peer_address` | 상대 주소 문자열 |
| `product_id` | registry 제품 바인딩. **바인딩이 없으면 클라이언트가 주장한 제품** |
| `license_id`, `license_status` | registry 바인딩 또는 검증된 라이선스만 (원문 주장은 표시하지 않음). `license_status` 가 VALID/UNKNOWN/NONE 을 구분 |

세션이 아직 열리지 않았거나 닫히는 중이면 `SG_NOT_FOUND`. `on_session_opened` 의 `info` 도 같은 구조이다.

```c
SG_ServerStats stats;
SG_ServerStats_Init(&stats);
st = SG_Server_GetStats(server, &stats);
```

`active_connections` (핸드셰이크 중 포함, graceful-close 중 제외), `active_sessions`, `total_connections` (수락되어 등록된 연결 누계),
`auth_succeeded`, `auth_failed` (최초 인증과 재인증 거부), `protocol_errors` (처리 오류로 끝난 연결, TLS 실패 포함),
`messages_received`, `messages_sent` (DATA 수).

## 10. 종료

```c
SG_Server_Stop(server);     /* 선택: Destroy 가 Stop 을 포함 */
SG_Server_Destroy(server);  /* NULL 허용 */
```

- `Stop` 은 새 연결 수락을 멈추고, 열린 세션에 CLOSE(SERVER_SHUTDOWN) 을 보내고, 잠시 송신을 비운 뒤 워커를 모두 join 하고 반환한다.
  `on_session_closed(SG_CLOSED)` 는 보통 **Stop 을 부른 스레드**에서 lifecycle lock 을 잡은 채 실행되지만, 그 세션의 이벤트를 이미 다른
  스레드가 전달하고 있으면 그 스레드가 (lifecycle lock 없이) 전달한다. 실행 중이 아니면 아무것도 하지 않는다.
- `Destroy` 는 `Stop` 후 모든 자원을 해제하고 저장소 lock (`<path>.lock`)을 푼다. 이후 핸들을 쓰지 않는다.
- `Start` / `Stop` / `Destroy` 는 콜백 안에서 `SG_INVALID_STATE` 이다. 다른 API 호출과 동시에 `Destroy` 하지 않는다.

## 11. 오류 코드 처리

모든 함수는 예외를 던지지 않는다. 내부 예외는 `SG_OUT_OF_MEMORY` / `SG_INTERNAL_ERROR` 로 바뀐다. `SG_StatusString()` 이 이름을 준다.

| 코드 | 주로 반환하는 API | 의미 / 대응 |
|---|---|---|
| `SG_INVALID_ARGUMENT` | 전부 | NULL, 구조체 `size`/`version`, 문자열 길이, 범위 위반 (`max_unauthenticated > max_connections` 포함), TLS 키 로드·불일치, 잘못된 proof key PEM, 모르는 응답 ID. 설정 수정 |
| `SG_NOT_SUPPORTED` | `Create`, 구조체 입력 API | 알 수 없는 flag·integrity 비트, 라이브러리가 모르는 뒤쪽 필드가 0 이 아님 (더 새 헤더). 라이브러리 업데이트 또는 필드 제거 |
| `SG_CERTIFICATE_ERROR` | `Create` | 인증서 체인을 읽을 수 없음 |
| `SG_NOT_FOUND` | `Create` (proof key 파일 없음), 세션·registry·license API | 대상 없음 |
| `SG_STORAGE_ERROR` | `Create`, registry/license 변경 API | 저장소 파일 손상·읽기 실패, 또는 저장 실패. 폐기 API 는 "메모리에서는 적용됨 — 다시 호출해 저장", 그 외는 "변경 취소" |
| `SG_INVALID_STATE` | `Create` (다른 프로세스가 저장소 `<path>.lock` 을 잡고 있음), `Start` (이미 실행), `GetPort` (미시작), `Start`/`Stop`/`Destroy` (콜백 안), 라이선스 관리 (폐기된 라이선스) | 상태 확인 |
| `SG_NETWORK_ERROR` | `Start` | 주소 해석·bind·listen 실패 |
| `SG_ALREADY_EXISTS` | `RegisterClient` | 이미 있는(또는 폐기된) installation |
| `SG_LIMIT_EXCEEDED` | `Send`, `AddLicense`, registry·license 변경 API | 미전송 32 MiB 초과(재시도), 라이선스 수 상한, 저장소 파일 크기 상한(512 MiB, 변경 취소) |
| `SG_BUFFER_TOO_SMALL` | `IssueEnrollmentToken` | `*written` 크기로 다시 호출 |
| `SG_CLOSED` | `Send` | 세션이 닫힘 |
| `SG_OUT_OF_MEMORY`, `SG_INTERNAL_ERROR` | 전부 | 자원 부족 / 내부 오류 |

`on_session_closed` 의 `reason` 은 원인별로 `SG_CLOSED`, `SG_AUTH_FAILED`, `SG_SESSION_EXPIRED`, `SG_TIMEOUT`, `SG_CHALLENGE_EXPIRED`,
`SG_PROTOCOL_ERROR`, `SG_REPLAY_DETECTED`, `SG_LIMIT_EXCEEDED`, `SG_NETWORK_ERROR` 등이다 ([ARCHITECTURE.md](ARCHITECTURE.md) §4.5).
클라이언트 쪽에서는 거부 사유가 구분되지 않는다 (`SG_SERVER_REJECTED`). 상세 사유는 서버 로그를 본다 ([PROTOCOL.md](PROTOCOL.md) §5).

## 12. `sg_admin` (오프라인 관리)

`tools/sg_admin.cpp`. registry / license 파일은 단일 프로세스 저장소이며 실행 중인 서버가 lock 을 잡고 있으므로, **그 파일을 쓰는 서버가
멈춘 동안에만** 저장소 명령을 쓴다. 서버가 열고 있으면 "the store is in use (stop the server that uses it first)" 로 실패한다.
실행 중에는 애플리케이션 안에서 서버의 C API 를 쓴다.

```text
sg_admin pin <cert.pem>                              SPKI pin (SHA-256, hex) 출력 — 클라이언트 pinning 용
sg_admin token-key <file> [--force yes]              32 bytes 무작위 token key 생성 (소유자 전용 파일)
sg_admin token issue --key FILE --product P [--license L [--licenses FILE]] [--ttl-ms N]
                                                     token key 로 enrollment token 발급 (기본 24 h, 1 ms..30 일)
sg_admin license add    --store FILE --id L --product P [--features N] [--expires-ms N] [--seats N]
sg_admin license revoke --store FILE --id L
sg_admin license show   --store FILE --id L
sg_admin client register --registry FILE --pubkey HEX [--product P] [--license L [--licenses FILE]]
                                                     --pubkey 는 65 bytes SEC1 공개키 (130 hex)
sg_admin client revoke   --registry FILE --iid HEX   --iid 는 32 hex
sg_admin client list     --registry FILE
sg_admin dev-pki <dir> [--host NAME] [--force yes]   개발 전용 CA / 서버 인증서(90 일) / 키 + pin 출력
```

- 명령마다 허용된 옵션만 받는다 (모르는 옵션, 중복 옵션은 오류). 위치 인자(파일·디렉터리)는 `-` 로 시작할 수 없다.
  숫자는 10진수 또는 `0x` 접두 16진수만 받는다 (부호·공백·overflow 거부). 종료 코드: 0 성공, 1 실패, 2 사용법 오류.
- `license add` 는 서버의 `AddLicense` 와 같다. 폐기된 라이선스는 다시 추가할 수 없다 (폐기는 영구).
- `token-key` 와 `dev-pki` 는 기존 파일을 `--force yes` 없이는 덮어쓰지 않는다. token key 를 바꾸면 발급된 token 이 모두 무효가 된다.
- `token issue` 는 서버의 `token_key` 파일과 같은 키를 써야 하며, 내장 token 검증(`on_enroll` 없음, `SG_SERVER_OPT_ALLOW_ENROLLMENT`)에서만 유효하다.
- `--licenses FILE` 을 주면 `token issue` / `client register` 가 바인딩 검사(라이선스 존재·활성·같은 제품)를 한다. 이 검사는 서버보다
  엄격하다: `REQUIRE_LICENSE` 가 없어도 라이선스가 store 에 있어야 한다. `--licenses` 를 주지 않으면 아무것도 검사하지 않는다
  (서버 API 는 이 경우에도 store 가 아는 라이선스라면 폐기·다른 제품을 거부한다).
- `client revoke` 는 registry 만 바꾼다. 서버의 `SG_Server_RevokeClient` 와 달리 license store 의 좌석을 반납하지 않으므로, 필요하면 서버 실행 후
  `SG_Server_ReleaseLicenseSeat` 로 회수한다.
- `dev-pki` 는 디렉터리를 만들고 `ca.crt` (365 일, `pathlen:0`), `server.crt` (90 일), `server.key` 를 소유자 전용 파일로 쓴 뒤 SAN 목록과
  SPKI pin 을 출력한다. `--host` 는 DNS 이름(→ DNS SAN) 또는 IP 주소(→ IP SAN)여야 하고 127.0.0.1, ::1 이 함께 들어간다.
  인증서는 무작위 127-bit 일련번호와 `O=SockGate DEVELOPMENT ONLY` 를 가진다. 운영에 쓰지 않는다.

## 13. ABI 규칙

- 모든 설정·입출력 구조체는 `uint32_t size; uint32_t version;` 로 시작한다. 항상 `*_Init()` 으로 초기화한다
  (`SG_ServerOptions_Init`, `SG_ServerCallbacks_Init`, `SG_ClientRecord_Init`, `SG_EnrollmentTokenRequest_Init`, `SG_LicenseRecord_Init`,
  `SG_LicenseInfo_Init`, `SG_ServerSessionInfo_Init`, `SG_ServerStats_Init`). `*_VERSION` 상수는 모두 1 이다.
- 라이브러리는 `size` 안의 필드만 읽고 쓴다. 입력 구조체의 `version` 이 0 이거나 `size` 가 필수 필드를 덮지 못하면 `SG_INVALID_ARGUMENT` 이다
  (옵션은 `tls_private_key_pem_size` 까지, 콜백은 `user` 까지, `SG_ClientRecord` 는 `public_key` 까지, token 요청은 `ttl_ms` 까지,
  `SG_LicenseRecord` 는 `max_installations` 까지). 출력 구조체도 최소 크기가 있다 (`SG_ServerSessionInfo` 는 `license_id` 까지 —
  `license_status` 는 `size` 가 덮을 때만 채움, `SG_LicenseInfo` 는 `revoked` 까지, `SG_ServerStats` 는 `messages_sent` 까지).
- **입력** 구조체(`SG_ServerOptions`, `SG_ServerCallbacks`, `SG_ClientRecord`, `SG_EnrollmentTokenRequest`, `SG_LicenseRecord`)에서 `size` 가
  라이브러리가 아는 크기보다 크면, 그 뒤쪽 바이트는 **모두 0 이어야 한다.** 0 이 아니면 `SG_NOT_SUPPORTED` — 새 헤더로 빌드한 애플리케이션이
  옛 라이브러리에서 보안 설정을 조용히 잃지 않게 하기 위함이다. 4 KiB 넘게 크면 `SG_INVALID_ARGUMENT`. 이 구조체들은 끝에 암묵적 padding 이
  없도록 라이브러리가 `static_assert` 로 검증한다.
- 콜백 필드는 `size` 가 해당 필드를 완전히 덮을 때만 복사된다.
- 콜백으로 받는 구조체(`SG_AuthRequest`, `SG_AuthDecision`, `SG_EnrollRequest`, `SG_ServerSessionInfo`, `SG_MessageInfo`)는 라이브러리가 자기 헤더의
  `size`/`version` 으로 채운다. 애플리케이션이 더 새 헤더로 빌드되었다면 새 필드를 읽기 전에 `size` 를 확인한다.
- 열거형은 `uint32_t` 필드 + `#define` 상수이다. 상태 코드 값은 ABI 의 일부이며 끝에만 추가된다 (모르는 값은 `SG_StatusString` 이 `"SG_UNKNOWN_STATUS"`).
- 문자열은 NUL 종료 UTF-8 이다. 라이브러리는 메모리를 할당해 넘기지 않으며, 출력은 호출자 버퍼로 복사한다.
- 세션은 포인터가 아니라 재사용되지 않는 `SG_SessionHandle` (0 = `SG_INVALID_SESSION_HANDLE`)로 참조한다.
- 공유 라이브러리는 `SG_SERVER_API` 로 선언된 함수만 export 한다. `SOCKGATE_API_VERSION` 은 호환되지 않는 ABI 변경 때만 올라간다.
- 0.x 버전 동안에는 minor 버전 사이에서도 ABI 가 바뀔 수 있다. 그래서 공유 라이브러리 soname 에 minor 가 들어가고
  (`libsockgate_server.so.0.1`), 설치 패키지의 버전 검사도 같은 minor 를 요구한다 (`find_package(SockGate 0.1)` 은 0.1.x 만 받는다).
