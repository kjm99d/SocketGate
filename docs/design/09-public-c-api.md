# 09. Public C API

## 1. 원칙

- **C ABI 만 공개**한다. C++ 클래스, STL, 예외는 경계를 넘지 않는다.
- 모든 객체는 **opaque handle** (`SG_Client*`, `SG_Server*`) 로만 다룬다.
- 서버 세션은 포인터가 아닌 **재사용되지 않는 `SG_SessionHandle` (uint64)** 로 식별한다.
- 모든 설정 구조체는 첫 두 필드가 `uint32_t size; uint32_t version;` 이다.
  `*_Init()` 함수가 기본값과 함께 채운다. 라이브러리는 `size` 이내의 필드만 읽는다(구 바이너리 호환).
- 열거형 값은 `uint32_t` 필드 + `#define` 상수로 전달한다 (컴파일러별 enum 크기 차이 회피).
- 문자열은 NUL 종료 UTF-8. 길이 상한은 각 필드에 명시한다.
- 라이브러리는 호출자에게 메모리를 할당해 넘기지 않는다. 출력은 호출자 버퍼로 복사한다.
- 콜백은 라이브러리 내부 lock 을 보유하지 않은 상태에서 호출된다.
- 모든 함수는 예외를 던지지 않는다 (내부 예외는 `SG_INTERNAL_ERROR`/`SG_OUT_OF_MEMORY` 로 변환).

## 2. 헤더 구성

| 헤더 | 제공 |
|---|---|
| `sockgate/version.h` | `SOCKGATE_API_VERSION`, `SOCKGATE_VERSION_MAJOR/MINOR/PATCH` |
| `sockgate/export.h` | `SG_CLIENT_API`, `SG_SERVER_API` 매크로 기반 |
| `sockgate/error.h` | `SG_Status` 와 코드, `SG_StatusString()` (static inline, 양쪽 라이브러리에서 중복 export 방지) |
| `sockgate/types.h` | `SG_InstallationId`, `SG_SessionId`, `SG_Sha256`, `SG_PublicKey`, 상태/정책/플래그 상수, 로그 콜백 |
| `sockgate/config.h` | `SG_ClientConfig`, `SG_ServerConfig`(클라이언트가 접속할 서버 기술), `SG_ProxyConfig` |
| `sockgate/client.h` | 클라이언트 함수 |
| `sockgate/sockgate.h` | 클라이언트 umbrella |
| `sockgate/server.h` | 서버 함수, `SG_ServerOptions`, 콜백 |

> 명칭 주의: 요구사항 예시의 `SG_ServerConfig` 는 **클라이언트가 접속할 서버**(host, port, CA, pin)를 뜻한다.
> 서버 라이브러리 자체의 설정은 `SG_ServerOptions` 이다.

## 3. 에러 코드

| 값 | 이름 | 분류 |
|---:|---|---|
| 0 | `SG_OK` | |
| 1 | `SG_INVALID_ARGUMENT` | API |
| 2 | `SG_OUT_OF_MEMORY` | 자원 |
| 3 | `SG_NETWORK_ERROR` | 네트워크 |
| 4 | `SG_TLS_ERROR` | TLS |
| 5 | `SG_CERTIFICATE_ERROR` | 서버 인증 |
| 6 | `SG_PINNING_ERROR` | 서버 인증 |
| 7 | `SG_AUTH_FAILED` | 인증 |
| 8 | `SG_INVALID_SIGNATURE` | 인증 |
| 9 | `SG_CHALLENGE_EXPIRED` | 인증 |
| 10 | `SG_REPLAY_DETECTED` | 세션 |
| 11 | `SG_PROTOCOL_ERROR` | 프로토콜 |
| 12 | `SG_SERVER_REJECTED` | 인증/권한 |
| 13 | `SG_SESSION_EXPIRED` | 세션 |
| 14 | `SG_INTEGRITY_FAILED` | 무결성 |
| 15 | `SG_TIMEOUT` | 네트워크 |
| 16 | `SG_INVALID_STATE` | API |
| 17 | `SG_BUFFER_TOO_SMALL` | API |
| 18 | `SG_NOT_SUPPORTED` | 플랫폼 |
| 19 | `SG_CLOSED` | 세션 |
| 20 | `SG_KEYSTORE_ERROR` | 키 저장소 |
| 21 | `SG_NOT_FOUND` | API |
| 22 | `SG_ALREADY_EXISTS` | API |
| 23 | `SG_LIMIT_EXCEEDED` | 자원 |
| 24 | `SG_PROXY_ERROR` | 네트워크 |
| 25 | `SG_VERSION_MISMATCH` | 프로토콜 |
| 26 | `SG_CRYPTO_ERROR` | 암호 |
| 27 | `SG_INTERNAL_ERROR` | 내부 |
| 28 | `SG_STORAGE_ERROR` | 서버 저장소 |

값은 ABI 의 일부이며 변경하지 않는다. 새 코드는 끝에만 추가한다.

## 4. 클라이언트 API

```c
void      SG_ClientConfig_Init(SG_ClientConfig* config);
void      SG_ServerConfig_Init(SG_ServerConfig* server);
void      SG_ProxyConfig_Init(SG_ProxyConfig* proxy);

SG_Status SG_Client_Create(const SG_ClientConfig* config, SG_Client** client);
SG_Status SG_Client_Destroy(SG_Client* client);

/* identity (installation key) */
SG_Status SG_Client_EnsureIdentity(SG_Client* client, SG_IdentityInfo* info /* nullable */);
SG_Status SG_Client_GetIdentity(SG_Client* client, SG_IdentityInfo* info);
SG_Status SG_Client_DeleteIdentity(SG_Client* client);

/* connection */
SG_Status SG_Client_Connect(SG_Client* client, const SG_ServerConfig* server);
SG_Status SG_Client_Authenticate(SG_Client* client);
SG_Status SG_Client_Enroll(SG_Client* client, const char* enrollment_token);
SG_Status SG_Client_Refresh(SG_Client* client);
SG_Status SG_Client_Disconnect(SG_Client* client);

/* data */
SG_Status SG_Client_Send(SG_Client* client, const void* data, size_t size);
SG_Status SG_Client_SendEx(SG_Client* client, const void* data, size_t size,
                           uint64_t reply_to_request_id, uint64_t* out_request_id);
SG_Status SG_Client_Receive(SG_Client* client, void* buffer, size_t capacity, size_t* received);
SG_Status SG_Client_ReceiveEx(SG_Client* client, void* buffer, size_t capacity, size_t* received,
                              SG_MessageInfo* info /* nullable */, uint32_t timeout_ms);
SG_Status SG_Client_Ping(SG_Client* client);

/* introspection */
SG_Status SG_Client_GetState(SG_Client* client, uint32_t* state);
SG_Status SG_Client_GetSessionInfo(SG_Client* client, SG_ClientSessionInfo* info);
uint32_t  SG_Client_GetApiVersion(void);
```

### 4.1 동작 계약

| 함수 | 계약 |
|---|---|
| `Create` | config 복사. 네트워크/키 저장소 접근 없음 |
| `EnsureIdentity` | key store 에서 로드 또는 생성. `SG_CLIENT_FLAG_AUTO_IDENTITY` 면 Authenticate 가 자동 호출 |
| `Connect` | TCP(+proxy) + TLS + 서버 검증까지. 실패 시 상태 `CLOSED`, 재호출 가능 |
| `Authenticate` | `TLS_ESTABLISHED` 에서만. 성공 시 `ACTIVE` |
| `Send` | `ACTIVE`/`REFRESHING` 에서만. 1 메시지 = 1 DATA 프레임. `size ≤ max_payload_size` |
| `Receive` | DATA 1개를 복사. 버퍼 부족 시 `SG_BUFFER_TOO_SMALL` + `*received` 에 필요 크기, 메시지는 큐에 유지. PING 자동 응답, PONG/CLOSE 내부 처리 |
| `Receive` 타임아웃 | `config.io_timeout_ms` (0 = 무한). `ReceiveEx` 는 호출별 타임아웃 |
| `Disconnect` | 멱등. 다른 스레드의 Send/Receive 를 깨움 |
| `Destroy` | Disconnect 포함. 다른 호출과 동시 호출 금지. NULL 허용 |

## 5. 서버 API

```c
void      SG_ServerOptions_Init(SG_ServerOptions* options);

SG_Status SG_Server_Create(const SG_ServerOptions* options, SG_Server** server);
SG_Status SG_Server_Start(SG_Server* server);
SG_Status SG_Server_Stop(SG_Server* server);
SG_Status SG_Server_Destroy(SG_Server* server);
SG_Status SG_Server_GetPort(SG_Server* server, uint16_t* port);

SG_Status SG_Server_Send(SG_Server* server, SG_SessionHandle session, const void* data, size_t size);
SG_Status SG_Server_SendEx(SG_Server* server, SG_SessionHandle session, const void* data, size_t size,
                           uint64_t reply_to_request_id);
SG_Status SG_Server_CloseSession(SG_Server* server, SG_SessionHandle session);
SG_Status SG_Server_GetSessionInfo(SG_Server* server, SG_SessionHandle session, SG_ServerSessionInfo* info);

/* registry / license */
SG_Status SG_Server_RegisterClient(SG_Server* server, const SG_ClientRecord* record);
SG_Status SG_Server_RevokeClient(SG_Server* server, const SG_InstallationId* installation_id);   /* 활성 세션 즉시 종료 */
SG_Status SG_Server_AddLicense(SG_Server* server, const SG_LicenseRecord* license);           /* 추가 또는 조건 변경 */
SG_Status SG_Server_RevokeLicense(SG_Server* server, const char* license_id);                  /* 영구, 활성 세션 즉시 종료 */
SG_Status SG_Server_ReleaseLicenseSeat(SG_Server* server, const char* license_id,
                                       const SG_InstallationId* installation_id);              /* 좌석 반납, 해당 세션 종료 */
SG_Status SG_Server_GetLicense(SG_Server* server, const char* license_id, SG_LicenseInfo* info);
SG_Status SG_Server_IssueEnrollmentToken(SG_Server* server, const SG_EnrollmentTokenRequest* request,
                                         char* token, size_t capacity, size_t* written);
SG_Status SG_Server_GetStats(SG_Server* server, SG_ServerStats* stats);
uint32_t  SG_Server_GetApiVersion(void);
```

### 5.1 라이선스와 내장 인가

```c
typedef struct SG_LicenseRecord {
    uint32_t size, version;
    const char* license_id;       /* 필수, 1..128 bytes */
    const char* product_id;       /* 필수, 1..64 bytes */
    uint64_t features;            /* 라이선스가 허용하는 feature bit */
    uint64_t expires_at_ms;       /* Unix ms, 0 = 무기한 */
    uint32_t max_installations;   /* 좌석 수, 0 = 무제한 */
    uint32_t reserved;
} SG_LicenseRecord;
```

- 저장소: `SG_ServerOptions.license_path` (NULL = 메모리). registry 와 같은 원자적 교체 방식으로 저장하며,
  로드 시 파일 전체를 비신뢰 입력으로 검증한다. registry 와 같은 파일(정규화 경로 비교)을 지정하면
  `SG_INVALID_ARGUMENT`. 라이선스 100만 개, 라이선스당 좌석 100만 개가 상한이며, 좌석 변경마다 파일 전체를
  다시 쓰므로 대규모 배포는 `on_authorize` 와 외부 DB 를 사용한다 (13 참고).
- 내장 인가 순서:
  1. installation 이 등록·활성 상태여야 한다.
  2. registry 에 기록된 product/license 바인딩이 우선한다. 이와 **다른** 클라이언트 주장은 거부한다.
  3. 유효 라이선스 = registry 에 바인딩된 license_id (`SG_ClientRecord` 또는 enrollment token 의 것).
     바인딩이 없는 installation 이 주장한 license_id 는 **검증되지 않은 주장**(`SG_LICENSE_STATUS_UNKNOWN`)일
     뿐이며 아무 권한도 주지 않는다. 존재하는 id 와 존재하지 않는 id 는 클라이언트에게 구분되지 않는다.
  4. `SG_SERVER_OPT_LICENSE_ACTIVATION` 이면 바인딩 없는 installation 이 store 의 라이선스를 주장해
     **활성화**할 수 있다. 첫 활성화가 registry 에 영구 바인딩되며(first wins) 이후 다른 라이선스로 옮길 수 없다.
     이 모드에서 license id 는 bearer secret 이므로 추측 불가능하게 발급해야 한다 (로그에는 해시만 기록).
  5. store 의 라이선스는 활성, 같은 product, 미만료여야 한다.
     `granted_features = requested_features & license.features` (요청이 없으면 license.features 전체),
     `license_expires_at_ms` 가 세션 수명을 제한한다. store 에 없는 라이선스는 권한 0.
  6. `SG_SERVER_OPT_REQUIRE_LICENSE` 이면 `SG_LICENSE_STATUS_VALID` 가 아닌 세션은 모두 거부한다.
  7. `on_authorize` 가 결과를 조정한다.
  8. **최종 허용된 세션만** 좌석을 잡고(활성화 바인딩 포함), 좌석이 없으면(`max_installations`) 거부로 바뀐다.
- 좌석은 **활성화 기록**이다 (동시 접속 수가 아님). installation 은 `SG_Server_ReleaseLicenseSeat` 또는
  `SG_Server_RevokeClient` 전까지 좌석을 유지한다. 세션이 인가 후 다른 이유로 열리지 못해도 좌석은 남는다.
  `max_installations` 를 줄여도 기존 좌석은 유지되고 새 좌석만 막힌다. 여전히 등록된 installation 은
  좌석을 반납해도 다음 인가 시 빈 좌석이 있으면 다시 잡는다 — 영구히 막으려면 installation 을 폐기한다.
- `SG_AuthRequest.license_status` / `license_features` 는 서버가 검증한 값이다 (주장 아님).
- 관리 API 의 바인딩 검증: `SG_Server_RegisterClient` / `SG_Server_IssueEnrollmentToken` 에 license 가
  지정되면, store 에 있는 라이선스는 활성(`SG_INVALID_STATE`)·같은 product(`SG_INVALID_ARGUMENT`)여야 하고,
  `REQUIRE_LICENSE` 이면 store 에 있어야 한다(`SG_NOT_FOUND`).
- 조건 변경(`AddLicense` 재호출)은 새 세션과 각 세션의 다음 재인증부터 적용된다. 즉시 차단은 `RevokeLicense`.
- 폐기는 영구적이다. 폐기된 라이선스에 `AddLicense` 는 `SG_INVALID_STATE`. 폐기 내용을 저장하지 못하면
  메모리 상으로는 폐기 상태를 유지하고 세션도 종료한 뒤 `SG_STORAGE_ERROR` 를 반환한다 (I/O 오류가 폐기를 되돌리지 않음).
- `SG_ServerSessionInfo.license_id` 는 registry 바인딩 또는 검증된 라이선스만 보여준다 (클라이언트 주장 원문은 아님).
  `license_status` 가 VALID/UNKNOWN 을 구분한다.

### 5.2 콜백

```c
typedef struct SG_ServerCallbacks {
    void* user;
    /* 인증 성공 직후, 세션 활성화 전. decision 은 내장 정책 결과로 미리 채워져 있음 */
    SG_Status (*on_authorize)(void* user, const SG_AuthRequest* request, SG_AuthDecision* decision);
    /* ENROLL 모드 token 검증. NULL 이면 내장 token 검증 사용.
       콜백은 token 공개 부분(token_pub)을 검증하고 그 token 의 K_tok(32 bytes)를 돌려준다.
       SockGate 는 K_tok 로 채널 결속 enroll_mac 을 검증한다 (05 §2). */
    SG_Status (*on_enroll)(void* user, const SG_EnrollRequest* request, uint8_t token_key_out[32]);
    void      (*on_session_opened)(void* user, const SG_ServerSessionInfo* info);
    void      (*on_message)(void* user, SG_SessionHandle session, const void* data, size_t size,
                            const SG_MessageInfo* info);
    void      (*on_session_closed)(void* user, SG_SessionHandle session, SG_Status reason);
} SG_ServerCallbacks;
```

- 콜백은 서버 워커 스레드에서 호출된다. 한 세션의 `on_message` 는 순서대로, 동시에 호출되지 않는다.
- 서로 다른 세션의 콜백은 동시에 호출될 수 있다.
- `on_authorize` 는 권한을 **축소하거나 거부**할 수 있고, 라이선스가 허용하지 않은 feature 를 추가할 수도 있다
  (서버 애플리케이션은 신뢰 주체이므로). 클라이언트가 보낸 값은 `request` 에 "주장" 으로만 전달된다.
- 콜백에서 `SG_Server_Stop`/`Destroy` 호출은 금지 (`SG_INVALID_STATE`).

## 6. ABI / 버전 정책

- `SOCKGATE_API_VERSION` 은 호환되지 않는 ABI 변경 시에만 증가한다.
- 구조체에는 끝에만 필드를 추가하고 `*_VERSION` 상수를 올린다. 라이브러리는 `size` 로 구 구조체를 인식한다.
- 공유 라이브러리 SONAME/DLL 이름에 major 버전을 포함한다 (`libsockgate_client.so.1`, `sockgate_client.dll` + 리소스 버전).
- Linux 는 `-fvisibility=hidden` + `SG_*_API` 로만 export, Windows 는 `__declspec(dllexport)` 로만 export 한다.

## 7. 사용 예

```c
#include <sockgate/client.h>

SG_ClientConfig config;
SG_ClientConfig_Init(&config);
config.identity_name = "com.example.product";
config.product_id    = "example-product";

SG_ServerConfig server;
SG_ServerConfig_Init(&server);
server.host    = "gate.example.com";
server.port    = 7443;
server.ca_file = "example-ca.pem";

SG_Client* client = NULL;
if (SG_Client_Create(&config, &client) != SG_OK) return;
SG_Client_EnsureIdentity(client, NULL);
if (SG_Client_Connect(client, &server) == SG_OK &&
    SG_Client_Authenticate(client) == SG_OK) {
    SG_Client_Send(client, "hello", 5);
}
SG_Client_Disconnect(client);
SG_Client_Destroy(client);
```
