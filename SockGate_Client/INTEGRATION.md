# Integrating SockGate_Client

애플리케이션에 SockGate_Client 를 임베딩하는 단계별 가이드이다. API 원칙은
[09-public-c-api.md](../docs/design/09-public-c-api.md), 빌드와 링크는 [BUILD.md](BUILD.md), 보안 설정의 판단 기준은
[SECURITY.md](SECURITY.md) 를 참고한다. 모든 기본값은 `src/core/client_api.cpp` 의 `*_Init()` 과 설정 파서에서 가져왔다.

## 1. 헤더와 링크

```c
#include <sockgate/client.h>    /* 이것 하나로 충분: config.h, types.h, error.h, export.h, version.h 포함 */
```

- Windows 와 Linux 에서 헤더, 함수, 구조체, 에러 코드, 동작이 같다. 순수 C(C99/C11)와 C++ 에서 모두 컴파일된다.
- CMake: `find_package(SockGate 0.1 REQUIRED)` 후 `target_link_libraries(app PRIVATE SockGate::Client)`. 설치 패키지에는
  공개 헤더 8 개만 있으므로 내부 헤더에 의존할 수 없다. 정적 빌드면 `SOCKGATE_CLIENT_STATIC` 이 자동으로 전파된다
  ([BUILD.md §5](BUILD.md#5-설치와-find_packagesockgate)).
- 실행 중인 라이브러리의 ABI 버전은 `SG_Client_GetApiVersion()` 으로 확인한다. 컴파일한 헤더의 `SOCKGATE_API_VERSION`
  과 다르면 호환되지 않는 라이브러리다.

```c
if (SG_Client_GetApiVersion() != SOCKGATE_API_VERSION) {
    /* 다른 major ABI 의 라이브러리가 로드됨 */
}
```

## 2. `SG_ClientConfig`

`SG_ClientConfig_Init(&config)` 로 초기화한 뒤 필요한 필드만 바꾼다. `SG_Client_Create` 가 전부 **복사**하므로
문자열과 proxy 구조체는 Create 호출 동안만 유효하면 된다(`log_callback` / `log_user` 는 핸들 수명 동안 사용된다).

| 필드 | `SG_ClientConfig_Init` 기본값 | 의미와 제약 |
|---|---|---|
| `size`, `version` | `sizeof(SG_ClientConfig)`, `SG_CLIENT_CONFIG_VERSION` (1) | `version == 0` 이거나 `size` 가 `identity_name` 까지 덮지 못하면 `SG_INVALID_ARGUMENT` |
| `identity_name` | `NULL` (**필수**) | `[A-Za-z0-9._-]{1,128}`, `.` 으로 시작 불가, Windows 장치 이름 불가. 사용자 단위로 공유되는 이름 공간이므로 reverse-DNS 로 짓는다 |
| `key_store_type` | `SG_KEYSTORE_AUTO` (0) | `SG_KEYSTORE_*`. 알 수 없는 값 `SG_INVALID_ARGUMENT`, 이 플랫폼/빌드에 없는 저장소 `SG_NOT_SUPPORTED` |
| `flags` | 0 | `SG_CLIENT_FLAG_*` 조합(아래 표). 알 수 없는 비트는 `SG_NOT_SUPPORTED` |
| `key_store_path` | `NULL` = 사용자별 기본 디렉터리 | 최대 4096 바이트. FILE, TPM2(blob 디렉터리), Linux AUTO(키와 locator)가 사용. CNG 저장소와 **Windows AUTO 는 무시**(CNG 키와 locator 는 항상 사용자 단위 `%LOCALAPPDATA%\SockGate\keys`) |
| `product_id` | `NULL` | 주장. 최대 64 바이트 UTF-8, 제어·비가시 문자 금지 |
| `product_version` | `NULL` | 주장. 최대 32 바이트 |
| `license_id` | `NULL` | 주장. 최대 128 바이트 |
| `requested_features` | 0 | 0 이면 보내지 않음 → 서버는 라이선스가 허용하는 기능 전체를 대상으로 판단 |
| `client_version_major/minor/patch` | 0 / 0 / 0 | CLIENT_HELLO 의 클라이언트 버전(서버의 최소 버전 정책용) |
| `connect_timeout_ms` | 10000 | 0 이면 기본값 유지. `SG_Client_Connect` 전체(시스템 proxy 조회, 이름 해석, TCP 연결, proxy 협상, TLS 핸드셰이크)의 **하나의** 예산 |
| `io_timeout_ms` | 30000 | 0 = 제한 없음. 인증/재인증 교환 전체, 모든 네트워크 쓰기, `SG_WAIT_DEFAULT` 수신 대기 |
| `max_payload_size` | 1048576 (1 MiB) | 0 이면 기본값, 16 MiB 초과 `SG_INVALID_ARGUMENT`. 송신 상한이자 **수신 상한**: 이보다 큰 DATA 를 받으면 `SG_PROTOCOL_ERROR` 로 연결이 닫힌다. 서버 `max_payload_size` 와 맞춘다 |
| `proxy` | `NULL` = DIRECT | 4 절 |
| `log_callback`, `log_user` | `NULL` = 기록 안 함 | `void SG_CALL cb(void* user, uint32_t level, const char* message)` |
| `log_level` | `SG_LOG_WARN` | `SG_LOG_NONE` … `SG_LOG_TRACE`. DEBUG/TRACE 는 Release 빌드에서 `SOCKGATE_ENABLE_DEBUG_LOG` 없이는 나오지 않는다 |
| `reserved0/1/2` | 0 | 0 으로 둔다 |

| 플래그 | 효과 |
|---|---|
| `SG_CLIENT_FLAG_APP_ENCRYPTION` | DATA payload 를 TLS 안에서 AES-256-GCM 으로 추가 암호화 (서버가 `REQUIRE_APP_ENCRYPTION` 이면 필수) |
| `SG_CLIENT_FLAG_ALLOW_TLS12` | TLS 1.2 허용 (EMS 필수) |
| `SG_CLIENT_FLAG_AUTO_IDENTITY` | `SG_Client_Authenticate` 가 identity 가 없으면 만든다 (없으면 `SG_NOT_FOUND`) |
| `SG_CLIENT_FLAG_INTEGRITY_REPORT` | 인증마다 integrity 관측을 보고. 실행 파일 해시는 Create 에서 미리 계산 |
| `SG_CLIENT_FLAG_AUTO_REFRESH` | 수명 80% 경과 후 Send/Receive 에 **진입할 때** 자동 재인증. 무한 대기 중인 Receive 는 돕지 못한다(6 절) |

`SG_Client_Create` 는 네트워크에 접속하지 않지만 **key store 는 생성한다**: FILE/AUTO/TPM2 는 key 디렉터리를
만들고 검증하며(실패 시 `SG_KEYSTORE_ERROR`), Windows 는 CNG provider 를 연다.

## 3. `SG_ServerConfig`

접속할 **서버**를 기술한다(서버 라이브러리 자체의 설정인 `SG_ServerOptions` 와 다르다). `SG_ServerConfig_Init` 은
`size`/`version` 외 모든 필드를 0/NULL 로 둔다. `SG_Client_Connect` 가 복사한다.

| 필드 | 기본값 | 의미와 제약 |
|---|---|---|
| `host` | `NULL` (**필수**) | DNS 이름 또는 IP literal, 최대 253 바이트 |
| `port` | 0 (**필수**) | 0 이면 `SG_INVALID_ARGUMENT` |
| `server_name` | `NULL` = `host` | 인증서에서 검증할 이름. DNS 이름이면 SNI 로도 보낸다. IP literal 은 iPAddress SAN 과 비교 |
| `ca_file` | `NULL` | PEM 번들 경로(최대 4096 바이트). 로드 실패 `SG_CERTIFICATE_ERROR` |
| `ca_pem`, `ca_pem_size` | `NULL`, 0 | 메모리 PEM. `ca_pem_size == 0` 이면 NUL 종료 문자열. 최대 16 MiB. 인증서가 하나도 없으면 `SG_CERTIFICATE_ERROR` |
| `flags` | 0 | `SG_TRUST_SYSTEM_STORE`, `SG_SERVER_FLAG_ALLOW_NO_PINNING`. 그 밖의 비트는 I/O 전에 `SG_NOT_SUPPORTED` |
| `spki_pin_count`, `spki_pins` | 0, `NULL` | SPKI SHA-256 배열, 최대 `SG_MAX_PINS` (8) |
| `proof_key_count`, `proof_keys` | 0, `NULL` | SEC1 비압축 P-256 공개키 배열, 최대 `SG_MAX_PROOF_KEYS` (4). 곡선 위 검증 실패 `SG_INVALID_ARGUMENT`. 설정하면 서버 서명 필수 |
| `reserved0/1` | 0 | |

신뢰 규칙(위반 시 `SG_INVALID_ARGUMENT`):

1. `ca_file`, `ca_pem`, `SG_TRUST_SYSTEM_STORE` 중 최소 하나.
2. `SG_TRUST_SYSTEM_STORE` 이면 pin 또는 proof key 가 최소 하나, 아니면 `SG_SERVER_FLAG_ALLOW_NO_PINNING` 을 명시.

```c
SG_Sha256 pins[2];              /* 현재 키 + 다음 키 */
/* SG_Client_ComputeSpkiPin(cert_pem, 0, &pins[0]); 또는 sg_admin pin <cert.pem> 결과를 넣는다 */
SG_ServerConfig server;
SG_ServerConfig_Init(&server);
server.host = "gate.example.com";
server.port = 7443;
server.ca_file = "/etc/example/gate-ca.pem";
server.spki_pins = pins;
server.spki_pin_count = 2;
```

## 4. `SG_ProxyConfig`

`SG_ProxyConfig_Init` 은 `mode = SG_PROXY_MODE_DIRECT` 와 0/NULL 을 채운다. `SG_ClientConfig.proxy` 로 넘기면
Create 가 복사한다(비밀번호는 복사 후 지운다).

| 필드 | 기본값 | 의미와 제약 |
|---|---|---|
| `mode` | `SG_PROXY_MODE_DIRECT` | `DIRECT`, `SYSTEM`, `EXPLICIT`. 그 밖 `SG_INVALID_ARGUMENT` |
| `type` | 0 | EXPLICIT 에서 필수: `SG_PROXY_TYPE_HTTP_CONNECT`, `SG_PROXY_TYPE_SOCKS4A`, `SG_PROXY_TYPE_SOCKS5` |
| `host`, `port` | `NULL`, 0 | EXPLICIT 에서 필수. host 최대 253 바이트, port ≠ 0 |
| `username` | `NULL` | 최대 255 바이트. HTTP: Basic 인증, SOCKS5: RFC 1929 user/password, SOCKS4a: user id |
| `password` | `NULL` | 최대 255 바이트. SOCKS4a 에서는 쓰지 않음 |

- **DIRECT**: 시스템 proxy 설정과 환경 변수를 무시하고 직접 연결.
- **SYSTEM**: Windows 는 WinHTTP 가 읽은 IE 설정의 정적 proxy(`https=` 항목 우선, 그다음 `socks=`(SOCKS4a 로 취급),
  `http=`, 단일 항목이면 그것)와 bypass 목록(`<local>` 포함). PAC/WPAD 만 설정된 경우 proxy 없이 직접 연결한다.
  Linux 는 `NO_PROXY`/`no_proxy` 에 해당하면 직접, 아니면 `ALL_PROXY`/`all_proxy`, 없으면 `HTTPS_PROXY`/`https_proxy`.
  URL scheme 은 `http`(기본 포트 8080), `socks4`/`socks4a`, `socks5`/`socks5h`(기본 1080). `https://` proxy 는
  `SG_NOT_SUPPORTED`, 형식 오류는 `SG_PROXY_ERROR`. 적용할 proxy 가 없으면 직접 연결.
- 대상 `host` 는 proxy 에 이름 그대로 전달되므로 영숫자와 `. - : _` 만 허용된다(그 밖은 Connect 에서 `SG_INVALID_ARGUMENT`).

```c
SG_ProxyConfig proxy;
SG_ProxyConfig_Init(&proxy);
proxy.mode = SG_PROXY_MODE_EXPLICIT;
proxy.type = SG_PROXY_TYPE_SOCKS5;
proxy.host = "proxy.corp.example";
proxy.port = 1080;
config.proxy = &proxy;          /* SG_Client_Create 전에 */
```

## 5. 호출 순서

```text
SG_Client_Create ─▶ SG_Client_EnsureIdentity ─▶ SG_Client_Connect ─▶ SG_Client_Authenticate
                                                      ▲                 (또는 SG_Client_Enroll)
                                                      │                          │
                                         재연결 ◀── 실패/만료/종료            ACTIVE
                                                      │                          │
                                                      │    SG_Client_SendEx / SG_Client_ReceiveEx / Ping
                                                      │    SG_Client_Refresh (또는 AUTO_REFRESH)
                                                      │                          │
                                                      └──── SG_Client_Disconnect ◀┘
                                                                    │
                                                            SG_Client_Destroy
```

```c
SG_Client* client = NULL;
SG_IdentityInfo id;
SG_Status st = SG_Client_Create(&config, &client);          /* 1. 핸들 + key store */
if (st != SG_OK) return st;

SG_IdentityInfo_Init(&id);
st = SG_Client_EnsureIdentity(client, &id);                  /* 2. 키 로드 또는 생성 */
/* id.installation_id, id.public_key, id.key_store_type, id.hardware_backed */

st = SG_Client_Connect(client, &server);                     /* 3. TCP(+proxy) + TLS + 서버 검증 */
if (st == SG_OK) st = have_token ? SG_Client_Enroll(client, token)   /* 4a. 첫 등록 */
                                 : SG_Client_Authenticate(client);  /* 4b. 이후 */

while (st == SG_OK && running) {                             /* 5. 데이터 */
    uint64_t rid = 0;
    st = SG_Client_SendEx(client, req, req_len, 0, &rid);
    if (st != SG_OK) break;
    SG_MessageInfo info;
    SG_MessageInfo_Init(&info);
    size_t n = 0;
    st = SG_Client_ReceiveEx(client, buf, sizeof(buf), &n, &info, SG_WAIT_DEFAULT);
    if (st == SG_TIMEOUT) { st = SG_OK; continue; }          /* 수신 타임아웃은 치명적이지 않다 */
}
SG_Client_Disconnect(client);                                /* 7. 멱등 */
SG_Client_Destroy(client);                                   /* 8. 다른 호출과 동시에 하지 않는다 */
```

단계별 요점:

1. **Create**: 설정 복사, key store 생성. 네트워크 접근 없음.
2. **EnsureIdentity**: 키가 있으면 로드, 없으면 생성. `info` 는 NULL 가능. 이미 있는 identity 만 조회하려면
   `SG_Client_GetIdentity`(없으면 `SG_NOT_FOUND`).
3. **Connect**: `DISCONNECTED` / `CLOSED` / `EXPIRED` 에서만(연결 중이면 `SG_INVALID_STATE`, 먼저 Disconnect).
   재연결은 항상 새 TCP, 새 TLS, 새 인증이다.
4. **Authenticate / Enroll**: `TLS_ESTABLISHED` 에서만. 성공하면 `ACTIVE`. `SG_Client_GetSessionInfo` 로 서버가 준
   `policy`, `granted_features`, `license_expires_at_ms`, `expires_in_ms`, TLS 버전/스위트를 확인한다.
5. **Send / Receive**: 1 호출 = 1 메시지 = 1 DATA 프레임. `ACTIVE` / `REFRESHING` 에서만.
6. **Refresh**: 수명이 끝나기 전에 재인증. `ACTIVE` 에서만. 최초 인증 또는 서버가 직전에 받아들인 REAUTH_REQUEST
   (challenge 발급 시점) 이후 서버의 `min_reauth_interval_ms`(기본 10 s) 이내에 호출하면 서버가 연결을 닫으므로 너무
   이르게 호출하지 않는다.
7. **Disconnect**: 어느 스레드에서나 호출 가능, 대기 중인 호출을 깨운다. 진행 중인 Connect 는 어느 단계(시스템 proxy 조회,
   TCP/proxy, 링크 게시 직전, TLS)에서든 `SG_CLOSED` 를 반환한다(로그 `event=connect_aborted`; 이미 판정된 인증서/pin
   실패는 그대로 보고). 활성 세션이면 CLOSE(NORMAL) 와 close_notify 를 각각 최대 200 ms 동안 best effort 로 보낸다.
8. **Destroy**: Disconnect 를 포함한다. `NULL` 은 `SG_OK`. 같은 핸들의 다른 호출과 동시에 부르면 안 된다.

## 6. Blocking 과 타임아웃

모든 호출은 호출 스레드에서 블록된다. 라이브러리는 스레드를 만들지 않는다.

| 호출 | 제한 |
|---|---|
| Connect | 시스템 proxy 조회 + 이름 해석 + TCP 연결(해석된 주소 순차 시도) + proxy 협상 + TLS 핸드셰이크가 `connect_timeout_ms` 하나를 나눠 쓴다. 각 단계는 남은 시간만 받고, TCP/proxy 단계가 예산을 다 쓰면 TLS 없이 `SG_TIMEOUT`. **한 번의 resolver 호출(`getaddrinfo`)은 중단할 수 없다**(걸린 시간은 예산에서 빠지고, 그 뒤 예산이 없으면 TCP 연결을 시작하지 않는다) |
| Authenticate / Enroll / Refresh | 교환 전체 = `io_timeout_ms` (0 = 무제한). 시간 초과는 `SG_TIMEOUT` 이며 연결이 닫힌다 |
| Send(Ex), Ping | 네트워크 쓰기 = `io_timeout_ms`. 시간 초과는 연결을 닫는다(부분 기록된 TLS 스트림은 복구 불가) |
| `SG_Client_Receive` | `SG_Client_ReceiveEx(..., SG_WAIT_DEFAULT)` 와 같다 |
| `SG_Client_ReceiveEx` `timeout_ms` | `SG_WAIT_DEFAULT` = `io_timeout_ms`(0 이면 무한), `SG_WAIT_INFINITE` = 메시지나 연결 종료/Disconnect 까지, `0` = 즉시 확인(약 1 ms), 그 밖 = 밀리초 |
| Disconnect | CLOSE / close_notify 각 200 ms 상한. 깨어난 호출이 빠져나갈 때까지 기다린다 |

- Receive 의 `SG_TIMEOUT` 은 **치명적이지 않다**. 세션은 `ACTIVE` 로 남는다.
- `SG_BUFFER_TOO_SMALL` 이면 `*received` 에 필요한 크기가 들어가고 메시지는 큐에 남는다. 더 큰 버퍼로 다시 호출한다.
  `buffer = NULL, capacity = 0` 도 허용되므로 크기만 알아내는 데 쓸 수 있다.
- 받은 PING 에 대한 PONG 응답과 PONG/CLOSE 처리는 Receive 안에서 일어난다. 서버의 idle 타임아웃(서버 기본 5 분)은
  서버가 **클라이언트로부터** 검증된 프레임을 받은 시각 기준이므로, 보낼 데이터가 없는 동안에는 주기적으로
  `SG_Client_Ping` 을 보낸다. idle 로 닫히면 이후 호출은 `SG_CLOSED` 이다.
- 수신 큐가 64 MiB 를 넘으면 `SG_LIMIT_EXCEEDED` 로 연결이 닫힌다.
- 자동 재인증은 Send/Receive 에 **진입할 때만** 수명의 80% 가 지났는지 확인하고, 수신 측 잠금을 `try_lock` 으로만
  잡는다. 그래서 다른 스레드가 Receive 에서 대기 중이면 Send 쪽의 자동 재인증은 미뤄지고, `SG_WAIT_INFINITE` 로 막혀 있는
  수신 스레드는 메시지가 올 때까지 다시 진입하지 않는다. **`AUTO_REFRESH` 만으로는 무한 대기 수신 스레드를 구하지 못한다.**
  수신 스레드는 유한한 타임아웃으로 Receive 를 반복하되, 재진입 간격이 재인증 창(수명의 마지막 20%)보다 충분히 짧아야
  한다(예: 기본 수명 1 시간이면 수 분 이하). 그러면 `SG_TIMEOUT` 뒤의 다음 Receive 진입에서 재인증이 실행된다.
- 자동 재인증은 그 Send/Receive 호출을 재인증 시간만큼 늦춘다. **수동 `SG_Client_Refresh` 는 대기 중인 Receive 가 끝날
  때까지 기다린다**(수신 측 잠금을 기다림) — 이 경우에도 수신 스레드는 유한한 타임아웃을 써야 한다.
- 재인증 서명은 서버가 challenge 를 보낸 뒤 서버의 `challenge_ttl_ms`(기본 30 s) 안에 도착해야 한다. 서명이 느리면(예:
  느린 TPM) 서버가 CLOSE(AUTH_FAILED) 로 닫고 클라이언트는 `SG_SERVER_REJECTED` 를 받는다.

## 7. 요청 ID

- 응답이 아닌 모든 DATA 는 방향별로 단조 증가하는 요청 ID 를 갖는다. `SG_Client_SendEx(..., 0, &out_request_id)` 가
  그 값을 돌려준다(`SG_Client_Send` 는 버린다).
- 상대의 요청에 응답하려면 `reply_to_request_id` 에 그 요청의 ID 를 준다. 이때 `*out_request_id` 는 0 이다.
  상대가 보낸 적 없는 ID(받은 최대 요청 ID 초과)에 응답하면 **로컬에서** `SG_INVALID_ARGUMENT` 이고 전송되지 않으며
  연결은 유지된다.
- 수신 메시지의 `SG_MessageInfo.request_id` 와 `flags`: `SG_MESSAGE_FLAG_RESPONSE` 이면 우리 요청에 대한 응답이고
  `request_id` 는 우리가 보낸 ID 다. 아니면 상대의 요청 ID 다(SockGate 서버는 항상 0 이 아닌 ID 를 붙인다).
  `SG_MESSAGE_FLAG_ENCRYPTED` 는 애플리케이션 계층 암호화 여부.
- 상대가 요청 ID 를 되풀이하면 `SG_REPLAY_DETECTED`, 우리가 지금까지 할당한 최대 요청 ID 보다 큰 ID 에 응답하면
  `SG_PROTOCOL_ERROR` 로 연결이 닫힌다. 같은 요청에 대한 중복 응답이나, 할당했지만 보내지 못한 ID 에 대한 응답은
  라이브러리가 거부하지 않는다.
- 요청-응답 짝 맞추기는 애플리케이션 몫이다. 예제 `sg_echo_client` 는 받은 메시지가 `SG_MESSAGE_FLAG_RESPONSE` 를 갖고
  `request_id` 가 방금 보낸 요청의 ID 와 같은지 확인하고, 아니면 루프를 끝낸다. payload 는 인증된 서버가 보낸 것이라도
  비신뢰 데이터이므로 예제는 출력할 수 없는 바이트를 `\xNN` 으로 escape 해 터미널을 조작하지 못하게 한다.

```c
uint64_t rid = 0;
st = SG_Client_SendEx(client, line, length, 0, &rid);
if (st == SG_OK) {
    SG_MessageInfo_Init(&info);
    st = SG_Client_ReceiveEx(client, reply, sizeof(reply), &received, &info, SG_WAIT_DEFAULT);
}
if (st == SG_OK && (!(info.flags & SG_MESSAGE_FLAG_RESPONSE) || info.request_id != rid)) {
    /* 우리 요청에 대한 응답이 아니다 */
}
```

## 8. 호출별 오류 처리

분류: **재시도** = 같은 설정으로 (백오프와 함께) 다시 연결/호출, **재등록** = identity 를 다시 등록하거나 enroll,
**설정** = 코드나 설정을 고쳐야 함, **보안** = 공격 가능성이 있으므로 자동 재시도로 덮지 말고 알림.
다음 표에 없는 `SG_OUT_OF_MEMORY`, `SG_INTERNAL_ERROR` 는 어느 호출에서나 나올 수 있다.

| 호출 | 코드 | 의미 | 조치 |
|---|---|---|---|
| Create | `SG_INVALID_ARGUMENT` | NULL, 이름 규칙 위반, 문자열 길이, `max_payload_size` > 16 MiB, 알 수 없는 key store, 구조체 크기/버전, 잘못된 proxy 설정, 허용되지 않은 `SOCKGATE_TPM2_TCTI` | 설정 |
| Create | `SG_NOT_SUPPORTED` | 알 수 없는 플래그, 이 플랫폼/빌드에 없는 key store, 0 이 아닌 미지 필드, AUTO 인데 쓸 수 있는 저장소 없음 | 설정 |
| Create | `SG_KEYSTORE_ERROR` | key 디렉터리를 만들거나 검증할 수 없음(소유자, 권한, 링크, ACL) | 환경 점검 |
| EnsureIdentity / GetIdentity | `SG_NOT_FOUND` | (GetIdentity) identity 없음 | EnsureIdentity 또는 Enroll |
| EnsureIdentity / GetIdentity | `SG_KEYSTORE_ERROR` | 기록된 저장소를 지금 쓸 수 없음(TPM provider/서비스), 파일 검사/무결성 실패, 일시적 TPM 오류 | 재시도, 지속되면 환경 점검. **identity 를 지우지 않는다.** TPM 을 쓸 수 있는지는 `SG_Client_Create` 때 정해지므로(아래 주) 같은 핸들로는 회복되지 않을 수 있다: Destroy + Create 후 재시도 |
| EnsureIdentity / GetIdentity | `SG_IDENTITY_LOST` | 기록된 저장소는 동작하지만 키가 없음(예: 키 파일 삭제). Linux TPM2 clear 는 여기가 아니라 서명 시 `SG_KEYSTORE_ERROR` 로 나타난다 | 재등록 ([SECURITY.md §4.4](SECURITY.md#44-sg_identity_lost-처리)) |
| EnsureIdentity | `SG_NOT_SUPPORTED` | 키를 만들 수 있는 저장소 없음(예: `SG_KEYSTORE_CNG_TPM` 인데 TPM 2.0 없음) | 설정 (다른 key store) |
| DeleteIdentity(Ex) | `SG_INVALID_STATE` | 연결 중 | Disconnect 후 |
| DeleteIdentity(Ex) | `SG_NOT_FOUND` | 지울 identity 없음 | 무시 가능 |
| DeleteIdentity(Ex) | `SG_KEYSTORE_ERROR` | 기록된 저장소를 쓸 수 없어 거부 | 재시도 또는 `SG_IDENTITY_DELETE_FORCE` |
| Connect | `SG_INVALID_STATE` | 이미 연결/인증 중 | Disconnect 후 |
| Connect | `SG_INVALID_ARGUMENT` | 3 절의 신뢰 규칙, 필드 제약(상태 변화 없음), proxy 대상 host 문자(`CONNECTING` 이후에 검사되므로 상태는 `CLOSED`) | 설정 |
| Connect | `SG_NETWORK_ERROR`, `SG_TIMEOUT` | 이름 해석/연결 실패, `connect_timeout_ms` 예산 소진 | 재시도 |
| Connect | `SG_PROXY_ERROR` | proxy 연결 실패, 거부(407/403/502 등), 형식 오류 | 재시도 또는 proxy 설정 |
| Connect | `SG_NOT_SUPPORTED` | 모르는 `SG_ServerConfig.flags` 비트나 0 이 아닌 미지 필드(I/O 전, 상태 변화 없음), SYSTEM proxy 가 지원하지 않는 scheme(`https://`) | 설정 |
| Connect | `SG_CERTIFICATE_ERROR` | CA 로드 실패, 체인·이름·유효기간 실패 | 설정 / 서버 인증서 / 시계 |
| Connect | `SG_PINNING_ERROR` | 신뢰된 체인이지만 pin 불일치 (`possible_tls_interception`) | **보안** |
| Connect | `SG_TLS_ERROR` | TLS 협상 실패, TLS 1.2 without EMS, 상대가 핸드셰이크 중 종료(예: 서버의 미인증 연결 상한 `max_unauthenticated` 초과로 accept 직후 닫힘) | 재시도(백오프), 지속되면 설정 |
| Connect | `SG_CLOSED` | 다른 스레드의 Disconnect — 어느 단계에서든(proxy·TLS 오류로 보고되지 않는다, 991a1b6) | 의도된 종료 |
| Authenticate / Enroll | `SG_INVALID_STATE` | `TLS_ESTABLISHED` 가 아님 | Connect 먼저 |
| Authenticate | `SG_NOT_FOUND` | identity 없음, `AUTO_IDENTITY` 아님. 연결은 `TLS_ESTABLISHED` 로 유지 | EnsureIdentity 후 다시 Authenticate |
| Authenticate / Enroll | `SG_KEYSTORE_ERROR`, `SG_IDENTITY_LOST` | 위와 같음 | 위와 같음 |
| Enroll | `SG_INVALID_ARGUMENT` | NULL/빈/1024 자 초과/형식이 틀린 token. 연결 유지 | 올바른 token |
| Authenticate / Enroll | `SG_INVALID_ARGUMENT` | 제품/라이선스 문자열이 프로토콜 문자열 규칙 위반. 연결이 닫힌다 | 설정 |
| Authenticate / Enroll | `SG_SERVER_REJECTED` | 미등록, 폐기, 서명 오류, challenge TTL 초과(느린 서명), token 무효/사용됨/만료, 제품·라이선스 불일치, 인가 거부, 서버 과부하(RETRY_LATER), TLS 1.2 에서 채널 바인딩 변경(b95a843) 전후 빌드 혼용 — 구분되지 않는다 | 몇 번 재시도 후 운영자 확인. 거부 결과는 서명되지 않으므로(아래 주) 이 코드만 보고 자동으로 재등록하지 않는다 |
| Authenticate / Enroll | `SG_VERSION_MISMATCH` | 프로토콜 버전 교집합 없음 | 운영자 확인 후 업그레이드(이 결과도 서명되지 않는다) |
| Authenticate / Enroll | `SG_INVALID_SIGNATURE` | server proof 누락/불일치 | **보안** (또는 proof key 설정 오류) |
| Authenticate / Enroll | `SG_PROTOCOL_ERROR`, `SG_TIMEOUT`, `SG_CLOSED`, `SG_NETWORK_ERROR`, `SG_TLS_ERROR` | 형식 위반, 무응답, 서버가 연결을 끊음 | 재시도 (새 Connect) |
| Send(Ex) / Ping | `SG_INVALID_ARGUMENT` | NULL 데이터, `size > max_payload_size`, 받은 적 없는 요청에 대한 응답. 연결 유지 | 코드 |
| Send / Receive / Ping | `SG_INVALID_STATE` | 인증되지 않음 | Connect + Authenticate |
| Send / Receive / Ping | `SG_CLOSED` | 연결이 닫힘(서버 CLOSE, idle, 서버 종료, Disconnect). Receive 는 그 전에 받아 둔 메시지를 먼저 돌려준다 (Disconnect 뒤에는 없음) | 재연결 |
| Send / Receive / Ping | `SG_SESSION_EXPIRED` | 세션 수명 만료 (`EXPIRED`). Receive 는 이미 받아 둔 메시지를 먼저 돌려준다 | 재연결 + 인증. 미리 Refresh/AUTO_REFRESH |
| Send / Ping | `SG_TIMEOUT`, `SG_NETWORK_ERROR`, `SG_TLS_ERROR` | 쓰기 실패, 연결 닫힘 | 재연결 |
| Receive(Ex) | `SG_TIMEOUT` | 대기 시간 안에 메시지 없음. **세션 유지** | 계속 |
| Receive(Ex) | `SG_BUFFER_TOO_SMALL` | `*received` = 필요 크기. 메시지 보존 | 더 큰 버퍼 |
| Receive(Ex) | `SG_SERVER_REJECTED` | 서버가 CLOSE(AUTH_FAILED): installation/라이선스 폐기, 좌석 반납, 또는 진행 중인 재인증의 서명이 `challenge_ttl_ms` 안에 오지 않음 | 무작정 재연결하지 않는다. 운영자 확인 |
| Receive(Ex) | `SG_REPLAY_DETECTED`, `SG_PROTOCOL_ERROR` | 채널 규칙 위반, 변조, 과대 DATA | **보안** (반복되면), 재연결 |
| Receive(Ex) | `SG_LIMIT_EXCEEDED` | 수신 큐 64 MiB 초과 | 더 자주 Receive |
| Send / Receive | (AUTO_REFRESH) Refresh 의 오류 | 자동 재인증 실패 | Refresh 행 참고 |
| Refresh | `SG_INVALID_STATE` | `ACTIVE` 가 아님(REFRESHING 포함) | 상태 확인 |
| Refresh | `SG_SESSION_EXPIRED` | 이미 만료 | 재연결 + 인증 |
| Refresh | `SG_SERVER_REJECTED` | 재인증 거부(폐기, 라이선스 변경) 또는 서명이 `challenge_ttl_ms`(기본 30 s)를 넘김 | 운영자 확인 (느린 서명이면 재연결 후 재시도) |
| Refresh | 그 밖 (`SG_CLOSED`, `SG_PROTOCOL_ERROR`, `SG_TIMEOUT` …) | 너무 이른 재인증(서버 rate limit) 포함, 연결 닫힘 | 재연결 |
| Disconnect | `SG_OK` (`NULL` 이면 `SG_INVALID_ARGUMENT`) | 멱등 | |

주:

- **거부 결과는 서명되지 않는다.** server proof key 는 `AUTH_RESULT(OK)` 만 인증한다. REJECTED / RETRY_LATER /
  UNSUPPORTED_VERSION 은 서명 없이 오므로, pin 없이(예: OS store + proof key 만) 연결한 가짜 서버는 `SG_SERVER_REJECTED` 나
  `SG_VERSION_MISMATCH` 를 만들어 낼 수 있고, 그 시점에 이미 CLIENT_HELLO 의 주장(제품, 라이선스 ID, integrity 보고)을 보았다.
  이 코드들을 근거로 자동 재등록·업그레이드를 하지 말고, 주장을 가짜 서버에게서 지키려면 사설 CA + pin 을 쓴다.
- **TPM 도달 가능 여부는 `SG_Client_Create` 때 정해진다.** Linux TPM2 는 그때 TCTI(`SOCKGATE_TPM2_TCTI` 또는
  `/dev/tpmrm0`)를 고르고, Windows 는 그때 열 수 없던 TPM provider 를 AUTO 목록에서 뺀다(어떤 이유로든 열지 못하면 "지원 안
  함" 으로 취급). 같은 핸들로 재시도해도 회복되지 않으므로 `SG_Client_Destroy` 후 다시 Create 한다.
- **TPM clear/reset 뒤**: Linux TPM2 는 키 blob 파일이 그대로 파싱되므로 identity 조회는 성공하고, 서명 단계에서 계속
  `SG_KEYSTORE_ERROR` 가 난다. Windows CNG 의 TPM clear 뒤 동작은 검증되지 않았다. TPM 을 clear/reset 한 것이 확실한데
  `SG_KEYSTORE_ERROR` 가 계속되면 `SG_Client_DeleteIdentityEx(client, SG_IDENTITY_DELETE_FORCE)` 후 새 identity 로 다시
  등록/enroll 한다.

`SG_StatusString(status)` 는 코드 이름을 돌려준다(never NULL). 로그 콜백을 연결해 두면 실패 원인(예: `tls_failed ...
detail="certificate verification failed: ..."`)을 볼 수 있다.

실패 후 상태: `AUTHENTICATING` 이후의 인증 실패, 세션 중 치명적 오류, Connect 의 네트워크/TLS 실패는 모두 `CLOSED`
(만료는 `EXPIRED`)로 끝나며, 다시 `SG_Client_Connect` 부터 시작하면 된다. `SG_Client_GetState` 로 확인할 수 있다.

## 9. Installation 등록: out-of-band vs enrollment

클라이언트의 신원은 installation 키이고, `installation_id = SHA-256("SockGate/v1/iid" ‖ public_key)[0..16)` 는 공개키에서
유도된다(비밀이 아니다). 서버가 공개키를 알아야 인증할 수 있다. 개인키는 어떤 경로로도 서버에 가지 않는다.

### 9.1 Out-of-band 등록

1. 클라이언트: `SG_Client_EnsureIdentity(client, &id)` → `id.public_key`(65 바이트 SEC1 `0x04‖X‖Y`)와
   `id.installation_id`. 예제 `sg_echo_client` 는 둘을 hex 로 출력한다:
   ```text
   installation id: 3f9c...
   public key:      04a1...
   ```
2. 관리자: 서버 API `SG_Server_RegisterClient`(`SG_ClientRecord.public_key`, 선택적 `product_id`/`license_id` 바인딩)
   또는 서버가 멈춘 상태에서
   `sg_admin client register --registry FILE --pubkey HEX [--product P] [--license L [--licenses FILE]]`
   (`--pubkey` 는 130 자리 hex, `--licenses` 를 주면 서버와 같은 바인딩 검사: 라이선스가 있고 활성이며 같은 제품).
   서버는 실행 중 registry/license 파일을 잠그므로, 서버가 쓰고 있으면 `sg_admin` 은 "the store is in use" 로 거부한다.
3. 클라이언트: `SG_Client_Connect` → `SG_Client_Authenticate`.

미등록 상태에서 Authenticate 하면 `SG_SERVER_REJECTED` 이다(서버는 미등록과 서명 오류를 구분해 알려주지 않는다).

### 9.2 Enrollment token

1. 서버가 `SG_SERVER_OPT_ALLOW_ENROLLMENT` 를 켜고 token 을 발급한다: `SG_Server_IssueEnrollmentToken`
   (`product_id` 필수, `license_id` 선택, `ttl_ms` 기본 24 h, 최대 30 일) 또는
   `sg_admin token issue --key FILE --product P [--license L [--licenses FILE]] [--ttl-ms N]`(`--ttl-ms` 는 1 ms..30 일).
2. token 문자열을 안전한 경로로 클라이언트에 전달한다. 로그나 명령줄 인자로 넘기지 않는다(프로세스 목록과 셸 기록에
   남는다). 예제 `sg_echo_client --enroll-file FILE` 은 token 을 파일에서 읽는다(파일은 owner 만 읽을 수 있게 둘 것을
   권장; 예제가 권한을 검사하지는 않는다). 파일 전체를 stdio 버퍼 없이 읽어 끝의 공백·개행을 지우고, 1023 바이트를 넘거나
   읽을 수 없으면 거부하며, Enroll 직후 버퍼를 volatile 저장으로 지운다(86cb919). 이후 읽지 않는 버퍼의 `memset` 은
   컴파일러가 없앨 수 있으므로, 애플리케이션도 `SecureZeroMemory`, `explicit_bzero` 나 volatile 루프처럼 없어지지 않는
   방법으로 지운다.
3. 클라이언트: `SG_Client_Connect` → `SG_Client_Enroll(client, token)`. identity 가 없으면 이때 만든다. 성공하면 그 연결은
   곧바로 `ACTIVE` 세션이고, 이후 연결은 `SG_Client_Authenticate` 를 쓴다.
4. 애플리케이션이 가진 token 사본을 지운다(라이브러리는 자기 사본을 지운다).

주의:

- token 은 1회용이며 만료된다. 같은 token 을 다시 쓰면 `SG_SERVER_REJECTED`. 서버는 사용 시점에도 수명(만료 − 발급)이
  30 일을 넘는 token 을 거부한다.
- token 의 claims(제품, 라이선스)가 권한 판단에 쓰인다. `SG_ClientConfig.product_id` / `license_id` 를 설정했다면 token
  의 값과 정확히 같아야 한다(다르면 거부). 비워 두면 보내지 않는다.
- token 비밀은 전송되지 않고 채널 바인딩된 MAC 으로만 증명되므로 TLS MITM 이 token 을 훔쳐 자기 키로 등록할 수 없다.
  그래도 가짜 서버가 enrollment 를 가로채는 것은 서버 인증(pin/proof key)으로만 막을 수 있다.

## 10. 라이선스 (클라이언트 관점)

- `product_id`, `product_version`, `license_id`, `requested_features` 는 **주장**이다. 서버는 registry 바인딩(등록 또는
  token 에서 온 것)을 우선하고, 바인딩과 다른 주장은 거부한다. 바인딩이 없는 installation 이 주장한 `license_id` 는
  검증되지 않은 주장으로 아무 권한도 주지 않는다(서버가 `SG_SERVER_OPT_LICENSE_ACTIVATION` 을 켠 경우에만 처음 주장한
  라이선스가 활성화되어 영구히 바인딩된다).
- 부여된 권한은 서버의 AUTH_RESULT 에서 온다: `SG_ClientSessionInfo.granted_features`
  (= 요청 ∩ 라이선스 기능, 요청이 0 이면 라이선스 기능 전체, `on_authorize` 가 조정 가능),
  `policy`(`SG_SESSION_POLICY_NORMAL` / `RESTRICTED`, RESTRICTED 의 의미는 애플리케이션이 정함),
  `license_expires_at_ms`(0 = 라이선스에 묶이지 않음). 세션 수명은 라이선스 만료를 넘지 않는다.
- 라이선스 조건 변경은 다음 재인증부터 반영되고, 폐기는 즉시 세션을 닫는다(Receive 에서 `SG_SERVER_REJECTED`).
- 클라이언트 쪽의 기능 제한은 편의일 뿐이다. 보안이 필요한 기능은 서버가 세션의 `granted_features` 로 검사해야 한다.
  클라이언트가 보는 값의 신뢰도는 서버 인증(사설 CA, pin, proof key)의 강도와 같다.

## 11. ABI 규칙

- 모든 구조체는 `{ uint32_t size; uint32_t version; }` 로 시작한다. **항상 `*_Init()` 으로 초기화**한 뒤 필드를 설정한다.
  입력: `SG_ClientConfig_Init`, `SG_ServerConfig_Init`, `SG_ProxyConfig_Init`. 출력: `SG_IdentityInfo_Init`,
  `SG_ClientSessionInfo_Init`, `SG_MessageInfo_Init`.
- 라이브러리는 `size` 안에 있는 필드만 읽는다. 구 헤더로 빌드한 바이너리는 (같은 ABI 계열의) 새 라이브러리에서 그대로
  동작한다.
- **0.x 동안은 어느 minor 버전이든 ABI 를 깰 수 있다.** 그래서 Linux soname 은 `libsockgate_client.so.0.1` 처럼
  `MAJOR.MINOR` 를 포함하고, `find_package(SockGate 0.1)` 은 0.1.x 만 받아들인다(`SameMinorVersion`). 1.0 부터는
  soname 과 패키지 호환성이 `MAJOR` 기준이 된다([BUILD.md §4](BUILD.md#4-공유-vs-정적-라이브러리)).
- 새 헤더로 빌드한 애플리케이션이 구 라이브러리에 더 큰 구조체를 넘기면, 라이브러리가 모르는 뒤쪽 필드는 **0 이어야
  한다**. 0 이 아니면 `SG_NOT_SUPPORTED`(보안 설정을 조용히 잃지 않게), 알려진 크기보다 4 KiB 넘게 크면
  `SG_INVALID_ARGUMENT`. `*_Init()` 은 모든 필드를 0 으로 채우므로 이 규칙을 자동으로 지킨다.
- `version == 0` 은 `SG_INVALID_ARGUMENT`. 필수 필드까지 덮지 못하는 `size` 도 `SG_INVALID_ARGUMENT`(입력: ClientConfig 는
  `identity_name`, ServerConfig 는 `port`, ProxyConfig 는 `mode`, 출력: IdentityInfo 는 `hardware_backed`, SessionInfo 는
  `tls_cipher`, MessageInfo 는 `flags` 까지).
- 열거형은 `uint32_t` 필드와 `#define` 상수로 전달된다. 알 수 없는 `SG_CLIENT_FLAG_*` 비트(Create)와
  `SG_ServerConfig.flags` 비트(Connect)는 `SG_NOT_SUPPORTED`.
- 문자열은 NUL 종료 UTF-8 이며 상한 길이가 있다. 라이브러리는 호출자에게 메모리를 할당해 넘기지 않는다(출력은 호출자
  버퍼로 복사).
- `SG_Status` 값은 ABI 의 일부로 바뀌지 않고 끝에만 추가된다. 모르는 값은 `SG_StatusString` 이 `"SG_UNKNOWN_STATUS"`.
- 공개 함수의 호출 규약은 `SG_CALL`(Windows `__cdecl`). 로그 콜백도 `SG_CALL` 로 선언한다.
- 정적 라이브러리를 CMake 없이 쓰면 `SOCKGATE_CLIENT_STATIC` 을 정의한다([BUILD.md §4](BUILD.md#4-공유-vs-정적-라이브러리)).

## 12. 스레드 사용 패턴

- 송신 스레드와 수신 스레드를 나눠도 된다(`Send` ↔ `Receive` 동시 호출 허용). 같은 방향의 동시 호출은 직렬화된다.
- 종료는 다른 스레드에서 `SG_Client_Disconnect` 를 호출해 대기 중인 호출을 깨운 뒤, 모든 스레드가 API 에서 빠져나온
  것을 확인하고 `SG_Client_Destroy` 한다.
- Connect/Authenticate/Refresh/DeleteIdentity 는 한 번에 하나씩 실행된다. 상세한 보장은
  [ARCHITECTURE.md §3](ARCHITECTURE.md#3-공개-api-의-스레드-안전성).
- 로그 콜백은 API 를 호출한 스레드에서 내부 잠금을 잡은 채 불릴 수 있으므로, 콜백 안에서 같은 핸들의 API 를 호출하지
  않고 빨리 반환한다.
