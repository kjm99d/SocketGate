# SockGate_Server Threat Model

서버 라이브러리 관점의 위협 모델이다. 시스템 전체의 STRIDE 분석은
[02-threat-model.md](../docs/design/02-threat-model.md), 신뢰 경계는 [03-trust-boundary.md](../docs/design/03-trust-boundary.md),
보장하지 않는 것은 [13-security-limitations.md](../docs/design/13-security-limitations.md) 를 기준으로 한다.
아래 대응은 모두 현재 코드에 구현된 것이다.

## 1. 서버측 자산

| ID | 자산 | 위치 | 유출·변조 시 |
|---|---|---|---|
| S1 | 서버 TLS 개인키 | `tls_private_key_file` / `tls_private_key_pem` (로드 후 메모리 PEM 사본은 지움) | 서버 사칭 (pinning 없는 클라이언트 대상) |
| S2 | 서버 proof key (선택) | `proof_key_file` / `proof_key_pem` | proof key 를 요구하는 클라이언트에 대한 서버 사칭 |
| S3 | Enrollment token key (`server_token_key`) | `token_key` 또는 `SG_Server_Create` 시 무작위 생성 | 임의 enrollment token 위조 → 공격자 키 등록 |
| S4 | Client registry | `registry_path` 또는 메모리 | 공개키 교체·추가, 폐기 해제, token 재사용 허용 |
| S5 | License store | `license_path` 또는 메모리 | 라이선스 추가·연장·기능 확대, 좌석 조작 |
| S6 | 인증된 세션 | `Connection` (메모리) | 권한 있는 요청 수행 |
| S7 | 세션 키 / 채널 바인딩 / transcript | 연결 메모리 (종료·rekey 시 cleanse) | 해당 세션 위조 |
| S8 | 라이선스 ID (`SG_SERVER_OPT_LICENSE_ACTIVATION` 사용 시) | license store, 발급 경로 | bearer secret — 추측·유출 시 좌석 도용 |
| S9 | 서버 가용성 | 연결, 메모리, CPU, 파일 descriptor | 서비스 거부 |

## 2. 공격자

| ID | 공격자 | 서버에 대한 능력 |
|---|---|---|
| A1/A2 | 수동·능동 네트워크 공격자 | 관찰, 변조, 삽입, 삭제, 재전송, 재정렬 |
| A3/A4 | Proxy 운영자, 사용자 설치 CA 로 TLS 를 종단하는 MITM | 클라이언트–서버 사이에서 TLS 를 두 번 종단하고 인증 메시지를 중계 |
| A5 | 자격 증명 없는 원격 클라이언트 | 임의 바이트, 대량·저속 연결, 파서 공격 |
| A6 | 자격 증명을 가진 악성 클라이언트 | 정상 인증 후 임의 프레임, 클레임 조작, 권한 상승 시도 |
| A7 | 클라이언트 호스트를 장악한 공격자 | 클라이언트가 보내는 모든 값(클레임, integrity 보고) 위조, installation 키로 서명 요청 |
| A9 | 서버 저장소 접근자 | registry / license 파일 읽기·쓰기 |

서버 호스트 자체, 서버 프로세스 메모리, 서버 개인키는 신뢰한다 (02 §5 가정 1). 임베딩 애플리케이션과 그 콜백도 신뢰 주체이다.

## 3. 신뢰 경계

```text
                network (비신뢰: A1–A5)
                        │
                        │ TB1  모든 바이트 비신뢰 (TLS 이전·이후 모두)
┌───────────────────────┼──────────────────────── Server Host (신뢰) ─────────────────────────┐
│                       ▼                                                                      │
│   TLS 종단 (OpenSSL) ──TB2──▶ FrameDecoder / 메시지 디코더 / ProtectedChannel                  │
│                                        │                                                     │
│                                        │ TB3  클라이언트 값은 "주장"                            │
│                                        ▼                                                     │
│                    ServerHandshake ─▶ BuiltinAuthorizer ─▶ on_authorize ─▶ 세션 권한 확정       │
│                                        │                                                     │
│   Application ──TB4──▶ C ABI           └──TB6──▶ registry / license 파일 (파일도 비신뢰 입력으로 파싱) │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

| 경계 | 서버 검증 주체 | 실패 시 |
|---|---|---|
| TB1 | OpenSSL (TLS 1.3, 선택적 TLS 1.2 + EMS) | TLS 실패, 연결 종료 |
| TB2 | `FrameDecoder` + `CheckHeaderForState`, 메시지 디코더, `ProtectedChannel` | 연결 종료 (인증 후에는 CLOSE(PROTOCOL_ERROR)) |
| TB3 | `ServerHandshake`, `BuiltinAuthorizer` | 일반화된 AUTH_RESULT(REJECTED) |
| TB4 | `server_api.cpp` (NULL, `size`/`version`, 문자열 길이, 알 수 없는 뒤쪽 필드) | `SG_INVALID_ARGUMENT` / `SG_NOT_SUPPORTED` |
| TB6 | registry / license 로더 | `SG_Server_Create` 실패 (`SG_STORAGE_ERROR`) |

## 4. 위협과 대응

### 4.1 위조된 클레임 (A6, A7)

클라이언트가 CLIENT_HELLO 에 싣는 `product_id`, `product_version`, `license_id`, `requested_features`, `client_version`,
integrity 보고는 모두 **주장**이다. 프로토콜에는 "인증됨", "라이선스 유효", "관리자" 같은 필드가 없다.

| 위협 | 대응 |
|---|---|
| 다른 제품·라이선스를 주장해 권한 획득 | registry 에 기록된 product/license 바인딩이 우선하고, 다른 주장은 거부된다 |
| 바인딩 없는 installation 이 남의 라이선스 ID 를 주장 | 기본적으로 검증되지 않은 주장(`SG_LICENSE_STATUS_UNKNOWN`)이며 아무 기능도 주지 않는다. `SG_SERVER_OPT_REQUIRE_LICENSE` 면 거부 |
| 요청 feature 를 그대로 받기 | `granted = requested & license.features` 를 서버가 계산. store 에 없는 라이선스는 0 |
| 세션 중 권한 변경 | 권한은 AUTH_RESULT/REAUTH_RESULT 로만 정해지고, 서버는 자기 세션 상태의 결정만 사용한다. 어떤 인증 후 프레임도 권한을 바꾸지 못한다 |
| 애플리케이션이 클레임을 사실로 오인 | `SG_AuthRequest` 는 클레임과 서버 검증 값(`installation_id`, `registered_*`, `license_status`, `license_features`, `integrity_conditions`)을 구분해 전달한다. `SG_ServerSessionInfo.license_id` 는 원문 클레임을 보여주지 않는다 |

주의: `SG_ServerSessionInfo.product_id` 는 registry 에 제품 바인딩이 없으면 클라이언트가 주장한 값이다 ([INTEGRATION.md](INTEGRATION.md) §9).

### 4.2 클라이언트 사칭 (A5)

- installation 별 ECDSA P-256 키로 서버 challenge 가 포함된 transcript 에 서명해야 한다. 서버는 **registry 에 저장된 공개키**로만 검증한다.
- installation ID 는 공개키에서 유도(`SHA-256("SockGate/v1/iid" ‖ key)[0..16)`)되며, 등록·enrollment·파일 로드 때 그 관계를 검증한다.
- 미등록·폐기 installation 도 challenge 를 받고, 서버는 **더미 공개키로 서명 검증을 수행**한 뒤 같은 REJECTED 를 보낸다
  → 응답 내용·시간으로 등록 여부를 구분하기 어렵다 (열거 오라클 완화).

### 4.3 Replay

| 위협 | 대응 |
|---|---|
| 이전 CLIENT_PROOF 재사용 | challenge 는 연결마다 새로 만들고 검증 시도 전에 소비한다. 연결당 인증 시도는 1회. 새 연결은 새 challenge 와 새 채널 바인딩을 가지므로 이전 서명은 무효 |
| 느린 증명 | challenge TTL (`challenge_ttl_ms`, 기본 30 s) 초과 시 REJECTED |
| 인증 후 프레임 재전송·중복·재정렬·삭제 | 방향별 sequence 가 정확히 +1 이어야 한다. 이전 값 이하 → `SG_REPLAY_DETECTED`, 건너뜀 → `SG_PROTOCOL_ERROR`, 연결 종료 |
| 중복 요청 | 요청 `request_id` 는 방향별 단조 증가. 위반 → `SG_REPLAY_DETECTED` |
| 다른 세션의 프레임 주입·반사 | 키가 session id·방향·epoch 별로 다르고 header(session id 포함)가 AAD 이다 |
| 재인증 replay | 재인증 transcript 는 session id, epoch, 채널 바인딩, 직전 transcript 해시에 결속되고 challenge 는 1회용 |
| enrollment token 재사용 | 채널 결속 token 증명·공개키·서명 검증이 끝난 뒤, `on_authorize` 전에 token ID 소비와 installation 삽입을 원자적으로 (영구) 기록한다 — 1회 사용은 registry 단위. 외부(`on_enroll`) token 은 `SHA-256(token_pub)` 앞 16 bytes 를 같은 방식으로 기록 |

### 4.4 MITM / 인증 중계 (A3, A4)

- 서명 대상 TH1 에 **서버 자신의 TLS 연결**에서 계산한 채널 바인딩(`EXPORTER-Channel-Binding`)이 들어간다.
  TLS 를 두 번 종단한 중계자가 피해자의 CLIENT_PROOF 를 전달해도 서버측 TH1 과 맞지 않아 REJECTED 된다.
- 채널 바인딩은 RFC 9266 tls-exporter (길이 0 context)이다. TLS 1.2 는 옵션이며 EMS 가 협상되지 않은 연결은 핸드셰이크 직후 끊는다.
- enrollment token 의 비밀(`K_tok`)은 전송되지 않는다. 클라이언트는 채널 결속된 `HMAC(K_tok, … TH1)` 로만 증명하므로,
  token 공개 부분을 본 MITM 도 자기 채널에서 enroll 할 수 없고 피해자의 MAC 을 중계해도 맞지 않는다.
- 세션 키는 TLS exporter 에서 유도되므로 프레임 tag 는 TLS 를 종단한 MITM 에 대한 추가 방어가 **아니다**
  (세션·sequence 결속과 TLS 구현 결함 대비 심층 방어).
- 서버는 클라이언트의 서버 인증(체인·hostname·pinning)을 강제할 수 없다. pinning 도 proof key 도 없이 시스템 trust store 를
  쓰는 클라이언트는 가짜 서버에 속을 수 있다 (서버측 인증 세션은 만들 수 없음). 서버 운영자는 사설 CA/SPKI pin 을 배포하거나
  `proof_key_*` 를 설정해 클라이언트가 proof key 를 요구하게 한다. proof key 는 AUTH_RESULT(OK) 에만 서명하므로 가짜 서버가 세션을
  성공시키는 것만 막는다. 서명 없는 REJECTED / UNSUPPORTED_VERSION 은 가짜 서버도 보낼 수 있고, 그 전에 CLIENT_HELLO 의 주장과
  integrity 보고가 이미 전달된다. 주장을 가짜 서버에 보내지 않게 하는 것은 pinning 이다.

### 4.5 서비스 거부 (A5, A6)

| 위협 | 대응 (기본값) |
|---|---|
| 대량 연결 | `max_connections` (10000). 용량 검사와 등록이 원자적이며 graceful-close 중인 소켓도 포함. 초과 연결은 수락 직후 닫는다 |
| 인증 전 연결 폭주가 세션 자리를 차지 | `max_unauthenticated` (기본 `max_connections / 2`, 최소 1): TLS·인증 단계에 있는 연결 수 상한. 초과 연결은 수락 직후 닫고(`reason=max_unauthenticated`), 열린 세션은 세지 않는다. 인증 전에 실패한 연결은 소켓이 닫힐 때까지 (최대 5 s) 자리를 유지하므로 쓰레기를 보내고 닫지 않는 피어도 상한을 우회하지 못한다 |
| 느린 핸드셰이크 (slowloris) | 수락부터 AUTH_RESULT 까지 `handshake_timeout_ms` (15 s), 250 ms 주기로 검사 |
| 인증 전 거대 프레임 | 인증 전 프레임은 type 과 무관하게 payload ≤ 4096 bytes, 48 bytes 헤더만 보고 거부 (본문 버퍼링 전). 인증 전 decoder 버퍼 16 KiB |
| 잘못된 상태의 프레임 | 방향·단계·auth_length·flags·request_id 를 헤더 단계에서 검사 |
| 인증 후 거대 프레임 | DATA ≤ `max_payload_size` (1 MiB, 설정 상한 16 MiB), 그 외 제어 메시지 ≤ 4096 |
| 서명 검증 CPU | 연결당 최초 인증 1회. 재인증 최소 간격 `min_reauth_interval_ms` (10 s, 세션 시작 또는 마지막으로 받아들인 REAUTH_REQUEST 부터 계산), 위반 시 연결 종료. enrollment 는 HMAC 검사를 서명 검증보다 먼저 수행 |
| 읽지 않는 피어 (PING/KeyUpdate 로 응답 누적) | 미전송 출력 32 MiB 초과 시 종료 |
| 콜백보다 빠른 송신 | 미전달 메시지 8 MiB 에서 읽기 중지, 64 MiB 에서 종료 |
| 장기 점유 | 세션 수명 (1 h, 최대 7 d), idle 타임아웃 (5 min; 검증된 프레임만 활동으로 인정) |
| graceful close 악용 | 반쯤 닫힌 소켓은 5 s 후 강제 종료 |

잔여: TLS 핸드셰이크 CPU 비용과 IP 별 속도 제한은 제공하지 않는다. 공격자는 `max_unauthenticated` 개의 인증 전 연결을
`handshake_timeout_ms` 동안 점유해 **새** 클라이언트의 접속을 막을 수 있다 (기존 세션은 유지된다). 앞단 L4 방어를 권장한다.

### 4.6 라이선스 남용 (A6, A7)

| 위협 | 대응 |
|---|---|
| 좌석 초과 사용 | 허용된 세션만 좌석을 잡고, `max_installations` 초과 시 거부. 좌석은 installation 단위 활성화 기록이다 |
| 활성화 라이선스 갈아타기 | `SG_SERVER_OPT_LICENSE_ACTIVATION` 의 첫 활성화가 registry 에 영구 바인딩된다 (first wins) |
| 라이선스 ID 추측 (활성화 모드) | 활성화 모드가 아니면 바인딩 없는 주장은 store 를 조회하지 않으므로 존재 여부가 드러나지 않는다. **활성화 모드에서는 드러난다**: 존재하는 ID 는 VALID 로 기능·만료가 AUTH_RESULT 에 실리고 (`REQUIRE_LICENSE` 면 허용 대 거부), 한 번 맞히면 그 installation 의 다른 ID 주장은 거부된다. installation 별 시도 횟수 제한은 없다 (시도마다 새 연결과 인증이 필요할 뿐). 따라서 ID 는 추측 불가능한 고엔트로피 비밀로 발급해야 한다. 로그에는 `lic:` + SHA-256 앞 8 bytes(hex)만 남긴다 |
| 만료·폐기 라이선스 사용 | 인가마다 store 에서 활성·제품·만료를 확인하고, 만료 시각이 세션 수명을 자른다. 폐기는 즉시 세션 종료, 조건 변경은 다음 재인증부터 적용 |
| enrollment token 의 라이선스 조작 | 내장 token 의 claims 는 `K_tok` 로 인증되고, CLIENT_HELLO 의 product/license 주장은 없거나 claims 와 같아야 한다. 외부 `on_enroll` 로 승인된 등록은 라이선스 주장을 바인딩으로 바꾸지 않는다 |
| 수명이 긴 token | 내장 token 은 발급 시와 사용 시 모두 유효 기간(`expires_at - issued_at`)이 30일 이하여야 한다. token key 로 다른 곳에서 만든 token 도 이 상한을 넘을 수 없다 |
| 관리 API 로 잘못된 바인딩 | `RegisterClient` / `IssueEnrollmentToken` 은 store 가 아는 라이선스라면 활성·같은 제품이어야 하고, `REQUIRE_LICENSE` 면 store 에 있어야 한다 |

잔여: 좌석은 동시 접속 수가 아니다. 등록된 installation 은 반납 후에도 빈 좌석이 있으면 다시 잡는다 (영구 차단은 installation 폐기).
재설치로 키가 바뀐 installation 의 구 좌석은 관리자가 `SG_Server_ReleaseLicenseSeat` 로 회수해야 한다.

### 4.7 폐기된 installation

- `SG_Server_RevokeClient` 는 registry 를 REVOKED 로 바꾸고, 열린 세션을 즉시 CLOSE(AUTH_FAILED) 로 닫고, 바인딩된 라이선스 좌석을 반납한다.
- 인가 콜백 도중의 경합은 폐기 세대 카운터로 세션을 열기 직전 다시 확인한다 ([ARCHITECTURE.md](ARCHITECTURE.md) §10).
- 재인증은 registry 상태를 다시 확인한다.
- 폐기된 ID 는 재등록·재enroll 할 수 없다. ID 가 키에서 유도되므로 새 키는 새 installation 이다.
- 폐기를 저장하지 못해도 메모리에서는 폐기가 유지되고 세션도 닫히며, 호출자는 `SG_STORAGE_ERROR` 로 영속화 실패를 안다.
  저장소는 저장되지 않은 폐기를 기억한다: 같은 폐기 함수를 다시 호출하면 쓰기를 재시도하고, 그 저장소의 다른 변경이 성공적으로 저장될 때도
  함께 저장된다 (19d1208). 그 전에 프로세스가 재시작되면 폐기가 사라지므로 호출자는 `SG_OK` 가 나올 때까지 재시도해야 한다.

### 4.8 저장소 파일 변조 (A9)

- 로드 시 파일 전체를 비신뢰 입력으로 파싱한다: magic/version, 개수 상한, 곡선 위 공개키, `iid == H(key)`, 상태·알고리즘 값,
  문자열 길이(라이선스는 protocol string 검증 포함), 중복(레코드·사용된 token ID·좌석), trailing data. 어느 하나라도 어긋나면
  `SG_Server_Create` 가 실패한다 (fail closed). 로드가 거부할 크기(512 MiB 초과)의 파일은 쓰지 않는다 (`SG_LIMIT_EXCEEDED`).
- 쓰기는 임시 파일 + 원자적 rename 이므로 중단된 쓰기가 반쯤 쓴 파일을 남기지 않는다. 새로 쓰는 파일은 소유자 전용이다
  (POSIX `0600`, Windows 는 현재 사용자·SYSTEM·Administrators 만 허용하는 보호된 DACL). POSIX 읽기는 `O_NOFOLLOW`.
- 파일 저장소는 열려 있는 동안 `<path>.lock` 의 배타적 lock 을 잡는다. 실행 중인 서버와 다른 프로세스(`sg_admin` 등)가 같은 저장소를
  동시에 고쳐 폐기 같은 변경이 조용히 사라지는 일을 막는다 (두 번째 사용자는 `SG_INVALID_STATE`). 이 lock 은 advisory 이므로
  파일을 직접 쓰는 공격자를 막지는 않는다.
- **파일 자체에는 MAC/서명이 없다.** 쓰기 권한을 가진 공격자는 형식에 맞는 공개키 추가, 폐기 해제, 라이선스 연장을 할 수 있다.
  방어는 파일·디렉터리 권한과 서버 호스트 보호에 의존한다 ([SECURITY.md](SECURITY.md) §2.4).
- registry 와 license store 를 같은 파일로 지정하면 `SG_INVALID_ARGUMENT` (정규화 경로 비교).

### 4.9 Integrity 보고 위조 (A7)

- 보고는 **신뢰를 낮추는 데만** 쓰인다: `integrity_reject_mask` → 거부, `integrity_restrict_mask` → `SG_SESSION_POLICY_RESTRICTED`.
  reject 가 restrict 보다 우선하며, 거부되면 `on_authorize` 는 호출되지 않는다.
- integrity 로 RESTRICTED 가 된 세션은 `on_authorize` 가 policy 를 NORMAL 로 바꿔도 RESTRICTED 로 남는다 (하한).
- 보고 누락은 그 자체로 조건(`SG_INTEGRITY_REPORT_MISSING`)이다. allowlist 가 있으면 누락도 `SG_INTEGRITY_UNKNOWN_EXECUTABLE` 이다.
- v1 에 정의되지 않은 관측 비트는 CLIENT_HELLO 디코딩에서 프로토콜 오류이고, 인가 단계는 알려진 비트만 다시 마스킹한다.
- 재인증은 첫 CLIENT_HELLO 의 보고를 그대로 쓴다.

잔여: 모든 관측은 우회 가능하다. 장악된 클라이언트는 깨끗한 보고와 허용된 실행 파일 해시를 보낼 수 있으므로,
플래그가 없다는 것은 아무것도 증명하지 않는다. integrity 를 단독 인증 수단으로 쓰지 않는다.

### 4.10 정보 노출과 오류 오라클

- 네트워크로는 일반화된 결과만 보낸다: AUTH_RESULT(REJECTED / UNSUPPORTED_VERSION), REAUTH_RESULT(REJECTED), CLOSE reason 코드.
  상세 사유(미등록, 폐기, 서명 오류, challenge 만료, 라이선스·integrity 판정 등)는 서버 로그에만 남는다.
- 로그에는 키, 세션 키, exporter 값, transcript, 서명, token 문자열, payload 를 쓰지 않는다. 식별자는 앞 8 bytes 의 hex 만,
  라이선스 ID 는 해시만 기록한다.
- 세션 키·채널 바인딩·challenge 는 종료 시 지운다. TLS 개인키 PEM 사본은 TLS 컨텍스트 로드 후 지운다.

### 4.11 파서와 API 입력 (A5, A6, TB4)

- bounds-checked reader, 길이 검사 후 산술, 엄격한 TLV (중복·길이 불일치·trailing data 거부), 알 수 없는 enum/예약 비트 거부.
- frame decoder, 메시지 codec, 채널, 저장소 파일 로더는 libFuzzer 타깃이며 CTest 에서 결정적 변이 테스트로도 실행된다.
- C ABI 는 구조체 `size`/`version` 을 검사하고, 라이브러리가 모르는 뒤쪽 필드가 0 이 아니면 `SG_NOT_SUPPORTED` 로 거부한다
  (새 헤더의 보안 설정이 옛 라이브러리에서 조용히 무시되지 않게).

## 5. 잔여 위험

설계 문서 [02 §5](../docs/design/02-threat-model.md), [13](../docs/design/13-security-limitations.md) 의 내용 중 서버에 해당하는 것:

1. 서버 호스트, 서버 TLS/proof 개인키, token key, registry/license 파일이 유출·변조되면 보장이 무너진다.
2. 저장소 파일에는 무결성 보호가 없고, 권한 설정은 배포 책임이다.
3. 내장 registry/license 저장소는 단일 서버 프로세스용이다 (`<path>.lock` 으로 동시 사용을 막는다). 다중 노드는 `on_authorize` /
   `on_enroll` 과 외부 저장소로 조정해야 한다. token 1회 사용은 **registry 단위**이므로, 같은 token key 를 여러 노드가 공유하면
   내장 token 은 노드마다 1회씩 쓰일 수 있다. 노드 간 1회 사용은 `on_enroll` 에서 공유 저장소로 원자적으로 소비하는 방식이 지원되지만,
   `on_enroll` 은 검증 전에 호출되므로 token 공개 부분을 본 누구나 그 token 을 소진시킬 수 있다 (등록은 불가능한 서비스 거부).
   이런 token 은 수명을 짧게 한다.
4. 메모리 registry 는 재시작 후 사용된 token 을 기억하지 못한다 (token 만료 시각으로만 제한). token key 를 설정하지 않으면
   재시작 시 이전 token 이 모두 무효가 된다.
5. 클라이언트 호스트가 장악되면 installation 키를 **사용**(서명 오라클)할 수 있고, 모든 클레임과 integrity 보고를 위조할 수 있다.
   서버는 폐기·라이선스 제한·이상 탐지로 대응해야 한다.
6. TLS 핸드셰이크 CPU 소모, 네트워크 계층 DDoS 는 범위 밖이다.
7. 만료 판단은 서버 시계에 의존한다 (라이선스·token 만료는 system clock, 세션 타이머는 monotonic clock).
8. 부채널 방어는 OpenSSL 수준에 의존한다. SockGate 자체의 비밀 비교(enrollment MAC)는 상수 시간 비교를 쓴다.
9. 서버는 클라이언트의 서버 인증 설정(pinning, proof key 요구)을 강제할 수 없다.
