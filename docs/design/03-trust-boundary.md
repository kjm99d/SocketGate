# 03. Trust Boundary

```text
 ┌──────────────────────── Client Host (부분 신뢰, A7 에 의해 장악 가능) ───────────────────────┐
 │                                                                                             │
 │   Application ──TB4──▶ SockGate_Client ──TB5──▶ OS Key Store (CNG/TPM, TPM2, keyring, file)  │
 │                               │                                                             │
 └───────────────────────────────┼─────────────────────────────────────────────────────────────┘
                                 │ TB1 (network, 완전 비신뢰: proxy / MITM / 공격자)
 ┌───────────────────────────────┼──────────────────── Server Host (신뢰) ─────────────────────┐
 │                               ▼                                                             │
 │   TLS 종단 ──TB2──▶ Protocol Parser ──TB3──▶ Auth/Authorization ──▶ Server Application       │
 │                                                     │                                       │
 │                                                     └──TB6──▶ Registry / License Storage     │
 └─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## TB1 — Network ↔ Process

- 소켓에서 들어오는 **모든 바이트는 비신뢰**이다. 이는 TLS 이전(proxy 응답 포함)과 이후 모두 해당한다.
- Proxy 응답(HTTP CONNECT 응답, SOCKS reply)도 파싱 상한(헤더 8 KiB 등)과 형식 검사를 거친다.
- DNS 응답은 비신뢰 → 서버 신원은 인증서 hostname 검증과 pinning 으로만 확정한다.

## TB2 — TLS 평문 ↔ Protocol Parser

- TLS 로 복호화되었다는 사실은 **상대가 정상적인 SockGate 구현이라는 뜻이 아니다.**
  인증된 서버/클라이언트도 악의적일 수 있다 (A6, A8).
- 모든 프레임은 FrameDecoder → 메시지 디코더 → 상태 머신 검증을 통과해야 한다.
- 클라이언트도 서버가 보낸 데이터를 비신뢰 입력으로 처리한다 (서버 사칭 A8 대비).

## TB3 — 클라이언트 주장 ↔ 서버 판단

클라이언트가 보내는 다음 값은 **주장(claim)** 일 뿐이다.

| 필드 | 서버 처리 |
|---|---|
| installation_id | registry 조회 키. 서명 검증 전까지 아무 권한 없음 |
| product_id / product_version | 서버 정책과 대조 |
| license_id | 서버 license store 에서 조회. 존재·만료·제품·installation 바인딩 검증 |
| requested_features | 서버가 교집합 계산 후 `granted_features` 로 응답 |
| integrity report | 신뢰 하향에만 사용 |
| client_version | 최소 버전 정책에만 사용 |

권한은 서버가 AUTH_RESULT 로 부여하고, 이후 서버는 **자기 세션 상태에 기록된 granted_features** 로만 판단한다.
클라이언트가 보내는 어떤 프레임도 세션 권한을 변경하지 못한다.

## TB4 — Application ↔ SockGate API

- 애플리케이션은 신뢰하지만, 입력은 검증한다 (NULL, 크기, 구조체 `size/version`, 문자열 길이).
- 구조체는 `size` 필드로 버전을 판별하고, 라이브러리가 아는 범위 밖 필드는 읽지 않는다.
- 콜백은 라이브러리 내부 lock 을 잡지 않은 상태에서 호출된다.
- 라이브러리가 반환한 메모리는 없다(호출자 버퍼에 복사). 소유권 이동이 없는 API 로 설계한다.

## TB5 — SockGate ↔ OS Key Store

- private key 는 가능한 한 key store 밖으로 나오지 않는다. Core 는 `KeyHandle` 과 `Sign()` 만 사용한다.
- CNG/TPM 구현은 non-exportable key 를 생성한다.
- File key store(fallback) 는 private key 를 파일에 저장하며, 이 경우 보안 수준은 **파일 권한/OS 사용자 격리**에 의존한다.
  Windows 에서는 DPAPI(사용자 범위)로 추가 보호한다. TPM 과 동등하다고 주장하지 않는다.

## TB6 — Server ↔ Storage

- registry / license 파일은 서버 프로세스만 쓰기 가능해야 한다 (배포 가이드에서 요구).
- 파일 로드 시에도 비신뢰 입력으로 파싱한다 (길이/형식/곡선 검증).
- 쓰기는 임시 파일 + rename 으로 원자적으로 수행한다.

## 경계별 검증 책임 요약

| 경계 | 검증 주체 | 실패 시 |
|---|---|---|
| TB1 proxy 응답 | ProxyConnector | `SG_PROXY_ERROR`, 연결 폐기 |
| TB1 TLS | TlsEngine + 검증 콜백 | `SG_TLS_ERROR` / `SG_CERTIFICATE_ERROR` / `SG_PINNING_ERROR` |
| TB2 프레임 | FrameDecoder, SequenceValidator, ChannelProtector | 연결 종료 |
| TB3 인증 | Authenticator | 일반화된 REJECTED |
| TB3 권한 | Authorizer | REJECTED 또는 Restricted |
| TB4 API 인자 | C ABI 계층 | `SG_INVALID_ARGUMENT` |
| TB5 key store | IKeyStore 구현 | `SG_KEYSTORE_ERROR` |
| TB6 storage | Registry loader | 서버 시작 실패 또는 레코드 무시 + 로그 |
