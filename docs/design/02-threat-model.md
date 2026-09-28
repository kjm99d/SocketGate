# 02. Threat Model

## 1. 보호 자산

| ID | 자산 | 설명 |
|---|---|---|
| AS1 | 클라이언트 installation private key | 클라이언트 신원의 근거. 유출 시 해당 installation 사칭 가능 |
| AS2 | 서버 TLS private key / 서버 proof key | 유출 시 서버 사칭 가능 |
| AS3 | 세션 키 (TLS 트래픽 키, 채널 보호 키) | 유출 시 해당 세션 복호화/위조 |
| AS4 | 인증된 세션 자체 | 권한 있는 요청을 수행할 수 있는 상태 |
| AS5 | 애플리케이션 payload | 기밀성 / 무결성 |
| AS6 | 라이선스 / 권한 판단 결과 | 서버만이 결정 |
| AS7 | Enrollment token / token 서명 키 | 새 installation 등록 권한 |
| AS8 | Client registry (공개키, 폐기 상태) | 서버측 신뢰 데이터 |
| AS9 | 서버 가용성 | 연결/메모리/CPU 자원 |

## 2. 공격자 모델

| ID | 공격자 | 능력 | 목표 |
|---|---|---|---|
| A1 | 수동 네트워크 관찰자 | 패킷 캡처 | 데이터/자격 증명 획득 |
| A2 | 능동 네트워크 공격자 | 패킷 변조, 삽입, 삭제, 재전송, 재정렬, DNS 스푸핑 | 세션 탈취, 위조 |
| A3 | Proxy 운영자 | HTTP/HTTPS CONNECT/SOCKS4/SOCKS5 경유 트래픽 전체 제어 | A2 와 동일 |
| A4 | TLS MITM (사용자 설치 CA 포함) | 클라이언트가 신뢰하는 CA 로 위조 인증서 발급 | TLS 종단 후 평문 획득·변조, 인증 세션 중계 |
| A5 | 자격 증명 없는 원격 클라이언트 | 임의 바이트 전송, 대량 연결 | 인증 우회, 파서 취약점, DoS |
| A6 | 자격 증명을 가진 악성 클라이언트 | 정상 인증 후 임의 메시지 | 권한 상승, 파서 취약점, 타 세션 간섭 |
| A7 | 클라이언트 호스트 관리자 | 메모리 조작, API hooking, DLL injection, LD_PRELOAD, 디버거, 바이너리 패치 | 클라이언트 로직 우회 |
| A8 | 가짜 서버 | 클라이언트를 자신에게 연결시킴 | 클라이언트 속이기(가짜 라이선스 OK 등) |
| A9 | 서버측 저장소 접근자 | registry 파일 읽기/쓰기 | 공개키 교체, 폐기 해제 |

A7 은 **완전한 방어 대상이 아니다**. 비용을 높이는 것이 목표이며, 서버는 A7 이 조작한 클라이언트의 주장을 신뢰하지 않는다.

## 3. STRIDE 분석

### 3.1 Spoofing

| 위협 | 대응 | 잔여 위험 |
|---|---|---|
| 서버 사칭 (A2, A8) | 체인 검증 + hostname + 유효기간 + 서명, SPKI pinning, (선택) 서버 proof 서명 | pinning 미설정 + 사용자 CA 설치 시 A4 가 서버를 사칭할 수 있음 (단, 서버측 인증 세션은 만들 수 없음) |
| 클라이언트 사칭 (A5) | installation 별 ECDSA P-256 키 + 서버 challenge 서명 | private key 유출 시 사칭 가능 → 폐기 API |
| 인증 중계 (A4 가 서버–클라이언트 사이 TLS 두 개를 종단) | 서명 transcript 에 **TLS exporter 채널 바인딩** 포함 → 서버가 자기 TLS 세션의 exporter 로 검증하므로 불일치 | 클라이언트 프로세스 장악(A7) 시 우회 가능 |
| installation ID 추측 | ID 는 식별자일 뿐 비밀이 아님. 인증은 항상 서명 | - |

### 3.2 Tampering

| 위협 | 대응 |
|---|---|
| 전송 중 변조 (A2/A3) | TLS AEAD + 프레임 단위 AES-256-GCM tag |
| 프레임 재정렬/삭제/중복 | 방향별 sequence 가 정확히 +1 이어야 함. 위반 시 즉시 종료 |
| 핸드셰이크 메시지 변조 | transcript 해시에 ClientHello/ServerHello 전체 바이트 포함 |
| 클라이언트 바이너리 변조 (A7) | integrity 보고 + 서버 정책 (단독 인증 수단 아님) |
| registry 변조 (A9) | 파일 권한, 원자적 쓰기, (권장) 서버 호스트 보호. 파일 무결성은 호스트 보안에 의존 |

### 3.3 Repudiation

- 서버는 인증 성공/실패, 세션 생성/종료를 구조화 로그로 남긴다(`timestamp, session_id, installation_id, message_type, sequence, error_code, connection_state`).
- 서명 자체는 부인방지 목적의 증거로 저장하지 않는다(범위 밖).

### 3.4 Information Disclosure

| 위협 | 대응 |
|---|---|
| 도청 (A1) | TLS 1.3, TLS 1.2 는 ECDHE+AEAD 만 허용 (옵션) |
| 로그 유출 | Release 로그에 키/세션 키/토큰/payload 기록 금지. 디버그 로그도 비밀값은 기록하지 않음 |
| 에러 오라클 | 네트워크로 반환하는 거부 사유는 일반화 (REJECTED). 인증 실패 사유 구분 불가 |
| 메모리 잔존 | 세션 키, 서명 입력 중 비밀값은 `OPENSSL_cleanse` 로 제거 |
| 바이너리 내 비밀 | master secret / private key 하드코딩 금지. 테스트 키도 런타임 생성 |

### 3.5 Denial of Service

| 위협 | 대응 |
|---|---|
| 대량 연결 | `max_connections`, 핸드셰이크 타임아웃, 미인증 연결 수 상한 |
| 거대 프레임 | 헤더 단계에서 `payload_length` 상한 검사 (핸드셰이크 4 KiB, 데이터 기본 1 MiB, 절대 상한 16 MiB) |
| 느린 전송 (slowloris) | 핸드셰이크 전체 타임아웃, idle 타임아웃 |
| 서명 검증 CPU 소모 | 연결당 인증 시도 1회. 미등록 installation 은 서명 검증 전에 거부 |
| 파서 크래시 | bounds-checked Reader, overflow 사전 검사, fuzzing |

### 3.6 Elevation of Privilege

| 위협 | 대응 |
|---|---|
| 클라이언트의 `authenticated=true`, `license=true`, `admin=true` 주장 | 프로토콜에 그런 필드가 없음. 권한은 AUTH_RESULT 로 서버가 부여 |
| 요청된 feature 를 그대로 부여 | `granted = requested ∩ license.features ∩ policy` 를 서버가 계산 |
| integrity 보고로 신뢰 상승 | integrity 보고는 신뢰를 **낮추는 데만** 사용 (Normal → Restricted → Fail) |
| 인증 전 DATA 전송 | 상태 머신이 인증 전 DATA 를 프로토콜 위반으로 처리 |

## 4. 요구사항 매핑 — 공격별 대응

| 공격 | 대응 메커니즘 | 결과 코드 |
|---|---|---|
| Invalid Certificate / Invalid CA | OpenSSL 체인 검증 | `SG_CERTIFICATE_ERROR` |
| Certificate Replacement | SPKI pinning | `SG_PINNING_ERROR` |
| TLS MITM (사용자 CA) | pinning, 채널 바인딩, 서버 proof | `SG_PINNING_ERROR` / 서버측 인증 실패 |
| Invalid Signature | ECDSA 검증 | 서버: 거부, 클라이언트: `SG_SERVER_REJECTED` |
| Invalid Public Key | SEC1 point 곡선 검증 | 거부 |
| Expired Challenge | challenge TTL | 거부 |
| Reused Challenge | challenge 1회 소비 + 연결당 1회 인증 | 거부 |
| Replayed Authentication | 새 연결은 새 challenge + 새 exporter → 이전 서명 무효 | 거부 |
| Modified / Expired Token | enrollment token HMAC + 만료 + 1회 사용 | 거부 |
| Invalid Client ID | registry 조회 실패 | 거부 |
| Packet Replay / Duplication / Reordering | TLS + 엄격한 sequence | `SG_REPLAY_DETECTED` / `SG_PROTOCOL_ERROR` |
| Packet Modification | TLS + GCM tag | 연결 종료 |
| Oversized / Malformed / Truncated / Invalid Length / Integer Overflow / Invalid Type / Invalid Version | FrameDecoder 검증 | `SG_PROTOCOL_ERROR` |
| Duplicate Request | request id 단조 증가 | `SG_REPLAY_DETECTED` |
| HTTP / HTTPS CONNECT / SOCKS proxy | 종단간 TLS + pinning + 채널 바인딩. proxy 는 암호문만 중계 | 정상 동작 또는 인증 실패 |

## 5. 가정

1. 서버 호스트와 서버 private key 는 안전하다.
2. OpenSSL 및 OS CSPRNG 는 올바르게 동작한다.
3. 클라이언트 호스트가 완전히 장악되지 않은 상태에서의 installation key 는 공격자에게 노출되지 않는다.
4. 시간: 서버 시계를 기준으로 만료를 판단한다. 클라이언트 시계는 신뢰하지 않는다 (TLS 인증서 유효기간 검사 제외).
