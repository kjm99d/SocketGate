# 13. Security Limitations

SockGate 가 **보장하지 않는 것**을 명시한다. 이 목록은 과장된 보안 주장을 막기 위한 것이다.

## 1. 장악된 클라이언트 호스트

클라이언트 시스템이 공격자(관리자/root 또는 같은 사용자 권한)에게 장악된 경우 다음을 완전히 막을 수 없다.

| 공격 | 결과 |
|---|---|
| Process memory manipulation | 복호화된 payload, 세션 키, 상태 변경 가능 |
| API hooking / DLL injection / LD_PRELOAD | SockGate 함수 결과 조작, 평문 가로채기 |
| Debugger / runtime instrumentation (Frida 등) | 로직 우회 |
| Binary patching | 검증 코드 제거 (integrity 검사 포함) |
| Decrypted payload interception | 애플리케이션 계층 평문 획득 |
| 서명 오라클 | TPM 키라도 공격자가 해당 프로세스/사용자로 서명 요청 가능 → 키 복제는 불가하지만 **사용**은 가능 |

SockGate 의 목표는 **네트워크 proxy / MITM 만으로 정상 인증 세션을 위조할 수 없게 하는 것**이다.
장악된 호스트는 서버측 정책(폐기, 이상 탐지, 라이선스 제한)으로 대응해야 한다.

## 2. Proxy / MITM

- "로컬 proxy 를 완전히 차단한다" 는 보안 목표가 아니다. proxy 사용 자체는 인증 실패 사유가 아니다.
- **pinning 을 설정하지 않고 시스템 trust store 를 사용**하면, 사용자 설치 CA 로 MITM 하는 공격자는
  - 서버측에서 인증된 세션을 만들 수는 **없지만** (채널 바인딩),
  - 클라이언트에게 가짜 서버로 보일 수는 **있다** (가짜 AUTH_RESULT).
  → 운영 환경에서는 사설 CA + SPKI pinning, 또는 서버 proof key 를 반드시 설정할 것.
- 클라이언트가 장악되면 pinning 설정 자체를 변경할 수 있다.

## 3. Integrity 검사

- 모든 integrity 관측은 우회 가능하다. **단독 인증 수단으로 사용하지 않는다.**
- integrity 보고는 신뢰를 낮추는 방향(Normal → Restricted → Fail)에만 사용된다.
- 서명되지 않은 실행 파일, 디버거 존재는 정상 개발 환경에서도 발생하므로 서버 정책으로 조정해야 한다.

## 4. 키 저장소

| 저장소 | 한계 |
|---|---|
| File (Linux) | 같은 사용자/root 가 읽을 수 있음. 파일 권한에만 의존 |
| File (Windows, DPAPI) | 같은 사용자 권한 코드가 복호화 가능 |
| CNG Software KSP | non-exportable 이지만 같은 사용자 권한으로 서명 요청 가능. 관리자는 키 추출 도구로 추출 가능 |
| CNG TPM / TPM2 | 키 추출은 불가하나 서명 오라클 가능. TPM 펌웨어 취약점은 범위 밖 |
| 삭제 | SSD wear-leveling, 저널링 FS, 백업으로 인해 파일 기반 키의 완전 삭제 보장 불가 |

## 5. 서버

- 서버 호스트, 서버 private key, registry 파일이 유출/변조되면 보안 보장이 무너진다.
- 내장 registry/license 파일 저장소는 단일 서버 프로세스용이다. 다중 서버 간 공유/동기화는 애플리케이션 책임
  (`on_authorize`, `on_enroll` 콜백으로 외부 시스템 연동).
- enrollment token 키를 설정하지 않으면 서버 재시작 시 새 키가 생성되어 이전 token 은 무효가 된다.
- 사용된 enrollment token 목록은 registry 파일에 저장되며, registry 를 메모리 모드로 쓰면 재시작 후 재사용을 막지 못한다
  (token 자체 만료 시간으로 한정).

## 6. 가용성

- 대량 연결/느린 연결에 대한 기본 상한과 타임아웃은 제공하지만, 네트워크 계층 DDoS 방어는 범위 밖이다.
- TLS 핸드셰이크 CPU 비용에 대한 방어(쿠키, rate limit)는 제공하지 않는다. 앞단 L4 방어를 권장한다.

## 7. 기타

- DNS 해석은 OS resolver 를 사용하며 타임아웃을 제어할 수 없다 (`getaddrinfo` 블로킹).
- PAC 스크립트 / WPAD 기반 시스템 proxy 는 지원하지 않는다.
- 시간: 서버 시계가 조작되면 만료 판단이 틀어진다.
- 부채널(타이밍, 캐시) 공격 방어는 OpenSSL 구현 수준에 의존한다. SockGate 자체 비교는 상수 시간 비교(`CRYPTO_memcmp`)를 사용한다.
- 난독화는 제공하지 않으며 보안 계층으로 간주하지 않는다. Release 빌드는 심볼 제거, export 최소화, hardening 만 적용한다.
- 오류 코드는 로컬 애플리케이션에 구체적으로 제공되지만, 네트워크로는 일반화된 결과만 전송한다.
  클라이언트 로컬 로그를 공격자가 볼 수 있다면 실패 원인을 알 수 있다.
