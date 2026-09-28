# SockGate Design Documents

구현 전 작성한 설계 문서이다. 코드와 설계가 어긋나면 설계 문서를 먼저 갱신한다.

| # | 문서 | 내용 |
|---:|---|---|
| 1 | [Architecture](design/01-architecture.md) | 계층, 구성 요소, 실행 모델 |
| 2 | [Threat Model](design/02-threat-model.md) | 자산, 공격자, STRIDE, 공격별 대응 |
| 3 | [Trust Boundary](design/03-trust-boundary.md) | 신뢰 경계와 검증 책임 |
| 4 | [Protocol Specification](design/04-protocol-specification.md) | 프레임, 메시지, 인코딩, 키 유도 |
| 5 | [Handshake Sequence](design/05-handshake-sequence.md) | 인증/등록/재인증 순서, 타임아웃, 실패 처리 |
| 6 | [Key Lifecycle](design/06-key-lifecycle.md) | 키 생성/등록/사용/교체/폐기 |
| 7 | [Session Lifecycle](design/07-session-lifecycle.md) | 상태 머신, 만료, 동시성 규칙 |
| 8 | [Directory Structure](design/08-directory-structure.md) | 저장소 구조, include 규칙 |
| 9 | [Public C API](design/09-public-c-api.md) | ABI 원칙, 함수, 에러 코드 |
| 10 | [Windows Platform Layer](design/10-windows-platform-layer.md) | Winsock/IOCP/CNG/DPAPI/hardening |
| 11 | [Linux Platform Layer](design/11-linux-platform-layer.md) | POSIX/epoll/TPM2/file key store/hardening |
| 12 | [Dependency List](design/12-dependencies.md) | 의존성과 최소 버전 |
| 13 | [Security Limitations](design/13-security-limitations.md) | 보장하지 않는 것 |
