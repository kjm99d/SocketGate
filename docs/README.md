# SockGate Design Documents

**English** | [한국어](README.ko.md) | [日本語](README.ja.md)

These are the design documents written before implementation. When the code and the design diverge, the design documents are updated first.
The design documents, like the detailed per-project documents, are written in Korean.

| # | Document | Contents |
|---:|---|---|
| 1 | [Architecture](design/01-architecture.md) | Layers, components, execution model |
| 2 | [Threat Model](design/02-threat-model.md) | Assets, attackers, STRIDE, mitigation per attack |
| 3 | [Trust Boundary](design/03-trust-boundary.md) | Trust boundaries and validation responsibilities |
| 4 | [Protocol Specification](design/04-protocol-specification.md) | Frames, messages, encoding, key derivation |
| 5 | [Handshake Sequence](design/05-handshake-sequence.md) | Authentication/enrollment/re-authentication sequence, timeouts, failure handling |
| 6 | [Key Lifecycle](design/06-key-lifecycle.md) | Key generation/registration/use/rotation/revocation |
| 7 | [Session Lifecycle](design/07-session-lifecycle.md) | State machine, expiration, concurrency rules |
| 8 | [Directory Structure](design/08-directory-structure.md) | Repository layout, include rules |
| 9 | [Public C API](design/09-public-c-api.md) | ABI principles, functions, error codes |
| 10 | [Windows Platform Layer](design/10-windows-platform-layer.md) | Winsock/IOCP/CNG/DPAPI/hardening |
| 11 | [Linux Platform Layer](design/11-linux-platform-layer.md) | POSIX/epoll/TPM2/file key store/hardening |
| 12 | [Dependency List](design/12-dependencies.md) | Dependencies and minimum versions |
| 13 | [Security Limitations](design/13-security-limitations.md) | What is not guaranteed |
