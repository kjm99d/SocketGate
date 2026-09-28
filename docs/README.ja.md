# SockGate Design Documents

[English](README.md) | [한국어](README.ko.md) | **日本語**

実装前に作成した設計ドキュメントです。コードと設計が食い違う場合は、まず設計ドキュメントを更新します。以下の設計ドキュメントは韓国語で書かれています。

| # | ドキュメント | 内容 |
|---:|---|---|
| 1 | [Architecture](design/01-architecture.md) | 層、構成要素、実行モデル |
| 2 | [Threat Model](design/02-threat-model.md) | 資産、攻撃者、STRIDE、攻撃ごとの対策 |
| 3 | [Trust Boundary](design/03-trust-boundary.md) | 信頼境界と検証の責任 |
| 4 | [Protocol Specification](design/04-protocol-specification.md) | フレーム、メッセージ、エンコーディング、鍵導出 |
| 5 | [Handshake Sequence](design/05-handshake-sequence.md) | 認証/登録/再認証の手順、タイムアウト、失敗時の処理 |
| 6 | [Key Lifecycle](design/06-key-lifecycle.md) | 鍵の生成/登録/使用/更新/失効 |
| 7 | [Session Lifecycle](design/07-session-lifecycle.md) | ステートマシン、有効期限切れ、並行性の規則 |
| 8 | [Directory Structure](design/08-directory-structure.md) | リポジトリ構成、include 規則 |
| 9 | [Public C API](design/09-public-c-api.md) | ABI の原則、関数、エラーコード |
| 10 | [Windows Platform Layer](design/10-windows-platform-layer.md) | Winsock/IOCP/CNG/DPAPI/ハードニング |
| 11 | [Linux Platform Layer](design/11-linux-platform-layer.md) | POSIX/epoll/TPM2/ファイルキーストア/ハードニング |
| 12 | [Dependency List](design/12-dependencies.md) | 依存関係と最小バージョン |
| 13 | [Security Limitations](design/13-security-limitations.md) | 保証しないこと |
