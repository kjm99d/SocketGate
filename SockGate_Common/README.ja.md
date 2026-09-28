# SockGate_Common

[English](README.md) | [한국어](README.ko.md) | **日本語**

> SockGate の共通実装層です。**内部静的ライブラリ**であり、アプリケーションが直接リンクする対象ではありません。
> 公開 API は `SockGate_Client`（`sockgate/client.h`）と `SockGate_Server`（`sockgate/server.h`）の C ABI だけです。

このディレクトリの詳細ドキュメントと設計ドキュメントは韓国語で書かれています。

## 1. 役割

SockGate_Common は次の2つを提供します。

1. **内部静的ライブラリ `sockgate_common`**（CMake alias `SockGate::Common`）
   - セキュリティ上重要なコード（シリアライズ、フレーム/メッセージのパーサー、暗号プリミティブ、TLS エンジン、ソケット抽象化）を**一式だけ**置きます。
     Client と Server が同じパーサー・同じ検証コードを使うため、片方だけが修正されるという欠陥は生じません
     （[01-architecture.md §2](../docs/design/01-architecture.md)）。
   - `sockgate_client_core` と `sockgate_server_core` が `PUBLIC` でリンクします。テストと fuzz ターゲットも直接リンクします。
   - `src/sockgate_common/**` のヘッダーは内部専用です。インストールされず、ABI/API の安定性は保証されません。
   - インストールパッケージ（`find_package(SockGate)`）では、shared ビルドには含まれず、static ビルドでのみ Client/Server のアーカイブの
     依存関係として `SockGate::Common` が export されます。アプリケーションが直接リンクする対象ではありません（[BUILD.md §1](BUILD.md)）。
2. **共通の public C ヘッダー**（`include/sockgate/`）
   - Client/Server 双方の公開ヘッダーがインクルードする共通定義です。Client/Server パッケージと一緒にインストールされます
     （インストールされる public ヘッダーは、この4個と Client の3個、Server の1個の計8個だけです）。

| ヘッダー | 内容 |
|---|---|
| `sockgate/version.h` | `SOCKGATE_VERSION_MAJOR/MINOR/PATCH`（現在 0.1.0）、`SOCKGATE_API_VERSION`（1）、`SOCKGATE_PROTOCOL_VERSION`（1）。最上位の `CMakeLists.txt` がこのファイルからプロジェクトのバージョンを読み取ります（バージョンの唯一の情報源） |
| `sockgate/export.h` | `SG_CLIENT_API` / `SG_SERVER_API`、`SG_CALL`、`SG_EXTERN_C_BEGIN/END` |
| `sockgate/error.h` | `SG_Status`（`int32_t`）、エラーコード 0–29、`SG_StatusString()`（`static inline`） |
| `sockgate/types.h` | ID/ハッシュ/公開鍵の構造体、ログレベル・コールバック、クライアントの状態、セッションポリシー、完全性の観測ビット、`SG_MessageInfo` |

エラーコードと ABI 規則は [INTEGRATION.md](INTEGRATION.md) にまとめています。

## 2. 構成

| モジュール | 名前空間 | 内容 |
|---|---|---|
| `core/` | `sg` | `Status`（`[[nodiscard]]`）、`ToPublicStatus`、`SecureBytes`/`SecureZero`/`ConstantTimeEqual`、モノトニッククロック/`Deadline`、ログコールバック `Logger`、ABI の補助（`abi.h`） |
| `serialization/` | `sg::ser` | ビッグエンディアンの `Reader`/`Writer`、厳格な TLV パーサー、base64url、プロトコル文字列（UTF-8）の検証 |
| `protocol/` | `sg::proto` | ワイヤー定数、48-byte の `FrameHeader` コーデック、`FrameDecoder`、段階ごとの規則 `CheckHeaderForState`、メッセージコーデック、トランスクリプト/鍵導出、enrollment トークン、認証後のフレーム保護 `ProtectedChannel` |
| `crypto/` | `sg::crypto` | OpenSSL 3 EVP ラッパー: SHA-256、HMAC-SHA256、HKDF-SHA256、AES-256-GCM、ECDSA P-256（P1363）、CSPRNG、`SoftwareP256Key` |
| `tls/` | `sg::tls` | sans-IO TLS エンジン（`ITlsProvider` / `ITlsContext` / `ITlsEngine`、OpenSSL memory BIO）、証明書・hostname の検証、SPKI ピンニング、exporter / チャネルバインディング、古いバンドル版 OpenSSL の判定 |
| `net/` | `sg::net` | バイトストリームの抽象化 `ITransport`、`Endpoint` |
| `platform/` | `sg::platform` | Winsock2 / POSIX のソケットプリミティブ、アドレス解決、OS トラストストアの読み込み |

モジュール間の依存方向と設計は [ARCHITECTURE.md](ARCHITECTURE.md)、ワイヤーフォーマットは [PROTOCOL.md](PROTOCOL.md) を参照してください。

## 3. ディレクトリ

```text
SockGate_Common/
├── CMakeLists.txt                     target: sockgate_common (STATIC), alias SockGate::Common
├── include/sockgate/                  共通の public C ヘッダー (C/C++ の両方でコンパイル)
│   ├── error.h  export.h  types.h  version.h
└── src/sockgate_common/               内部実装 (インストールしない)
    ├── core/            status.h  bytes.h/.cpp  clock.h  log.h/.cpp  abi.h
    ├── serialization/   byte_order.h  reader.*  writer.*  tlv.*  base64.*
    ├── protocol/        constants.h  frame.*  rules.*  messages.*  transcript.*
    │                    enrollment_token.*  channel.*
    ├── crypto/          crypto.h  openssl_crypto.cpp
    ├── tls/             tls.h  openssl_tls.cpp
    ├── net/             transport.h
    └── platform/        socket.h  trust_store.h
        ├── windows/     socket_win.cpp  trust_store_win.cpp
        └── linux/       socket_posix.cpp  trust_store_linux.cpp
```

- 内部の include の形式: `#include "sockgate_common/protocol/frame.h"`。public ヘッダー: `#include <sockgate/types.h>`。
- OS のヘッダーは、`platform/windows`、`platform/linux` 以下のファイルだけがインクルードします。該当しないプラットフォームのファイルは、
  CMake がソースリストから除外します（`SOCKGATE_PLATFORM`）。

## 4. 依存関係

- OpenSSL ≥ 3.0（`OpenSSL::SSL`、`OpenSSL::Crypto`）、`Threads::Threads` — `PUBLIC` リンク。
- Windows: `ws2_32`、`crypt32`。
- それ以外の外部ライブラリはありません。詳細は [BUILD.md](BUILD.md)、[12-dependencies.md](../docs/design/12-dependencies.md) を参照してください。

## 5. ドキュメント

| ドキュメント | 内容 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | モジュール構造、エラーモデル、メモリの消去、TLS エンジン、フレームデコーダー、チャネル保護、プラットフォームの抽象化 |
| [THREAT_MODEL.md](THREAT_MODEL.md) | パーサー/暗号層に対する脅威と対策、残存リスク |
| [PROTOCOL.md](PROTOCOL.md) | ワイヤーフォーマットの概要（ヘッダー、メッセージ、TLV、段階ごとの規則、トランスクリプト、鍵導出、トークン） |
| [SECURITY.md](SECURITY.md) | 暗号の選択、TLS 設定、消去、定数時間比較、パーサーの強化、ファジング、脆弱性の報告 |
| [BUILD.md](BUILD.md) | ビルド、OpenSSL の要件、プリセット、ファザー、テスト |
| [INTEGRATION.md](INTEGRATION.md) | SockGate 開発者向け: モジュールの使い方、メッセージ/TLV の追加、共通ヘッダー、ABI 規則 |
| [CHANGELOG.md](CHANGELOG.md) | 変更履歴 |

設計の基準ドキュメントは [docs/design](../docs/design/)（01–13）です。特に
[01 Architecture](../docs/design/01-architecture.md)、[04 Protocol Specification](../docs/design/04-protocol-specification.md)、
[05 Handshake Sequence](../docs/design/05-handshake-sequence.md)、[08 Directory Structure](../docs/design/08-directory-structure.md)、
[09 Public C API](../docs/design/09-public-c-api.md) が、このライブラリに直接関係します。
