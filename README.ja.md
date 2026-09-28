# SockGate

[English](README.md) | [한국어](README.ko.md) | **日本語**

アプリケーションに組み込む**ネットワーク認証ゲート** C/C++ ライブラリです（0.1.0、未リリース）。
各クライアントのインストールインスタンス（installation）が固有の非対称鍵でサーバーに自身を証明し、サーバーは認証・ライセンス・ポリシーを
すべてサーバー側で決定します。以降のトラフィックは TLS 1.3 の上で、フレームごとにシーケンス番号と AES-256-GCM 認証タグで保護されます。ペイロードの暗号化（AEAD）は任意です。

```c
#include <sockgate/client.h>   /* Windows と Linux で同じ API */
```

## 構成

| プロジェクト | 役割 | ドキュメント |
|---|---|---|
| [SockGate_Client](SockGate_Client/README.ja.md) | アプリケーションに組み込むクライアントライブラリ (`SockGate::Client`) | README, ARCHITECTURE, THREAT_MODEL, PROTOCOL, SECURITY, BUILD, INTEGRATION, CHANGELOG |
| [SockGate_Server](SockGate_Server/README.ja.md) | 認証ゲートサーバーライブラリ (`SockGate::Server`) | 〃 |
| [SockGate_Common](SockGate_Common/README.ja.md) | 2つのライブラリが共有するプロトコル・暗号・TLS・シリアライズ層と共通ヘッダー | 〃 |

各プロジェクトの README 以外の詳細ドキュメントと設計ドキュメントは韓国語で書かれています。

設計ドキュメント: [docs/design](docs/README.ja.md) — アーキテクチャ、脅威モデル、信頼境界、プロトコル、ハンドシェイク、
鍵・セッションのライフサイクル、公開 C API、プラットフォーム層、依存関係、**保証しないこと**。

## セキュリティの概要

- **TLS 1.3 がデフォルト**、TLS 1.2 は明示的に許可した場合のみ（EMS 必須）。証明書チェーン・ホスト名・有効期間の検証、
  複数の SPKI ピンニング（オプション）、サーバー proof key 署名（オプション）。
- **インストールごとの鍵**: TPM（Windows CNG Platform Crypto Provider / Linux TPM2）、CNG Software KSP（non-exportable）、
  DPAPI・0600 のファイルストア。バイナリに秘密情報はありません。インストール ID は公開鍵から導出します。
- **チャレンジレスポンス**: 1回限りのチャレンジ、TLS チャネルバインディングとトランスクリプトに対する署名 — リレー・リプレイを防止します。
- **サーバーが決定**: クライアントが送る product・license・feature・integrity はすべて*申告*です。
  granted = requested ∩ license、ライセンスの有効期限がセッション寿命の上限となり、失効すると即座にセッションを終了します。
- **厳格なパーサー**: ビッグエンディアンのバイナリプロトコル、段階ごとのヘッダー規則、認証前のサイズ上限、ファジング。
- **DoS 緩和**: 接続数の上限と、それとは別の認証前の接続数の上限、ハンドシェイク・アイドルタイムアウト、再認証の最小間隔。
- **プロキシ検出に依存しない**: MITM は証明書の検証・ピンニング・チャネルバインディングで防ぎます。
- 行わないこと: 独自の暗号アルゴリズム、ハードコードされたマスターシークレット、バイナリ内の秘密鍵、クライアントの boolean に基づく判断。
  詳しい限界は [docs/design/13-security-limitations.md](docs/design/13-security-limitations.md) を参照してください。

## クイックスタート

```sh
# Windows (Developer PowerShell, VCPKG_ROOT 設定)          # Linux (libssl-dev, ninja, cmake)
cmake --preset windows-msvc-release                          cmake --preset linux-gcc-release
cmake --build --preset windows-msvc-release                  cmake --build --preset linux-gcc-release
ctest --preset windows-msvc-release                          ctest --preset linux-gcc-release
```

開発用の証明書でサンプルを実行します（`out/build/<preset>/bin`）:

```sh
sg_admin dev-pki ./dev                        # 開発専用 CA + localhost サーバー証明書、SPKI ピンを出力
sg_admin token-key ./dev/token.key
sg_echo_server --cert dev/server.crt --key dev/server.key --port 7443 \
               --registry dev/registry.bin --token-key dev/token.key --issue-token sockgate-echo
# サーバーが出力した1回限りの enrollment トークンを dev/token.txt に保存してから (コマンドラインには渡さない):
sg_echo_client --host localhost --port 7443 --ca dev/ca.crt --pin <SPKI pin> \
               --key-dir dev/keys --enroll-file dev/token.txt
```

サーバーは実行中、registry・license ファイルをロックします（`<path>.lock`）。`sg_admin` でこれらのファイルを変更するときは、サーバーを停止してください。

インストール後、別の CMake プロジェクトから:

```cmake
find_package(SockGate 0.1 REQUIRED)
target_link_libraries(app PRIVATE SockGate::Client)   # または SockGate::Server
```

## リポジトリ構成

```text
SockGate_Common/   共通ヘッダー(error/types/version/export) + 内部共通ライブラリ
SockGate_Client/   クライアントライブラリ (C API: include/sockgate/client.h, config.h)
SockGate_Server/   サーバーライブラリ (C API: include/sockgate/server.h)
examples/          C のサンプル: sg_echo_server, sg_echo_client
tools/             sg_admin: オフライン管理 (ピン, トークン, ライセンス, クライアント, dev PKI)
tests/             unit / protocol / security / integration テスト (CTest ラベル), パッケージコンシューマー
fuzz/              libFuzzer ターゲット + CTest 用の決定的なミューテーションドライバー
cmake/             オプション, コンパイラーのハードニング, サニタイザー, インストール/パッケージ
docs/design/       設計ドキュメント 01–13
.github/workflows/ CI (Windows/Linux/ARM64, サニタイザー, TPM2(swtpm), パッケージ, コンテナ, fuzz)
```

## ステータス

0.1.0 は最初のリリース前であり、ABI のベースラインです。0.x の間は minor バージョンごとに ABI が変わる可能性があります
（soname `libsockgate_*.so.0.1`、CMake パッケージの互換性 SameMinorVersion）。変更履歴は各プロジェクトの CHANGELOG.md を参照してください。
脆弱性は公開 issue ではなく、メンテナーに非公開で報告してください。
