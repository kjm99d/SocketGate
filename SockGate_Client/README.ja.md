# SockGate_Client

[English](README.md) | [한국어](README.ko.md) | **日本語**

> バージョン 0.1.0 (Unreleased) · C ABI バージョン `SOCKGATE_API_VERSION = 1` · ワイヤープロトコル v1

SockGate_Client は、C/C++ アプリケーションに組み込む**認証ゲートクライアントライブラリ**です。
単なるソケットラッパーではなく、サーバーを検証した TLS チャネルの上でインストール（installation）単位の鍵によるチャレンジレスポンス認証を行い、
認証済みセッションのすべてのフレームをシーケンス番号と AEAD タグで保護します。権限（ポリシー、機能、寿命）は常にサーバーが決定します。

設計の根拠は [docs/design](../docs/design/) の 01–13 のドキュメントであり、このディレクトリのドキュメントはクライアントの観点から
**現在のコードが実際に行うこと**を説明します。このディレクトリの詳細ドキュメントと設計ドキュメントは韓国語で書かれています。

## 機能

| 領域 | 内容 |
|---|---|
| TLS | OpenSSL 3 ベースの TLS 1.3（TLS 1.2 は `SG_CLIENT_FLAG_ALLOW_TLS12` 指定時のみ、Extended Master Secret 必須）。チェーン・hostname/IP・有効期間の検証、部分ワイルドカードの禁止、セッション再開・圧縮・再ネゴシエーションなし |
| サーバー認証 | アプリケーションが指定した CA（`ca_file` / `ca_pem`）または OS のトラストストア（`SG_TRUST_SYSTEM_STORE`）、**SPKI ピンニング**（オプション、最大8個、検証済みのチェーンに対してのみ比較）、**server proof key**（オプション、最大4個、設定時はサーバー署名が必須） |
| インストール鍵 | ECDSA P-256 鍵を **TPM**（Windows CNG Platform Crypto Provider / Linux TPM2）、**CNG Software KSP**（DPAPI で保護、non-exportable）、**FILE**（Windows DPAPI、Linux 0600）、**MEMORY** に保管。`SG_KEYSTORE_AUTO` は最も強力なストアを選び、locator ファイルによって identity がストア間を行き来しないようにします |
| 認証 | サーバーのチャレンジと TLS exporter によるチャネルバインディングを含むトランスクリプトへの署名（`SG_Client_Authenticate`）。1回限りの enrollment トークンによる新しいインストールの登録（`SG_Client_Enroll`） — トークンの秘密値は送信しません |
| 保護チャネル | 方向別のシーケンス番号（厳密に +1）、リクエスト ID の単調増加、フレームごとの AES-256-GCM タグ。`SG_CLIENT_FLAG_APP_ENCRYPTION` で DATA ペイロードをアプリケーション層でも暗号化 |
| 再認証 | `SG_Client_Refresh` または `SG_CLIENT_FLAG_AUTO_REFRESH`（寿命の 80% 経過時）: 新しい署名、方向別の鍵更新（epoch+1）、TLS 1.3 KeyUpdate |
| プロキシ | デフォルトは **DIRECT**（システム設定・環境変数を読まない）。`SG_PROXY_MODE_SYSTEM`（要求時にのみ OS の設定を照会）、`SG_PROXY_MODE_EXPLICIT`（HTTP CONNECT / SOCKS4a / SOCKS5）。プロキシは TLS の暗号文を中継するだけです |
| 完全性（integrity） | `SG_CLIENT_FLAG_INTEGRITY_REPORT` 指定時に、実行ファイル/ライブラリの SHA-256、デバッガー、ASLR などの観測値をサーバーに報告。**サーバーが信頼を下げる用途にのみ**使う申告（claim）です |
| 実行モデル | 同期（blocking）+ タイムアウト API。ライブラリはスレッドを作成しません。Send/Receive の同時呼び出しと、別スレッドからの Disconnect による待機中の呼び出しのウェイクアップをサポート |

## Windows と Linux で同じ API

公開 API は `#include <sockgate/client.h>` ひとつで十分です（`config.h`、`types.h`、`error.h`、`export.h`、
`version.h` も併せてインクルードされます）。ヘッダーは C99/C++ の両方でコンパイルでき、OS のヘッダー、C++ の型、STL をインクルードしません。
関数名、構造体のレイアウト、エラーコードの値、動作の契約は両プラットフォームで同じです。プラットフォームの違いは次の点だけであり、
すべて**同じ API の戻り値**として現れます。

- そのプラットフォームにないキーストアの種類（例: Linux の `SG_KEYSTORE_CNG_TPM`、tpm2-tss なしでビルドした `SG_KEYSTORE_TPM2`）は、`SG_Client_Create` で `SG_NOT_SUPPORTED` になります。
- デフォルトの鍵ディレクトリ、`SG_PROXY_MODE_SYSTEM` の設定の取得元、完全性の観測項目は OS ごとに異なります。

```c
#include <sockgate/client.h>   /* Windows (MSVC, clang-cl) と Linux (GCC, Clang) で同一 */
```

## 最小限の使用例

[examples/echo_client.c](../examples/echo_client.c) を縮めたものです（純粋な C、公開 API のみを使用）。

```c
#include <sockgate/client.h>
#include <stdio.h>

int echo_once(const char* host, uint16_t port, const char* ca_file, const SG_Sha256* pin)
{
    SG_ClientConfig config;
    SG_ServerConfig server;
    SG_IdentityInfo id;
    SG_MessageInfo info;
    SG_Client* client = NULL;
    char reply[1024];
    size_t received = 0;
    uint64_t request_id = 0;
    SG_Status st;

    SG_ClientConfig_Init(&config);                      /* デフォルト値を設定 (size/version を含む) */
    config.identity_name = "com.example.sockgate-echo"; /* reverse-DNS: ユーザー単位で共有される名前 */
    config.key_store_type = SG_KEYSTORE_AUTO;           /* デフォルト: TPM を優先 */
    config.product_id = "sockgate-echo";                /* 申告(claim)にすぎず、サーバーが判断 */
    config.flags = SG_CLIENT_FLAG_APP_ENCRYPTION | SG_CLIENT_FLAG_AUTO_REFRESH;
    st = SG_Client_Create(&config, &client);
    if (st != SG_OK) return (int)st;

    SG_IdentityInfo_Init(&id);
    st = SG_Client_EnsureIdentity(client, &id);         /* なければ生成、あれば読み込み */
    if (st == SG_OK) {
        /* id.public_key (65 bytes) をサーバーに登録するか、SG_Client_Enroll を使用する。 */
        SG_ServerConfig_Init(&server);
        server.host = host;
        server.port = port;
        server.ca_file = ca_file;                       /* プライベート CA */
        server.spki_pins = pin;                         /* 本番環境ではピンを推奨 */
        server.spki_pin_count = pin != NULL ? 1u : 0u;

        st = SG_Client_Connect(client, &server);        /* TCP (+proxy) + TLS + サーバー検証 */
        if (st == SG_OK) st = SG_Client_Authenticate(client);
        if (st == SG_OK) st = SG_Client_SendEx(client, "hello", 5, 0, &request_id);
        if (st == SG_OK) {
            SG_MessageInfo_Init(&info);
            st = SG_Client_ReceiveEx(client, reply, sizeof(reply), &received, &info, SG_WAIT_DEFAULT);
        }
        if (st != SG_OK) fprintf(stderr, "sockgate: %s\n", SG_StatusString(st));
    }
    SG_Client_Disconnect(client);
    SG_Client_Destroy(client);
    return (int)st;
}
```

サンプルの実行ファイル `sg_echo_client` は、`SOCKGATE_BUILD_EXAMPLES=ON`（デフォルト）のビルドに含まれます。

```text
sg_echo_client --host HOST --port N --ca FILE [--pin HEX] [--identity NAME]
               [--key-dir DIR] [--product ID] [--enroll-file FILE]
```

- 起動するとインストール ID と公開鍵を16進数で出力します。未登録のインストールであれば、その公開鍵をサーバーに登録するか、
  `--enroll-file FILE` で登録（enrollment）します（[INTEGRATION.md §9](INTEGRATION.md#9-installation-등록-out-of-band-vs-enrollment)）。
  トークンは、プロセス一覧やシェル履歴に残らないよう、コマンドラインではなく**ファイル**（1行）から読み取り、使用直後に volatile な書き込みで
  消去します（`memset` はコンパイラーに除去されることがあります。アプリケーション側でも `SecureZeroMemory` / `explicit_bzero` / volatile ループで消去してください）。
- `--port` は 1..65535 の10進数のみを受け付けます。`--key-dir` を指定すると FILE キーストア、指定しなければ AUTO になります。
- 受け取った応答は信頼できないデータとして扱います: `SG_MESSAGE_FLAG_RESPONSE` があり、`request_id` が直前に送ったリクエストの ID であることを確認し、
  表示できないバイトは `\xNN` にエスケープします。

## ビルドとリンク

```cmake
find_package(SockGate 0.1 REQUIRED)                    # 0.x の間は同じ minor バージョンのみ互換
target_link_libraries(myapp PRIVATE SockGate::Client)
```

インストールパッケージには、公開ヘッダー8個とライブラリ、CMake 設定だけが含まれます。プリセット、オプション、共有/静的の違い、soname については
[BUILD.md](BUILD.md) を参照してください。

## ディレクトリ構成

```text
SockGate_Client/
├── CMakeLists.txt                sockgate_client_core (内部 static) + sockgate_client (公開, SockGate::Client)
├── include/sockgate/
│   ├── client.h                  クライアント C API
│   ├── config.h                  SG_ClientConfig, SG_ServerConfig, SG_ProxyConfig, 定数
│   └── sockgate.h                umbrella ヘッダー (version/error/types/config/client)
├── src/
│   ├── core/client_api.cpp       C ABI: 引数の検証, 構造体の size/version, 例外 → SG_Status
│   ├── session/                  ClientSession: ステートマシン, 接続世代, ロック, 再認証
│   ├── auth/                     ClientHandshake: CLIENT_HELLO / CLIENT_PROOF / AUTH_RESULT (sans-IO)
│   ├── tls/                      TlsChannel: ITransport 上の blocking TLS
│   ├── transport/                TcpTransport, プロキシのネゴシエーション, transport_factory (プロキシポリシー)
│   ├── crypto/                   IKeyStore, MEMORY / FILE / AUTO キーストア, factory
│   └── platform/
│       ├── windows/              CNG キーストア, DPAPI 鍵ファイル, システムプロキシ(WinHTTP), 完全性
│       └── linux/                POSIX 鍵ファイル, TPM2 キーストア, システムプロキシ(環境変数), 完全性
└── *.md                          これらのドキュメント
```

プロトコルのシリアライズ、フレーム保護、TLS エンジン、ソケットプリミティブは、サーバーと共有する
[SockGate_Common](../SockGate_Common/README.ja.md) に一式だけあります。

## ドキュメント

| ドキュメント | 内容 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 構成要素、ステートマシン、接続世代とロック、キーストア、スレッドセーフティ |
| [THREAT_MODEL.md](THREAT_MODEL.md) | クライアント側の脅威と対策、残存リスク |
| [PROTOCOL.md](PROTOCOL.md) | クライアントから見たハンドシェイク/再認証/チャネルの規則と SG_* コードの対応 |
| [SECURITY.md](SECURITY.md) | 安全な設定、キーストアの選択、セキュリティテスト、脆弱性の報告 |
| [BUILD.md](BUILD.md) | 要件、プリセット、オプション、テスト、インストールと `find_package(SockGate)`、CI |
| [INTEGRATION.md](INTEGRATION.md) | 組み込みの手順ガイド: 設定フィールドとデフォルト値、呼び出し順序、エラー処理、ABI 規則 |
| [CHANGELOG.md](CHANGELOG.md) | 変更履歴 |

設計ドキュメント: [01 Architecture](../docs/design/01-architecture.md) ·
[02 Threat Model](../docs/design/02-threat-model.md) ·
[04 Protocol](../docs/design/04-protocol-specification.md) ·
[05 Handshake](../docs/design/05-handshake-sequence.md) ·
[06 Key Lifecycle](../docs/design/06-key-lifecycle.md) ·
[07 Session Lifecycle](../docs/design/07-session-lifecycle.md) ·
[09 Public C API](../docs/design/09-public-c-api.md) ·
[13 Security Limitations](../docs/design/13-security-limitations.md)
