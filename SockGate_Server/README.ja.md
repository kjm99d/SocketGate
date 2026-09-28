# SockGate_Server

[English](README.md) | [한국어](README.ko.md) | **日本語**

SockGate の**サーバーライブラリ**です。C/C++ サーバーアプリケーションに組み込まれ、TLS の上でクライアントのインストール（installation）を
暗号学的に認証し、ライセンス・機能・完全性ポリシーを**サーバーで**最終判断したうえで、認証済みセッションのメッセージを
アプリケーションのコールバックに渡します。公開インターフェースは C ABI ひとつ（`sockgate/server.h`）だけです。

- バージョン: 0.1.0（未リリース）、`SOCKGATE_API_VERSION` 1、ワイヤープロトコル v1
- プラットフォーム: Windows 10/11 x64（IOCP）、Linux x64/ARM64（epoll）
- ランタイム依存関係: OpenSSL ≥ 3.0（[BUILD.md](BUILD.md)）

設計の基準ドキュメントは [`docs/design`](../docs/design/) の 01–13 です。このディレクトリのドキュメントはサーバーライブラリの実際の実装を
基準に書かれており、設計と実装が異なる部分は実装に従います。このディレクトリの詳細ドキュメントと設計ドキュメントは韓国語で書かれています。

## 機能

| 領域 | 内容 |
|---|---|
| トランスポートセキュリティ | TLS 1.3（デフォルト）。`SG_SERVER_OPT_ALLOW_TLS12` で TLS 1.2 を許可すると ECDHE + AEAD スイートのみを使い、**Extended Master Secret がネゴシエートされた接続のみ**を受け付けます。圧縮・再ネゴシエーション・セッション再開（ticket、session cache）は無効 |
| クライアント認証 | インストール単位の ECDSA P-256 鍵 + 1回限りのチャレンジへの署名。署名対象のトランスクリプトに TLS exporter によるチャネルバインディング（RFC 9266）を含みます → TLS を終端した中継者は認証済みセッションを確立できません |
| 登録 | ① `SG_Server_RegisterClient` による公開鍵の直接登録、② `SG_Server_IssueEnrollmentToken` が発行した1回限りの enrollment トークン（トークンの秘密値は送信されず、チャネルバインディングされた HMAC によってのみ証明）、③ 外部で発行されたトークンを `on_enroll` コールバックで検証 |
| サーバー proof（任意） | `proof_key_file` / `proof_key_pem` を設定すると、AUTH_RESULT(OK) にサーバー署名を付けます（TLS PKI とは独立したサーバー認証。拒否応答には署名しない） |
| ライセンス | サーバー側の license store（メモリまたはファイル）、組み込みの認可（`BuiltinAuthorizer`）: registry のバインディングを優先、`granted = requested & license.features`、有効期限がセッション寿命を制限、シート（`max_installations`）、`SG_SERVER_OPT_REQUIRE_LICENSE`、`SG_SERVER_OPT_LICENSE_ACTIVATION` |
| アプリケーションによる認可 | `on_authorize` コールバックが組み込みの決定を見て、拒否・縮小・拡大できます |
| 完全性（integrity）ポリシー | クライアントの報告（`SG_INTEGRITY_*`）とサーバー側の判断条件（報告なし、allowlist にない実行ファイル）を `integrity_reject_mask` / `integrity_restrict_mask` で評価。**信頼を下げる用途にのみ**使用 |
| 失効 | `SG_Server_RevokeClient` / `SG_Server_RevokeLicense` / `SG_Server_ReleaseLicenseSeat` は、該当するアクティブなセッションを即座に終了します。認可処理中の接続との競合は、失効世代カウンターで再確認します。保存に失敗した失効もプロセス内では有効であり、再度呼び出すと保存を再試行します |
| セッション保護 | 認証後のすべてのフレームに方向別のシーケンス番号 + AES-256-GCM タグ、ペイロード暗号化（オプション、`SG_SERVER_OPT_REQUIRE_APP_ENCRYPTION`）、再認証時の epoch ごとの鍵更新（rekey）+ TLS KeyUpdate |
| リソース保護 | `max_connections`、認証前の接続数の上限（`max_unauthenticated`）、ハンドシェイクタイムアウト、認証前（および認証後の DATA 以外）のフレームのペイロード上限 4 KiB、セッション寿命・アイドルタイムアウト、再認証の最小間隔、受信/送信のバックプレッシャー上限 |
| I/O | Windows IOCP（`AcceptEx`/`WSARecv`/`WSASend`）、Linux epoll（`EPOLLONESHOT`）。ワーカースレッドのデフォルト値 = ハードウェアスレッド数（明示した値も含めて最大64） |
| ストレージ | client registry / license store をファイルに永続化（所有者専用の一時ファイル + アトミックな rename、ロード時に信頼できない入力として検証、開いている間は `<path>.lock` で他プロセスによる使用を阻止） |

保証しないことについては、[THREAT_MODEL.md](THREAT_MODEL.md) の残存リスクと
[13-security-limitations.md](../docs/design/13-security-limitations.md) を参照してください。

## 最小限の使用例

[`examples/echo_server.c`](../examples/echo_server.c) を縮めた骨組みです。受け取ったメッセージを、リクエスト ID に対する応答として送り返します。

```c
#include <sockgate/server.h>
#include <stdio.h>

static SG_Server* g_server = NULL;

static void SG_CALL on_log(void* user, uint32_t level, const char* message)
{
    (void)user;
    fprintf(stderr, "[sockgate:%u] %s\n", (unsigned)level, message);
}

static void SG_CALL on_message(void* user, SG_SessionHandle session, const void* data, size_t size,
                               const SG_MessageInfo* info)
{
    (void)user;
    /* コールバック内で SG_Server_SendEx を呼び出してもよい (内部ロックを保持していない状態で呼び出される)。 */
    SG_Status st = SG_Server_SendEx(g_server, session, data, size, info->request_id);
    if (st != SG_OK) fprintf(stderr, "echo failed: %s\n", SG_StatusString(st));
}

static void SG_CALL on_closed(void* user, SG_SessionHandle session, SG_Status reason)
{
    (void)user;
    printf("session %llu closed (%s)\n", (unsigned long long)session, SG_StatusString(reason));
}

int main(void)
{
    SG_ServerCallbacks callbacks;
    SG_ServerOptions options;
    SG_Status st;
    uint16_t port = 0;

    SG_ServerCallbacks_Init(&callbacks);
    callbacks.on_message = on_message;
    callbacks.on_session_closed = on_closed;

    SG_ServerOptions_Init(&options);            /* すべてのデフォルト値 + size/version */
    options.port = 7443;
    options.tls_cert_chain_file = "server.crt"; /* leaf が先、その後に中間証明書 */
    options.tls_private_key_file = "server.key";
    options.registry_path = "registry.bin";     /* NULL ならメモリ上の registry */
    options.license_path = "licenses.bin";      /* NULL ならメモリ上の license store */
    options.callbacks = &callbacks;             /* SG_Server_Create でコピーされる */
    options.log_callback = on_log;
    options.log_level = SG_LOG_INFO;

    st = SG_Server_Create(&options, &g_server);
    if (st != SG_OK) { fprintf(stderr, "create: %s\n", SG_StatusString(st)); return 1; }
    st = SG_Server_Start(g_server);
    if (st != SG_OK) { fprintf(stderr, "start: %s\n", SG_StatusString(st)); SG_Server_Destroy(g_server); return 1; }
    SG_Server_GetPort(g_server, &port);
    printf("listening on %u, press Enter to stop\n", (unsigned)port);

    (void)getchar();
    SG_Server_Destroy(g_server);                /* Stop を含む: セッション終了後に解放 */
    return 0;
}
```

クライアントを受け入れるには、そのインストールを先に登録する（`SG_Server_RegisterClient`、`sg_admin client register`）か、
enrollment（トークンによる登録）を許可してトークンを発行する必要があります。手順ごとの説明は [INTEGRATION.md](INTEGRATION.md) にあります。

ビルドしたサンプルの実行（開発用 PKI は `sg_admin dev-pki` で作成します）:

```text
sg_admin dev-pki ./pki --host localhost
sg_echo_server --cert ./pki/server.crt --key ./pki/server.key --port 7443 \
               --registry registry.bin --issue-token example-product
(出力されたトークンを token.txt に保存)
sg_echo_client --host localhost --port 7443 --ca ./pki/ca.crt --product example-product --enroll-file token.txt
```

- `sg_echo_server` は、`--bind` を指定しないと `127.0.0.1` でのみ listen します（ライブラリ自体の `bind_address` のデフォルト値は `0.0.0.0`）。
  `--port` は 0–65535 の10進数のみを受け付けます（0 = 空きポートを自動割り当て）。`--issue-token PRODUCT [--license ID]` は enrollment を許可し、1回限りのトークンを出力します。
  `--token-key FILE` は 32–256 bytes のファイルでなければなりません（それより長いとエラー）。ライセンス ID は出力しません。
- `sg_echo_client` は、トークンをコマンドラインではなく `--enroll-file` のファイルから読み取ります（プロセス一覧やシェル履歴に残らないようにするため）。
  `--enroll-file` がなければ登録済みのインストールとして認証し、out-of-band 登録用の公開鍵を出力します。

## ディレクトリ構成

```text
SockGate_Server/
├── CMakeLists.txt              sockgate_server_core (内部静的) + sockgate_server (公開, SockGate::Server)
├── include/sockgate/
│   └── server.h                公開 C API (SG_ServerOptions, コールバック, registry/license 管理)
└── src/
    ├── core/
    │   ├── server_api.cpp      C ABI 境界: 引数/構造体の検証, オプション解析, コールバックブリッジ, 例外の遮断
    │   └── server_engine.*     ServerEngine: accept, 接続テーブル, sweeper, 管理 API, 失効世代カウンター
    ├── session/
    │   └── connection.*        Connection: TLS + FrameDecoder + ハンドシェイク + ProtectedChannel + 再認証 + イベントキュー
    ├── auth/
    │   ├── server_handshake.*  CLIENT_HELLO / CLIENT_PROOF の処理, enrollment の検証, AUTH_RESULT
    │   ├── authorizer.h        IAuthorizer, AuthorizationRequest / AuthorizationDecision
    │   └── builtin_authorizer.* ライセンス・完全性の組み込み認可 + on_authorize フック + シートの確定
    ├── storage/
    │   ├── client_registry.*   インストールのレコード + 使用済みトークン ID (メモリ / ファイル "SGRG")
    │   ├── license_store.*     ライセンスとシート (メモリ / ファイル "SGLC")
    │   └── atomic_file.h       ReadWholeFile / WriteFileAtomically
    ├── transport/
    │   └── io_service.h        IIoService / AsyncStream (completion スタイルの非同期 I/O 抽象化)
    └── platform/
        ├── windows/            iocp_io_service.cpp, atomic_file_win.cpp
        └── linux/              epoll_io_service.cpp, atomic_file_posix.cpp
```

プロトコルのコーデック、TLS エンジン、暗号プリミティブ、チャネル保護（`ProtectedChannel`）は、クライアントと共有する
`SockGate_Common` に一式だけあります。関連するツールとサンプルは、リポジトリのルートにある `tools/sg_admin.cpp`、
`examples/echo_server.c` です。

## ドキュメント

| ドキュメント | 内容 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 構成要素、スレッドモデル、コールバックのスレッド契約、ストレージ形式、sweeper、失効世代カウンター |
| [THREAT_MODEL.md](THREAT_MODEL.md) | サーバー側の資産、攻撃者、信頼境界、脅威ごとの対策、残存リスク |
| [PROTOCOL.md](PROTOCOL.md) | サーバーから見たワイヤープロトコル: 段階ごとに許可されるフレーム、メッセージの検証、拒否の方式、鍵/シーケンス番号の規則 |
| [SECURITY.md](SECURITY.md) | セキュリティ特性、安全なデプロイの指針、ハードニング、既知の制限、脆弱性の報告 |
| [BUILD.md](BUILD.md) | 要件、プリセット、CMake オプション、テスト、サニタイザー/fuzz、インストールと `find_package(SockGate)` |
| [INTEGRATION.md](INTEGRATION.md) | 組み込みの手順ガイド: オプションのデフォルト値、コールバック、登録/ライセンス/完全性、エラー処理、`sg_admin`、ABI 規則 |
| [CHANGELOG.md](CHANGELOG.md) | 変更履歴 |
