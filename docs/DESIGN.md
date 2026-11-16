# T3 Code / GitHub → ChatGPT（dots / Work）向け MCP Events サーバー設計

公式仕様を確認した設計（2026年11月16日時点）。リポジトリ名・バイナリ名は `events-bridge` に統一する（設計中の `t3gh-mcpd` 表記は本バイナリを指す）。

## 1. 結論：MCP Events の実装方式

ChatGPT には dots や Work から利用できる専用の「MCP Events」機能が実装されている。ChatGPT の MCP Events は SSE で通知を待ち受ける方式ではなく、**購読登録と署名付き Webhook 配信を組み合わせる方式**である。

| 項目 | 採用方針 |
| --- | --- |
| 常駐 Rust デーモン | 採用 |
| Streamable HTTP | 採用 |
| ローカル `stdio` | 汎用 MCP クライアント向けのオプション |
| `notifications/resources/updated` | dots の起動トリガーには使わない |
| `notifications/message` | dots の起動トリガーには使わない |
| `events/list` | 必須 |
| `events/subscribe` | 必須 |
| `events/unsubscribe` | 必須 |
| Standard Webhooks による署名付き POST | 必須 |
| SQLite でのイベント・購読管理 | 採用 |

ChatGPT の MCP Events は、Work のクラウド実行、対応するデスクトップ Work、dots で利用できる。一般的な ChatGPT 会話が常時 SSE を監視する仕組みではない。また ChatGPT はローカル `stdio` MCP サーバーへ直接接続せず、リモート HTTPS エンドポイントまたは Secure MCP Tunnel を使用する。

## 2. ChatGPT MCP Events の正確なプロトコル

### 2.1 イベント購読のライフサイクル

1. **イベントの公開**: MCP サーバーが `initialize` の `capabilities.events` を返す。MCP 2.0 を使う場合は `server/discover` で公開する。ChatGPT が `events/list` を実行し、イベント一覧とフィルターのスキーマを取得する。
2. **購読登録**: ユーザーが dots に監視内容を指示すると、ChatGPT が `events/subscribe` を呼び出し、購読対象、フィルター、Webhook URL、署名用シークレットを渡す。
3. **コールバックの検証**: Rust サーバーが署名付き `verification` リクエストを送信する。ChatGPT がチャレンジ文字列を返したことを確認して購読を有効化する。
4. **イベントの配信**: 対象イベントが発生したら、Rust サーバーが ChatGPT の Webhook URL に署名付き JSON を POST する。
5. **ChatGPT 側で処理**: ChatGPT がイベントを受け取り、登録済みのタスクを起動する。必要に応じて MCP ツールから追加情報を取得する。

イベント受信後の処理は ChatGPT 側が管理する。サーバー側は ChatGPT のモデル実行セッションを保持する必要がない。

### 2.2 提供するイベント

| イベント名 | 発生条件 | 優先度 |
| --- | --- | --- |
| `t3.run.completed` | T3 の実行が正常完了 | 通常 |
| `t3.run.failed` | エージェント実行が失敗 | 高 |
| `t3.approval.required` | 承認・入力待ち | 高 |
| `github.workflow.failed` | CI ワークフローが失敗 | 高 |
| `github.review.requested` | PR のレビュー要求 | 通常 |
| `github.pr.merged` | PR がマージされた | 通常 |

イベントを細かく分割することで、dots に「承認待ちは即時通知、完了は集約通知」といった異なる処理を設定できる。

`events/list` のイベント定義例（`result.events` 配列に格納する）:

```json
{
  "name": "t3.run.completed",
  "description": "A T3 Code coding-agent run has completed.",
  "delivery": ["webhook"],
  "inputSchema": {
    "type": "object",
    "properties": {
      "environment_id": {"type": "string"},
      "project_id": {"type": "string"}
    },
    "required": ["environment_id"],
    "additionalProperties": false
  },
  "payloadSchema": {
    "type": "object",
    "properties": {
      "environment_id": {"type": "string"},
      "project_id": {"type": "string"},
      "thread_id": {"type": "string"},
      "run_id": {"type": "string"},
      "summary": {"type": "string"},
      "url": {"type": "string"}
    },
    "required": ["environment_id", "project_id", "thread_id", "run_id", "summary"],
    "additionalProperties": false
  }
}
```

`inputSchema` は ChatGPT が購読時に指定するフィルターであり、`payloadSchema` は実際に配信するイベントの `data` の構造である。

### 2.3 `events/subscribe` と購読の永続化

購読要求の形式:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "events/subscribe",
  "params": {
    "name": "t3.run.completed",
    "arguments": {
      "environment_id": "linux-main"
    },
    "delivery": {
      "mode": "webhook",
      "url": "https://receiver.example.com/mcp-events/callback_123",
      "secret": "whsec_<base64-encoded-signing-key>"
    },
    "cursor": null
  }
}
```

サーバーはこの要求を認証・検証し、決定的な購読 ID を割り当てる。購読 ID の生成には、認証されたユーザー識別子、コールバック URL、イベント名、正規化したフィルターを使用する。

レスポンス:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "id": "sub_123",
    "refreshBefore": "2026-11-17T00:00:00Z",
    "cursor": null,
    "truncated": false
  }
}
```

`refreshBefore` はサーバーが許可した購読期限（例示であり固定値ではない）。同一の購読要求は新しい購読を重複生成せず、既存の購読を更新する。ChatGPT は期限前に `events/subscribe` を再実行して購読を更新できる。

**購読状態は MCP 接続セッションではなく SQLite に永続化する。** ChatGPT との HTTP 接続が切れても、購読と配信キューは維持される。

### 2.4 実際の Webhook 配信

```json
{
  "eventId": "evt_linux-main_run-102_completed",
  "name": "t3.run.completed",
  "timestamp": "2026-11-16T01:00:00+09:00",
  "data": {
    "environment_id": "linux-main",
    "project_id": "lnako",
    "thread_id": "thread-42",
    "run_id": "run-102",
    "summary": "Coding agent run completed",
    "url": "https://t3.example.com/threads/42"
  },
  "cursor": null
}
```

イベント ID、日時、URL は形式を示す例示。実際の URI は T3 Code が提供する正規のリンクを使用する。

HTTP ヘッダー:

```
POST /mcp-events/callback_123 HTTP/1.1
Content-Type: application/json
webhook-id: evt_linux-main_run-102_completed
webhook-timestamp: 1794762000
webhook-signature: v1,<computed-signature>
X-MCP-Subscription-Id: sub_123
```

署名には **Standard Webhooks の HMAC-SHA256** を使用する。`webhook-id`、タイムスタンプ、シリアライズ済み本文のバイト列を署名対象にし、リトライ時も同じイベント ID を維持する。

公式の配信条件:

| 条件 | 仕様 |
| --- | --- |
| 配信先 | HTTPS |
| 署名方式 | Standard Webhooks |
| 1リクエスト | 1イベント |
| 最大本文 | 256 KiB |
| 成功判定 | HTTP `2xx` |
| 一時障害 | 指数バックオフで再送 |
| `410` / `413` | 再送しない |
| 順序保証 | 到着順が入れ替わる可能性あり |

ChatGPT の `2xx` は **Webhook の受信確認**であり、dots が処理を完了したことの保証ではない。この2つは独立した状態として管理する。

### 2.5 コールバック検証と SSRF 対策

`events/subscribe` を受理する前に、次の検証を行う。

- シークレットが `whsec_` 形式で、Base64 デコード後に24〜64バイトあること。
- コールバック URL が HTTPS であること。
- DNS 解決結果がパブリックアドレスで、ローカル・プライベート IP に到達しないこと。
- リダイレクトを許可せず、接続時に再検証すること。
- 署名付きの単発チャレンジに対して、同じ値が返ったこと。

チャレンジ不一致やタイムアウト時は `CallbackEndpointError`（JSON-RPC `-32015`）を返す。検証成功前に通常イベントを配信してはいけない。

## 3. T3 Code / GitHub 側のイベント取得方式

T3 Code では、ファイルシステム監視よりも **Orchestrator V2 の永続イベントと状態遷移**を利用する方が正確である。

### 3.1 T3 Code の監視方式

T3 Code の公式実装では、Orchestrator V2 がイベントログを正本として使用している。イベント・Projection・副作用の Outbox をトランザクションで記録し、コミット後にイベントを購読者へ流す。永続イベントには単調増加の `sequence` が付与され、スナップショット以降のイベントを追跡できる設計である。

| 方式 | 評価 | 用途 |
| --- | --- | --- |
| T3 Code の認証済み RPC / WebSocket | 最優先 | 実行状態をリアルタイム追跡 |
| T3 Code 側の小さな Event Adapter | 推奨代替 | 内部イベントを安定した形式で取得 |
| SQLite の読み取り専用参照 | フォールバック | 起動時の復元・補正 |
| `notify` によるファイル監視 | 最終手段 | ファイル変更を再読込の契機にする |

認証済み RPC で必要なイベントが外部取得できるかは、導入する T3 Code のバージョンごとに確認する。内部のイベントストリームが直接公開されていない場合は、T3 Code サーバー側に読み取り専用 Event Adapter を追加する方法が堅実である。

**エージェントのターン終了と、チェックポイント等も含む Run の最終確定は区別する。** `provider turn ended` をそのまま `t3.run.completed` に変換すると、バックグラウンドタスクが残っている実行を誤って完了として通知する可能性がある。

### 3.2 GitHub の監視方式

GitHub は Webhook を第一候補とし、REST / GraphQL の定期照合で取りこぼしを回復する。

- GitHub からの Webhook は `X-Hub-Signature-256` で検証し、`X-GitHub-Delivery` で重複排除する。
- GitHub は失敗した Webhook を自動再送しないため、API ポーリングによる定期照合も必要（ETag とウォーターマークを管理）。
- 対象イベントは `workflow_run`、`pull_request`、`pull_request_review`、`pull_request_review_comment`、`check_run` など。同じ CI 失敗を `workflow_run` と `check_run` の両方から通知しないよう、実行 ID と Attempt を使って正規化する。

## 4. 複数 T3 Code サーバーを統合する構成

Linux 機と Mac mini の両方に T3 Code を配置する環境では、**Edge Collector と中央 Hub を分ける構成**を採る。

- Hub（AlmaLinux 10）: Event Normalizer、SQLite Event Store、Subscription Manager、Webhook Dispatcher、GitHub Collector、MCP HTTP Server を持つ中央集約。
- Edge（各ホスト）: 対象 T3 Code の状態を収集して Hub に転送する（認証済み HTTPS / Private Network）。
- ChatGPT へは Secure MCP Tunnel または HTTPS で接続する。

同一 Rust バイナリに `hub`、`edge`、オプションの `stdio` サブコマンドを実装する。

```
# 中央管理ホスト
events-bridge hub --config /etc/events-bridge/config.toml

# T3 Code が動作するホスト
events-bridge edge --config /etc/events-bridge/config.toml

# 汎用 MCP クライアントやトンネル向け
events-bridge stdio
```

単一ホストだけで使う構成にも対応できるよう、`hub` がローカル Collector を直接起動するモードを設ける。

## 5. Rust の内部設計

### 5.1 ディレクトリ構成

```
events-bridge/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── auth.rs
│   ├── event.rs
│   ├── rules.rs
│   ├── store/
│   │   ├── mod.rs
│   │   ├── migrations.rs
│   │   └── repository.rs
│   ├── collectors/
│   │   ├── t3_rpc.rs
│   │   ├── t3_snapshot.rs
│   │   ├── github_webhook.rs
│   │   └── github_poll.rs
│   ├── mcp/
│   │   ├── handler.rs
│   │   ├── event_catalog.rs
│   │   ├── subscriptions.rs
│   │   └── tools.rs
│   ├── delivery/
│   │   ├── dispatcher.rs
│   │   ├── verification.rs
│   │   ├── signing.rs
│   │   └── retry.rs
│   └── transport/
│       ├── http.rs
│       ├── edge.rs
│       └── stdio.rs
└── migrations/
    └── 001_initial.sql
```

### 5.2 Rust クレート

| 用途 | クレート |
| --- | --- |
| MCP 本体 | `rmcp` 3.x（少なくとも 3.6.0 以降。Streamable HTTP の DoS 脆弱性修正のため） |
| HTTP / ルーティング | `axum`, `tower-http` |
| 実行基盤 | `tokio` |
| Webhook 署名 | `standardwebhooks` |
| GitHub API / 配信 | `reqwest` |
| SQLite | `rusqlite` |
| スキーマ | `serde`, `schemars` |
| セキュリティ | `secrecy`, `subtle` |
| ログ・メトリクス | `tracing`, `metrics` |
| 設定 | `clap`, `toml` |

MCP Events はまだドラフト拡張である。`rmcp` の標準的なツール・Resource サポートと、OpenAI の `events/*` 実装を同一視してはいけない。そこで Events 専用アダプターを設ける。

```
HTTP /mcp
    |
    +-- initialize / server/discover
    |       -> capabilities.events を公開
    |
    +-- events/list
    |       -> EventCatalog
    |
    +-- events/subscribe
    |       -> SubscriptionManager
    |
    +-- events/unsubscribe
    |       -> SubscriptionManager
    |
    +-- tools/* その他
            -> rmcp ServerHandler
```

実装時には SDK が提供する拡張ポイントを確認し、不足する場合だけ `axum` の JSON-RPC ルーティング層で対応する。MCP 2.0 のリクエストメタデータと、旧プロトコルの初期化・セッション管理を壊さないことが条件である。

### 5.3 SQLite の状態モデル

| テーブル | 主要な情報 |
| --- | --- |
| `events` | `id`, `sequence`, `source`, `kind`, `payload`, `occurred_at` |
| `source_cursors` | ホスト別・収集元別の最終処理位置 |
| `subscriptions` | 購読 ID、所有者、フィルター、Webhook URL、鍵、期限 |
| `deliveries` | 購読 ID × イベント ID、送信状態、試行回数、次回送信日時 |
| `delivery_attempts` | HTTP ステータス、エラー、送信時刻 |
| `collector_checkpoints` | GitHub ETag、T3 Code の取得位置 |
| `acks` | オプションのユーザー確認履歴 |

`deliveries` は購読単位で `UNIQUE(subscription_id, event_id)` を持たせる。

`tokio::sync::broadcast` は永続キューではなく、ワーカーを起こすための通知経路として使用する。イベントの取り込み時には、イベント本体と配信対象レコードを SQLite の単一トランザクションで保存してから `broadcast` に通知する。再起動後は `deliveries` の未完了レコードから送信を再開する。

`cursor` を使った履歴再生は、最初は配送確認が取れた連続範囲のみカーソルを進める方式にする。MCP Events の `cursor` と、T3 Code 自体の `sequence` は別々に管理する。

## 6. ChatGPT 向け Pull ツール

Webhook のイベント本文には、dots が判断するのに必要な短い情報を含める。追加調査が必要な場合は、次のツールを呼び出せるようにする。

| MCP Tool | 内容 | 権限 |
| --- | --- | --- |
| `list_events` | 期間・ソース・重要度別のイベント取得 | Read |
| `get_event` | イベント ID の詳細取得 | Read |
| `get_t3_run` | T3 Code Run の最新状態取得 | Read |
| `get_t3_approvals` | 現在の承認待ち取得 | Read |
| `get_github_status` | PR・CI の最新状態取得 | Read |
| `ack_events` | ユーザー確認状態の記録 | Write、任意 |

`ack_events` は MCP Events の配信確認ではない。ChatGPT が受信済みであることと、ユーザーが確認したことは区別する。初期バージョンは読み取り専用ツールだけでも成立する。

### 6.1 Phase B6: ペイロードの任意拡張フィールド

Webhook の `data` には、既存の必須フィールドを変えずに次の任意フィールドを追加する。すべて省略可能であり、`additionalProperties: false` と既存の必須項目は維持するため、旧形式のペイロードはそのまま検証・配信できる。

| フィールド | 型 | 意味 |
| --- | --- | --- |
| `title` | string | 通知一覧向けの 1 行タイトル。改行・制御空白は 1 スペースへ畳み、200 文字程度で打ち切る。 |
| `project_name` | string | T3 Code のプロジェクト表示名。解決できた場合のみ付与する。 |
| `thread_title` | string | T3 Code のスレッド表示名。解決できた場合のみ付与する。 |
| `severity` | `"high"` / `"normal"` | イベント自体の重要度。購読フィルターの `severity` と同じ語彙。 |
| `requires_action` | boolean | ユーザーまたはエージェントの対応が必要かどうか。 |
| `error_excerpt` | string | 失敗理由の 1 行抜粋。改行を畳み、`payload.error_excerpt_max_chars` 文字以内に収める。 |

`requires_action` の意味は「このイベントを受け取ったエージェントが、通知だけでなく確認・承認・修正などの操作を検討すべきか」である。`t3.run.completed` と `github.pr.merged` は `false`、`t3.run.failed`・`t3.approval.required`・`github.workflow.failed`・`github.review.requested` は `true` とする。

`severity` は `high` / `normal` の列挙値のみを受け付ける。スキーマに `enum` がある場合、`validate_payload` は文字列型の一致だけでなく列挙値も検証する。

`error_excerpt` の長さは `[payload]` セクションの `error_excerpt_max_chars`（既定 500、0 は起動時に拒否）で制御する。T3 Collector は `T3Reducer::with_error_excerpt_max_chars`、GitHub Collector は webhook / poller の設定配線を通じて同じ上限を使う。抜粋は UTF-8 境界を壊さず、切り詰め時は上限に収まる範囲で `...` を付ける。

### 6.2 Phase B7: `list_events` の差分取得

`list_events` は `after`（integer、0 以上）を受け付ける。`after` はイベントの `sequence` に対する厳密な下限（`sequence > after`）であり、`limit` と組み合わせることで「前回の続きから N 件だけ取得」する差分取得ができる。

- 既存の `cursor` は `nextCursor`（`seq_<n>`）をそのまま渡す方式として維持する。
- `after` と `cursor` を同時に指定した場合はエラーにする（どちらか一方のみ）。
- `since` / `until` / `source` / `kind` / `severity` / `limit` / `cursor` の既存動作は変更しない。
- 差分取得の典型例: 初回に `{"limit": 50}` を呼び、`nextCursor` があれば次回 `{"after": <最後の sequence>, "limit": 50}` を呼ぶ。`after` は `cursor` と違い、クライアントが保存した数値シーケンスから直接再開できる。

## 7. 認証と接続経路

### 推奨：Secure MCP Tunnel

OpenAI の Secure MCP Tunnel は、プライベートネットワーク内の HTTP または `stdio` MCP サーバーを、外部公開せず ChatGPT に接続できる。`tunnel-client` が OpenAI に向けてアウトバウンド HTTPS 接続を確立する。対象の MCP サーバーをインターネットに直接公開する必要はない。ただし利用には Platform 側のトンネル権限と対象 ChatGPT ワークスペースとの関連付けが必要である。

代替は Cloudflare Tunnel（公開 HTTPS + OAuth 2.1 を適切に構成）。

HTTP 公開する場合、単純な固定 Bearer トークンを ChatGPT に手入力して渡す設計は避ける。ユーザー認証には OAuth 2.1 が推奨される。推奨スコープは例えば `events.read`、`events.subscribe`、`events.ack`。

Tailscale や Cloudflare Mesh は Edge Collector と Hub の内部通信には適しているが、それだけで ChatGPT クラウドからプライベートアドレスへ直接接続できるわけではない。

## 8. dots の通知とステータス表示の扱い

| やりたいこと | ChatGPT での実現方法 |
| --- | --- |
| T3 Code 完了で dots を起動 | MCP Events 購読 |
| CI 失敗時に dots が原因を調査 | MCP Events + MCP Tool |
| イベントを dots の会話へ報告 | イベントトリガータスクの指示 |
| 複数イベントをまとめて報告 | タスクのバッチ設定とサーバー側集約 |
| dots の通知・アクティビティに結果を反映 | ChatGPT 側の処理・通知設定による |
| 任意のステータスバッジを直接点灯 | MCP Events サーバーからは直接制御不可 |

**Webhook の配信成功を「通知バッジ点灯成功」とみなさない。** Webhook 受信後に ChatGPT が登録済みタスクを処理するが、MCP サーバーが UI の表示状態を直接指定する API は定義されていない。

dots への監視指示の例:

> 接続した `events-bridge` の MCP Events を購読してください。T3 Code の承認待ち・実行失敗と GitHub CI 失敗は発生時に調査して報告してください。正常完了は短時間のイベントをまとめ、プロジェクト別に報告してください。問題の修正や承認操作は勝手に行わず、まず原因と対応案を提示してください。同一イベントの再配送では重複処理を避けてください。

## 9. 実装・検証の優先順位

1. **MCP Events プロトコルの最小実装**: events/list・subscribe・unsubscribe、Webhook 検証、署名、SQLite 永続化
2. **T3 Code Collector**: Run 完了・承認待ち・失敗の3種類を取得し、再接続後の状態を復元
3. **GitHub Collector**: Webhook 受信、API 補正、重複排除、PR・CI の対応付け
4. **複数ホスト統合**: Linux と macOS の Edge Collector、中央 Hub への認証済み転送
5. **ChatGPT 実機検証**: 購読生成、チャレンジ検証、イベント配信、dots の自動処理、再起動復旧

実機検証では Webhook の HTTP `2xx` だけでなく、実際の dots タスクが起動し、指定された内容がユーザーに提示されるまで確認する。

## 最終推奨構成

Rust 単一バイナリ、Edge / Hub 二層構成、MCP Events Webhook 配信を正式な主経路とする設計。

特に重要な点は、ファイル監視中心の T3 Collector を永続イベント中心に変更すること、MCP SSE 通知を Webhook 配信に置き換えること、購読と配信の永続化を独立させること、認証を ChatGPT の正式な方式に合わせることである。

また、T3 Code 自身にも完了・失敗・承認待ちのモバイル通知機能がある。単純な即時通知は T3 Code に任せ、dots では複数プロジェクトの状況集約、CI 原因調査、対応案の提示を担当させると役割が明確になる。

## 主要な参照仕様

- OpenAI — MCP Events 公式実装ガイド: https://developers.openai.com/plugins/build/mcp-events
- MCP Events ドラフト仕様: https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md
- OpenAI — Secure MCP Tunnel: https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
- OpenAI — MCP プラグイン認証仕様: https://developers.openai.com/plugins/build/auth
- T3 Code — 内部アーキテクチャ: https://github.com/pingdotgg/t3code/blob/main/docs/internals/overview.md
- 公式 Rust MCP SDK: https://github.com/modelcontextprotocol/rust-sdk
