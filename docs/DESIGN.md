# Orca / GitHub → ChatGPT（dots / Work）向け MCP Events サーバー設計

MCP Events の公式仕様を確認した設計（2026年11月16日時点）。Orca の取得経路は 2026 年 11 月 25 日時点。リポジトリ名・バイナリ名は `events-bridge` に統一する（設計中の `t3gh-mcpd` 表記は本バイナリを指す）。

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
| `events/poll`（SEP-3415） | 任意（カーソルベースのポーリング） |
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
| `orca.session.completed` | Orca エージェントのターンが完了 | 通常 |
| `orca.session.failed` | Orca が失敗または予期しない中断を報告 | 高 |
| `orca.approval.required` | Orca が承認・入力待ちを観測 | 高 |
| `github.workflow.failed` | CI ワークフローが失敗 | 高 |
| `github.review.requested` | PR のレビュー要求 | 通常 |
| `github.pr.merged` | PR がマージされた | 通常 |

既存の `t3.*` は過去のイベントを読むために引き続き公開する。

イベントを細かく分割することで、dots に「承認待ちは即時通知、完了は集約通知」といった異なる処理を設定できる。

`events/list` のイベント定義例（`result.events` 配列に格納する）:

```json
{
  "name": "orca.session.completed",
  "description": "An Orca agent finished a turn.",
  "delivery": ["webhook", "poll"],
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
      "session_id": {"type": "string"},
      "summary": {"type": "string"},
      "severity": {"type": "string", "enum": ["high", "normal"]},
      "requires_action": {"type": "boolean"}
    },
    "required": ["environment_id", "session_id", "summary"],
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
    "name": "orca.session.completed",
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
  "eventId": "evt_orca_<sha256>",
  "name": "orca.session.completed",
  "timestamp": "2026-11-16T01:00:00+09:00",
  "data": {
    "environment_id": "linux-main",
    "session_id": "orca_session_id:00000000-0000-4000-8000-000000000001",
    "summary": "An Orca agent finished a turn.",
    "severity": "normal",
    "requires_action": false
  },
  "cursor": null
}
```

イベント ID と日時は形式を示す例。Orca のイベント ID は §4 の規則で生成する。

HTTP ヘッダー:

```
POST /mcp-events/callback_123 HTTP/1.1
Content-Type: application/json
webhook-id: evt_orca_<sha256>
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

### 2.6 `events/poll`（SEP-3415）

`events/list` の `delivery` は `["webhook", "poll"]` を返す。Webhook を使わないクライアントは `events/poll` でカーソルベースの取得ができる。HTTP の `POST /mcp` と `stdio` の両方で同じ JSON-RPC メソッドとして提供し、HTTP では既存の認証・Host/Origin 検証を通過したリクエストだけを処理する。

リクエスト:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "events/poll",
  "params": {
    "name": "orca.session.completed",
    "arguments": {"environment_id": "linux-main"},
    "cursor": "seq_42",
    "maxAgeMs": 600000,
    "maxEvents": 50,
    "_meta": {"progressToken": "poll-1"}
  }
}
```

| パラメータ | 必須 | 内容 |
| --- | --- | --- |
| `name` | 必須 | `events/list` が公開するイベント名。未知の名前は `-32023 NotFound`（`data.kind = "event"`）。 |
| `arguments` | 任意 | `inputSchema` に対する購読フィルター。省略時は `{}`。検証失敗は `-32602 InvalidParams`。 |
| `cursor` | 任意 | `"seq_<N>"` 形式の不透明カーソル。`null` / 省略は「現在時刻から開始」。 |
| `maxAgeMs` | 任意 | 指定時は `now - maxAgeMs` より古い一致イベントをスキップし、スキップが発生したら `truncated: true` を返す（`0` は現在時刻境界）。省略時は年齢制限なし。 |
| `maxEvents` | 任意 | 1 レスポンスあたりの最大件数。既定 50、上限 200 にクランプ。`0` は `-32602`。 |
| `_meta` | 任意 | MCP 2.0 のリクエストメタデータ。JSON オブジェクト以外は `-32602`。 |

レスポンス:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "resultType": "complete",
    "events": [
      {
        "eventId": "evt_...",
        "name": "orca.session.completed",
        "timestamp": "2026-11-16T01:00:00.000Z",
        "data": {"environment_id": "linux-main", "session_id": "orca_session_id:00000000-0000-4000-8000-000000000001", "summary": "An Orca agent finished a turn."}
      }
    ],
    "cursor": "seq_42",
    "truncated": false,
    "hasMore": false,
    "nextPollMs": 5000
  }
}
```

カーソルとページングの規則:

- `cursor: null` / 省略: 履歴を返さず、`events: []` と現在のウォーターマーク `"seq_<latest_sequence>"` を返す。以後に発生したイベントだけが対象になる。
- `cursor: "seq_<N>"`: `name` が一致し `sequence > N` のイベントを昇順に走査し、`arguments` を Webhook 購読と同じ `arguments_match` でフィルタする。
- `maxAgeMs` でスキップした一致イベントがある場合、または `N` が現在のウォーターマークより未来（DB リセット・別 DB のカーソル）の場合は `truncated: true`。未来カーソルは履歴を再生せず、`cursor` を最新に戻す。
- 一致イベントが `maxEvents` を超える場合は先頭 `maxEvents` 件を返し、`hasMore: true`、`cursor` は最後に返したイベントの `sequence` にする。次回はその続きから読む。
- 一致イベントが残っていない場合は `hasMore: false` とし、`cursor` を現在のウォーターマークまで進める。一致 0 件や `arguments` 不一致のみのポーリングでも再走査しない。
- `nextPollMs` は次回ポーリングの推奨間隔（既定 5000 ms）。

エラー:

| 条件 | コード |
| --- | --- |
| 未知の `name` | `-32023`（`data: {"kind": "event"}`） |
| `arguments` が `inputSchema` に違反 | `-32602` |
| `cursor` が `"seq_<非負整数>"` でない | `-32602` |
| `maxEvents: 0`（負値・非整数を含む） | `-32602` |
| `_meta` が JSON オブジェクトでない | `-32602` |

## 3. Orca / GitHub 側のイベント取得方式

### 3.1 Orca の監視方式

各 Edge は Orca 1.4.273 の `worktree ps --agent-wait --environment local --json` を読み、
`hostId = "local"` の行から終了結果と承認・入力待ちを取得する。終了結果を持たない端末の
`done` は必要に応じて `agent read` でも確認する。状態は定期採取のため、採取間隔より短い
遷移は観測できないことがある。取得経路の比較と判定条件は
[Orca Edge コレクター](ORCA-COLLECTOR.md) に記載する。

### 3.2 GitHub の監視方式

GitHub は Webhook を第一候補とし、REST / GraphQL の定期照合で取りこぼしを回復する。

- GitHub からの Webhook は `X-Hub-Signature-256` で検証し、`X-GitHub-Delivery` で重複排除する。
- GitHub は失敗した Webhook を自動再送しないため、API ポーリングによる定期照合も必要（ETag とウォーターマークを管理）。
- 対象イベントは `workflow_run`、`pull_request`、`pull_request_review`、`pull_request_review_comment`、`check_run` など。同じ CI 失敗を `workflow_run` と `check_run` の両方から通知しないよう、実行 ID と Attempt を使って正規化する。

## 4. 複数 Orca ホストを統合する構成

Mado の orca-serve と Mini のデスクトップ版はそれぞれ Edge を持ち、pm-01 の Hub に送る。

- Hub（AlmaLinux 10）: Event Normalizer、SQLite Event Store、Subscription Manager、Webhook Dispatcher、GitHub Collector、MCP HTTP Server を持つ中央集約。
- Edge（各ホスト）: ローカルの Orca の状態を収集し、署名付きで Hub へ転送する。
- ChatGPT へは Secure MCP Tunnel または HTTPS で接続する。

同一 Rust バイナリに `hub`、`edge`、オプションの `stdio` サブコマンドを実装する。

```
# 中央管理ホスト
events-bridge hub --config /etc/events-bridge/config.toml

# Orca が動作するホスト
events-bridge edge --config /etc/events-bridge/config.toml

# 汎用 MCP クライアントやトンネル向け
events-bridge stdio
```

Edge は採取したイベントを SQLite の送信待ちキューに保存する。Hub は
`POST /internal/edge/orca` で既存の Edge 署名・時刻・ノンスを検証し、受理したイベントを
通常のイベントログと Webhook 配信キューに取り込む。Edge は HTTP 2xx を受け取った本文だけを
送信済みにする。イベント ID は `evt_orca_` + SHA-256（ホスト ID・セッション ID・種別・状態開始時刻）。
Orca と旧 T3 に共通の実行 ID はないため、移行中は同じ作業を両基盤で起動しない。

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
│   │   ├── orca.rs
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
│       ├── orca_edge.rs
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
    +-- events/poll
    |       -> SubscriptionManager（SEP-3415）
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
| `collector_checkpoints` | GitHub ETag、旧 T3 Code の取得位置 |
| `orca_edge_baselines` | Edge の初回採取時刻 |
| `orca_edge_outbox` | Orca の観測済みイベント ID、送信待ち本文 |
| `acks` | オプションのユーザー確認履歴 |
| `consumers` | ポーリング consumer の名前・カーソル・最終 poll/ack 時刻 |
| `oauth_authorization_codes` | 認可コードの SHA-256 hash、client、scopes、PKCE challenge、TTL、使用時刻 |
| `oauth_access_tokens` | アクセストークンの SHA-256 hash、client、scopes、family、TTL、失効時刻 |
| `oauth_refresh_tokens` | リフレッシュトークンの SHA-256 hash、family、ローテーション元、TTL、使用・失効時刻 |

`deliveries` は購読単位で `UNIQUE(subscription_id, event_id)` を持たせる。

`tokio::sync::broadcast` は永続キューではなく、ワーカーを起こすための通知経路として使用する。イベントの取り込み時には、イベント本体と配信対象レコードを SQLite の単一トランザクションで保存してから `broadcast` に通知する。再起動後は `deliveries` の未完了レコードから送信を再開する。

Edge の採取・再送位置と Hub の消費カーソルはそれぞれ独立して管理する。`events/poll` のカーソルは Hub の `events.sequence` を `seq_<N>` 形式で表し、`sequence > N` のイベントを昇順に返す。

## 6. ChatGPT 向け Pull ツール

Webhook のイベント本文には、dots が判断するのに必要な短い情報を含める。追加調査が必要な場合は、次のツールを呼び出せるようにする。

| MCP Tool | 内容 | 権限 |
| --- | --- | --- |
| `list_events` | 期間・ソース・重要度別のイベント取得 | Read |
| `get_event` | イベント ID の詳細取得 | Read |
| `get_t3_run` | 保存済みの T3 Code Run を取得 | Read |
| `get_t3_approvals` | 保存済みの T3 Code 承認を取得 | Read |
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

`requires_action` の意味は「このイベントを受け取ったエージェントが、通知だけでなく確認・承認・修正などの操作を検討すべきか」である。`orca.session.completed` と `github.pr.merged` は `false`、`orca.session.failed`・`orca.approval.required`・`github.workflow.failed`・`github.review.requested` は `true` とする。

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

Tailscale や Cloudflare Mesh は Edge Collector と Hub の内部通信には適しているが、それだけで ChatGPT クラウドからプライベートアドレスへ直接接続できるわけではない。

### OAuth 2.1 認可サーバー（Phase C2）

HTTP 公開時に固定 Bearer トークンを ChatGPT へ手入力する構成は避ける。Phase C2 では Hub 自身が OAuth 2.1 の認可サーバー兼リソースサーバーとして動作する。認可コードフローは **PKCE S256 必須**で、`code_challenge_method=plain` や PKCE なしの要求は認可しない。

#### ディスカバリ

| エンドポイント | 仕様 | 内容 |
| --- | --- | --- |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | `issuer`、認可・トークン・失効エンドポイント、対応 grant、`S256`、スコープ、クライアント認証方式 |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 | `resource`、`authorization_servers`、`scopes_supported`、`bearer_methods_supported` |

`issuer` は `[oauth].issuer` の値（末尾 `/` を正規化）を使う。401 の `WWW-Authenticate` は OAuth 有効時に次の形で保護リソースメタデータを案内する。

```text
WWW-Authenticate: Bearer resource_metadata="<issuer>/.well-known/oauth-protected-resource"
```

#### 認可と同意

`GET /oauth/authorize` は次を検証して同意画面を返す。

- `response_type=code`
- 登録済み `client_id`
- 登録値と**完全一致**する `redirect_uri`
- `code_challenge_method=S256` と 43 文字の base64url S256 challenge
- クライアントに許可された `scope` の部分集合
- 任意の `state` / `resource`

`client_id` が不明、または `redirect_uri` が未登録の場合は**リダイレクトせず 400**を返す。オープンリダイレクトにしないための境界である。

同意画面は次の防御を持つ。

- `HttpOnly; SameSite=Lax; Path=/oauth/authorize` の CSRF cookie と hidden field の double-submit
- `[oauth].admin_secret_env` が指す管理者承認 secret（定時間比較）
- `Cache-Control: no-store`、`X-Frame-Options: DENY`、`Content-Security-Policy`
- 動的な client id・principal・redirect URI・state・scope はすべて HTML escape

承認時は CSPRNG 256 bit の認可コードを発行し、`303 See Other` で `redirect_uri` へ `code` と `state` を返す。拒否時は同じく 303 で `error=access_denied` を返す。コードの TTL は `authorization_code_ttl_secs`（既定 300 秒）。

#### トークン

`POST /oauth/token` は `application/x-www-form-urlencoded` のみを受け付け、成功・失敗とも `Cache-Control: no-store` と `Pragma: no-cache` を返す。

`grant_type=authorization_code`:

- confidential client は Basic 認証または form の `client_secret`、public client は secret なし
- `redirect_uri` は認可要求時と完全一致
- `code_verifier` は `[A-Za-z0-9\-._~]{43,128}`
- SHA-256(`code_verifier`) の base64url を定時間比較
- コード消費は `used_at IS NULL` を条件にした単一 UPDATE で原子的に行う
- 消費済みコードの再利用では、そのコードに紐づくトークン family 全体を失効させて 400 `invalid_grant`

`grant_type=refresh_token`:

- クライアント所有権を確認
- リフレッシュトークンを原子的にローテーションし、`rotated_from_hash` を記録
- ローテーション済み・失効済みトークンの再利用では family 全体を失効させて 400 `invalid_grant`
- `scope` によるダウンスコープを許可し、元の grant を超える要求は `invalid_scope`

#### 失効

`POST /oauth/revoke`（RFC 7009）はクライアントを認証し、トークン所有権を確認して失効させる。リフレッシュトークンの失効は family 全体（アクセストークンを含む）に及ぶ。他クライアント所有のトークンや未知のトークンは存在を漏らさず HTTP 200 `{}` を返す。レスポンスは `Cache-Control: no-store`。

#### 保存する情報

`migrations/006_oauth.sql` は次のテーブルを作る。

- `oauth_authorization_codes`
- `oauth_access_tokens`
- `oauth_refresh_tokens`

SQLite に保存するのは認可コード・アクセストークン・リフレッシュトークンの **SHA-256 hex digest** のみである。`code_hash` / `token_hash` を主キーとし、raw secret は保存しない。`used_at`、`revoked_at`、`expires_at`、`rotated_from_hash`、`family_id` で再生・ローテーション・family 失効を判定する。

#### スコープとエンドポイント対応

| スコープ | HTTP | MCP |
| --- | --- | --- |
| `events.read` | `GET /consumers/{name}/probe`、`GET /consumers/{name}/poll` | `events/list`、`events/poll`（実装時）、`list_events`、`get_event`、`get_t3_run`、`get_t3_approvals`、`get_github_status`、`probe_consumer`、`poll_consumer_events` |
| `events.subscribe` | — | `events/subscribe`、`events/unsubscribe` |
| `events.ack` | `POST /consumers/{name}/ack` | `ack_events`、`ack_consumer_events` |

`POST /mcp` では単一 JSON-RPC と batch array の両方について、rmcp へ転送する前に `tools/call` のツール名と `events/*` のメソッド名を検査する。不足時は 403 と次のヘッダを返す。

```text
WWW-Authenticate: Bearer error="insufficient_scope", scope="events.ack"
```

認証済み OAuth principal は HTTP request extension で rmcp の `RequestContext` に渡され、`ack_events` などの所有権判定に使う。stdio では従来どおり `[auth].principal` にフォールバックする。

#### 静的 Bearer との共存

`[auth].token_env` の静的トークンは引き続き利用できる。静的トークンは全スコープ（`events.read`、`events.subscribe`、`events.ack`）を持つ。OAuth と静的トークンは同時に有効化できる。

`oauth.enabled = true` かつ `auth.token_env` が未設定の場合、`/mcp` と `/consumers/*` は**必ず OAuth Bearer を要求**し、未認証アクセスへフォールバックしない。OAuth も静的トークンも無効な場合だけ、従来の loopback / ローカル principal 動作になる。

`GET /healthz`、`/.well-known/oauth-*`、`/oauth/*`、`/webhooks/github`、`/internal/edge/t3` はそれぞれの既存の扱いを維持する。`/oauth/*` と `/.well-known/*` にも Host allowlist 検証を適用し、`POST /oauth/authorize` は `Origin` がある場合に同一 origin / allowlist を要求する。

#### 事前登録クライアントを選ぶ理由

Phase C2 は Dynamic Client Registration（DCR）を公開しない。クライアントは `[[oauth.clients]]` に事前登録する。

- 管理者承認 secret と組み合わせて、誰が consent を承認できるかを運用側で固定できる
- redirect URI の allowlist を設定ファイルでレビューできる
- 公開 DCR が持つ client registration の abuse・掃除・信頼境界の問題を避けられる
- principal を client ごとに固定でき、ack の所有権を安定させられる

#### 静的 Bearer から OAuth 2.1 への移行

1. `[oauth]` を有効化し、`issuer`（公開 HTTPS URL）と `admin_secret_env` を設定する。
2. `[[oauth.clients]]` に MCP クライアントを登録する。confidential client は `client_secret_env`、public client は省略する。`redirect_uris` は完全一致で登録する。
3. クライアントの `scopes` を最小権限で設定する。読み取りだけなら `events.read`、承認操作が必要なら `events.ack` を追加する。
4. `auth.token_env` を残したまま OAuth を併用し、クライアントを OAuth フローへ切り替える。この間、静的トークンは全スコープで動作する。
5. すべてのクライアントが OAuth に移行したら `auth.token_env` を削除し、Hub を再起動する。以後 `/mcp` と `/consumers/*` は OAuth 必須になる。
6. `client_secret_env` と `admin_secret_env` の実値は環境変数または secret manager に置き、設定ファイルやリポジトリへ書かない。
7. DB にはハッシュだけが残る。既存の静的トークン文字列を DB へ移す必要はない。

## 8. dots の通知とステータス表示の扱い

| やりたいこと | ChatGPT での実現方法 |
| --- | --- |
| Orca のターン完了で dots を起動 | MCP Events 購読 |
| CI 失敗時に dots が原因を調査 | MCP Events + MCP Tool |
| イベントを dots の会話へ報告 | イベントトリガータスクの指示 |
| 複数イベントをまとめて報告 | タスクのバッチ設定とサーバー側集約 |
| dots の通知・アクティビティに結果を反映 | ChatGPT 側の処理・通知設定による |
| 任意のステータスバッジを直接点灯 | MCP Events サーバーからは直接制御不可 |

**Webhook の配信成功を「通知バッジ点灯成功」とみなさない。** Webhook 受信後に ChatGPT が登録済みタスクを処理するが、MCP サーバーが UI の表示状態を直接指定する API は定義されていない。

dots への監視指示の例:

> 接続した `events-bridge` の MCP Events を購読してください。Orca の承認・入力待ちや失敗と GitHub CI 失敗は発生時に調査して報告してください。正常完了は短時間のイベントをまとめ、プロジェクト別に報告してください。問題の修正や承認操作は勝手に行わず、まず原因と対応案を提示してください。同一イベントの再配送では重複処理を避けてください。

## 9. 実装・検証の優先順位

1. **MCP Events プロトコルの最小実装**: events/list・poll・subscribe・unsubscribe、Webhook 検証、署名、SQLite 永続化
2. **Orca Collector**: ターン完了、承認・入力待ち、失敗を採取し、観測したイベントを永続化
3. **GitHub Collector**: Webhook 受信、API 補正、重複排除、PR・CI の対応付け
4. **複数ホスト統合**: Linux と macOS の Edge Collector、中央 Hub への認証済み転送
5. **ChatGPT 実機検証**: 購読生成、チャレンジ検証、イベント配信、dots の自動処理、再起動復旧

実機検証では Webhook の HTTP `2xx` だけでなく、実際の dots タスクが起動し、指定された内容がユーザーに提示されるまで確認する。

## 10. Muse ポーリングコンシューマー（Phase A / A2）

ChatGPT の MCP Events 購読は「クライアントが URL と秘密鍵を登録し、サーバーが署名付き Webhook を push する」方式である。これに対して Muse などの常駐クライアントは、SSH 越しの CLI や cron/hook から**サーバー側カーソルを poll/ack する pull 方式**の方が扱いやすい。Phase A ではこの pull 経路を `consumers` として追加する。

### 10.1 subscriptions と consumers の概念的な違い

| 項目 | `subscriptions`（ChatGPT Webhook） | `consumers`（Muse polling） |
| --- | --- | --- |
| 主導権 | クライアントが購読を登録 | クライアントが任意のタイミングで poll |
| 配信方向 | サーバーから callback URL へ push | クライアントがサーバーから pull |
| 状態 | `subscriptions` + `deliveries` + `delivery_attempts` | `consumers.cursor_sequence` のみ |
| フィルター | 購読ごとの `arguments`（イベント定義の inputSchema） | `[consumers.<name>]` の `events` / `filters` プロファイル |
| 有効期限 | `refreshBefore` による TTL。期限前に再購読が必要 | なし。行は永続 |
| 重複制御 | `UNIQUE(subscription_id, event_id)` による Webhook 配信の冪等性 | カーソルを ack まで進めない at-least-once |
| 消費者ごとの独立性 | 購読 ID 単位 | consumer 名単位でカーソルを完全分離 |
| 用途 | ChatGPT / dots の自動タスク起動 | Muse の SSH CLI・cron・hook チェック |

両者は同じ `events` テーブルを読むが、`consumers` は `deliveries` を一切作らない。`ack_events`（ユーザー確認履歴）とも独立しており、consumer の ack は `consumers.cursor_sequence` だけを動かす。

### 10.2 スキーマ（A1）

`migrations/005_consumers.sql` で次を追加する（`PRAGMA user_version = 5`）。

```sql
CREATE TABLE consumers (
    name            TEXT PRIMARY KEY,
    cursor_sequence INTEGER NOT NULL DEFAULT 0 CHECK (cursor_sequence >= 0),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_polled_at  TEXT,
    last_acked_at   TEXT
);
```

`probe` は行がなければ `cursor_sequence = 0` で自動初期化する。`poll` は `last_polled_at` と `updated_at` だけを更新し、`cursor_sequence` は変更しない。`ack` は `0 <= upToSequence <= latestSequence` を検証したうえで `max(current, upToSequence)` へ単調に進める。古い sequence の ack は no-op（`advanced: false`）とし、既読イベントを再び開かない。

### 10.3 プロファイルと disposition（A3）

`[consumers.<name>]` でイベント名ごとの扱いを定義する。

- `immediate`: 即時通知対象。`probe` の unread に数え、`poll.events` に 1 件ずつ返す。
- `digest`: 集約対象。`poll.digests` に時間ウィンドウ単位の要約として返す（A4）。
- `off`: `probe`・`poll` の両方から除外する。

未指定イベントの扱いは `default_disposition`（既定 `off`）。`filters` は `environment_ids` / `project_ids` / `repositories` の allowlist で、空配列は制限なしを意味する。イベント payload に対応するキーがない場合は不一致として除外する。

`muse` という名前は組み込みプロファイルとして常に解決できる（大文字小文字を区別しない）。`[consumers.muse]` または `[consumers.Muse]` を書いた場合は、組み込みのイベント表に対してキー単位でマージされる。たとえば `"github.pr.merged" = "off"` と書くと、そのイベントだけが無効になる。

| イベント | 組み込み Muse の disposition |
| --- | --- |
| `orca.approval.required` | `immediate` |
| `orca.session.failed` | `immediate` |
| `github.workflow.failed` | `immediate` |
| `github.review.requested` | `digest` |
| `github.pr.merged` | `digest` |
| `orca.session.completed` | `digest` |

既存の T3 イベントにも従来の disposition を適用する。

### 10.4 3つのサーフェス（A1/A2）

**CLI**

```console
events-bridge poll --consumer muse --probe
events-bridge poll --consumer muse --limit 50
events-bridge poll --consumer muse --ack 123
events-bridge ack --consumer muse --up-to 123
```

`--config` / `--db` で設定と DB を明示できる。stdout は 1 個の JSON ドキュメントのみで、ログは stderr に限定する。

**Hub HTTP**

```text
GET  /consumers/{name}/probe
GET  /consumers/{name}/poll?limit=N
POST /consumers/{name}/ack   {"upToSequence": 123}
```

3 エンドポイントとも `Authorization: Bearer` と Host/Origin の HTTP セキュリティ検証を通す。ack は `{"cursor": 123}` も受け付ける。

**MCP tools**

| ツール | 引数 | 権限 |
| --- | --- | --- |
| `probe_consumer` | `consumer` | Read |
| `poll_consumer_events` | `consumer`, `limit` (1..=200) | Read |
| `ack_consumer_events` | `consumer`, `up_to_sequence` | Write |

既存の `ack_events` は変更しない。`ack_consumer_events` は consumer カーソル専用である。

### 10.5 2段階チェック

高頻度の hook/cron では、まず `probe` だけを呼ぶ。`hasUpdates` / `unreadCount` が 0 なら本文取得も ack も行わない。更新がある場合だけ `poll` し、処理完了後に返却された `nextCursorSequence` で `ack` する。poll と ack の間にプロセスが落ちても、カーソルは進んでいないためイベントは再返却される（at-least-once）。

### 10.6 digest 集約（A4）

`digest` disposition のイベントは `poll.events` に混ぜず、`poll.digests` に時間ウィンドウ単位で集約する。

- ウィンドウは `occurred_at` を `chrono::DateTime::parse_from_rfc3339` で解釈し、`digest_window_secs`（既定 `600` 秒）で floor する。
  `window_start_epoch = timestamp - timestamp.rem_euclid(window_secs)`、`windowEnd = windowStart + window_secs`。
- `windowStart` / `windowEnd` は RFC 3339 UTC（例 `2026-11-16T01:00:00Z`）で、半開区間 `[windowStart, windowEnd)` を表す。
- `digests` は `windowStart` の昇順。1 エントリは次の形。

```json
{
  "windowStart": "2026-11-16T01:00:00Z",
  "windowEnd": "2026-11-16T01:10:00Z",
  "count": 3,
  "countsByKind": { "orca.session.completed": 2, "github.review.requested": 1 },
  "eventIds": ["evt_...", "evt_...", "evt_..."],
  "eventIdsTruncated": false,
  "maxSequence": 42
}
```

- `count` はウィンドウ内の digest イベント総数、`countsByKind` はイベント種別ごとの件数、`maxSequence` はウィンドウ内の最大 sequence。
- `eventIds` は昇順 sequence の先頭から `max_digest_event_ids`（既定 `50`）件まで。`count` がそれを超える場合は `eventIdsTruncated: true`。
- `nextCursorSequence` は `events` と `digests` の両方がカバーする最大 sequence。したがって `ack(nextCursorSequence)` は immediate と集約済み digest の両方を前進させる。

### 10.7 catchup 制御（A5）

`limit_override` があればそれを、なければ `max_events_per_poll` を使い、どちらも `1..=MAX_CONSUMER_POLL_LIMIT`（200）に clamp する。

- **immediate は決して落とさない。** まず immediate イベントを `limit + 1` 件読み、`limit` 件まで返す。digest の backlog が大きくても immediate が後回しにされることはない。
- immediate が `limit` 件に達したページでは、それ以降の digest は返さず `hasMore: true` とする。ただし、最後に返した immediate 以下の sequence にある digest は ack で飛ばさないよう、その範囲だけ要約に含める。
- immediate が `limit` 件未満なら未読 immediate は全件含まれる。残り予算 `limit - immediate_count` に対して未読 digest を調べる。
  - 未読 digest が残り予算以下: 全件をウィンドウ集約し、`truncated: false`、`hasMore: false`。
  - 未読 digest が残り予算を超える: immediate を全件保持したまま digest を最大 `MAX_DIGEST_CATCHUP_EVENTS`（10,000）件まで走査して要約し、`truncated: true`。
- digest の走査上限を超えた場合は `hasMore: true` とし、`nextCursorSequence` は返却済みの要約の最大 sequence に留める。未返却イベントを飛ばすことはない。
- `truncated` は「limit 以外の理由で詳細を要約に落とした」ことを示し、`hasMore` は「未返却イベントが残っている」ことを示す。

## 最終推奨構成

Rust 単一バイナリ、Edge / Hub 二層構成、MCP Events Webhook 配信を正式な主経路とする設計。

## 主要な参照仕様

- OpenAI — MCP Events 公式実装ガイド: https://developers.openai.com/plugins/build/mcp-events
- MCP Events ドラフト仕様: https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md
- OpenAI — Secure MCP Tunnel: https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
- OpenAI — MCP プラグイン認証仕様: https://developers.openai.com/plugins/build/auth
- [Orca CLI リファレンス](https://orca.dev/docs/cli/reference)
- 公式 Rust MCP SDK: https://github.com/modelcontextprotocol/rust-sdk
