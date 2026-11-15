# events-bridge

T3 Code と GitHub のイベント（実行完了・失敗・承認待ち、CI 失敗、レビュー要求、PR マージ）を収集・正規化し、MCP Events（SEP-3415 ドラフト / OpenAI 実装方式）の署名付き Webhook 配信で ChatGPT（dots / Work）へ届ける Rust デーモンです。

- 単一バイナリ、サブコマンド `hub` / `edge` / `stdio`
- 購読・イベント・配信状態は SQLite に永続化し、再起動後も未配信分から再開します
- 配信は Standard Webhooks（HMAC-SHA256）署名つき、指数バックオフ再送つき

設計の正本は [docs/DESIGN.md](docs/DESIGN.md)、T3 Code Collector の調査・実装メモは
[docs/T3-COLLECTOR.md](docs/T3-COLLECTOR.md)、ChatGPT / dots 接続の運用側手順は
[docs/CHATGPT-SETUP.md](docs/CHATGPT-SETUP.md) です。

## Phase 1 の実装範囲

- `hub`: Streamable HTTP `/mcp`、SQLite ストア、Webhook ディスパッチャー
- MCP `initialize` / `server/discover` で `capabilities.events` を公開
- `events/list`（6 イベント）、`events/subscribe`、`events/unsubscribe`
- コールバック検証: `whsec_` 形式検証、HTTPS 必須、DNS 解決結果のパブリック IP 限定、
  IP ピン留め + リダイレクト禁止、署名付きチャレンジのエコー確認
- 1 リクエスト 1 イベントの署名付き配信（本文 256 KiB 上限）、
  5xx / 429 / ネットワークエラーの指数バックオフ再送、410 / 413 の非再送
- Pull ツール `list_events` / `get_event` / `ack_events`
- `stdio`: 汎用 MCP クライアント向けの基本初期化（Phase 4 で Collector 連携と
  統合テストを追加）
- `edge`: Phase 4 で実装（上記「Phase 4 の実装範囲」参照）

## Phase 2 の実装範囲（T3 Code Collector）

- T3 Code 0.1.9 の `statev2.sqlite` を **読み取り専用**で参照し、
  `orchestration_events` の `sequence` をカーソルとして追従
- 初回起動時は Projection からスナップショットを水和し、過去の完了 Run を配信しない
- `run.updated` の最終確定だけから `t3.run.completed` / `t3.run.failed` を導出
  （`provider-turn.updated` / `run-attempt.updated` では発火しない）
- `runtime-request.updated` から `t3.approval.required` を導出
- Pull ツール `get_t3_run` / `get_t3_approvals`
- 詳細は [docs/T3-COLLECTOR.md](docs/T3-COLLECTOR.md)

## Phase 3 の実装範囲（GitHub Collector）

- `POST /webhooks/github`（MCP の Bearer / `allowed_hosts` とは独立）
  - `X-Hub-Signature-256` を生バイト列に対して HMAC-SHA256 検証
  - `X-GitHub-Delivery` で重複排除し、配信記録・状態・イベントを単一トランザクションで保存
  - `ping`、`workflow_run`、`check_run`、`pull_request`、`pull_request_review`、
    `pull_request_review_comment` に対応
- `workflow_run` と `check_run` の CI 失敗を「run id + attempt」で正規化し、
  どちらの順序でも 1 回だけ `github.workflow.failed` を配信
  - GitHub Actions の `check_run` はジョブ名しか持たないため、真の workflow 名と
    attempt が分かるまで `github_pending_checks` に保留し、イベントを発火しない
  - 後から来た `workflow_run`（Webhook または REST 照合）が正規の workflow 名・
    attempt で 1 回だけ通知し、対応する保留行を削除
  - Actions 以外の外部 `check_run` は `check_run:<id>` を正規キーとし、
    success / in_progress などの非失敗状態も反映
  - rerun（attempt 2 以降）は新しい失敗として通知
- REST API による定期照合（`collectors.github.poll_enabled`）
  - `collector_checkpoints` に ETag / watermark を保存し、`304 Not Modified` を尊重
  - `Link: rel="next"` を辿ってページングし、設定した API origin / path prefix 以外へは
    リクエストしない
  - watermark より古いページで打ち切り、初回ベースラインでは既存のマージ済み PR・
    失敗 Run を通知しない
  - ローカルで追跡中の未完了 Run と保留中の Actions check は、一覧ページに無くても
    `GET /actions/runs/{id}` で個別に照合
  - 取りこぼしたマージ・レビュー要求・CI 失敗を補完し、後続 Webhook と重複しない
  - 古い Webhook / ポーリング応答では `updated_at` を巻き戻さず、レビュー要求も
    再発火しない
- Pull ツール `get_github_status`（PR・CI の最新状態とサマリー）
- 環境変数で秘密情報を指定: `webhook_secret_env`、任意の `token_env`

## Phase 4 の実装範囲（Edge / Hub 統合）

- `edge` サブコマンド: T3 Code の `statev2.sqlite` を読み取り専用で追従し、
  `T3Reducer` が生成した `T3WriteBatch` を Hub へ HMAC-SHA256 署名付きで転送
  - 初回はスナップショット、以降は `orchestration_events.sequence` 単位の差分
  - 未確認スナップショットは `edge_pending_snapshots` に基準 sequence ごと保存し、
    再試行・再起動時は同じスナップショットを再送（新しい `N+k` を撮り直さない）
  - 大きなスナップショットは `edge.max_snapshot_chunk_bytes` 単位の
    `SnapshotChunk` に分割し、`SnapshotCommit` で Hub 側が原子的に適用
  - ローカルの `source_cursors` / 投影テーブルは **Hub が 2xx を返した後だけ** 更新
  - Hub 停止・ネットワーク障害時は `retry_initial_ms`〜`retry_max_ms` の
    指数バックオフで再送し、復旧後に欠損なく追いつく
  - 古い／重複した Batch は Hub 側で no-op とし、投影とカーソルを巻き戻さない
- Hub の `POST /internal/edge/t3`
  - `X-Edge-Id` / `X-Edge-Timestamp` / `X-Edge-Nonce` / `X-Edge-Signature`
  - 署名対象は `"{edge_id}.{timestamp}.{nonce}." + raw body`
  - 時刻ずれ・署名不一致・同一 `(edge_id, nonce)` の再利用は `401` で拒否し、
    状態を変更しない
  - `edge_nonces` テーブルでリプレイを防止し、期限切れは自動削除
  - スナップショット / 複数バッチを Hub 側の単一トランザクションで適用
  - Batch 内の投影・イベントの `environment_id` 不一致は `422` で拒否
  - チャンク欠損のある `SnapshotCommit` は `422` で拒否し、投影とカーソルを汚さない
- `hub` 単一ホストモード: `collectors.t3.enabled` と `collectors.github.*` を
  有効にした 1 プロセス構成もそのまま動作
- `stdio`: HTTP と同じ 6 ツール + `events/list` / `events/subscribe` /
  `events/unsubscribe` を公開。`--config` で Collector / GitHub Poller も起動し、
  終了時にキャンセル・join
- 複数ホスト: 異なる `environment_id` の Edge と Hub ローカル T3 が同一 Hub に
  共存し、`environment_id` フィルター付き購読が分離される

## 起動

### Hub（中央集約）

```sh
cp config.example.toml /etc/events-bridge/config.toml
# /etc/events-bridge/config.toml で auth.token_env = "EVENTS_BRIDGE_TOKEN" を設定
$EDITOR /etc/events-bridge/config.toml

export EVENTS_BRIDGE_TOKEN="$(openssl rand -base64 32)"
events-bridge hub --config /etc/events-bridge/config.toml
```

Edge を受け付ける場合は Hub 側で次を設定します。

```toml
[server]
enable_edge_ingest = true
edge_shared_secret_env = "EVENTS_BRIDGE_EDGE_SECRET"
```

```sh
export EVENTS_BRIDGE_EDGE_SECRET="$(openssl rand -hex 32)"
```

### Edge（T3 Code が動作するホスト）

```toml
[database]
path = "/var/lib/events-bridge/edge.db"

[collectors.t3]
enabled = true
state_db_path = "/home/example/.t3/userdata/statev2.sqlite"
environment_id = "mac-mini"

[edge]
hub_url = "https://bridge.example.com"
shared_secret_env = "EVENTS_BRIDGE_EDGE_SECRET"
edge_id = "mac-mini"
```

```sh
export EVENTS_BRIDGE_EDGE_SECRET="..."   # Hub と同じ値
events-bridge edge --config /etc/events-bridge/config.toml
```

`edge.hub_url` と `edge.shared_secret_env` は `edge` サブコマンドでのみ必須です。
Hub は `[edge]` セクションが無くても起動します。シークレットは TOML に書かず、
環境変数（または systemd の `EnvironmentFile` など）から渡してください。
`collectors.t3.environment_id` と `environment-id` ファイルのどちらも無い場合、
Edge は OS のホスト名を使用します。ホスト名も解決できない場合は共通の
`"edge"` にフォールバックせず、`collectors.t3.environment_id` の明示設定を
求めて起動に失敗します。

### stdio（汎用 MCP クライアント / トンネル）

```sh
events-bridge stdio
# 設定を渡す場合
events-bridge stdio --config /etc/events-bridge/config.toml
```

`--config` を指定し、`collectors.t3.enabled` または
`collectors.github.poll_enabled` が有効な場合は、Hub と同じ Collector / Poller が
バックグラウンドで起動します。stdout は MCP メッセージ専用で、ログは stderr に
出力されます。

`auth.token_env` を設定しない場合、ハブは認証なしで起動します。ループバックまたは
Secure MCP Tunnel の内側など、信頼できる経路でのみ使用してください。

イベント注入は `server.enable_internal_ingest = true` のときだけ
`POST /internal/events` で有効になります。MCP 認証（`auth.token_env`）が有効な場合は
`Authorization: Bearer ...` が必要であり、さらに `internal_token_env` を設定した場合は
`X-Internal-Token` ヘッダーも必要です（無認証テスト構成では両方省略できます）。

```sh
curl -sS http://127.0.0.1:8787/internal/events \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer ${EVENTS_BRIDGE_TOKEN}" \
  -H "X-Internal-Token: ${EVENTS_BRIDGE_INTERNAL_TOKEN}" \
  -d '{
    "kind": "t3.run.completed",
    "payload": {
      "environment_id": "linux-main",
      "project_id": "lnako",
      "thread_id": "thread-42",
      "run_id": "run-102",
      "summary": "Coding agent run completed",
      "url": "https://t3.example.com/threads/42"
    }
  }'
```

## テスト

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

統合テストはループバック上のモック Webhook レシーバーを使い、購読・チャレンジ検証・
署名付き配信・5xx 再送・410 停止・再起動後の未配信再開までを検証します。
本番の SSRF ポリシーは別途、HTTP URL・プライベート IP・リダイレクト・不正な
`whsec_`・チャレンジ不一致のケースで検証しています。

`tests/e2e_edge_hub.rs` は Phase 4 のローカル E2E です。実際の SQLite フィクスチャ、
Hub、Edge、GitHub Webhook / Poll、Mock ChatGPT Webhook Receiver、stdio を
ループバックで組み合わせ、次を検証します。

- Edge の初回スナップショットと差分転送、Hub 側の単一トランザクション取り込み
- 署名付き Edge リクエストの不正署名・時刻ずれ・ノンスリプレイ拒否（401）
- Hub 停止中の Edge イベントが Hub 再起動後に欠損なく追いつくこと
- 配信途中の Hub 再起動で pending delivery が再送されること
- Receiver の 410 で再送が停止し、バックログが終端化されること
- 複数 `environment_id` の購読分離
- stdio の `initialize` / `tools/list` / `events/list` / `events/subscribe` /
  `tools/call`

これらはローカルの自動テストであり、ChatGPT 実機・dots・クラウド側の動作を
検証したものではありません。

## セキュリティ上の注意

- `config.toml`、`.env`、SQLite データベースはコミットしないでください
  （`.gitignore` 済み）。
- 購読の署名シークレットは SQLite に保存されます。データベースファイルの
  パーミッションをデーモンの実行ユーザーだけに制限してください。
- 本番のコールバック URL は HTTPS のみです。テスト用の緩和ポリシー
  (`CallbackPolicy::for_tests`) は設定ファイルや CLI からは有効化できません。

## 状態

Phase 1・Phase 2（T3 Code Collector）・Phase 3（GitHub Collector）・
Phase 4（Edge / Hub 統合、`stdio` 完成、ローカル E2E）実装済みです。
ChatGPT 実機・dots・クラウド側の接続と確認は **未実施の運用側作業** であり、
[docs/CHATGPT-SETUP.md](docs/CHATGPT-SETUP.md) に手順と確認項目をまとめています。
ローカルの自動テストは Edge / Hub / GitHub / 署名配信 / 再起動復旧 / 410 / リプレイ
拒否 / stdio をループバックで検証しますが、ChatGPT 実機の動作を保証するものでは
ありません。
