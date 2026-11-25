# events-bridge

Orca と GitHub のイベント（セッションの完了・失敗・承認待ち、CI 失敗、レビュー要求、PR マージ）を収集・正規化し、MCP Events（SEP-3415 ドラフト / OpenAI 実装方式）の署名付き Webhook 配信で ChatGPT（dots / Work）へ届ける Rust デーモンです。

- 単一バイナリ、サブコマンド `hub` / `edge` / `stdio`
- 購読・イベント・配信状態は SQLite に永続化し、再起動後も未配信分から再開します
- 配信は Standard Webhooks（HMAC-SHA256）署名つき、指数バックオフ再送つき

設計は [docs/DESIGN.md](docs/DESIGN.md)、Orca Edge の運用は
[docs/ORCA-COLLECTOR.md](docs/ORCA-COLLECTOR.md)、Muse のポーリング契約は
[docs/CLAUDE-CONSUMER.md](docs/CLAUDE-CONSUMER.md) を参照してください。
ChatGPT / dots への接続手順は [docs/CHATGPT-SETUP.md](docs/CHATGPT-SETUP.md) にあります。

## Phase 1 の実装範囲

- `hub`: Streamable HTTP `/mcp`、SQLite ストア、Webhook ディスパッチャー
- MCP `initialize` / `server/discover` で `capabilities.events` を公開
- `events/list`、`events/subscribe`、`events/unsubscribe`
- コールバック検証: `whsec_` 形式検証、HTTPS 必須、DNS 解決結果のパブリック IP 限定、
  IP ピン留め + リダイレクト禁止、署名付きチャレンジのエコー確認
- 1 リクエスト 1 イベントの署名付き配信（本文 256 KiB 上限）、
  5xx / 429 / ネットワークエラーの指数バックオフ再送、410 / 413 の非再送
- Pull ツール `list_events` / `get_event` / `ack_events`
- `stdio`: 汎用 MCP クライアント向けの基本初期化（Phase 4 で Collector 連携と
  統合テストを追加）
- `edge`: 各ホストから Orca イベントを転送

## 旧 T3 Code イベント

Hub に保存済みの T3 イベントと投影は、`list_events` / `get_event`、
`get_t3_run` / `get_t3_approvals` で参照できます。
移行前の実装は [docs/T3-COLLECTOR.md](docs/T3-COLLECTOR.md) に記録しています。

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

## Orca Edge / Hub

- Orca と同じホストの Edge が読み取り用 CLI からエージェントの状態を採取します。
- Edge はイベントを SQLite に保存し、HMAC-SHA256 署名付きの
  `POST /internal/edge/orca` で転送します。Hub の HTTP 2xx まで再送対象として保持します。
- 同じ状態を再観測したときや再送時には、ホスト・セッション・種別・状態開始時刻から
  求めたイベント ID で重複排除します。
- GitHub の収集と Muse の cursor / ack は従来の経路を使います。
- 旧 T3 Edge の転送は移行期間に限り、Hub の `accept_legacy_t3_edge` で許可できます。

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

### Edge（Orca が動作するホスト）

```toml
[database]
path = "/var/lib/events-bridge/edge.db"

[collectors.orca]
environment_id = "mado"
cli_path = "/opt/orca-server/bin/orca-ide"

[edge]
hub_url = "https://bridge.example.com"
shared_secret_env = "EVENTS_BRIDGE_EDGE_SECRET"
```

Orca と同じユーザーおよびランタイム環境で `events-bridge edge --config /etc/events-bridge/config.toml`
を実行します。ホストごとに固有の `environment_id` を設定します。
共有シークレットは Hub と同じ値を環境変数から渡してください。
Mini と Mado の設定および移行順は [docs/ORCA-COLLECTOR.md](docs/ORCA-COLLECTOR.md) を参照してください。

### stdio（汎用 MCP クライアント / トンネル）

```sh
events-bridge stdio
# 設定を渡す場合
events-bridge stdio --config /etc/events-bridge/config.toml
```

`collectors.github.poll_enabled` が有効な設定を渡すと、Hub と同じ GitHub ポーラーが
バックグラウンドで起動します。stdout は MCP メッセージ専用で、ログは stderr に出力されます。

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
    "kind": "orca.session.completed",
    "payload": {
      "environment_id": "mado",
      "session_id": "orca_session_id:00000000-0000-4000-8000-000000000001",
      "summary": "An Orca agent finished a turn."
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

`tests/e2e_edge_hub.rs` では、署名付き Orca 取り込みと Muse の cursor / ack を
ローカルの Hub で検証します。Orca CLI の応答・ホスト境界・再起動時の再送はコレクターの単体テスト、
旧 T3 Edge の互換性と配信経路は同じローカル E2E で検証します。

- 旧 T3 Edge の初回スナップショットと差分転送、Hub 側の単一トランザクション取り込み
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

Orca / GitHub の収集、Hub の Webhook 配信、MCP と Muse のポーリングに対応しています。
ChatGPT 実機・dots・クラウド側の接続と確認は **未実施の運用側作業** であり、
[docs/CHATGPT-SETUP.md](docs/CHATGPT-SETUP.md) に手順と確認項目をまとめています。
ローカルの自動テストは Edge / Hub / GitHub / 署名配信 / 再起動復旧 / 410 / リプレイ
拒否 / stdio をループバックで検証しますが、ChatGPT 実機の動作を保証するものでは
ありません。
