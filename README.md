# events-bridge

T3 Code と GitHub のイベント（実行完了・失敗・承認待ち、CI 失敗、レビュー要求、PR マージ）を収集・正規化し、MCP Events（SEP-3415 ドラフト / OpenAI 実装方式）の署名付き Webhook 配信で ChatGPT（dots / Work）へ届ける Rust デーモンです。

- 単一バイナリ、サブコマンド `hub` / `edge` / `stdio`
- 購読・イベント・配信状態は SQLite に永続化し、再起動後も未配信分から再開します
- 配信は Standard Webhooks（HMAC-SHA256）署名つき、指数バックオフ再送つき

設計の正本は [docs/DESIGN.md](docs/DESIGN.md) です。

## Phase 1 の実装範囲

- `hub`: Streamable HTTP `/mcp`、SQLite ストア、Webhook ディスパッチャー
- MCP `initialize` / `server/discover` で `capabilities.events` を公開
- `events/list`（6 イベント）、`events/subscribe`、`events/unsubscribe`
- コールバック検証: `whsec_` 形式検証、HTTPS 必須、DNS 解決結果のパブリック IP 限定、
  IP ピン留め + リダイレクト禁止、署名付きチャレンジのエコー確認
- 1 リクエスト 1 イベントの署名付き配信（本文 256 KiB 上限）、
  5xx / 429 / ネットワークエラーの指数バックオフ再送、410 / 413 の非再送
- Pull ツール `list_events` / `get_event` / `ack_events`
- `stdio`: 汎用 MCP クライアント向けの基本初期化
- `edge`: 骨格のみ（Phase 2 以降）

## 起動

```sh
cp config.example.toml /etc/events-bridge/config.toml
# /etc/events-bridge/config.toml で auth.token_env = "EVENTS_BRIDGE_TOKEN" を設定
$EDITOR /etc/events-bridge/config.toml

export EVENTS_BRIDGE_TOKEN="$(openssl rand -base64 32)"
events-bridge hub --config /etc/events-bridge/config.toml
```

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

## セキュリティ上の注意

- `config.toml`、`.env`、SQLite データベースはコミットしないでください
  （`.gitignore` 済み）。
- 購読の署名シークレットは SQLite に保存されます。データベースファイルの
  パーミッションをデーモンの実行ユーザーだけに制限してください。
- 本番のコールバック URL は HTTPS のみです。テスト用の緩和ポリシー
  (`CallbackPolicy::for_tests`) は設定ファイルや CLI からは有効化できません。

## 状態

Phase 1 実装済み。ChatGPT 実機との接続（Secure MCP Tunnel の権限・ワークスペース
関連付け、dots の監視指示登録）は運用側の手順として別途行います。
