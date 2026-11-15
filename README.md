# events-bridge

T3 Code と GitHub のイベント（実行完了・失敗・承認待ち、CI 失敗、レビュー要求、PR マージ）を収集・正規化し、MCP Events（SEP-3415 ドラフト / OpenAI 実装方式）の署名付き Webhook 配信で ChatGPT（dots / Work）へ届ける Rust デーモンです。

- 単一バイナリ、サブコマンド `hub` / `edge` / `stdio`
- 購読・イベント・配信状態は SQLite に永続化し、再起動後も未配信分から再開します
- 配信は Standard Webhooks（HMAC-SHA256）署名つき、指数バックオフ再送つき

設計の正本は [docs/DESIGN.md](docs/DESIGN.md) です。

## 状態

実装中。ChatGPT 実機との接続（Secure MCP Tunnel の権限・ワークスペース関連付け、dots の監視指示登録）は運用側の手順として別途行います。
