# ChatGPT / dots 接続セットアップ

このドキュメントは、`events-bridge` を ChatGPT（dots / Work）から利用するための
**運用側の作業手順** をまとめたものです。

> **重要**
>
> ここに書かれている ChatGPT 実機、dots、OpenAI Platform、Cloudflare などの
> クラウド側の操作・設定・確認は、すべて **未実施・運用側の作業** です。
> このリポジトリの実装やローカル自動テストが、ChatGPT 実機での動作を検証した
> ことを意味しません。実機で確認するまで「検証済み」「動作確認済み」と
> 表現しないでください。
>
> ローカルで自動検証済みなのは、ループバック上の Hub / Edge / GitHub Webhook /
> Mock ChatGPT Webhook Receiver / stdio を使った範囲です。詳細は
> `tests/e2e_edge_hub.rs` と `README.md` の「テスト」を参照してください。

## 1. 推奨経路: OpenAI Secure MCP Tunnel

設計（[DESIGN.md](DESIGN.md) §7）では、ChatGPT からプライベートネットワーク内の
MCP サーバーへ接続する経路として **OpenAI Secure MCP Tunnel** を推奨しています。

### 1.1 前提（運用側で確認）

- OpenAI Platform 側で Secure MCP Tunnel を利用できる権限があること。
- 対象の ChatGPT ワークスペースとトンネルを関連付けられること。
- Hub はループバックまたはプライベートネットワーク上で起動し、`/mcp` を
  インターネットへ直接公開しないこと。
- `tunnel-client` が Hub へ到達できること（同一ホストまたはプライベート経路）。

### 1.2 手順（未実施・運用側の作業）

1. Hub を起動します。

   ```sh
   export EVENTS_BRIDGE_TOKEN="$(openssl rand -base64 32)"
   events-bridge hub --config /etc/events-bridge/config.toml
   ```

2. 別ターミナルで `tunnel-client` を起動し、Hub の `/mcp` を対象にします。
   具体的なコマンド・トンネル ID・認証情報は OpenAI の最新ドキュメントに従って
   ください。**このリポジトリにはトンネル資格情報を保存しません。**

3. OpenAI Platform / ChatGPT 側で、トンネルを対象ワークスペースに関連付けます。

4. ChatGPT から MCP サーバーへ接続し、`initialize` と `tools/list` が返ることを
   確認します。

5. `events/list` で `orca.session.completed`、`orca.session.failed`、
   `orca.approval.required` と GitHub のイベントが見えることを確認します。

### 1.3 代替: Cloudflare Tunnel + OAuth 2.1

HTTPS で公開する場合は Cloudflare Tunnel なども使えますが、次の点に注意して
ください（これも **未実施・運用側の作業** です）。

- 単純な固定 Bearer トークンを ChatGPT に手入力させない。OAuth 2.1 を構成する。
- 推奨スコープの例: `events.read`、`events.subscribe`、`events.ack`。
- `server.allowed_hosts` に公開ホスト名を追加する。
- Origin 検証と Host 検証を無効化しない。
- 公開 URL は HTTPS とし、Hub の `auth.token_env` だけに依存しない。
- Tailscale / Cloudflare Mesh は Edge と Hub の内部通信には向きますが、
  それだけで ChatGPT クラウドからプライベート IP へ直接接続できるわけでは
  ありません。

## 2. dots への監視指示プロンプト例

設計（[DESIGN.md](DESIGN.md) §8）に基づく例です。実際のプロジェクト名・
リポジトリ名・環境 ID に置き換えてください。

```text
接続した events-bridge の MCP Events を購読してください。

- Orca の承認・入力待ち（orca.approval.required）とターン失敗（orca.session.failed）は
  発生時にホストとセッション ID をすぐに報告してください。
- GitHub Actions の失敗（github.workflow.failed）は、失敗した workflow、
  ブランチ、実行 URL を確認し、原因と対応案を提示してください。
- Orca のターン完了（orca.session.completed）は短時間のイベントをまとめ、
  プロジェクト別に報告してください。
- 問題の修正や承認操作は勝手に行わず、まず原因と対応案を提示してください。
- 同一イベントの再配送では重複処理を避けてください。
- Webhook の 2xx は受信確認であり、dots の処理完了を意味しません。
```

購読の例（環境 ID で分離する場合）:

```json
{
  "name": "orca.approval.required",
  "arguments": { "environment_id": "mac-mini" },
  "delivery": {
    "mode": "webhook",
    "url": "https://<chatgpt-webhook-endpoint>",
    "secret": "whsec_<...>"
  }
}
```

`secret` は ChatGPT 側が発行する値をそのまま使い、リポジトリや設定ファイルへ
コミットしないでください。

## 3. 実機検証手順（未実施・運用側の作業）

以下はすべて、ChatGPT 実機・dots・クラウド側で運用担当者が実施する項目です。
ローカル自動テストの結果とは独立しています。

### 3.1 購読生成

1. ChatGPT から `events/list` を呼び、イベント定義を取得する。
2. `events/subscribe` を呼び、`orca.approval.required` などを購読する。
3. レスポンスの `id`、`refreshBefore`、`cursor` を記録する。
4. 同じ購読要求を再送し、新しい購読が重複生成されず既存が更新されることを
   確認する。

### 3.2 チャレンジ検証

1. `events/subscribe` の直後に、Hub からコールバック URL へ署名付き
   `verification` が届くことを確認する。
2. 受信側が `challenge` をそのまま返していることを確認する。
3. チャレンジ不一致・タイムアウト時に購読が有効化されないことを確認する。
4. 検証成功前に通常イベントが配信されないことを確認する。

### 3.3 イベント配信

1. Orca で承認・入力待ちまたはターン完了を発生させる。
2. Hub の `list_events` / `get_event` でイベントが永続化されていることを確認する。
3. ChatGPT 側の Webhook が `2xx` を返すことを確認する。
4. `webhook-id`、`webhook-timestamp`、`webhook-signature`、
   `X-MCP-Subscription-Id` が付与されていることを確認する。
5. 同じイベントの再送で `webhook-id` が変わらないことを確認する。

### 3.4 dots タスク起動

1. dots に §2 の監視指示を登録する。
2. 承認待ちイベントを発生させ、dots のタスクが起動することを確認する。
3. dots が `get_event` / `get_github_status` を呼び、
   追加情報を取得できることを確認する。
4. 通知・アクティビティ表示が期待どおりであることを確認する。
5. **Webhook の `2xx` だけを「dots タスク起動成功」とみなさない。**
   実際に dots のタスクが起動し、ユーザーへ内容が提示されるまで確認する。

### 3.5 再起動復旧

1. Hub を停止する。
2. Edge 側で Orca イベントを発生させる。
3. Hub を再起動する。
4. Edge が指数バックオフで再送し、停止中のイベントが欠損なく Hub に取り込まれる
   ことを確認する。
5. Hub の `deliveries` に残った未配信分が再起動後に再送されることを確認する。
6. 購読が期限切れ・無効化されている場合、バックログが再送されないことを確認する。

### 3.6 410 / 413 の扱い

1. 受信側が `410 Gone` を返すと、その購読の再送が停止し、バックログが終端化
   されることを確認する。
2. `413 Payload Too Large` が再送されないことを確認する。
3. 410 後に同じ購読を再作成した場合、古いバックログが復活しないことを確認する。

## 4. ローカル自動テストとの区別

| 項目 | ローカル自動テスト | ChatGPT 実機・dots・クラウド |
| --- | --- | --- |
| Hub / Edge の署名付き転送 | `tests/e2e_edge_hub.rs` で検証済み | 未実施・運用側の作業 |
| 不正署名・時刻ずれ・リプレイ拒否 | `tests/e2e_edge_hub.rs` で検証済み | 未実施・運用側の作業 |
| Hub 再起動後の Edge 追いつき | `tests/e2e_edge_hub.rs` で検証済み | 未実施・運用側の作業 |
| pending delivery の再起動再送 | `tests/e2e_edge_hub.rs` で検証済み | 未実施・運用側の作業 |
| 410 による再送停止 | `tests/e2e_edge_hub.rs` で検証済み | 未実施・運用側の作業 |
| GitHub Webhook / Poll | `tests/e2e_edge_hub.rs` で検証済み | 未実施・運用側の作業 |
| stdio の initialize / tools/list / events/* / tools/call | `tests/e2e_edge_hub.rs` で検証済み | 未実施・運用側の作業 |
| Secure MCP Tunnel の権限・関連付け | 対象外 | 未実施・運用側の作業 |
| ChatGPT からの購読生成・チャレンジ検証 | 対象外 | 未実施・運用側の作業 |
| dots タスクの起動・通知表示 | 対象外 | 未実施・運用側の作業 |

## 5. セキュリティ上の注意

- `EVENTS_BRIDGE_TOKEN`、`EVENTS_BRIDGE_EDGE_SECRET`、
  `EVENTS_BRIDGE_GITHUB_WEBHOOK_SECRET`、ChatGPT の `whsec_...` は
  コード・設定ファイル・ドキュメントへハードコードしないでください。
- シークレットは環境変数、systemd の `EnvironmentFile`、クラウドのシークレット
  管理など、リポジトリ外の仕組みで渡してください。
- SQLite データベースには購読の署名シークレットが保存されます。ファイルの
  パーミッションをデーモンの実行ユーザーだけに制限してください。
- Edge と Hub の通信は、信頼できるプライベートネットワークまたは HTTPS で
  保護してください。`edge.hub_url` にクエリ・フラグメント・userinfo を含めないで
  ください。
- 本番のコールバック URL は HTTPS のみです。テスト用の緩和ポリシー
  （`CallbackPolicy::for_tests`）は設定ファイルや CLI からは有効化できません。
