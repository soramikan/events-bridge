# Orca Edge コレクター

Mini と Mado で Orca CLI を定期実行し、各ホストのセッション状態からイベントを生成する。
Edge は採取したイベントを SQLite に保存し、署名付きで pm-01 の Hub に転送する。

## Orca 1.4.273 で確認した取得経路

| 経路 | 確認結果 |
| --- | --- |
| `agent list --json` / `agent read --json` | Mado のサーバー版 `/opt/orca-server/bin/orca-ide` でも動作する。サーバー版では Orca と同じ実行ユーザーと `ORCA_USER_DATA_PATH=/home/sora/.config/orca` でローカルランタイムを読めた。list の `done` には終了理由が含まれない。read は端末の履歴に最終応答を伴う終了がある場合に `done` を返す。 |
| `worktree ps --agent-wait --json` | Mado のサーバー版と、既存のペアリング経由で Mini のデスクトップ版から JSON を取得できた。主エージェントの状態・終了結果・状態開始時刻と、対応する端末では待機の観測結果を取得できる。 |
| Orca の保存ファイル | Mado には `agent-session-domain.db` のセッションジャーナルと `orchestration.db` の Run / Dispatch / Gate などの内部テーブルがある。形式や更新規則は CLI の契約に含まれず、端末とチャットで保存経路も異なるため採用しない。 |
| `agent hooks`、orchestration | Mado の `agent hooks status --json` は有効を返した。これはフック設定の照会。`gate-list` は Run の明示的な決定ゲート、`worker-show` の `observation.agentWait` は対象 Dispatch の端末状態を返す。セッション全体の状態は `worktree ps` を使う。 |

[Orca CLI リファレンス](https://orca.dev/docs/cli/reference) ·
[1.4.273 の worktree 応答型](https://github.com/stablyai/orca/blob/v1.4.273/src/shared/worktree/catalog/runtime-worktree-contracts.ts) ·
[1.4.273 の agent read 実装](https://github.com/stablyai/orca/blob/v1.4.273/src/main/runtime/agent-conversations/agent-conversation-read.ts)

## 通知の条件

Edge は `worktree ps --limit 2000 --agent-wait --environment local --json` を実行し、
`hostId = "local"` のワークスペースを処理する。

| イベント | Muse の disposition | 観測条件 |
| --- | --- | --- |
| `orca.session.completed` | `digest` | 主エージェントの結果が `success` で、子タスクを含む行の状態が `done`。結果が欠けている端末では、応答のある `done` 行に対し `agent read --limit 5` でも最新ターン終了を確認する。 |
| `orca.session.failed` | `immediate` | 主エージェントの終了結果が `failure` または Orca が予期しない中断と判定した `interruption`。ユーザーによる中止は通知対象外。 |
| `orca.approval.required` | `immediate` | ネイティブチャットの主エージェントが `blocked` / `waiting`、または端末の `agentWait` に承認・入力待ちの根拠と採取に使える時刻がある。 |

端末では、承認・対話プロンプトの明示的な理由、またはフックやタイトルによる権限待ちの観測と
`blocked` / `waiting` の組み合わせを使う。理由がサインインや起動時の確認と明示されている場合は除外する。
Orca が終了結果や待機を報告できないエージェントでは、そのイベントを発行できない。
ポーリング間に状態が上書きされたりセッションが一覧から消えたりすると、イベントを取りこぼすことがある。
応答に `truncated: true` がある場合やローカルホストが対象に含まれていない場合は、その回の採取を中止する。

[1.4.273 のチャット状態判定](https://github.com/stablyai/orca/blob/v1.4.273/src/shared/agent-session/view/structured-agent-session-agent-status.ts) ·
[1.4.273 の端末待機判定](https://github.com/stablyai/orca/blob/v1.4.273/src/main/runtime/terminal/wait/terminal-interactive-wait.ts)

Hub に送るのはホスト識別子、Orca セッション ID、利用できる場合はプロジェクト ID、
イベント種別、状態開始時刻。プロンプト、応答本文、端末出力、エラー本文は保存・転送しない。
Hub は定型の `summary` と `severity`、`requires_action` を加える。

## 再送と並行稼働

初回の正常なスナップショット取得を開始した時刻を Edge の起点として保存し、それより前の状態は通知しない。
イベント ID はホストの `environment_id`、Orca のセッション ID、イベント種別、Orca の状態開始時刻を
JSON 配列にして SHA-256 でハッシュし、`evt_orca_` を付ける。同じセッションで次のターンが終わると
時刻が変わり、別のイベントになる。Mini と Mado には異なる値を設定し、サービス再起動や更新で変えない。

Edge は HTTP 2xx を受け取るまで送信待ちの本文を保持する。再送では新しい署名ノンスを使う。
同じ観測を繰り返した場合は Edge の SQLite で、応答消失などで再送した場合は Hub の
`events.id` で重複排除する。Hub への通信に失敗しても Edge は状態を採取し続ける。

旧 T3 Edge と Orca Edge を重ねて稼働させる場合、T3 のイベントは `evt_t3_`、
Orca は `evt_orca_` に属する。収集元をまたぐ共通の実行 ID がないため、同じ作業を
両方で実行するとそれぞれ通知される。移行中は作業ごとに実行基盤を一つにする。

## 本番切り替え手順

1. pm-01 の既存 Hub データベースを引き継いで新しいバイナリへ更新する。
   `[server]` の `enable_edge_ingest` と、既存の HMAC シークレットを参照する
   `edge_shared_secret_env` を設定する。経路を制限している場合は
   `POST /internal/edge/orca` を既存 Edge と同じ保護下で通す。
   旧 Edge をホストごとに入れ替える期間だけ `accept_legacy_t3_edge = true` を設定する。
2. Muse のプロファイルに個別上書きや環境・プロジェクトのフィルターがある場合は、
   Orca のイベント名と ID を含める。通知テンプレートや処理側のイベント名分岐を
   `orca.*` に対応させる。完了 digest の `countsByKind` にも対応させる。
   カーソルを維持し、これまでどおり処理後に `nextCursorSequence` を ack する。
3. Mini と Mado で、Edge の実行ユーザーから Orca CLI がローカルランタイムを読めることを確認する。
   Mini はデスクトップの同じログインユーザーで CLI の絶対パスを指定する。
   Mado は `/opt/orca-server/bin/orca-ide` を指定し、サービス環境に
   `ORCA_USER_DATA_PATH=/home/sora/.config/orca` を渡す。
   各ホストで `[collectors.orca].environment_id` と Edge 用の永続 DB を設定する。
4. 各ホストの旧 T3 Edge を停止し、新しい `events-bridge edge` を起動する。
   起動後の新しいターンで、Hub に `source = "orca"` とホストの ID が届くこと、
   Muse の完了 digest と即時通知が期待どおり表示されることを確認する。
5. 両ホストの入れ替え後は `accept_legacy_t3_edge` を無効にし、旧サービス定義と
   使わなくなった `[collectors.t3]` 設定を外す。Hub 内の T3 イベントやカーソルは引き継ぐ。
