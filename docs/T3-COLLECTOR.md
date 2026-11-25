# T3 Code Collector（Phase 2、旧実装）

この文書は旧実装の記録です。現行の Edge と切り替え手順は [Orca Edge コレクター](ORCA-COLLECTOR.md) を参照してください。

T3 Code の実行完了・失敗・承認待ちを、events-bridge のイベントログへ取り込む
Collector の設計と実装メモです。対象はホスト上の **T3 Code 0.1.9** です。

## 1. 実機調査の結果

### 1.1 RPC / WebSocket

`t3 serve`（0.1.9）は `127.0.0.1:3773` で稼働し、
`/ws?orchestrationProtocolVersion=2` と `t3 auth session` を提供しています。
しかし公開 RPC（`orchestration.subscribeThread`、
`orchestration.getThreadProjection` など）は **スレッド単位**です。
全スレッドを横断する単調増加イベントストリームや、任意の位置からのリプレイ RPC は
公開されていません。

そのため「接続のたびに全スレッドを列挙し、スレッドごとに購読・差分比較する」方式に
なります。これはスレッド数に比例した接続と、スレッド間で順序のないイベントを
アプリケーション側で再構成する必要があり、Collector の障害復旧を単純にできません。

### 1.2 Event Adapter の組み込み

T3 Code 本体は `~/.t3/runtime/versions/0.1.9/t3` のビルド済みランタイムです。
events-bridge は他リポジトリ・ランタイムを改変しない方針のため、
T3 Code 側に読み取り専用 Event Adapter を追加する方式は対象外です。

### 1.3 SQLite の実体

`~/.t3/userdata/statev2.sqlite` は WAL モードで、Orchestrator V2 の永続イベントログを
保持しています。

| テーブル | 役割 |
| --- | --- |
| `orchestration_events` | 永続イベントログ。`sequence INTEGER PRIMARY KEY AUTOINCREMENT` |
| `orchestration_v2_projection_runs` | Run の現在状態 |
| `orchestration_v2_projection_threads` | Thread の現在状態（`project_id` を含む） |
| `orchestration_v2_projection_runtime_requests` | 承認・入力待ちの現在状態 |
| `projection_projects` | Project の現在状態 |
| `orchestration_v2_events` | スキーマ上は存在するが 0.1.9 では 0 件 |

`orchestration_events` の主な列は次のとおりです。

```text
sequence, event_id, aggregate_kind, stream_id, stream_version, event_type,
occurred_at, command_id, causation_event_id, correlation_id, actor_kind,
payload_json, metadata_json
```

`stream_id` は実質的に thread id です。観測された主な `event_type`:

```text
run.created, run.updated, run-attempt.created, run-attempt.updated,
provider-turn.updated, node.updated, subagent.updated,
runtime-request.updated, turn-item.updated, checkpoint.captured,
thread.created, thread.metadata-updated, thread.deleted,
project.created, project.deleted
```

`run.updated` の payload には `id`（run id）、`threadId`、`ordinal`、
`providerInstanceId`、`status`、`requestedAt`、`startedAt`、`completedAt`、
`checkpointId` などが入ります。`status` は `preparing`、`queued`、`starting`、
`running`、`waiting`、`completed`、`interrupted`、`failed`、`cancelled`、
`rolled_back` を観測しています。

`runtime-request.updated` の payload には `id`（runtime request / approval id）、
`nodeId`、`providerTurnId`、`kind`、`status`、`createdAt`、`resolvedAt`、
`decision`、`feedback` などが入ります。`kind` は `command`、`file-read`、
`file-change`、`mcp-elicitation`、`permission`、`dynamic_tool_call`、
`user_input`、`auth_refresh`、`status` は `pending`、`resolved`、`expired`、
`cancelled` です。

ホスト識別子は `~/.t3/userdata/environment-id` にあります（例: UUID 文字列）。

## 2. 方式選定

`docs/DESIGN.md` §3.1 の優先順位は次のとおりです。

1. T3 Code の認証済み RPC / WebSocket
2. T3 Code 側の小さな Event Adapter
3. SQLite の読み取り専用参照
4. ファイル監視

0.1.9 では 1 が全スレッド横断の単調増加ストリーム／リプレイを提供せず、2 は
ランタイム改変になるため対象外です。したがって **3 の SQLite 読み取り専用参照**を
採用し、低遅延化のために WAL/DB ファイルのメタデータを短周期で確認する
**軽量な変更検知 + ポーリングフォールバック**を併用します。

この方式の利点:

- `orchestration_events.sequence` が単調増加で、Collector のカーソルにそのまま使える。
- Projection テーブルが現在状態を持ち、初回起動時のスナップショットを低コストで作れる。
- イベントログと Projection は T3 Code 側のトランザクションで更新されるため、
  読み取りトランザクションで一貫したスナップショットが得られる。
- 認証トークンを events-bridge に渡す必要がない。SQLite ファイルの読み取り権限だけで動く。

### 2.1 読み取り専用の保証

T3 Code の DB は次の条件で開きます（`src/collectors/t3_sqlite.rs`）。

```rust
Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
conn.busy_timeout(Duration::from_secs(5))
conn.execute_batch("PRAGMA query_only = ON;")
```

さらに起動時に `orchestration_events` と各 Projection テーブルの存在を確認し、
T3 Code 0.1.x 以外の DB を誤って監視した場合は明示的に失敗します。
Collector は T3 DB に対して `SELECT` 以外を発行しません。

### 2.2 低遅延化

`collectors.t3.watch_wal = true`（既定）では、`statev2.sqlite` と `-wal` の
サイズ・mtime を最大 250 ms 間隔で確認します。変化があれば即座に
`orchestration_events` を読み、変化がなくても `poll_interval_ms` ごとに
フルポーリングします。`notify` などの inotify 依存は追加していません。

## 3. 初回起動と再起動

### 3.1 初回起動（カーソル未保存）

`source_cursors` と `collector_checkpoints` の両方に T3 のカーソルが無い場合、
**1 つの読み取りトランザクション**で Projection を読み、次を一度に保存します。

- `t3_projects` / `t3_threads` / `t3_runs` / `t3_approvals` の現在スナップショット
- `source_cursors(host = environment_id, source = 't3')` に `MAX(sequence)`
- `collector_checkpoints(collector = 't3', scope = environment_id)` に同じ値

このとき **イベントは 1 件も生成しません**。過去に完了した Run について Webhook を
大量発火させないためです。ただし起動時点で `pending` の承認は `t3_approvals` に
保持し、Pull ツールから参照できます。

### 3.2 再起動（カーソル保存済み）

`source_cursors.cursor` を優先し、無ければ
`collector_checkpoints.watermark` から `last_sequence` を復元します。
以後は

```sql
SELECT ... FROM orchestration_events
WHERE sequence > ?1
ORDER BY sequence ASC
LIMIT ?2
```

で N+1 以降だけを取り込みます。N 以前は再処理しません。

各上流イベントの処理は次の **単一トランザクション**です。

1. `t3_*` のマテリアライズド状態を更新
2. 導出イベントを `ingest_event` 相当で保存（購読に合う `deliveries` 行も作成）
3. `source_cursors` を更新
4. `collector_checkpoints` を更新

イベント ID は `(environment_id, aggregate, suffix)` から決定的に生成するため、
カーソル更新前にクラッシュして同じイベントを再処理しても `events.id` の
一意制約で重複配信になりません。

### 3.3 DB 置換・復元・エラー時の回復と制約

`statev2.sqlite` がバックアップからの復元やファイル置換で入れ替わった場合、
同じ SQLite 接続を持ち続けると古い inode を読み続けたり、上流の最大 `sequence` が
保存済みカーソルより小さくなって収集が停止したりします。これを防ぐため、
Collector は次を行います。

- **ファイル識別子の監視と再接続**: 収集パスの開始時に `statev2.sqlite` の
  `(dev, ino)`（Unix 以外ではサイズ・mtime）を確認し、起動時または前回と異なれば
  接続を開き直す。また、読み取りエラー発生時は次回パスで強制的に再オープンする。
- **シーケンス後退時の再スナップショット**: 上流の `COALESCE(MAX(sequence), 0)` が
  保存済みカーソルより小さい場合、DB が復元・初期化されたとみなして警告ログを出し、
  Projection テーブルからスナップショットを再水和してカーソルを現在の `MAX(sequence)` に
  再設定する。

**制約**: シーケンス後退を検出して再スナップショットする方式では、復元後の DB に
含まれていた過去の完了済み Run は再通知されず、再設定後の新規イベントから追跡を再開します。

## 4. イベント導出ルール

### 4.1 ターン終了と Run 終了の区別

T3 Code では `provider-turn.updated`、`run-attempt.updated`、`node.updated`
（`kind = root_turn`）が先に終了し、その後 `run.updated` が最終状態になります。
エージェントのターン終了は、バックグラウンドタスクやチェックポイントを含む
Run の最終確定ではありません。

| 上流イベント | 更新する状態 | 生成イベント |
| --- | --- | --- |
| `provider-turn.updated` | `t3_runs.last_turn_status` | **なし** |
| `run-attempt.updated` | `t3_runs.last_turn_status` | **なし** |
| `node.updated`（`root_turn`） | `t3_runs.last_turn_status` | **なし** |
| `run.updated` → `completed` | `t3_runs.status = completed` | `t3.run.completed`（初回のみ） |
| `run.updated` → `failed` | `t3_runs.status/error` | `t3.run.failed`（初回のみ） |
| `runtime-request.updated` → `pending` | `t3_approvals.status = pending` | `t3.approval.required`（初回のみ） |
| `runtime-request.updated` → `resolved` / `expired` / `cancelled` | `t3_approvals.status`、`resolved_at`、`decision` | なし |

`run.updated` が `completed` / `failed` 以外（`running`、`waiting` など）の場合は
状態だけを更新し、イベントを生成しません。同じ Run について
`run.updated (completed)` が複数回来ても、直前の `t3_runs.status` が
`completed` なら再発火しません。`failed` も同様です。

### 4.2 失敗理由の抽出

`run.updated` の payload にエラー本文が無い場合があるため、次の順で探します。

1. `run.updated` payload の `error`、`failure`、`errorMessage`、`failureReason`、
   `reason`、`message`（オブジェクトなら `message` / `error` / `reason` / `detail` / `code`）
2. 同じ `runId` を持つ直近の `turn-item.updated` / `node.updated` /
   `run-attempt.updated`（`status = failed`）の `failure.message` など
3. 見つからなければ `"T3 run failed without a reported error"`

`t3_runs.error` と `t3.run.failed` の `error` は同じ値を使います。
`t3.run.failed` の payload は `payloadSchema` の必須項目
（`environment_id`、`project_id`、`thread_id`、`run_id`、`summary`、`error`）を
常に満たします。

### 4.3 承認

`runtime-request.updated` の `pending` で `t3.approval.required` を生成します。
`approval_id`（payload の `id`）単位で、直前が `pending` でなければ発火します。
`resolved` / `expired` / `cancelled` ではイベントを生成せず、
`t3_approvals.status`、`resolved_at`、`decision` を更新します。

Run との対応付けは次の順です。

1. payload の `runId`
2. payload の `nodeId` を `node.updated` の `id` で引いた `runId`
3. payload の `threadId` の最新 Run
4. 既存 `t3_approvals.run_id`

Thread は payload の `threadId`、`node.updated` の `threadId`、既存行の順で解決します。

### 4.4 URL と決定性

`collectors.t3.t3_web_base_url` が設定されている場合だけ、`url` に
`<base>/threads/<thread_id>` を設定します。未設定なら `url` は省略します。

イベント ID の例:

```text
evt_t3_<env>_<aggregate>_<hash>_completed
evt_t3_<env>_<aggregate>_<hash>_failed
evt_t3_<env>_<aggregate>_<hash>_approval
```

`<aggregate>` は Run ID または承認 ID、`<hash>` は環境・種別・集約 ID の
SHA-256 先頭 10 文字です。長い ID は切り詰めてもハッシュで衝突を避けます。
全イベントは `event_catalog::validate_payload` を通してから保存します。

## 5. テーブル対応

| T3 Code | events-bridge | 備考 |
| --- | --- | --- |
| `projection_projects` / `project.*` | `t3_projects` | `deleted_at` を保持 |
| `orchestration_v2_projection_threads` / `thread.*` | `t3_threads` | `project_id`、`branch`、`deleted_at` |
| `orchestration_v2_projection_runs` / `run.*` | `t3_runs` | `last_turn_status` は turn/attempt/node から |
| `orchestration_v2_projection_runtime_requests` / `runtime-request.*` | `t3_approvals` | `run_id` は node / 最新 Run から補完 |
| `orchestration_events.sequence` | `source_cursors` + `collector_checkpoints` | Collector の再開位置 |

`t3_runs.error` は失敗時のみ設定し、`completed` 遷移ではクリアします。
`t3_approvals.decision` は文字列ならそのまま、オブジェクトなら JSON 文字列として
保存します。

## 6. Pull ツール

| ツール | 引数 | 戻り値 |
| --- | --- | --- |
| `get_t3_run` | `run_id`, 任意 `environment_id` | `run`（`pendingApprovalsCount` を含む） |
| `get_t3_approvals` | `environment_id`, `project_id`, `thread_id`, `status`（既定 `pending`、`all` 可）, `limit` | `approvals` 配列 |

`get_t3_approvals` の `project_id` は `t3_threads` を結合して判定します。
`status` は `pending` / `resolved` / `expired` / `cancelled` / `all` を受け付けます。
既存の `list_events` / `get_event` / `ack_events` の挙動は変更していません。

## 7. 設定

```toml
[collectors.t3]
enabled = true
# state_db_path = "/home/example/.t3/userdata/statev2.sqlite"
# environment_id = "59f9e9a5-51a0-41b4-9790-6bc8cbc2245e"
# environment_id_path = "/home/example/.t3/userdata/environment-id"
# t3_web_base_url = "https://t3.example.com"
poll_interval_ms = 1000
watch_wal = true
batch_size = 500
```

- `state_db_path` を省略すると `~/.t3/userdata/statev2.sqlite`。
- `environment_id` を省略すると `environment_id_path`、さらに省略時は
  state DB と同じディレクトリの `environment-id` を読みます。
- `t3_web_base_url` は `http` / `https` の階層 URL のみ。query / fragment は拒否します。
- 秘密情報はありません。T3 Code の認証トークンは読みません。
- `enabled = true` で Hub 起動時に Collector タスクが起動します。初回スナップショットに
  失敗した場合は Hub の起動も失敗します（誤った DB を監視し続けないため）。

## 8. テスト

`tests/t3_collector.rs` は T3 Code 0.1.9 の実スキーマを再現した一時 SQLite を使い、
次を検証します。

1. `provider-turn.updated (completed)` と `run-attempt.updated (completed)` だけでは
   `t3.run.completed` が発火せず、`run.updated (completed)` で初めて発火する。
2. `run.updated (failed)` で `t3.run.failed` が発火し、`get_t3_run` で失敗状態と
   エラーが取得できる。
3. `runtime-request.updated (pending)` で `t3.approval.required` が発火し、
   `resolved` 後に pending 一覧から外れる。
4. 初回スナップショットで過去の完了 Run が配信されない。
5. 再起動時に `source_cursors` / `collector_checkpoints` から復元し、
   N 以前を再送せず N+1 以降だけを取り込む。
6. `tests/integration.rs` の MCP `tools/call` で `get_t3_run` /
   `get_t3_approvals` を呼び出す。

## 9. 既知の制約

- 0.1.9 の `orchestration_v2_events` は 0 件のため使用していません。
- `orchestration_events` の payload は T3 Code の内部形式です。0.2 以降で
  スキーマが変わった場合は Collector のマッピング更新が必要です。
- `provider-turn.updated` は payload に `runId` を持たないため、`nodeId` または
  `runAttemptId` から Run を引きます。対応する `node.updated` /
  `run-attempt.updated` がイベントログに無い場合は `last_turn_status` を
  更新できません（Run の最終状態には影響しません）。
- 承認の `runId` がどの方法でも解決できない場合は空文字を保存します。
  実機では `node.updated` が先に記録されるため通常は解決できます。
- WAL の変更検知は inotify ではなくメタデータのポーリングです。最大 250 ms の
  検知遅延と `poll_interval_ms` のフォールバックがあります。
