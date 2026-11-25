# Muse ポーリングコンシューマー運用ガイド

`events-bridge` の `consumers` は、Muse のような常駐クライアントが SSH 越しの CLI や cron/hook から
イベントを **pull** するためのサーバー側カーソルである。ChatGPT の Webhook 購読
（`subscriptions`）とは独立しており、同じイベントログを読むが `deliveries` は作らない。

- `poll` はカーソルを進めない。
- `ack` だけがカーソルを進める。
- したがって配信保証は **at-least-once**。ack 前に落ちてもイベントは失われない。

## 1. プロファイル設定

`/etc/events-bridge/config.toml` に `[consumers.<name>]` を書く。秘密情報は置かない
（consumer は認証トークンを持たず、HTTP の Bearer 認証は `[auth]` 側で設定する）。

### 組み込み Muse プロファイル

`muse` は設定なしで使える。組み込みの disposition は次の通り。

| イベント | disposition |
| --- | --- |
| `orca.approval.required` | `immediate` |
| `orca.session.failed` | `immediate` |
| `github.workflow.failed` | `immediate` |
| `github.review.requested` | `digest` |
| `github.pr.merged` | `digest` |
| `orca.session.completed` | `digest` |

過去の T3 イベントも同じカーソルから読める。`t3.approval.required` と `t3.run.failed` は
`immediate`、`t3.run.completed` は `digest`。切り替え手順は
[Orca Edge コレクター](ORCA-COLLECTOR.md#本番切り替え手順) を参照。

### イベントを上書きする

```toml
[consumers.muse]
default_disposition = "off"   # 表にないイベントは受け取らない
digest_window_secs = 600      # A2 の集約ウィンドウ（秒、> 0）
max_events_per_poll = 50      # poll の既定件数（> 0）
max_digest_event_ids = 50     # A2 の digest 1 件あたりの最大 ID 数（> 0）

[consumers.muse.events]
"orca.approval.required" = "immediate"
"orca.session.failed" = "immediate"
"github.workflow.failed" = "immediate"
"github.review.requested" = "digest"
"github.pr.merged" = "digest"
"orca.session.completed" = "digest"
```

組み込みプロファイルへの上書きは **キー単位でマージ** される。上の例のように
`"github.pr.merged" = "off"` とだけ書けば、そのイベントだけを無効にできる。

### ペイロードフィルター

`filters` は allowlist。空配列は「制限なし」を意味し、値が設定されている場合は
payload に対応するキーが必要。

```toml
[consumers.muse.filters]
environment_ids = ["mado", "mini"]
project_ids = ["orca-project-id"]
repositories = ["soramikan/events-bridge"]
```

- `environment_ids` → `data.environment_id`
- `project_ids` → `data.project_id`
- `repositories` → `data.repository`

Orca イベントの `source` は `orca`。 `data` の必須項目は `environment_id`、`session_id`、
`summary` で、Edge から届くイベントには `severity`、`requires_action` も入る。
`project_id` は Orca が返した場合に付く。`environment_ids` に Orca Edge の ID を含めること。
`repositories` の allowlist を設定したプロファイルでは、Orca イベントは対象外になる。

### 独自コンシューマー

```toml
[consumers.reviewer]
default_disposition = "off"

[consumers.reviewer.events]
"github.review.requested" = "immediate"
"github.pr.merged" = "digest"

[consumers.reviewer.filters]
repositories = ["soramikan/events-bridge"]
```

未設定の名前を指定すると、CLI / HTTP / MCP はいずれも
`unknown consumer ...` という明示的なエラーを返す。

## 2. CLI

`--config` を省略した場合は `EVENTS_BRIDGE_CONFIG`、次に
`/etc/events-bridge/config.toml` が使われる。`--db` は `database.path` を上書きする。
stdout は 1 個の JSON だけなので、そのまま `jq` に渡せる。

### probe（安い確認）

```console
$ events-bridge poll --consumer muse --probe
{"consumer":"muse","latestSequence":42,"cursorSequence":40,"unreadCount":2,"hasUpdates":true}
```

未読がなければ `unreadCount` は 0、`hasUpdates` は false。

### poll（本文取得、カーソルは進めない）

`immediate` イベントは `events` に 1 件ずつ、`digest` イベントは `digests` に
時間ウィンドウ単位の要約として返る。`digest` イベントが `events` に重複して現れることはない。

```console
$ events-bridge poll --consumer muse --limit 50
{
  "consumer": "muse",
  "cursorSequence": 40,
  "nextCursorSequence": 42,
  "latestSequence": 42,
  "hasMore": false,
  "truncated": false,
  "events": [
    {
      "eventId": "evt_...",
      "sequence": 41,
      "name": "orca.approval.required",
      "source": "orca",
      "disposition": "immediate",
      "occurredAt": "2026-11-16T01:00:00.000Z",
      "data": {
        "environment_id": "mado",
        "session_id": "orca_session_id:00000000-0000-4000-8000-000000000001",
        "summary": "An Orca agent is waiting for approval or input.",
        "severity": "high",
        "requires_action": true
      }
    }
  ],
  "digests": [
    {
      "windowStart": "2026-11-16T01:00:00Z",
      "windowEnd": "2026-11-16T01:10:00Z",
      "count": 3,
      "countsByKind": { "orca.session.completed": 2, "github.review.requested": 1 },
      "eventIds": ["evt_...", "evt_...", "evt_..."],
      "eventIdsTruncated": false,
      "maxSequence": 42
    }
  ]
}
```

`--limit` は 1..=200 にクランプされる。`nextCursorSequence` は `events` と `digests` の
両方がカバーする最大 sequence。0 件なら現在の `cursorSequence`。

#### digest の集約（A4）

- `digest_window_secs`（既定 `600`）で `occurredAt` を floor した時間ウィンドウにまとめる。
  `windowStart` / `windowEnd` は RFC 3339 UTC で、半開区間 `[windowStart, windowEnd)`。
- `count` はウィンドウ内の digest 件数、`countsByKind` は種別ごとの件数、`maxSequence` は
  ウィンドウ内の最大 sequence。
- `eventIds` は昇順に `max_digest_event_ids`（既定 `50`）件まで。`count` がそれを超えると
  `eventIdsTruncated: true` になる。
- `digests` は `windowStart` の昇順。

#### catchup 制御（A5）

- `immediate` は決して落とさない。digest の backlog が `max_events_per_poll` を超えても、
  immediate が先に返る。
- immediate が `limit` 件に達したページでは、それ以降の digest を返さず `hasMore: true`。
  最後に返した immediate 以下の sequence にある digest は ack で飛ばさないよう要約に含める。
- immediate が `limit` 件未満で、未読 digest が残り予算以下なら全件を集約して
  `truncated: false` / `hasMore: false`。
- 未読 digest が残り予算を超えると、immediate を全件保持したまま digest を最大 10,000 件まで
  走査して要約し、`truncated: true`。digest の走査上限を超えた場合は `hasMore: true`。
- `hasMore` は未返却イベントが残っていること、`truncated` は詳細を要約に落としたことを示す。
  どちらも `nextCursorSequence` より後ろのイベントを飛ばす理由にはならない。

### ack（カーソルを前進）

```console
$ events-bridge poll --consumer muse --ack 42
{"consumer":"muse","previousCursorSequence":40,"cursorSequence":42,"advanced":true}
```

`ack` サブコマンドでも同じ。

```console
$ events-bridge ack --consumer muse --up-to 42
{"consumer":"muse","previousCursorSequence":42,"cursorSequence":42,"advanced":false}
```

古い sequence を ack してもカーソルは戻らない（`advanced: false`）。
`0 <= upToSequence <= latestSequence` の範囲外はエラーになる。

### SSH 越しの例

```console
$ ssh muse@hub 'events-bridge poll --consumer muse --probe'
$ ssh muse@hub 'events-bridge poll --consumer muse --limit 50'
$ ssh muse@hub 'events-bridge poll --consumer muse --ack 42'
```

パスワードやトークンをコマンドラインに埋めない。HTTP を使う場合の Bearer トークンは
環境変数から読み、シェル履歴やログに残さない。

## 3. Muse VM への HTTP ポーラーの組み込み

Python 3 の `scripts/muse-poll.py` を Muse VM に配置する。
既定の接続先は `http://100.85.211.2:8788`（Tailscale 内の HTTP）。
検証用 Hub を使う場合は `EVENTS_BRIDGE_MUSE_URL` でオリジンを上書きする。
`EVENTS_BRIDGE_TOKEN` は Muse の秘密情報管理からプロセス環境に渡す。
cron を使う場合は、Muse ユーザーだけが読めるモード 0600 の環境ファイルから読み込む。

```cron
* * * * * /bin/sh -c 'set -a; . "$HOME/.config/muse/events-bridge.env" || exit 1; set +a; exec /usr/local/bin/muse-poll.py --state-dir "$HOME/.local/state/muse-events" -- /usr/local/bin/muse-event-handler'
```

hook からも同じコマンドを毎分 1 回呼べる。同じ consumer には cron と hook の
どちらか一方を選び、VM 内で同じ状態ディレクトリを使う。状態 DB には未処理の
ページ本文と処理済み ID が入るため、Muse ユーザー専用のディレクトリに置く。

ハンドラーは標準入力の JSON 1 件を受け取る。
`kind` は `immediate` または `digest`、`item` は Hub が返したイベントまたは
digest、`id` は冪等処理に使うキー。成功時だけ 0 を返す。
通知先で処理が成功してからローカル DB に記録するまでに落ちる場合があるため、
ハンドラー側でも同じ `id` の再処理を防ぐ。

ポーラーは毎分 probe し、未読時だけ新しいページを poll する。途中で失敗した
ページはローカルに保持し、処理済み ID を飛ばして再開する。digest は掲載された
イベント ID の組で識別し、ID が省略された場合はウィンドウと最大 sequence も使う。
省略された個々の ID は Hub から取得できないため、要約単位で重複を排除する。
ページ内のイベントと digest がすべて成功した後で `nextCursorSequence` を ack する。
続きのページは次の tick で取得する。

### 注意点

- **ack は処理成功後だけ**。処理途中で落ちた場合、次回の poll で同じイベントが返る
  （at-least-once）。イベント ID で重複処理を排除する。
- `poll` はカーソルを進めない。`--limit` で分割しても、ack するまで先頭から返る。
- `digests` も処理対象。`nextCursorSequence` で ack すると `events` と `digests` の両方が
  まとめて前進するため、`digests` を無視したまま ack しない。
- `truncated: true` は「digest backlog が大きく要約した」ことを示す。`eventIdsTruncated` が
  true の場合は `count` / `countsByKind` を見て通知内容を決める。必要なら `probe` ではなく
  未読のうちに別の consumer や `list_events` で詳細を確認する。
- `probe` と `poll` は同じプロファイルを使う。`off` のイベントはどちらにも現れない。
- `ack_events`（MCP のユーザー確認ツール）は consumer カーソルとは無関係。
  誤って `ack_events` を呼んでも consumer の未読状態は変わらない。
- consumer カーソルは名前ごとに独立している。`muse` と `reviewer` は互いに影響しない。
