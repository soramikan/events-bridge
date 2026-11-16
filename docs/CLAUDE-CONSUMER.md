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
| `t3.approval.required` | `immediate` |
| `t3.run.failed` | `immediate` |
| `github.workflow.failed` | `immediate` |
| `github.review.requested` | `digest` |
| `github.pr.merged` | `digest` |
| `t3.run.completed` | `digest` |

### イベントを上書きする

```toml
[consumers.muse]
default_disposition = "off"   # 表にないイベントは受け取らない
digest_window_secs = 600      # A2 の集約ウィンドウ（秒、> 0）
max_events_per_poll = 50      # poll の既定件数（> 0）
max_digest_event_ids = 50     # A2 の digest 1 件あたりの最大 ID 数（> 0）

[consumers.muse.events]
"t3.approval.required" = "immediate"
"t3.run.failed" = "immediate"
"github.workflow.failed" = "immediate"
"github.review.requested" = "digest"
"github.pr.merged" = "digest"
"t3.run.completed" = "digest"
```

組み込みプロファイルへの上書きは **キー単位でマージ** される。上の例のように
`"github.pr.merged" = "off"` とだけ書けば、そのイベントだけを無効にできる。

### ペイロードフィルター

`filters` は allowlist。空配列は「制限なし」を意味し、値が設定されている場合は
payload に対応するキーが必要。

```toml
[consumers.muse.filters]
environment_ids = ["linux-main", "mac-mini"]
project_ids = ["lnako"]
repositories = ["soramikan/events-bridge"]
```

- `environment_ids` → `data.environment_id`
- `project_ids` → `data.project_id`
- `repositories` → `data.repository`

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
      "name": "t3.approval.required",
      "source": "t3",
      "disposition": "immediate",
      "occurredAt": "2026-11-16T01:00:00.000Z",
      "data": { "...": "..." }
    }
  ],
  "digests": [
    {
      "windowStart": "2026-11-16T01:00:00Z",
      "windowEnd": "2026-11-16T01:10:00Z",
      "count": 3,
      "countsByKind": { "t3.run.completed": 2, "github.review.requested": 1 },
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

## 3. HTTP（任意）

Hub を直接叩く場合の 3 エンドポイント。`[auth].token_env` を設定している場合は
`Authorization: Bearer <token>` が必須。

```console
$ curl -fsS -H "Authorization: Bearer $TOKEN" \
    https://bridge.example.com/consumers/muse/probe
$ curl -fsS -H "Authorization: Bearer $TOKEN" \
    'https://bridge.example.com/consumers/muse/poll?limit=50'
$ curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"upToSequence":42}' \
    https://bridge.example.com/consumers/muse/ack
```

## 4. 2段階 hook / cron パターン

高頻度チェックでは、毎回イベント本文を取得しない。まず `probe` だけを実行し、
`hasUpdates` または `unreadCount > 0` のときだけ `poll` と `ack` を行う。

```bash
#!/usr/bin/env bash
set -euo pipefail

CONSUMER=muse
PROBE_JSON="$(events-bridge poll --consumer "$CONSUMER" --probe)"

if ! jq -e '.hasUpdates == true and .unreadCount > 0' >/dev/null <<<"$PROBE_JSON"; then
  # 未読なし: 何もせず終了する（本文取得も ack もしない）
  exit 0
fi

POLL_JSON="$(events-bridge poll --consumer "$CONSUMER" --limit 50)"
NEXT_CURSOR="$(jq -r '.nextCursorSequence' <<<"$POLL_JSON")"

# ここでイベントを処理する。処理が成功した場合だけ ack する。
# jq の例: jq -c '.events[]' <<<"$POLL_JSON" | while read -r event; do ...
process_events "$POLL_JSON"

events-bridge poll --consumer "$CONSUMER" --ack "$NEXT_CURSOR"
```

cron の例（5 分ごと。多重起動を避けるため `flock` を使う）:

```cron
*/5 * * * * flock -n /run/events-bridge-muse.lock /usr/local/bin/muse-check.sh
```

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
