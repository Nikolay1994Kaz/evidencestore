# PostgreSQL and an MCP server for an AI agent

[← README](../README.md)

An AI agent works on a PostgreSQL database through an MCP server, and every change to the tables you name reaches the store: the agent's own actions whole, with the rows before and after, so that they can be undone, and every other change as a fingerprint. People get alerts, and an operator undoes an action with two commands. This is new in v0.6.0. This page is the overview; the full reference, with the reason for every rule and the record of every review finding, is in Russian: [experiments/pg-undo](../experiments/pg-undo/README.md).

```
AI agent
  → esmcp           the MCP server and the gateway: runs the agent's SQL in its own transaction, under its own role;
                    before the SQL a signed intent with the transaction's id, after it the outcome (receipt/v1)
  → PostgreSQL      observed, not changed: no triggers, no markers, no key of ours in the database
  → escollect       the "postgres" input: reads the database's log by logical replication (pgoutput)
                    and the gateway's receipts file
  → evidencestore   the transactions, with "subject_field": "xid"; the receipts as a source of their own
  → esundo          the operator: the inverse operations, checked against the database, in one transaction
```

## What it promises

**No transaction on the named tables gets past the store, whatever role it ran under, and whose it is comes from the gateway's signed receipt, not from the database.** The database log names no role, so the collector does not take "who" from the database at all.

- **A transaction named in a signed intent of the gateway** is kept whole: rows before and after, so that `esundo` can undo it. `esmcp` writes the intent with the transaction's id before the agent's SQL runs and before `COMMIT`, and the stream gives the transaction only after it, so the collector decides at its start. The intent is signed with the gateway's key, which lies with the gateway: not in the database, its log or its copies.
- **Any other transaction** on those tables — people, applications, someone who logged in with the server's role past the server — is kept as a fingerprint: id, commit time, tables, row keys, the kind of change and hashes of the old and the new row. No rows: it cannot be undone from the store, and `esundo` names the record that holds it. Fingerprints reach the store in packs: a pack leaves when it is full or a minute after its first transaction, so a change made past the server shows up in the store up to a minute later. With `"require_gateway": true` each such transaction raises the alert `not-via-gateway`, for a database where only the gateway writes.
- **The stream always starts from the replication slot**, and a transaction the store already holds is recognized and not written twice. A database restored from a copy, or a lagging replica that took its place, is seen (`db-rewound`), and the intents of the earlier history no longer decide anything: `esmcp` and `esundo` put the start time of the database into every intent (`db_started`), so that the decision follows the database's own clock.
- **Loss is named.** A slot dropped or moved, or a log the database removed before the collector read it, becomes a sequence gap in the store's chain and the alert `gap`. A receipt missing from the gateway's chain, or an intent that is missing or came after its transaction, raises `receipts-gap` or `intent-missing`: that transaction went in as a fingerprint.

The roles of the database are the second line, not the first: `escollect -setup-sql` grants the server's role the right to write the named tables and the agent's own role only to read them, by an allow-list, and refuses roles that could get more through membership or ownership. There are more ways to grant rights in PostgreSQL than any check can list, so the promise rests on what the collector sees.

## The trust boundary

What this page promises holds within these bounds; whatever needs to break them is a limit, not a defect:

- **The gateway's key is out of the agent's reach, even for reading, and only the gateway and the collector write the receipts directory, the gateway's chain head and the collector's state.** They run as a user of their own, not the one the agent has a shell as (so in [`compose.yaml`](../compose.yaml)). Whoever writes the receipts directory without the key cannot forge a receipt, but can take a line out and put it back, rewrite the file, or get around the server's limits before commit; the collector names much of that, not all.
- **A restore of the database from a copy is an event people know about.** The collector sees it and drops the earlier intents, but in rare combinations of a restore with a restart of the database, whose a transaction right after the restore was is worth checking.

## Try it in Docker

[`compose.yaml`](../compose.yaml) is a trial on one machine: PostgreSQL 17 with `wal_level=logical` and demo tables, the store, the collector and the MCP server.

```sh
docker compose up -d                        # the first start makes certificates, keys and passwords in ./state
docker compose run --rm -T --no-deps esmcp  # the MCP server over stdio: the command to give your MCP client
docker compose exec store esundo check -config /state/store/undo.json -xid N
docker compose exec store esundo apply -config /state/store/undo.json -plan undo-N.json -by NAME
```

- The first start (`deploy/docker/init.sh`) does what an installation does by hand: a demo CA and certificates, `evidencestore init`, the configs of every program, random passwords for the roles and the database setup SQL. A second start changes nothing. Each container gets only its own directory under `./state`.
- Alerts go to `./state/pg-index/alerts.jsonl` and the collector's log (`docker compose logs collector`); to people, with a `notify` section in `./state/collector/collector.json` (below).
- `./state/agent.txt` is a read-only connection for the agent itself. The files under `./state` belong to the programs' user in the containers (uid 10001) and are closed to others.
- Another PostgreSQL version: `PG_VERSION=14` to `18`, from scratch (`docker compose down -v && rm -rf ./state`).
- The CA is a demo one and the time-stamps come from the store's built-in service. A real installation: [Installing on hosts](install.md).

## The MCP server: esmcp

Tools: `query` (read; at most `max_rows` rows, 200 by default), `execute` (one statement in `sql`, or up to 100 in `statements`, run in order as one transaction), `actions` (the latest actions of this session, with their transaction ids and outcomes), and `undo_preview` and `undo_apply` when the config has an `undo` section.

The server runs the transaction, and nothing is committed before its `COMMIT`. Each statement goes to the database wrapped in `PREPARE` over the extended protocol, so the database's own parser lets only `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE` and `VALUES` through: `BEGIN`, `COMMIT`, `SET`, `DO`, `CALL`, `COPY` and schema changes are refused before anything runs. Every call starts with `DISCARD ALL`.

```json
{
  "dsn": "host=db user=esmcp_bot dbname=shop sslmode=verify-full",
  "agent": "support-bot",
  "receipts": "/var/lib/esmcp/receipts.jsonl",
  "key": "/etc/esmcp/esmcp.key",
  "pg_source": "pg-agent",
  "action_row_limit": 500,
  "window_rows": 5000, "window": "10m",
  "actions_per_minute": 30,
  "statement_timeout": "1m",
  "lock_timeout": "10s"
}
```

| Limit | What it stops | What happens |
|---|---|---|
| `action_row_limit` | one action changes too many rows | rolled back before commit |
| `window_rows` per `window` | the agent splits a large change into parts | the part that overflows the window is rolled back before commit |
| `actions_per_minute` | an agent in a loop | refused before the action reaches the database |
| `statement_timeout` | a query that hangs or waits on a lock | cancelled on the database server, the connection closed |

In each case the agent is told not to split or retry and to call a person, the receipts keep the outcome and its cause, and the collector raises `refused` from the outcome receipt, so people learn about what did not happen in the database (an alert about the rate at most once a minute). Rows are counted by the database itself, from the statistics of the transaction, so changes made by triggers, cascades and inside `WITH` count. The limits are counted from the receipts file, shared by all of the agent's sessions.

`key` is an Ed25519 key in PKCS#8 PEM (`esreceipt keygen`); `esmcp -config mcp.json -pubkey` prints its public key, which goes into the collector's `receipts.gateway_keys` and the store's `gateway_key` of the receipts source. The gateway keeps the head of its chain next to the key (`head`, by default `<key>.head-<8 hex>`): it must be writable, and not in the receipts directory, or the server refuses to start.

## Undo: esundo

```sh
esundo check -config undo.json -xid 749                         # the command from the alert: the plan, checked against the database
esundo apply -config undo.json -plan undo-749.json -by alice    # apply it
```

`esundo` fetches the records of the transaction from the store and verifies them itself (`stamp`, `proof` and `verify` in `undo.json` are the commands it calls), builds the inverse operations and compares every row with the database. `apply` writes its own signed intent before it changes anything: an undo is an action too, kept whole, and it can be checked and undone. Exit codes: 0 done; 1 a bad call or a database error; 2 the undo cannot be built (a `TRUNCATE`, a table without `REPLICA IDENTITY FULL`, a transaction not whole); 3 a row changed after the check, nothing applied; 4 the connection broke during the undo's `COMMIT`, so it may be committed: look at the transaction first.

```json
{
  "dsn": "host=db user=undo_op dbname=shop sslmode=verify-full",
  "index": "/var/lib/escollect/pg-index/index.jsonl",
  "stamp": ["evidencestore", "stamp", "-config", "/etc/evidencestore.json"],
  "proof": ["evidencestore", "proof", "-config", "/etc/evidencestore.json", "-source", "pg-agent", "-dek"],
  "verify": ["esverify", "-store-key", "…", "-tsa-trust", "/etc/evidence/tsa-root.crt"],
  "receipts": "/var/lib/esundo/receipts.jsonl",
  "key": "/etc/evidence/esundo.key",
  "pg_source": "pg-agent"
}
```

The same section, under `undo`, gives the agent `undo_preview` and `undo_apply` in `esmcp`; then the agent can undo only actions from its own server's receipts.

## The collector's postgres input

One `escollect` runs several sources, each with its own certificate, spool and input (`file`, `glob` or `postgres`); a config without `sources` works as before:

```json
{
  "server": "https://store:8443", "ca": "ca.crt", "store_key": "…",
  "sources": [
    {"cert": "pg-agent.crt", "key": "pg-agent.key", "spool_dir": "spool-pg-agent",
     "postgres": {
       "dsn": "host=db user=evidence_tap dbname=shop sslmode=verify-full",
       "dir": "pg-index",
       "mcp_roles": ["esmcp_bot"], "roles": ["agent_bot"], "undo_roles": ["undo_op"],
       "tables": ["public.accounts", "public.orders"],
       "receipts": {"files": ["mcp/receipts.jsonl", "undo/receipts.jsonl"],
                    "gateway_keys": ["<esmcp -pubkey>", "<the key of esundo>"],
                    "source": "pg-agent"},
       "alert_rows": 500}},
    {"cert": "agent-mcp.crt", "key": "agent-mcp.key", "spool_dir": "spool-agent-mcp", "file": "mcp/receipts.jsonl"},
    {"cert": "undo-op.crt", "key": "undo-op.key", "spool_dir": "spool-undo-op", "file": "undo/receipts.jsonl"}
  ]
}
```

- `dsn`: a role with `REPLICATION`; `slot` and `publication` default to `evidence_tap` and `evidence_pub`. `dir` holds the index (`index.jsonl`: which transaction went under which record numbers; `esundo` and `esmcp` read it), `alerts.jsonl` and `slot.json`; by default the source's `spool_dir`.
- `tables`: the tables (`schema.table`) under watch. `mcp_roles`, `roles`, `undo_roles`: the roles of the MCP servers, of the agents' direct read-only access and of `esundo`.
- `receipts`: the gateways' receipts files and their public keys; `source` is the name the intents refer to (`pg_source` of `esmcp` and `esundo`). Without the section there is no gateway: every transaction is kept whole, and the records do not say whose it is.
- `require_gateway`, `alert_rows` (the threshold of `mass-change`), `canaries` (rows whose change raises `canary`), `down_after` (1m), `status_every` (5s), `slot_alert_mb`, `notify`.

`escollect -config collector.json -setup-sql` prints the SQL that prepares the database: the roles and their rights by an allow-list, `REPLICA IDENTITY FULL` on the tables and the publication. Run it as a superuser, and again after adding tables or partitions. It needs PostgreSQL 14 or newer with `wal_level=logical`; `pgoutput` is built in. The receipts files go to the store as sources of their own (`"content_type": "receipt/v1"`, see [Gateway receipts](receipts.md)), so the intents and outcomes are evidence too, and `esverify -linked` checks an action's receipts together with the bundle of its transaction.

## Alerts

```json
"notify": {
  "undo_hint": "esundo check -config /etc/evidence/undo.json -xid {xid}",
  "to": [
    {"type": "telegram", "token": "123456:ABC…", "chat": "-1001234567890"},
    {"type": "slack", "url": "https://hooks.slack.com/services/T…/B…/…"},
    {"type": "json", "url": "https://alerts.example.com/hook"}
  ]
}
```

One message per transaction, with every cause, a summary of the change and the undo command. `slack` takes any compatible incoming webhook (`{"text": …}`), `json` gets `{"text": …, "title": …, "events": […]}`. An alert lands in `alerts.jsonl` with `fsync` first and is sent after: each target has its own queue, delivery is at least once, and after a long outage the old alerts go as one summary. The addresses are secrets and never reach the collector's log; only `https://`, or `http://` to the same machine.

| Alert | When |
|---|---|
| `mass-change` | at least `alert_rows` row changes in one transaction |
| `canary` | a row from `canaries` was touched |
| `not-via-gateway` | with `require_gateway`: a transaction without the gateway's intent |
| `forged-receipt` | lines of a receipts file not signed with the gateway's key |
| `receipts-gap`, `intent-missing` | a receipt of the gateway's chain is missing from the file; an outcome without its intent, or an intent that came after its transaction: the transaction went in as a fingerprint |
| `receipts-unreadable` | a receipts file cannot be read: the gateway's transactions go as fingerprints until it can |
| `truncate`, `identity` | the transaction cannot be restored whole from the log |
| `refused` | the MCP server stopped an action: rows, rate or time |
| `escaped` | the agent's SQL closed the server's transaction itself: what it changed may have been committed past the limits (a safeguard: `PREPARE` keeps this from happening) |
| `db-down`, `db-up` | no connection to the database for longer than `down_after`; it is back |
| `slot-lag`, `slot-ok` | the database keeps log for the slot: half and 80 % of its limit; released |
| `gap` | records lost: the slot was dropped, recreated or moved while the collector was away, or the database removed its log |
| `slot-unknown` | the collector's `slot.json` is gone, so whether the slot moved meanwhile cannot be told |
| `db-rewound` | the database went back: restored from a copy, replaced by a replica on another timeline, another cluster, or a transaction below the collector's place that it does not hold; the gateway's earlier intents no longer count |

The collector's `/metrics` (`metrics_listen`) shows every source, the slot, the log the database keeps for it and its limit, and the alert queues.

## Limits

The most important ones; all of them, with their causes, are in [experiments/pg-undo](../experiments/pg-undo/README.md) (in Russian), and those of the store in [Known limitations](limitations.md).

- The limits stop only actions through `esmcp`. The agent's own role only reads; a write right granted to it after `-setup-sql` is a fingerprint and, with `require_gateway`, an alert after commit. The rate lock works on one machine.
- `pgoutput` gives a transaction after commit: an alert about a change made past the MCP server says what has already happened.
- Through `esmcp` the agent gets only `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE` and `VALUES`: an agent that needs to change the schema needs another path.
- The full rows of the gateway's transactions are personal data in the store. They can be erased by month (the month key), not per person.
- A server that dies between the intent and the outcome leaves the action `pending`, without an alert.
- The index (`index.jsonl`) and the alerts file are not rotated.
- No ready-made Prometheus rules or dashboards; no mail or other channels than Telegram, Slack-compatible webhooks and your own address.
- The live tests ran on PostgreSQL 16. On 24 November 2026 the trial ran under Docker (PostgreSQL 17): `docker compose up` from scratch, an action of an agent through the MCP server, its undo with `esundo check` and `apply`, a change made past the server kept as a fingerprint, a statement the server refuses, and the agent's own read-only connection refused a change; it is not run by CI.
