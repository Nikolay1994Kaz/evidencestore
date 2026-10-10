# evidencestore

Tamper-evident storage for audit records: actions of AI agents, logs of core banking systems, a copy of the SIEM stream.

Every record is accepted over mutual TLS, encrypted with its own key, written to disk (the store answers "accepted" only after `fsync`) and chained by hash. The chain head is time-stamped by an external RFC 3161 authority, e.g. the National Certification Authority of Kazakhstan (`tsp.pki.gov.kz`). For any record the store produces a proof bundle. An auditor checks it **offline**, without access to the store and without trusting it: the record bytes, a Merkle path into the chain, the chain up to a signed head, and time-stamps from before and after the record.

Retention is enforced by destroying keys (crypto-erasure). Every record of a source for a month is encrypted under that month's key. Destroying the key needs two approvers and a waiting period, and it makes those bodies unreadable in every copy (log segments, backups). The chain and the proofs stay intact: you can still prove that record #42 from `abs-core` existed, was received at a given time and was never altered. You can no longer read it.

## Quick start

```sh
scripts/demo.sh                    # builds everything, runs a full scenario offline
DEMO_TSA=digicert scripts/demo.sh  # same, time-stamps from the public DigiCert TSA
DEMO_TSA=nca scripts/demo.sh       # same, time-stamps from the NCA of Kazakhstan
PIPELOCK_BIN=$(which pipelock) scripts/demo-pipelock.sh  # a real Pipelock gateway, see below
```

The demo runs these steps:

1. Issues demo certificates and starts the store.
2. Ships three log lines through the collector.
3. Verifies a proof with `esverify`.
4. Shows that a one-byte forgery is caught.
5. Destroys the month key (a single approval is refused) and shows that the proof still verifies while the body is gone.

## Components

| Binary | Role |
|---|---|
| `evidencestore` | the store: `init`, `serve`, plus operator commands over a local admin socket (`status`, `stamp`, `proof`, `keys …`, `sources bind`, `dev-pki`) |
| `escollect` | collector next to the source: tails a log file (or a set of files by glob), numbers lines, spools them on disk, delivers them over mTLS, keeps the store's signed promises |
| `esverify` | auditor's tool: verifies a proof bundle offline and prints what is and is not proven; exit code 0 — verified, 1 — not verified (including an unparsable bundle or a broken promise), 2 — bad usage or an unreadable key, certificate or promise file |

## Configuration

See [`configs/evidencestore.example.json`](configs/evidencestore.example.json) and [`configs/collector.example.json`](configs/collector.example.json). The example time-stamps with the public DigiCert TSA (`configs/tsa/digicert`); any RFC 3161 service works if its certificates are listed in `tsa.trust`, e.g. `http://tsp.pki.gov.kz` with `configs/tsa/nca-kz/*.cer` in Kazakhstan. Tokens are verified before they enter the chain. Every source is registered by name. The name must equal the CommonName of the collector's client certificate, and the certificate can be pinned by its SHA-256 fingerprint. The source is always taken from the certificate, never from the request.

Risky values are rejected at start instead of being silently replaced: non-positive periods, `keys.min_wait` under one hour, `roots_dir` and `data_dir` nested in either direction, a `content_type` over 255 bytes, an empty `listen`. A demo stand that must destroy a key within minutes sets `"demo": true`; never in production, where it leaves seconds to cancel a destruction. Without a `tsa` section the store starts with a warning: its proofs then carry no time-stamp, and `esverify` rejects them unless told `-allow-no-tsa`.

One process per `data_dir`: `serve`, `init` and `restore` take a lock on `data_dir/LOCK` before writing anything.

### Collector

`escollect` needs the store's public key pinned as `store_key` (printed by `evidencestore init`) and an `https://` server address; risky values (`http://`, `batch` above 512, a negative `flush_every`) are rejected at load instead of being silently replaced. Lines wait in an on-disk spool (`spool_dir`), each with its file position, so a crash never renumbers them. A record counts as delivered only when the store answers with a signed promise that verifies against the pinned key and names that very record; otherwise the record stays in the spool and the bad promise is kept in `promises-rejected.jsonl` as evidence against the store.

The collector stops instead of handing out numbers the store already holds: when `spool_dir` was restored from an old copy (a VM snapshot, a backup), or when a copy of the same installation runs next to it. The store, in turn, compares the body of every resent number with the accepted one and refuses a batch carrying another body under a taken number (`409`, `"code": "seq_conflict"`, a conflict event in the chain). It also refuses a resend it cannot compare, because the accepted body sits under a month key pending destruction (cancelling the destruction lets the resend through) or already destroyed; the store names the reason, and the collector logs it as is.

Every collector installation has an epoch: a random id kept in `spool_dir/epoch.json` and sent with every request. The store binds a source to the first installation it hears from (an event in the chain) and refuses any other installation that uses the source certificate, already at start, before it reads a line (`409`, `"code": "epoch_mismatch"`). A legitimate reinstall (`spool_dir` lost or emptied) is accepted by the operator with `evidencestore sources bind -source S -epoch E`; the refusal names the command, and the previous installation is refused from then on. Copies of one installation (a VM snapshot, a copied `spool_dir`) share the epoch; the number checks above catch them.

If `spool_dir` is lost while `state.json` or `files.json` survived, the collector refuses to start: restore `spool_dir` from a backup. Emptying it starts over as a new installation (bind it as above) from the store's last number and skips lines that were not delivered; with `from_start` the whole log is delivered again under new numbers, so the store holds duplicates.

Upgrade the store before the collectors: collectors of this version expect a signed promise on a resend too, and older stores did not give one. An older collector sends no epoch; the store accepts it until the source is bound to an installation.

The current file is held open. After a rotation the old file is read through that descriptor until it has been quiet for 10 seconds — applications keep writing into the rotated file until they reopen their log — and only then the collector takes a last line without a newline and moves on; a deleted file is read to its end the same way. A file truncated or replaced in place, or a rotated file that is gone after a collector restart, costs one sequence number: the store records the gap in the chain, so the loss is visible. A missing log file or an empty glob is logged once a minute.

With `glob`, the collector remembers how far it has read every file under the mask (`files.json`), so a shard whose modification time lands in the past (clock stepped back) is still read. Limits: with `file`, two rotations between two reads (the collector stopped for longer than the rotation period) skip the middle file; after a restart, a compressed or moved-away rotation (`compress` without `delaycompress`, `olddir`) is not found, and its unread tail becomes a sequence gap. The collector connects to the store directly and ignores `HTTPS_PROXY`.

### Keys

Month keys live in `keyring.dat`. It is encrypted under a fresh file key on every write, and only that 32-byte file key is wrapped by the root key in `roots_dir`, so the root can move into an HSM or a KMS unchanged. Three places matter:

- `keys.backup_dir` receives a copy of `keyring.dat` after every change. A new month key is not used until that copy has landed, so losing `data_dir` never loses a key that sealed a record. The copy is useless without the root.
- `keys.roots_mirror_dir` is a second copy of the roots on another disk or machine. Every root is written to both places and destroyed in both; a missing copy of the current root is restored at start and every minute, and a damaged copy is bypassed when reading. A missing directory is not created (it looks like an unmounted disk): create it yourself. An unreachable mirror does not stop the store, but destruction is not final until both directories can be listed (`roots_unreachable` in `status`). Without a mirror, losing `roots_dir` makes every stored body unreadable for good; the chain and the proofs survive.
- Nothing else may hold a copy of `roots_dir` or of the mirror. An old root copy plus an old `keyring.dat` still opens a destroyed key, so destruction is only as final as your control over those copies. The config check rejects layouts where one directory would hold both `keyring.dat` (or its backup) and a root.

The waiting period before a key is destroyed (at least `keys.min_wait`, which outside a demo stand is one hour or more, and at most ten years) starts at a TSA time-stamp taken with the request, and it ends by the store clock and by a fresh TSA time-stamp, whichever is earlier: a host clock that is behind at request time or moved forward later does not shorten it, and without a time-stamp destruction waits. The time-stamp lands in the chain before the destruction receipt.

`init` refuses to run when `keys.backup_dir` already holds `keyring.dat` or `sign.key`: that is what a store that lost `data_dir` looks like, and a fresh keyring would overwrite the keys of every month. Put those files back into `data_dir` instead. The backup also remembers the generation of `keyring.dat`, so an older file (a disk rolled back) never overwrites a newer backup.

A key state change enters the chain only after it has reached `keys.backup_dir`. If the backup is down, the change still takes effect, the operator gets an error saying the copy is pending, and the store retries every minute; `status` shows `keyring_backup_pending` meanwhile.

`status` also lists `orphan_roots`: roots that `keyring.dat` does not know. They appear after a crash in the middle of a key rotation, or after `keyring.dat` was restored from a backup older than the last rotation. In the second case an orphan can still open an old `keyring.dat` from the dead machine, so destruction is not reported as final (`destroyed-effective`) while orphans exist. Remove them with `evidencestore keys destroy-orphan-roots`, but only if `roots_dir` is not shared with another store.

### Copy and restore

With `replica.url` set (`s3://bucket/prefix?endpoint=…&region=…` or `file:///path`), the evidence log and the chain are copied in immutable chunks, together with signed chain heads. Nothing is ever deleted from the copy, and keys never go there. `evidencestore restore` rebuilds the log and the chain from the copy and verifies them against the latest signed head whose link the copy holds. `keyring.dat` and `sign.key` come back from `keys.backup_dir` (the store copies `sign.key` there on every start, and refuses to start with a chain but without `sign.key`), the roots from `keys.roots_mirror_dir`. On start the store checks that every record in the log is sealed with a key that `keyring.dat` knows: a wrong or too old `keyring.dat` stops the start instead of leaving bodies unreadable.

### Gateway journals (Pipelock)

A source with `"content_type": "pipelock/recorder"` carries the flight recorder of a [Pipelock](https://github.com/luckyPipewrench/pipelock) gateway: JSONL where every entry is hash-chained to the previous one and checkpoints are signed with the gateway's Ed25519 key. Pin that key in the source as `gateway_key` (64 hex, `pipelock signing pubkey`). Point the collector at the shards with a glob, since Pipelock writes every shard to a new file (full example: [`configs/collector.pipelock.example.json`](configs/collector.pipelock.example.json)):

```json
{"glob": "/var/lib/pipelock/recorder/evidence-*.jsonl", "from_start": true}
```

At intake the store recomputes each entry's hash (Pipelock's frozen v1–v3 projections), checks the `prev_hash` linkage per writer and verifies checkpoint signatures with the pinned key. Nothing is rejected: the entry is stored as received, and a verdict goes into the chain next to it. The chain fields of the gateway (`seq`, `hash`, `prev_hash`) stay readable after the month key is destroyed.

A proof bundle for such a record also shows that the body is exactly that gateway entry (the hash is recomputed offline from the body) and that a checkpoint signed by the gateway covers it. Pass the gateway key to `esverify -gateway-key` to check that signature yourself. Limits: the linkage between the entry and the checkpoint was checked by the store at intake (the bundle does not carry the entries in between); a Pipelock restart starts a new chain, and the signed `chain-link` file that connects sessions is not checked yet; one writer per recorder directory. Verified against real Pipelock v3.6.0 output (`internal/gateway/testdata`).

### Monitoring

Set `metrics_listen` (for example `127.0.0.1:9464`) to expose `/metrics` in the Prometheus text format. Worth an alert:

| Condition | Meaning |
|---|---|
| `evidencestore_log_failed == 1` | the evidence log or the chain stopped after a write or fsync error; intake is refused until a human looks (`evidencestore_chain_failed` tells which) |
| `increase(evidencestore_receive_clock_capped_total[1h]) > 0` | the host clock runs ahead of TSA time; receive times follow the last time-stamp and the monotonic clock |
| `evidencestore_receive_time_ahead_seconds > 60` | the log holds receive times ahead of the host clock (an earlier clock jump) |
| `evidencestore_keyring_backup_pending == 1` for 10 minutes | `keyring.dat` changes are not reaching `keys.backup_dir`; new month keys are not issued |
| `time() - evidencestore_tsa_last_stamp_timestamp_seconds > 2 × tsa.every` | time-stamps are not landing |
| `time() - evidencestore_replica_last_success_timestamp_seconds > 3 × replica.every` | the copy is falling behind |
| `evidencestore_source_silent == 1` | a source has been quiet longer than its `expect_every` |
| `increase(evidencestore_gateway_problems_total[1h]) > 0` | a gateway journal entry was broken, out of order or badly signed |
| `increase(evidencestore_epoch_refused_total[1h]) > 0` | another collector installation used the source certificate and was refused: an impostor, or a reinstall waiting for `sources bind` |
| `increase(evidencestore_records_conflict_total[1h]) > 0` | a resend was refused: another body under a taken number (a spool restored from an old copy, or two collectors share one certificate), or a body that cannot be compared (month key pending destruction or destroyed); the reason is in the chain event and in the collector log |
| `evidencestore_keys_due > 0` | months past retention wait for a destruction request (two approvers) |
| `evidencestore_keyring_orphan_roots > 0` | key destruction is not final until orphan roots are dealt with |
| `evidencestore_keyring_roots_unreachable == 1` | the root directories cannot be listed (`keys.roots_mirror_dir` down?); key destruction is not final meanwhile |
| `rate(evidencestore_ingest_errors_total[5m]) > 0` | ingest requests are failing |

Also exported: records, duplicates and conflicts per source, evidence-log batches and their fsync time, the chain head.

## What is proven, and what is not

Proven offline:

- these exact bytes were received from this source;
- they have not been altered since;
- they entered the chain between the two time-stamps T1 and T2;
- the store committed to including them by the signed deadline it gave the collector;
- with the record key: the body as received; the key is bound to the record's digest, so the store cannot show two auditors two different bodies;
- for gateway journals: the body is the gateway's own entry, and a checkpoint signed by the gateway covers it — when that signature was checked by the store with the pinned `gateway_key` or by you with `-gateway-key`. A gateway record whose bundle lacks the gateway part does not verify.

T2 is required: a bundle without a time-stamp after the record only carries the store's own signature, and whoever holds `sign.key` can make up a record with any date. `esverify` rejects such a bundle unless told `-allow-no-tsa`. The verdict is printed first and last, and control characters in the body are escaped, so a body cannot paint a false verdict on the auditor's screen.

Not proven:

- that the content is true: a lying source is recorded faithfully;
- anything before the record reached the store;
- anything about records the source never wrote.

Root on the store host can delete files. After the next time-stamp, deletion or alteration cannot be hidden, but it cannot be prevented either. The pilot cryptography (AES-256-GCM from the Go standard library, root keys in files) is not certified. The design keeps a plug-in point for an HSM.

## Development

```sh
go build ./... && go vet ./... && go test -race ./...
python3 scripts/mutate.py keyring     # mutation testing: every injected bug must fail a test
                                      # sets: keyring, evlog, tsa, store, edge, auditchain, gateway, config
```

Design notes in Russian: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (code map), [`docs/DECISIONS.md`](docs/DECISIONS.md) (decisions and open questions), [`docs/CONCEPT.md`](docs/CONCEPT.md), [`docs/PROVENANCE.md`](docs/PROVENANCE.md).

## License

Apache License 2.0, see [`LICENSE`](LICENSE).
