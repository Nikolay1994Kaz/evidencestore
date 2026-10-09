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
| `evidencestore` | the store: `init`, `serve`, plus operator commands over a local admin socket (`status`, `stamp`, `proof`, `keys …`, `dev-pki`) |
| `escollect` | collector next to the source: tails a log file (or a set of files by glob), numbers lines, spools them on disk, delivers them over mTLS, keeps the store's signed promises |
| `esverify` | auditor's tool: verifies a proof bundle offline and prints what is and is not proven |

## Configuration

See [`configs/evidencestore.example.json`](configs/evidencestore.example.json) and [`configs/collector.example.json`](configs/collector.example.json). The example time-stamps with the public DigiCert TSA (`configs/tsa/digicert`); any RFC 3161 service works if its certificates are listed in `tsa.trust`, e.g. `http://tsp.pki.gov.kz` with `configs/tsa/nca-kz/*.cer` in Kazakhstan. Tokens are verified before they enter the chain. Every source is registered by name. The name must equal the CommonName of the collector's client certificate, and the certificate can be pinned by its SHA-256 fingerprint. The source is always taken from the certificate, never from the request.

### Collector

`escollect` needs the store's public key pinned as `store_key` (printed by `evidencestore init`) and an `https://` server address; risky values (`http://`, `batch` above 512, a negative `flush_every`) are rejected at load instead of being silently replaced. Lines wait in an on-disk spool (`spool_dir`), each with its file position, so a crash never renumbers them. A record counts as delivered only when the store answers with a signed promise that verifies against the pinned key and names that very record; otherwise the record stays in the spool and the bad promise is kept in `promises-rejected.jsonl` as evidence against the store.

The collector stops instead of handing out numbers the store already holds: when `spool_dir` was restored from an old copy (a VM snapshot, a backup), or when a second collector runs with the same certificate. The store, in turn, compares the body of every resent number with the accepted one and refuses a batch carrying another body under a taken number (`409`, `"code": "seq_conflict"`, a conflict event in the chain).

With `glob`, the collector remembers how far it has read every file under the mask (`files.json`), so a shard whose modification time lands in the past (clock stepped back) is still read. Limits: with `file`, two rotations between two reads (the collector stopped for longer than the rotation period) skip the middle file; compressed or moved-away rotations (`compress` without `delaycompress`, `olddir`) turn an unread tail into a sequence gap. The collector connects to the store directly and ignores `HTTPS_PROXY`.

### Keys

Month keys live in `keyring.dat`. It is encrypted under a fresh file key on every write, and only that 32-byte file key is wrapped by the root key in `roots_dir`, so the root can move into an HSM or a KMS unchanged. Three places matter:

- `keys.backup_dir` receives a copy of `keyring.dat` after every change. A new month key is not used until that copy has landed, so losing `data_dir` never loses a key that sealed a record. The copy is useless without the root.
- `keys.roots_mirror_dir` is a second copy of the roots on another disk or machine. Every root is written to both places and destroyed in both. Without a mirror, losing `roots_dir` makes every stored body unreadable for good; the chain and the proofs survive.
- Nothing else may hold a copy of `roots_dir` or of the mirror. An old root copy plus an old `keyring.dat` still opens a destroyed key, so destruction is only as final as your control over those copies. The config check rejects layouts where one directory would hold both `keyring.dat` (or its backup) and a root.

The waiting period before a key is destroyed is measured by the store clock and by a fresh TSA time-stamp, whichever is earlier: moving the host clock forward does not shorten it, and without a time-stamp destruction waits. The time-stamp lands in the chain before the destruction receipt.

A key state change enters the chain only after it has reached `keys.backup_dir`. If the backup is down, the change still takes effect, the operator gets an error saying the copy is pending, and the store retries every minute; `status` shows `keyring_backup_pending` meanwhile.

`status` also lists `orphan_roots`: roots that `keyring.dat` does not know. They appear after a crash in the middle of a key rotation, or after `keyring.dat` was restored from a backup older than the last rotation. In the second case an orphan can still open an old `keyring.dat` from the dead machine, so destruction is not reported as final (`destroyed-effective`) while orphans exist. Remove them with `evidencestore keys destroy-orphan-roots`, but only if `roots_dir` is not shared with another store.

### Copy and restore

With `replica.url` set (`s3://bucket/prefix?endpoint=…&region=…` or `file:///path`), the evidence log and the chain are copied in immutable chunks, together with signed chain heads. Nothing is ever deleted from the copy, and keys never go there. `evidencestore restore` rebuilds the log and the chain from the copy and verifies them against the last signed head. `keyring.dat` and `sign.key` come back from `keys.backup_dir`, the roots from `keys.roots_mirror_dir`. On start the store checks that every record in the log is sealed with a key that `keyring.dat` knows: a wrong or too old `keyring.dat` stops the start instead of leaving bodies unreadable.

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
| `evidencestore_log_failed == 1` | the evidence log stopped after a write or fsync error; intake is refused until a human looks |
| `evidencestore_keyring_backup_pending == 1` for 10 minutes | `keyring.dat` changes are not reaching `keys.backup_dir`; new month keys are not issued |
| `time() - evidencestore_tsa_last_stamp_timestamp_seconds > 2 × tsa.every` | time-stamps are not landing |
| `time() - evidencestore_replica_last_success_timestamp_seconds > 3 × replica.every` | the copy is falling behind |
| `evidencestore_source_silent == 1` | a source has been quiet longer than its `expect_every` |
| `increase(evidencestore_gateway_problems_total[1h]) > 0` | a gateway journal entry was broken, out of order or badly signed |
| `increase(evidencestore_records_conflict_total[1h]) > 0` | a collector resent a taken number with another body: its spool was restored from an old copy, or two collectors share one certificate; the batch was refused |
| `evidencestore_keys_due > 0` | months past retention wait for a destruction request (two approvers) |
| `evidencestore_keyring_orphan_roots > 0` | key destruction is not final until orphan roots are dealt with |
| `rate(evidencestore_ingest_errors_total[5m]) > 0` | ingest requests are failing |

Also exported: records, duplicates and conflicts per source, evidence-log batches and their fsync time, the chain head.

## What is proven, and what is not

Proven offline:

- these exact bytes were received from this source;
- they have not been altered since;
- they entered the chain between the two time-stamps T1 and T2;
- the store committed to including them by the signed deadline it gave the collector;
- with the record key: the body as received;
- for gateway journals: the body is the gateway's own entry, and a checkpoint signed by the gateway covers it.

Not proven:

- that the content is true: a lying source is recorded faithfully;
- anything before the record reached the store;
- anything about records the source never wrote.

Root on the store host can delete files. After the next time-stamp, deletion or alteration cannot be hidden, but it cannot be prevented either. The pilot cryptography (AES-256-GCM from the Go standard library, root keys in files) is not certified. The design keeps a plug-in point for an HSM.

## Development

```sh
go build ./... && go vet ./... && go test -race ./...
python3 scripts/mutate.py keyring     # mutation testing: every injected bug must fail a test
                                      # sets: keyring, evlog, tsa, store, edge, auditchain, gateway
```

Design notes in Russian: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (code map), [`docs/DECISIONS.md`](docs/DECISIONS.md) (decisions and open questions), [`docs/CONCEPT.md`](docs/CONCEPT.md), [`docs/PROVENANCE.md`](docs/PROVENANCE.md).

## License

Apache License 2.0, see [`LICENSE`](LICENSE).
