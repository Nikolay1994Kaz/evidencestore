# evidencestore

Tamper-evident storage for audit records: actions of AI agents, logs of core banking systems, a copy of the SIEM stream.

Every record is accepted over mutual TLS, encrypted with its own key, written to disk (the store answers "accepted" only after `fsync`) and chained by hash. The chain head is time-stamped by an external RFC 3161 authority, e.g. the National Certification Authority of Kazakhstan (`tsp.pki.gov.kz`). For any record the store produces a proof bundle. An auditor checks it **offline**, without access to the store and without trusting it: the record bytes, a Merkle path into the chain, the chain up to a signed head, and time-stamps from before and after the record.

Retention is enforced by destroying keys (crypto-erasure). Every record of a source for a month is encrypted under that month's key. Destroying the key needs two approvers and a waiting period, and it makes those bodies unreadable in every copy (log segments, backups). The chain and the proofs stay intact: you can still prove that record #42 from `abs-core` existed, was received at a given time and was never altered. You can no longer read it.

## Quick start

```sh
scripts/demo.sh                 # builds everything, runs a full scenario offline
DEMO_TSA=nca scripts/demo.sh    # same, time-stamps from the real NCA RK TSA
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
| `escollect` | collector next to the source: tails a log file, numbers lines, spools them on disk, delivers them over mTLS, keeps the store's signed promises |
| `esverify` | auditor's tool: verifies a proof bundle offline and prints what is and is not proven |

## Configuration

See [`configs/evidencestore.example.json`](configs/evidencestore.example.json) and [`configs/collector.example.json`](configs/collector.example.json). Every source is registered by name. The name must equal the CommonName of the collector's client certificate, and the certificate can be pinned by its SHA-256 fingerprint. The source is always taken from the certificate, never from the request.

`roots_dir` holds the key that locks the keyring. It must live outside `data_dir` and must never be backed up together with it.

With `replica.url` set (`s3://bucket/prefix?endpoint=…&region=…` or `file:///path`), the evidence log and the chain are copied in immutable chunks, together with signed chain heads. Nothing is ever deleted from the copy, and keys never go there. `evidencestore restore` rebuilds the log and the chain from the copy and verifies them against the last signed head. `keyring.dat` and `sign.key` come back from `keys.backup_dir`.

## What is proven, and what is not

Proven offline:

- these exact bytes were received from this source;
- they have not been altered since;
- they entered the chain between the two time-stamps T1 and T2;
- the store committed to including them by the signed deadline it gave the collector;
- with the record key: the body as received.

Not proven:

- that the content is true: a lying source is recorded faithfully;
- anything before the record reached the store;
- anything about records the source never wrote.

Root on the store host can delete files. After the next time-stamp, deletion or alteration cannot be hidden, but it cannot be prevented either. The pilot cryptography (AES-256-GCM from the Go standard library, root keys in files) is not certified. The design keeps a plug-in point for an HSM.

## Development

```sh
go build ./... && go vet ./... && go test -race ./...
python3 scripts/mutate.py keyring     # mutation testing: every injected bug must fail a test
```

Design notes in Russian: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (code map), [`docs/DECISIONS.md`](docs/DECISIONS.md) (decisions and open questions), [`docs/CONCEPT.md`](docs/CONCEPT.md), [`docs/PROVENANCE.md`](docs/PROVENANCE.md).
