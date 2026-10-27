<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo-light.svg" alt="evidencestore" width="500">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/Nikolay1994Kaz/evidencestore/actions/workflows/ci.yml"><img src="https://github.com/Nikolay1994Kaz/evidencestore/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Nikolay1994Kaz/evidencestore/releases"><img src="https://img.shields.io/github/v/release/Nikolay1994Kaz/evidencestore" alt="Release"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/Nikolay1994Kaz/evidencestore" alt="Go version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Nikolay1994Kaz/evidencestore" alt="License"></a>
</p>

A log is written by the system it describes and usually lies on the same machine, so whoever controls the machine controls the log. An intruder cleans `auth.log`; an administrator, or an AI agent that did something it shouldn't have, often has the same access. evidencestore is a witness that lives elsewhere: a collector next to the log sends every line to a store on another machine, and the store can later prove any of those lines to an auditor.

It takes any line-based log: system logs, application and core banking audit logs, a copy of the SIEM stream, the flight recorder of an AI agent gateway such as [Pipelock](https://github.com/luckyPipewrench/pipelock), whose own hash chain and signatures the store also checks at intake.

Every record is accepted over mutual TLS, encrypted with its own key, written to disk (the store answers "accepted" only after `fsync`) and chained by hash. The chain head is time-stamped by an external RFC 3161 authority, e.g. the National Certification Authority of Kazakhstan (`tsp.pki.gov.kz`). For any record the store produces a proof bundle. An auditor checks it **offline**, without access to the store and without trusting it: the record bytes, a Merkle path into the chain, the chain up to a signed head, and time-stamps from before and after the record. The chain heads can also go to a witness of their own, out of reach of the store's administrator, so that a rewrite by that administrator shows as well ([Witness of the chain heads](#witness-of-the-chain-heads)).

Retention is enforced by destroying keys (crypto-erasure). Every record of a source for a month is encrypted under that month's key. Destroying the key needs two approvers and a waiting period, and it makes those bodies unreadable in every copy (log segments, backups). The chain and the proofs stay intact: you can still prove that record #42 from `abs-core` existed, was received at a given time and was never altered. You can no longer read it.

How it works and how it was tested, as one long read: [docs/ARTICLE.md](docs/ARTICLE.md) (на русском: [docs/ARTICLE.ru.md](docs/ARTICLE.ru.md)).

## Try it

The demos run on Linux with bash and python3 (the Pipelock one also needs curl). They build the binaries with Go 1.25.4 or newer; with binaries installed from a release, `ES_BIN=/usr/local/bin` runs the demos on those instead ([Install](#install)); the whole-session step at the end of `demo-intruder.sh` needs binaries newer than v0.2.0.

```sh
git clone https://github.com/Nikolay1994Kaz/evidencestore && cd evidencestore
scripts/demo.sh                    # builds everything, runs a full scenario offline
DEMO_TSA=digicert scripts/demo.sh  # same, time-stamps from the public DigiCert TSA
DEMO_TSA=nca scripts/demo.sh       # same, time-stamps from the NCA of Kazakhstan
scripts/demo-intruder.sh           # an intruder cleans auth.log; every deleted line comes back from the store
PIPELOCK_BIN=$(which pipelock) scripts/demo-pipelock.sh  # a real Pipelock gateway, see below
```

The demo runs these steps:

1. Issues demo certificates and starts the store.
2. Ships three log lines through the collector.
3. Verifies a proof with `esverify`.
4. Shows that a one-byte forgery is caught.
5. Destroys the month key (a single approval is refused) and shows that the proof still verifies while the body is gone.

`scripts/demo-intruder.sh` plays an intrusion on a web server. The collector follows a practice `auth.log` (inside the demo directory; nothing on the host is touched). An intruder logs in as root and then removes every line with their address (`sed -i`). The script pulls every record of that source out of the store, verifies each one offline with `esverify` and writes its body with `-body`: the four deleted lines come back byte for byte, each with the window in which the store received it, and the time-stamps show they were in the store before the file was rewritten. Last, the auditor asks for the whole session of web-1 as one bundle: it holds every line the store received from web-1 in that time, the deleted ones among them, and leaving any out would not verify. A window is closed by a time-stamp taken more than two minutes after its end, and a one-source bundle ends at the source tails of the time-stamp after that one, so the demo waits two minutes and takes two time-stamps. `DEMO_TSA=digicert` takes the time-stamps from the public DigiCert TSA.

## Run it yourself

The first three steps of the demo, by hand and on a log of your own. Everything runs on one machine. You need the three binaries on your `PATH`: from a release ([Install](#install)), or `go install ./cmd/...` in the clone. Time-stamps come from a demo TSA built into the store (`"url": "local"`), so nothing leaves the machine; a real TSA is set in `tsa` ([Configuration](#configuration)).

Certificates and the store. `dev-pki` writes a demo CA, a server certificate and a client certificate for the source `app` into `pki/` (the store takes the source name from the certificate's CommonName). The last line `init` prints is the store's public key:

```sh
mkdir -p ~/es-try && cd ~/es-try
evidencestore dev-pki -source app
cat > store.json <<'EOF'
{
  "data_dir": "data",
  "roots_dir": "roots",
  "listen": "127.0.0.1:8443",
  "tls": {"cert": "pki/server.crt", "key": "pki/server.key", "client_ca": "pki/ca.crt"},
  "tsa": {"url": "local"},
  "sources": [{"name": "app", "content_type": "text"}]
}
EOF
evidencestore init -config store.json | tee init.txt
tail -1 init.txt > store.pub
```

Start the store in a second terminal and leave it running. It warns that `keys.backup_dir` is not set, which is fine for a try:

```sh
cd ~/es-try && evidencestore serve -config store.json
```

The collector pins the store's public key and reads `app.log`; `file` can name any log your user can read. With `-once` it sends what the file holds and exits; a collector running as a service leaves `-once` out and follows the file:

```sh
cat > collector.json <<EOF
{
  "server": "https://127.0.0.1:8443",
  "ca": "pki/ca.crt", "cert": "pki/app.crt", "key": "pki/app.key",
  "store_key": "$(cat store.pub)",
  "spool_dir": "spool",
  "file": "app.log", "from_start": true
}
EOF
echo "$(date -Is) user=alice action=login" >> app.log
escollect -config collector.json -once
```

A proof of record 1, checked the way an auditor does it. A bundle verifies only once a time-stamp lies over the chain after its record: the store takes one every `tsa.every` (10 minutes by default), and `stamp` takes one now. `-dek` adds the key of this one record, so `esverify` also prints the body; a bundle without it proves the record and leaves the body closed. `esverify` runs offline, with the store's public key and the TSA certificate:

```sh
evidencestore stamp -config store.json
evidencestore proof -config store.json -source app -seq 1 -dek -out proof.json
evidencestore tsa-root -config store.json -out tsa-root.crt
esverify -proof proof.json -store-key store.pub -tsa-trust tsa-root.crt
```

`esverify` ends with `VERIFIED` (exit code 0); `evidencestore status -config store.json` shows how many records each source has. A real installation also needs certificates from your own PKI, a real TSA, `keys.backup_dir` and `keys.roots_mirror_dir` on other disks, and the store on another machine than its sources ([Install](#install)). To start over, stop the store and remove `~/es-try`.

## Components

| Binary | Role |
|---|---|
| `evidencestore` | the store: `init`, `serve`, `restore`, `dev-pki` (demo certificates), plus operator commands over a local admin socket (`status`, `statement`, `stamp`, `proof`, `tsa-root`, `keys …`, `sources bind`) |
| `escollect` | collector next to the source: tails a log file (or a set of files by glob), numbers lines, spools them on disk, delivers them over mTLS, keeps the store's signed promises |
| `esverify` | auditor's tool: verifies a proof bundle offline and prints what is and is not proven; `-body FILE` writes the record body to a file byte for byte, only once the bundle verifies; a bundle over a window of time (`evidencestore proof -source S -from -to`, or `-window` for every source) is checked for completeness, and `-bodies DIR` writes out the bodies it carries; exit code 0 — verified, 1 — not verified (including an unparsable bundle or a broken promise), 2 — bad usage, an unreadable key, certificate or promise file or heads directory, `-body` for a bundle without the record key, or `-bodies` for a window without bodies |

`evidencestore version`, `escollect -version` and `esverify -version` print the version and the commit a binary was built from.

## Install

The store and the collector run on Linux (amd64, arm64). `esverify` also runs on macOS and Windows: an auditor needs nothing else.

**From a release.** Download the binaries and `SHA256SUMS` from [Releases](https://github.com/Nikolay1994Kaz/evidencestore/releases), then check the checksum and where the binary was built: the attestation shows that this repository's release workflow built the file from the tagged commit.

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify evidencestore-linux-amd64 --repo Nikolay1994Kaz/evidencestore
sudo install -m 0755 evidencestore-linux-amd64 /usr/local/bin/evidencestore   # likewise escollect, esverify
evidencestore version
```

**With Go** 1.25.4 or newer: `go install github.com/Nikolay1994Kaz/evidencestore/cmd/esverify@latest`, likewise `cmd/evidencestore` and `cmd/escollect`.

**From source.** With Go 1.25.4 or newer: `git clone https://github.com/Nikolay1994Kaz/evidencestore && cd evidencestore && go build -o /usr/local/bin/ ./cmd/...`.

**A store host**, with the unit file from [`configs/systemd/`](configs/systemd):

1. Create the service user and its directories: `useradd --system --home-dir /var/lib/evidencestore --shell /usr/sbin/nologin evidencestore`, then `install -d -o evidencestore -g evidencestore -m 0700 /var/lib/evidencestore /var/lib/evidencestore-roots`.
2. Put `keys.backup_dir` and `keys.roots_mirror_dir` on other disks, better on another machine, and create those directories for the same user before `init`, with the disks mounted. Use a directory on the mounted disk, not the mount point itself: an empty mount point is there even when nothing is mounted on it. Neither `init` nor the store creates these directories, since a missing one looks like an unmounted disk: `init` refuses to run, and the store reports every copy there as failed (`evidencestore_keyring_backup_pending`, `evidencestore_sign_key_backup_pending`) until the directory is back.
3. Put the config into `/etc/evidencestore/evidencestore.json`, starting from [`configs/evidencestore.example.json`](configs/evidencestore.example.json). Relative paths in it resolve against the config's directory, so copy `configs/tsa/` next to it. Add the server certificate and key (readable by the service user) and the CA that issues collector certificates: your own PKI (`dev-pki` is for demos).
4. `sudo -u evidencestore evidencestore init -config /etc/evidencestore/evidencestore.json`. It prints the store's public key: collectors pin it as `store_key`, auditors pass it to `esverify -store-key`.
5. `cp configs/systemd/evidencestore.service /etc/systemd/system/ && systemctl enable --now evidencestore`. The unit sees the file system read-only apart from its own directories (`ProtectSystem=strict`): a `file://` `replica.url` or `witness.url` has to be added to `ReadWritePaths`. Operator commands talk to the admin socket, which belongs to the service user: `sudo -u evidencestore evidencestore status -config /etc/evidencestore/evidencestore.json`.

**A collector host**: one service per source. Create the user (`useradd --system --no-create-home --shell /usr/sbin/nologin escollect`); the unit adds it to group `adm`, which reads `/var/log` on Debian and Ubuntu. For each source put its certificate and `/etc/escollect/<source>.json` (from [`configs/collector.example.json`](configs/collector.example.json), with `spool_dir` set to `/var/lib/escollect/<source>`), then `cp configs/systemd/escollect@.service /etc/systemd/system/ && systemctl enable --now escollect@<source>`.

There is no container image yet.

## Configuration

See [`configs/evidencestore.example.json`](configs/evidencestore.example.json) and [`configs/collector.example.json`](configs/collector.example.json). The example time-stamps with the public DigiCert TSA (`configs/tsa/digicert`); any RFC 3161 service works if its certificates are listed in `tsa.trust`, e.g. `http://tsp.pki.gov.kz` with `configs/tsa/nca-kz/*.cer` in Kazakhstan. Tokens are verified before they enter the chain. With a TSA configured, receive times are kept between the time-stamps that `esverify` checks them against: the store knows TSA time within a window from its last time-stamp and the monotonic clock, and a receive time is the host clock held inside that window, so neither a host clock running ahead nor one lagging behind makes a record unverifiable. The intake accepts records only while that window is narrow enough and the process has taken two time-stamps: the first one only sets the window (whatever entered the chain while it was under way carries the raw host clock), and the store takes the second right after it. Before that, and when the last time-stamp is about three days old (about 75 hours; less if the TSA answered slowly), it answers `503` and collectors keep the lines in their spool. The store requests a time-stamp at start, retries every 10 seconds while the intake waits (less often after failures in a row, down to every 2 minutes), and stamps at least once an hour even when nothing new entered the chain; a TSA that stays unreachable for about three days closes the intake. Every source is registered by name. The name must equal the CommonName of the collector's client certificate, and the certificate can be pinned by its SHA-256 fingerprint. The source is always taken from the certificate, never from the request.

Risky values are rejected at start instead of being silently replaced: negative periods (zero or absent means the default), `keys.min_wait` under one hour, `roots_dir` and `data_dir` nested in either direction, a `content_type` over 255 bytes, an empty `listen`. A demo stand that must destroy a key within minutes sets `"demo": true`; never in production, where it leaves seconds to cancel a destruction. Without a `tsa` section the store starts with a warning: its proofs then carry no time-stamp, and `esverify` rejects them unless told `-allow-no-tsa`.

One process per `data_dir`: `serve`, `init` and `restore` take a lock on `data_dir/LOCK` before writing anything.

### Collector

`escollect` needs the store's public key pinned as `store_key` (printed by `evidencestore init`) and an `https://` server address; risky values (`http://`, `batch` above 512, a negative `flush_every` or `heartbeat_every`) are rejected at load instead of being silently replaced. Lines wait in an on-disk spool (`spool_dir`), each with its file position, so a crash never renumbers them. A record counts as delivered only when the store answers with a signed promise that verifies against the pinned key and names that very record; otherwise the record stays in the spool and the bad promise is kept in `promises-rejected.jsonl` as evidence against the store. The collector also checks the receive time in each promise against its own clock: the store's receive time never runs ahead of real time, so one more than a minute later than the store's answer means the store shifts receive times forward, which could move a record out of the window it arrived in. The collector logs an error and keeps such a promise in `promises-ahead.jsonl`; the record counts as delivered, since the store has it. Keep the collectors' clocks within a minute of real time (NTP).

The collector stops instead of handing out numbers the store already holds: when `spool_dir` was restored from an old copy (a VM snapshot, a backup), or when a copy of the same installation runs next to it. The store, in turn, compares the body of every resent number with the accepted one and refuses a batch carrying another body under a taken number (`409`, `"code": "seq_conflict"`, a conflict event in the chain). It also refuses a resend it cannot compare, because the accepted body sits under a month key pending destruction (cancelling the destruction lets the resend through) or already destroyed; the store names the reason, and the collector logs it as is.

Every collector installation has an epoch: a random id kept in `spool_dir/epoch.json` and sent with every request. The store binds a source to the first installation it hears from (an event in the chain) and refuses any other installation that uses the source certificate, already at start, before it reads a line (`409`, `"code": "epoch_mismatch"`). A legitimate reinstall (`spool_dir` lost or emptied) is accepted by the operator with `evidencestore sources bind -source S -epoch E`; the refusal names the command, and the previous installation is refused from then on. Copies of one installation (a VM snapshot, a copied `spool_dir`) share the epoch; the number checks above catch them.

With nothing to send, the collector sends a heartbeat every `heartbeat_every` (30 seconds by default): `GET /v1/state`, the request it makes at start, with the last sequence number it issued. A gap the collector left at the end of its numbering (a file that vanished before it was read through) reaches the chain with that heartbeat, not only with the next record of the source. The heartbeat comes from the loop that reads the log, so a hung collector goes quiet like a killed one, and a refusal of its epoch stops it even when it has nothing to send: after `sources bind` the previous installation stops within a heartbeat. The store remembers the last request of each source it let through (a refused installation does not count). When a source's collector has not been heard from for longer than the source's `expect_contact` (2 minutes by default, at least 1 minute), the store writes "collector lost" into the chain with the last contact and raises `evidencestore_source_contact_lost`; when the collector is back, it writes the window without contact. `status` shows `last_contact` and `contact_lost` per source. Time counts from the store's own start, so a store that was down does not report its collectors lost, and an open episode survives a restart. A quiet log with a live collector is not a lost collector but silence (`expect_every`). Lines written while the collector was away are read when it is back, with receive times after the window; lines deleted meanwhile are not, and the window shows when that could happen.

If the spool (`spool_dir/spool/`) is lost while `state.json` or `files.json` in `spool_dir` survived, the collector refuses to start: restore `spool_dir` from a backup. Emptying it starts over as a new installation (bind it as above) from the store's last number and skips lines that were not delivered; with `from_start` the whole log is delivered again under new numbers, so the store holds duplicates.

Upgrade the store before the collectors: collectors of this version expect a signed promise on a resend too, and older stores did not give one. An older collector sends no epoch; the store accepts it until the source is bound to an installation. Collectors of v0.2.0 and earlier send no heartbeat either: with this store their quiet minutes read as a lost collector, so upgrade them soon after the store. A configuration with `chain.promise_mmd` under 55 seconds plus two chain ticks (the demo scripts had 10 seconds) or above a minute is now refused at start: with a shorter deadline an honest store could miss its own promise. `esverify` of this version checks the time of every link that holds a time-stamp token it is shown: a chain written by v0.2.0 or earlier on a host whose clock ran more than a minute behind the TSA when it took a time-stamp fails that check in the bundles that show that token.

The collector keeps a registry of the files it reads, by inode, each with its own read position, first line, birth time and quiet timer; it is written to the spool before a file's first line and survives a crash. Every file at the log path (or under the mask) is opened as soon as the collector sees it and read while it grows. A file that leaves the path — rotated, moved out of the mask (`*.log` and `app.log` → `app.log.1`), deleted — is read through its open descriptor until it has been quiet for 10 seconds after it left (applications keep writing into a rotated file until they reopen their log), and only then the collector takes a last line without a newline and closes it. Files are read independently, so a second rotation during that wait, or two applications writing under one mask, lose nothing; lines of different files interleave in the numbering, lines of one file keep their order. After a restart a rotated file is found by its inode in the same directory, under any name, and recognised by its birth time. A file truncated or replaced in place, or a known file that is gone after a restart, costs one sequence number: the store records the gap in the chain, so the loss is visible. Reading goes on at the `flush_every` pace while the store is unreachable; only sending backs off. A file the collector cannot open (permissions after logrotate `create`) is still registered: it is read as soon as it can be opened, wherever it has moved in its directory, and if it disappears first, its loss is a gap. A directory that cannot be listed (permissions, out of file descriptors, a file-system error) is not taken for an empty one: nothing is concluded from that pass, and files already open are read on. A missing log file, an empty glob, a file that cannot be opened or a directory that cannot be listed is logged once a minute.

With `glob`, wildcards are allowed in the file name only: the collector lists that one directory and looks for rotated files in it. The registry remembers how far every file under the mask has been read (`files.json`), so a shard whose modification time lands in the past (clock stepped back) is still read; a finished file under the mask is closed after a minute of quiet when a newer one exists, and opened again if it grows. Limits: after a restart, a compressed or moved-away rotation (`compress` without `delaycompress`, `olddir`) is not found, and its unread tail becomes a sequence gap. The collector connects to the store directly and ignores `HTTPS_PROXY`.

### Keys

Month keys live in `keyring.dat`. It is encrypted under a fresh file key on every write, and only that 32-byte file key is wrapped by the root key in `roots_dir`, so the root can move into an HSM or a KMS unchanged. Three places matter:

- `keys.backup_dir` receives a copy of `keyring.dat` after every change. A new month key is not used until that copy has landed, so losing `data_dir` never loses a key that sealed a record. The copy is useless without the root.
- `keys.roots_mirror_dir` is a second copy of the roots on another disk or machine. Every root is written to both places and destroyed in both; a missing copy of the current root is restored at start and every minute, and a damaged copy is bypassed when reading. A missing mirror directory is never created, by `init` either (it looks like an unmounted disk): create it yourself. An unreachable mirror does not stop the store, but destruction is not final until both directories can be listed (`roots_unreachable` in `status`). Without a mirror, losing `roots_dir` makes every stored body unreadable for good; the chain and the proofs survive.
- Nothing else may hold a copy of `roots_dir` or of the mirror. An old root copy plus an old `keyring.dat` still opens a destroyed key, so destruction is only as final as your control over those copies. The config check rejects layouts where one directory would hold both `keyring.dat` (or its backup) and a root.

The waiting period before a key is destroyed (at least `keys.min_wait`, which outside a demo stand is one hour or more, and at most ten years) starts at a TSA time-stamp taken with the request, and it ends by the store clock and by a fresh TSA time-stamp, whichever is earlier: a host clock that is behind at request time or moved forward later does not shorten it, and without a time-stamp destruction waits. The time-stamp lands in the chain before the destruction receipt.

`init` refuses to run when `keys.backup_dir` already holds `keyring.dat` or `sign.key`: that is what a store that lost `data_dir` looks like, and a fresh keyring would overwrite the keys of every month. Put `keyring.dat` back into `data_dir` and `sign.key` into `data_dir/chain/` instead. The store, for its part, makes a new signing key only for an empty chain and when `keys.backup_dir` holds none: without `data_dir/chain/sign.key` it refuses to start while the chain holds links, while the backup holds a key (the error names the file to copy), or while the backup cannot be read. A different `sign.key` in the backup stops the start while the chain is empty; with a chain the store starts and raises `evidencestore_sign_key_backup_pending`. The backup copy is never overwritten. The backup also remembers the generation of `keyring.dat`, so an older file (a disk rolled back) never overwrites a newer backup.

A key state change enters the chain only after it has reached `keys.backup_dir`. If the backup is down, the change still takes effect, the operator gets an error saying the copy is pending, and the store retries every minute; `status` shows `keyring_backup_pending` meanwhile.

`status` also lists `orphan_roots`: roots that `keyring.dat` does not know. They appear after a crash in the middle of a key rotation, or after `keyring.dat` was restored from a backup older than the last rotation. In the second case an orphan can still open an old `keyring.dat` from the dead machine, so destruction is not reported as final (`destroyed-effective`) while orphans exist. Remove them with `evidencestore keys destroy-orphan-roots`, but only if `roots_dir` is not shared with another store.

### Copy and restore

With `replica.url` set (`s3://bucket/prefix?endpoint=…&region=…` or `file:///path`), the evidence log and the chain are copied in immutable chunks, together with signed chain heads. Nothing is ever deleted from the copy, and keys never go there. S3 credentials for the copy come from `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (with `AWS_SESSION_TOKEN` if set). The directory of a `file://` URL is not created by the store, since a missing one looks like an unmounted NFS or rclone mount: create it on the mounted disk, as a directory inside it rather than the mount point itself. Until it is there, every pass fails (`evidencestore_replica_errors_total`) and nothing lands on the local disk. `evidencestore restore` rebuilds the log and the chain from the copy and verifies the chain links against the latest signed head whose link the copy holds. The chain is cut at that head: a pass that was interrupted before its head may have left links whose leaves never arrived, or leaves whose links never did, and nothing the head does not sign is taken; records past the head are linked again from the evidence log when the store starts. The restored store does not write on the copy in place, since its bytes would land on that cut tail: it writes the copy again as a new generation, from scratch, under `gen/<n>/` in the same location. Earlier generations stay as they are, and `restore` takes the newest generation that holds a signed head. On its first pass after start the store also checks that the copy ends where `data_dir` does. If `data_dir` lost data that had already been copied (a disk that lied about fsync), or did not write that copy, the store refuses to write on it (`the copy is not where data_dir left it` in the log, `evidencestore_replica_errors_total` grows): restore from the copy into an empty `data_dir`, or point `replica.url` at a new location. The evidence log and the leaves are not checked against the chain at that point: a damaged chunk shows when the store starts (frame checksum) or when a proof of its records is built, so do not discard another copy of `data_dir` on the strength of `restore` alone. `keyring.dat` and `sign.key` come back from `keys.backup_dir` (the store checks `sign.key` against that copy on every start, and refuses to start with a chain but without `sign.key`), the roots from `keys.roots_mirror_dir`. On start the store checks that every record in the log is sealed with a key that `keyring.dat` knows: a wrong or too old `keyring.dat` stops the start instead of leaving bodies unreadable. What the store accepted after the last copy is lost with the disk: collectors keep the signed promises as proof, and the next record or heartbeat of each source shows the gap in the chain. So is a collector binding made after the last copy: that source is bound again to the first installation that contacts the restored store, and a legitimate one refused meanwhile is accepted with `sources bind`. A record whose evidence reached the copy but whose chain link did not is linked when the restored store starts, so its promise shows a missed deadline; for a Pipelock source, the entry after a lost one is marked as not intact (its chain link to the previous entry is broken).

### Witness of the chain heads

Whoever holds `sign.key` can sign a second version of the chain, and a bundle from it verifies on its own. Only someone who saw a head early and keeps it out of that administrator's reach can show that the chain was rewritten: a witness. Each link carries the hash of the one before, so a head the witness holds fixes the whole chain up to it.

With `witness.url` set (`s3://bucket/prefix?endpoint=…&region=…` or `file:///path`), the store sends the witness its signed chain heads only — number, hash, link count, signing time, key and signature; no records and no metadata — under `heads/<number>.json`: the head under every TSA time-stamp, where a single-record bundle ends, the head of the link that holds its token, where window and one-source bundles end, and the current head every `witness.every` (1 minute by default). With a copy configured, the witness never gets ahead of it: only heads the copy already holds after a successful pass are sent, so a restore from the copy cannot contradict the witness, and heads reach it up to `replica.every` later. S3 credentials come only from `ES_WITNESS_ACCESS_KEY_ID` and `ES_WITNESS_SECRET_ACCESS_KEY` (and `ES_WITNESS_SESSION_TOKEN`), never from the copy's. `witness.url` must differ from `replica.url`. As with the copy, the directory of a `file://` witness is not created: while it is missing, every send fails (`evidencestore_witness_errors_total`).

The witness has to be run by someone the store's administrator does not control: the auditor, another organization, or a cloud bucket with S3 Object Lock in compliance mode, which not even the account owner can delete from before the retention ends. S3 on a host where that administrator has root is a backup, not a witness: root deletes or rewrites its files past S3. Give the store a user that may only write objects, and keep versioning on: an overwrite then adds a version, and the original one stays. Tried on MinIO with Object Lock: a locked version cannot be deleted, but a newer version or a delete marker hides it from a plain read and from the listing, so take all versions.

An auditor checks a bundle against the witness with `esverify -heads DIR`, where `DIR` holds the heads they took from the witness themselves, all versions (for S3, `aws s3api list-object-versions` with `get-object --version-id`, or `rclone copy --s3-versions`; any S3-compatible storage, through `--endpoint-url`). Files that are not heads signed with the store key are skipped. The first head the witness holds at or after the record's link fixes the record: a chain rewritten after the witness saw that head does not agree with it. Two different heads with one number prove that the store signed two versions of the chain. Where that touches the record's part of the chain, the bundle does not verify; elsewhere the record stays proven, and the report names the second version: a rewrite, or a store that lost data without a copy. If that head lies past the end of the bundle, ask for a longer one: `evidencestore proof … -to-head N`. Anything else the administrator cannot take back works as a witness too, for example `evidencestore statement` mailed or published once a day: put those heads into `DIR` the same way.

### Bundles over a window of time

A single-record bundle proves one record and says nothing about the records the auditor was not given. A bundle over a window of time (RFC 3339 times, by the store's receive time) answers "everything received between FROM and TO" and also proves that nothing is left out. It is bounded by two TSA time-stamps: the last one taken more than a second before FROM and the first one taken more than two minutes after TO. A time-stamp certifies the chain up to the moment the store asked for it; whatever entered the chain while the request was under way lies after that point and is certified only by the next time-stamp. The store does not use a TSA answer that took longer than 30 seconds, and a receive time lags real time by at most 55 seconds, so such a record carries a receive time later than two minutes before the time-stamp, outside the window. Receive times follow the last time-stamp and the host's monotonic clock, which stands still while the host is suspended or its VM paused: after such a pause they lag by its length until the next time-stamp. The store asks for one as soon as the host clock jumps ahead of its estimate, and a TSA answer whose time lies beyond the receive-time window is not used: the store pauses the intake for the moment it takes the records already received to reach the chain (collectors retry on `503`), moves its estimate to the TSA time and stamps again, so whatever arrived during that request lies before the time-stamp and every receive time follows one estimate or the other. There are two kinds:

- `evidencestore proof -source S -from FROM -to TO [-dek]`: every record of one source, for an auditor from outside. Other sources stay closed.
- `evidencestore proof -window -from FROM -to TO [-source S -dek]`: every record of every source, for an investigation inside the organization.

**One source.** Every evidence leaf carries the hash of the previous leaf of its source, so the records of a source form a chain of their own inside the store's chain. Right before each TSA request the store writes the source tails, the hash of each source's latest leaf, alone in a link, and that link is what the time-stamp certifies. The lower end of the bundle is the tails of the time-stamp before the window. The upper end needs the opposite bound, that everything put into the chain after it came after the window, and a time-stamp over an end does not give it: one can be taken over old tails at any time and appended to the chain without rewriting anything. So the bundle carries the token of the time-stamp that closes the window, which lies in the chain before the upper end, and the upper end is the tails of the first time-stamp after that token: whatever follows the token entered the chain after its time. A one-source bundle is therefore ready one time-stamp later than a window bundle. It carries both ends and every record of S between them with its Merkle path; in those paths other sources' leaves are only hashes. `esverify` checks that each record refers to the one before it, from the lower tails up to the upper ones: a record left out breaks the reference of the next one or leaves the chain short of the upper tails. Each end is certified by its own time-stamp, so moving an end means rewriting the chain after it and taking fresh time-stamps. A witness (`-heads`) catches such a rewrite; without one, a rewrite made within about an hour of the window cannot be told from an honest bundle by T2 alone. `esverify` also checks every receive time against the time-stamps of the ends. In the tails each source is named by a hash of its name, and its entry, with the kind of the source, is sealed with a salt only the store can derive; the bundle opens only S. Of the other sources the auditor sees how many there are, could test a guessed name, and sees the pace of the whole store: for every link between the ends, when it was made and how many leaves it holds. Their record numbers and which of them wrote what stay closed. The tails are the store's own statements, written when it took the time-stamps: a store that understated them would have lied at that moment, and a window bundle or the hidden record's own bundle shows the lie. For gateway journal records the bundle also carries the store's verdict from intake: records found broken are named in the report, and their bodies are not opened (a single-record bundle shows what is wrong). The tails name a gateway journal as such, so its bundle does not verify without a verdict for every record, with bodies or without; a source whose kind changed between the ends (its configuration did) does not verify either.

**Every source.** The window bundle carries every leaf of the chain between the two time-stamps. `esverify` recomputes the Merkle root of every link from its leaves and checks that the leaves continue right after the lower head: a record left out, added or moved breaks a root. It verifies every time-stamp in the stretch and checks each record's receive time against the time-stamps around its link: not later than the first one over it, not earlier than a minute before the latest time-stamp whose token lies before it, and later than two minutes before any time-stamp whose certified head it lies after. "Latest" is by the time in the time-stamp, not by place: a copy of an old token can be added anywhere later in the chain. Records after the head the upper time-stamp certifies are not in the report and cannot be attached: nothing in the bundle certifies them. Their receive times must still be later than two minutes before that time-stamp, so a store that held its request back to push records of the window behind the certified head is caught. The report lists every source in the window with its record numbers, recorded gaps, silences, a lost collector and seq conflicts, and names number holes that have no recorded gap. It shows the metadata of every source: names, record numbers, receive times, digests. Bodies come only for one source, with `-source S -dek`.

Give your own window with `esverify -from FROM -to TO`; without it the window named in the bundle is used, and the report says so. `esverify -bodies DIR` writes the bodies out byte for byte. The window can be closed only by a time-stamp taken more than two minutes after its end: the store takes one every `tsa.every` while records arrive and at least once an hour, and `evidencestore stamp` takes one at once. One bundle spans up to 250 000 leaves of the chain; split longer windows. The window is the store's receive time, not the time written in a line. A record the store held back and put into the chain after the time-stamp that closes the window is not in the window bundle; the collector's promise for it shows the missed deadline (`esverify -promise` on the record's own bundle). That check rests on the time-stamps, not on the store's word: `promise_mmd` is at most a minute (and at least 55 seconds plus two chain ticks, since a receive time may lag real time by up to 55 seconds while link times do not), a link that holds a time-stamp token must carry a time at most a minute before the time-stamp (checked in every bundle that shows the token), and the deadline is compared with the latest link time from the link after the head that the time-stamp before the record (T1) certifies to the record's link. Not from the link that holds T1's token: the store picks T1, and a copy of an old token, or a token it held back, can be put anywhere later in the chain, but not before the head it certifies. A store that also dates the closing token's link back passes that check, but then every window or one-source bundle over that window either shows the record or does not verify.

Records from release v0.2.0 and earlier carry no reference to the previous record, and their time-stamps have no tails: for such a window the store refuses a one-source bundle and points to `-window`. Their single-record and window bundles still verify. The other way round, `esverify` v0.2.0 does not read bundles from a newer store, not even of older records: single-record bundles are now version 2, since they need checks that v0.2.0 does not make, and it answers "bundle version 2, supported 1". Use the `esverify` of the same release as the store, or a newer one.

### Gateway journals (Pipelock)

A source with `"content_type": "pipelock/recorder"` carries the flight recorder of a [Pipelock](https://github.com/luckyPipewrench/pipelock) gateway: JSONL where every entry is hash-chained to the previous one and checkpoints are signed with the gateway's Ed25519 key. Pin that key in the source as `gateway_key` (64 hex, `pipelock signing pubkey`). Point the collector at the shards with a glob, since Pipelock writes every shard to a new file (full example: [`configs/collector.pipelock.example.json`](configs/collector.pipelock.example.json)):

```json
{"glob": "/var/lib/pipelock/recorder/evidence-*.jsonl", "from_start": true}
```

At intake the store recomputes each entry's hash (Pipelock's frozen v1–v3 projections), checks the `prev_hash` linkage per writer and verifies checkpoint signatures with the pinned key. Nothing is rejected: the entry is stored as received, and a verdict goes into the chain next to it. The chain fields of the gateway (`seq`, `hash`, `prev_hash`) stay readable after the month key is destroyed.

A proof bundle for such a record also shows that the body is exactly that gateway entry (the hash is recomputed offline from the body) and that a checkpoint signed by the gateway covers it. Pass the gateway key to `esverify -gateway-key` to check that signature yourself. Limits: the linkage between the entry and the checkpoint was checked by the store at intake (the bundle does not carry the entries in between); a Pipelock restart starts a new chain, and the signed `chain-link` file that connects sessions is not checked yet; one writer per recorder directory. Verified against real Pipelock v3.6.0 output (`internal/gateway/testdata`) and end to end with a live Pipelock v3.6.0 (`scripts/demo-pipelock.sh`, and a night of a running gateway with restarts).

### Monitoring

Set `metrics_listen` (for example `127.0.0.1:9464`) to expose `/metrics` in the Prometheus text format. Worth an alert:

| Condition | Meaning |
|---|---|
| `evidencestore_log_failed == 1` | the evidence log or the chain stopped after a write or fsync error; intake is refused until a human looks (`evidencestore_chain_failed` tells which) |
| `increase(evidencestore_receive_clock_capped_total[1h]) > 0` | the host clock runs ahead of TSA time, or lags behind it by about a minute, or the monotonic clock stood still (the host was suspended, the VM paused) until the next time-stamp; receive times are held inside the window known from the last time-stamp and the monotonic clock |
| `evidencestore_receive_time_ahead_seconds > 60` | the log holds receive times ahead of the host clock (an earlier clock jump) |
| `evidencestore_keyring_backup_pending == 1` for 10 minutes | `keyring.dat` changes are not reaching `keys.backup_dir`; new month keys are not issued |
| `evidencestore_sign_key_backup_pending == 1` for 10 minutes | `sign.key` is not confirmed in `keys.backup_dir`: the directory is missing (an unmounted disk?) or unwritable, or another key lies there (the log says which); after losing `data_dir` the store could not sign as itself |
| `time() - evidencestore_tsa_last_stamp_timestamp_seconds > 3600 + 2 × tsa.every` | time-stamps are not landing (with nothing new in the chain the store stamps only once an hour; `increase(evidencestore_tsa_errors_total[30m]) > 0` shows failed attempts sooner) |
| `time() - evidencestore_replica_last_success_timestamp_seconds > 3 × replica.every` for `2 × replica.every` | the copy is falling behind (the gauge is 0 after a start until the first pass): the remote is down or its `file://` directory is missing, or the store refuses a copy that `data_dir` does not continue (see Copy and restore) |
| `increase(evidencestore_witness_errors_total[10m]) > 0` | signed heads do not reach `witness.url`; they wait in memory, and heads under time-stamps queued before a restart are not resent |
| `evidencestore_source_silent == 1` | a source has been quiet longer than its `expect_every` |
| `evidencestore_source_contact_lost == 1` | a source's collector has not contacted the store (a batch or a heartbeat) for longer than its `expect_contact`: stopped, crashed or hung, its host down, or the network cut; the chain marks the window |
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
- with the record key: the body as received (`esverify -body FILE` writes it out byte for byte, so the original log can be rebuilt from the store); the key is bound to the record's digest, so the store cannot show two auditors two different bodies;
- for gateway journals: the body is the gateway's own entry, and a checkpoint signed by the gateway covers it — when that signature was checked by the store with the pinned `gateway_key` or by you with `-gateway-key`. A gateway record whose bundle lacks the gateway part does not verify;
- with `-heads DIR`: the chain in the bundle agrees with every head a witness holds for that part of the chain; a second version of the chain elsewhere is named in the report (see Witness of the chain heads);
- with a bundle over a window of time (`evidencestore proof -source S -from FROM -to TO`, or `-window` for every source): every record the store put into its chain between two TSA time-stamps is in the bundle, so a record received in the window cannot be kept from the auditor unless the store holds it back past the window, and then the deadline the store promised the collector for it is missed and `esverify -promise` shows it (see Bundles over a window of time). The window is by the store's receive time, which the collector checks against its own clock to within a minute: this holds for records the collector delivered more than a minute before the window ends.

T2 is required: a bundle without a time-stamp after the record only carries the store's own signature, and whoever holds `sign.key` can make up a record with any date. `esverify` rejects such a bundle unless told `-allow-no-tsa`. The verdict is printed first and last, and control characters in the body are escaped, so a body cannot paint a false verdict on the auditor's screen.

Not proven:

- that the content is true: a lying source is recorded faithfully;
- anything before the record reached the store;
- anything about records the source never wrote;
- from a single-record bundle, that you were given every record: it proves that one record only. A bundle over a window of time proves the whole window, by the store's receive time, not by the time written in the lines;
- from a one-source bundle, that the source tails are true: they are the store's own statements, written when it took the time-stamps, and an understated one shows in a window bundle or in the hidden record's own bundle;
- that a bundle over a window of time was built from the chain as it was then: a rewrite after the lower time-stamp needs fresh time-stamps after it. A T2 more than an hour after the window is a sign of that (the store takes a time-stamp at least once an hour); a rewrite made sooner is caught only by a witness, with `-heads`.

Root on the store host can delete or rewrite the store's files, and whoever holds `sign.key` can sign a second version of the chain. That leaves traces: a rewritten chain gets only fresh time-stamps, the collectors hold signed promises for the original records (`esverify -promise` shows a replaced one), and a witness or a remote copy kept out of that administrator's reach still holds the original signed heads. The traces help only someone who checks them: `esverify -heads` compares a bundle with a witness's heads, nothing compares the collectors' promises by itself, and nothing can prevent the rewrite. Keep the store, its remote copy and the sources under different administrators where you can. With one administrator for everything, only the time-stamps and a witness that administrator does not control stand against them. The pilot cryptography (AES-256-GCM from the Go standard library, root keys in files) is not certified. The design keeps a plug-in point for an HSM.

## How it was tested

Numbers below are for commit `957345c` (12 October 2026), unless a later date is given.

- **Test gate.** `go build ./... && go vet ./... && go test -race ./...` passes.
- **Mutation testing** (27 October 2026). 557 bugs injected one at a time (`scripts/mutations/`), and every one of them makes a test fail: store and proofs 325, collector and intake 84, keyring 62, evidence log 20, gateway journals 15, chain 15, TSA 14, configuration 16, copy transport 6.
- **Simulations:** randomized scenarios checked against an oracle (commands under Development).
  - Store with crashes: 2,000 scenarios of 300 steps, no failures. They went through 36,038 crashes (3,848 in the middle of a write), 6,649 restores from the copy (1,154 after the disk was lost in the middle of a copy pass), 1,368 disks that lied about fsync, 2,185 destroyed keys (231 crashes in the middle of a root rotation) and 75,858 rounds of parallel intake (1.25 million batches, 312,900 pairs of identical concurrent requests). 300 more scenarios under the race detector found no data race. Later, on 17 October, CI caught a data race in the simulation's own bookkeeping (test code, not the store); it is fixed (Z-12 in [`docs/FINDINGS.md`](docs/FINDINGS.md)).
  - Receive-time clock: 3,000 scenarios, no failures.
  - Collector: 2,000 scenarios in each of four worlds (one file or a glob, with and without destruction) against an in-memory store, 150 per world against the real store over mTLS, and 400 per world against the real store with all faults at once; no failures.
  - On 27 October, on the code of the bundles over a window of time: store with crashes 1,500 scenarios of 300 steps and the receive-time clock 2,000 scenarios, no failures; the collector 2,000 scenarios in each of four worlds and 200 per world against the real store, with one failure in a world with destruction (a gap the collector left reached the store only with the next record; fixed the same day: the heartbeat carries the last issued number, and the scenario passes).
  - On 27 October, evening, after the third review round: store with crashes 1,500 scenarios of 300 steps and the collector 2,000 scenarios per world and 200 against the real store, no failures; the receive-time clock run of 2,000 scenarios failed 226 on a fault in the simulation's own check (two time-stamps in one second after a restart), and after that was fixed 300 scenarios ran with no failures. A new simulation of a dishonest store owner (`TestOwnerSim`: held-back records and tokens, copies of old tokens, links dated back as far as the checks allow, shifted receive times) found that a receive time shifted forward hid a record from the window bundle with its promise kept; the collector now checks receive times.
- **Live gateway.** `scripts/demo-pipelock.sh` passes against Pipelock v3.6.0 built from the tag's commit.
- **A night on real data** (11–12 October, 21:19–06:23). The store ran with four collectors: the host's own `/var/log/syslog`, `auth.log` and `kern.log` (read from the start), and the flight recorder of a live Pipelock v3.6.0 that blocked an "agent" all night (no request left the host). During the night logrotate rotated all three logs at midnight (`create`, `delaycompress`, rsyslog HUP), the store was restarted 5 times, a collector was killed with `kill -9`, Pipelock was restarted twice (3 sessions, 359 shards), and the copy went to a directory every minute. Every one of the 104,738 records matched its source line, in order, with no duplicates and no losses: syslog 71,120 (67,596 from the rotated file, 3,524 from the new one), auth.log 1,246, kern.log 10,752, Pipelock 21,620. A sample of 7,560 proof bundles across the whole range verified the way `esverify` does, the Pipelock ones with the gateway's checkpoint signature. A store restored from the copy (76 MB, chain checked up to signed head 8005) gave the same result. The store log had no errors. The scripts of this run were a one-off and are not in the repository.
- **Witness and copy on real S3** (25 October, MinIO RELEASE.2025-10-15 with Object Lock in compliance mode). The store sent its signed heads to a locked bucket and its copy to another; `esverify -heads` verified a bundle against all versions of the witnessed heads, a junk version and a delete marker put over a head afterwards changed nothing, and `restore` from the copy passed. A one-off run; AWS itself was not tried.

## Known limitations

- **A file the collector never saw.** A file that appears at the log path (or under the mask) and leaves it while the collector is not looking — it was stopped, or both happened within one `flush_every` — is never read, and no gap is recorded. Likewise, lines that are written and destroyed (deleted, truncated) between two reads leave no trace — and so do lines of a file the collector cannot open yet, if the file is truncated in place before it can be read. Every file the collector has seen is followed until it is read or its loss is recorded as a gap.
- **A file closed after a minute of quiet** (`glob` only, when a newer file exists) that is then written again and destroyed within one `flush_every` loses those lines without a gap.
- **Long lines.** A line is read into the collector's memory whole before it is cut, so a source writing one line of hundreds of megabytes inflates the collector. A line longer than 1 047 552 bytes becomes several records with no continuation mark; the cut may fall inside a UTF-8 character, and for `pipelock/recorder` every piece fails the gateway-entry check.
- **`copytruncate` rotation** costs one sequence number whether or not unread lines were lost: the collector cannot tell the two cases apart.
- **The collector epoch is an installation id, not a secret.** Whoever copies the source certificate together with `spool_dir` also has `epoch.json`. Protect `spool_dir` as you protect the certificate key.
- **Gateway journals.** The store checks the gateway's signed checkpoint. Signatures of individual receipts inside Pipelock entries, their `chain_prev_hash` chains and the `chain-link` file between sessions are not verified.
- **A gap event can be missing after a crash.** When the store crashes right after a record that skips sequence numbers, power fails while the chain writes its leaves, or a restore from the copy cuts the chain at its signed head, the record may already be in the chain while the explicit gap event is not, and the event is not announced after restart. The gap itself stays visible in the chain from the record numbers.
- **Key backup unreachable at restart.** `keyring.dat` knows which of its keys have reached `keys.backup_dir` only up to its previous write, so after a restart the keys created by its last write are not used until the copy succeeds again. If `keys.backup_dir` is unreachable at that moment (a network share is down), intake for those months waits: right after installation until the next keyring change, and in the first minutes of a month. Nothing is lost — collectors keep the lines — and `evidencestore_keyring_backup_pending` shows it.
- **Bulk proof export.** A single-record bundle is built under the chain lock. It reads the whole leaf file (`leaves_*.log`, up to 64 MiB before it rotates) that holds the record's leaf, the T1 or the T2 token, two or three times per bundle, and `chain.log` from the start up to the bundle's last link. At about 77 thousand records (one 6 MB leaf file) that took 50–100 ms per bundle on a loaded host, almost all of it reading the leaf file, and intake waits meanwhile. Export many single bundles off-peak, or ask for a bundle over a window of time: it is built without holding the chain lock and reads every leaf file once, up to 250 000 leaves per bundle. A one-source bundle holds the lock only to find the source's last record before the window, a pass over that source's records: 6 ms at 300 thousand records, so about 0.2 s at 10 million.
- **A receive time shifted by up to a minute goes unnoticed.** The receive time is the store's word, and the collector catches only a shift of more than a minute past its answer (`promises-ahead.jsonl`): a store can move a record that arrived in the last minute of a window into the next one.
- **A held-back record shows only with the collector's promise.** A store owner who holds a record back past the time-stamp that closes its window keeps it out of the window bundle, and the record's own bundle verifies. The missed deadline shows when someone checks the collector's promise for that record (`esverify -promise`); nothing compares the promises by itself. An owner who also dates the closing token's link back passes that check, and then every window or one-source bundle over that window either shows the record or does not verify.
- **The heartbeat shows a running collector, not an honest one.** Root on the source host holds the collector's certificate, key and epoch, so it can keep the heartbeat going itself while the collector is stopped. A stop shorter than `expect_contact` leaves no event either: a collector stopped for a minute and started again is not reported.
- **Index in memory.** The sequence-to-position and position-to-leaf indexes are rebuilt from the evidence log at start and take 16 bytes per record in memory; the index of chain links takes 24 bytes per link, and with a link every second that is about 0.75 GB a year.
- **Witness queue in memory.** Heads waiting for an unreachable witness are kept in memory: every head under a time-stamp, the head of its token's link and the latest current one. Those not sent before the store stops are not resent after the restart; for their records, ask for a bundle up to the next head the witness holds (`proof -to-head`). The heads cannot be read back through `evidencestore`: take them from the witness with an S3 tool that lists versions.
- **The witness follows the copy.** With `replica.url` set, heads reach the witness only after the copy holds them, so the copy being down stalls the witness too, and after a restore the witness waits until the new copy generation is written. Without a copy a lost disk cannot be restored, and a store that lost the tail of its chain (a disk that lied about fsync) writes other links under numbers the witness saw: a second version of the chain, which the report names.
- **Input.** The collector reads files only: no journald, no syslog receiver, no database tables, no Windows Event Log. rsyslog bridges most of these into files the collector reads: it takes the messages journald gets (install it where it is missing, for example `apt install rsyslog` on Debian 12), receives syslog over the network (`imudp`, `imtcp`, or TLS), and most databases can write their audit to a file or to syslog (PostgreSQL with pgaudit, MySQL, Oracle, MS SQL). The bridge runs next to the source, so whoever controls that host can stop it, just like the collector.
- **Untested failure paths.** Recovery from a failed `fsync` of a directory or of a fresh `sign.key`, and from an S3 listing without a marker, is checked by reading the code, not by tests: those paths need a hardware or service fault.

## Development

GitHub Actions runs the same gate on every push to master and every pull request (`.github/workflows/ci.yml`). A `v*` tag also builds the release binaries with `scripts/release.sh`, attests where they were built and publishes the release with notes from `docs/releases/`.

```sh
go build ./... && go vet ./... && go test -race ./...
scripts/release.sh dist               # release binaries and SHA256SUMS
ES_BIN=/usr/local/bin scripts/demo.sh # the demo on installed binaries instead of a fresh build
python3 scripts/mutate.py keyring     # mutation testing: every injected bug must fail a test
                                      # sets: keyring, evlog, tsa, store, edge, auditchain, gateway, config, ship
SIM_SEEDS=1000 go test -timeout 0 -run TestCollectorSim ./internal/collector/   # collector simulation: rotations (dateext too),
                                      # renames, restarts and crashes before, after and in the middle of a write, long lines,
                                      # lost store answers, permissions, destruction — every line once, or a visible gap
SIM_REAL_SEEDS=100 go test -run 'TestCollectorSim/real' ./internal/collector/   # the same against the real store
                                      # over mTLS: every record's proof verifies, every gap is a chain event
CLOCKSIM_SEEDS=1000 go test -timeout 0 -run TestClockSim ./internal/store/       # receive-time simulation: clocks off, drifting,
                                      # jumping; slow, absent TSA; idle days — every accepted record verifies
                                      # and keeps its promise
ADVSIM_SEEDS=1000 go test -timeout 0 -run TestOwnerSim ./internal/proof/         # a dishonest store owner: held-back records and tokens,
                                      # copies of old tokens, backdated links, shifted receive times — every
                                      # record of a window is in each window bundle that verifies, or its promise
                                      # shows the missed deadline
STORESIM_SEEDS=1000 go test -timeout 0 -run TestStoreCrashSim ./internal/store/  # store crashes at every write point (chain leaves,
                                      # link, head; key backup; root rotation; before the answer; torn writes), keyring.dat
                                      # restored from backup, key destruction, segment rotation, a disk that lies about
                                      # fsync, disk loss and restore from the copy (also mid-copy), parallel intake with
                                      # duplicate requests — every promise kept, every record once, every gap in the chain,
                                      # everything copied by a finished pass back after a restore
```

`go test` runs the simulations with a few dozen scenarios each; a failure prints `SIM_SEED=` (`CLOCKSIM_SEED=`, `STORESIM_SEED=`), which replays that scenario with its full trace (a store scenario with parallel intake replays its steps, not the exact interleaving). Every collector scenario draws its own set of faults; `SIM_FAULTS=all` (or a comma list: `long,after,torn,flaky,perm-new,perm-file,perm-dir,perm-spool,dateext`) fixes it.

Design notes in Russian: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (code map), [`docs/DECISIONS.md`](docs/DECISIONS.md) (decisions and open questions).

## License

Apache License 2.0, see [`LICENSE`](LICENSE).
