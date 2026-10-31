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

Every record is accepted over mutual TLS, encrypted with its own key, written to disk (the store answers "accepted" only after `fsync`) and chained by hash. The chain head is time-stamped by an external RFC 3161 authority, e.g. the National Certification Authority of Kazakhstan (`tsp.pki.gov.kz`). For any record the store produces a proof bundle. An auditor checks it **offline**, without access to the store and without trusting it: the record bytes, a Merkle path into the chain, the chain up to a signed head, and time-stamps from before and after the record. The chain heads can also go to a witness of their own, out of reach of the store's administrator, so that a rewrite by that administrator shows as well ([Witness of the chain heads](docs/copy-and-witness.md#witness-of-the-chain-heads)).

Retention is enforced by destroying keys (crypto-erasure). Every record of a source for a month is encrypted under that month's key. Destroying the key needs a waiting period and two named approvals, which the chain records but the store does not authenticate ([Known limitations](docs/limitations.md)), and it makes those bodies unreadable in every copy (log segments, backups). The chain and the proofs stay intact: you can still prove that record #42 from `abs-core` existed, was received at a given time and was never altered. You can no longer read it.

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

The first three steps of the demo, by hand and on a log of your own. Everything runs on one machine. You need the three binaries on your `PATH`: from a release ([Install](#install)), or `go install ./cmd/...` in the clone. `dev-setup` is in binaries newer than v0.3.0; with v0.3.0, take the steps by hand under "Step by step by hand" instead.

`dev-setup` prepares a directory for a try: a demo CA with certificates for the store and for the source `app`, the store's config, `init`, and the collector's config with the store's public key pinned in it. Time-stamps come from a demo TSA built into the store (`"url": "local"`), so nothing leaves the machine; a real TSA is set in `tsa` ([Configuration](docs/configuration.md)). It writes only into a new or empty directory; `-log FILE` points the collector at a log of your own (any file your user can read), and `-port` moves the store off port 8443:

```sh
evidencestore dev-setup -dir ~/es-try -source app
```

<details>
<summary>Step by step by hand: certificates, both JSON configs and <code>init</code></summary>

`dev-pki` writes a demo CA, a server certificate and a client certificate for the source `app` into `pki/` (the store takes the source name from the certificate's CommonName). The last line `init` prints is the store's public key: the collector pins it as `store_key`, and an auditor passes it to `esverify`:

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
cat > collector.json <<EOF
{
  "server": "https://127.0.0.1:8443",
  "ca": "pki/ca.crt", "cert": "pki/app.crt", "key": "pki/app.key",
  "store_key": "$(cat store.pub)",
  "spool_dir": "spool",
  "file": "app.log", "from_start": true
}
EOF
```

</details>

Start the store in a second terminal and leave it running. It warns that `keys.backup_dir` is not set, and two minutes after the collector's last contact it warns that the collector of `app` is lost: a collector run with `-once` sends no heartbeat. Both are fine for a try:

```sh
cd ~/es-try && evidencestore serve -config store.json
```

Back in the first terminal, a line goes into `app.log` and the collector sends it; with `-log`, skip the `echo`: record 1 is the first line of your log. With `-once` the collector sends what the file holds and exits; a collector running as a service leaves `-once` out and follows the file:

```sh
cd ~/es-try
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
| `evidencestore` | the store: `init`, `serve`, `restore`, `dev-pki` (demo certificates), `dev-setup` (a demo store in one directory: certificates, both configs, `init`), plus operator commands over a local admin socket (`status`, `statement`, `stamp`, `proof`, `tsa-root`, `keys …`, `sources bind`) |
| `escollect` | collector next to the source: tails a log file (or a set of files by glob), numbers lines, spools them on disk, delivers them over mTLS, keeps the store's signed promises |
| `esverify` | auditor's tool: verifies a proof bundle offline and prints what is and is not proven; `-body FILE` writes the record body to a file byte for byte, only once the bundle verifies; a bundle over a window of time (`evidencestore proof -source S -from -to`, or `-window` for every source) is checked for completeness, and `-bodies DIR` writes out the bodies it carries; exit code 0 — verified, 1 — not verified (including an unparsable bundle or a broken promise), 2 — bad usage (including a flag meant for the other kind of bundle, or a bad `-from` or `-to`), an unreadable bundle, key, certificate or promise file or heads directory, `-body` for a bundle without the record key, or `-bodies` for a window without bodies |

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
2. Put `keys.backup_dir` and `keys.roots_mirror_dir` on other disks, better on another machine, and create those directories for the same user before `init`, with the disks mounted. Use a directory on the mounted disk, not the mount point itself: an empty mount point is there even when nothing is mounted on it. Neither `init` nor the store creates these directories, since a missing one looks like an unmounted disk: `init` refuses to run, and the store reports every copy there as failed until the directory is back (`evidencestore_keyring_backup_pending` and `evidencestore_sign_key_backup_pending` for `keys.backup_dir`, `evidencestore_keyring_roots_unreachable` for `keys.roots_mirror_dir`).
3. Put the config into `/etc/evidencestore/evidencestore.json`, starting from [`configs/evidencestore.example.json`](configs/evidencestore.example.json). Relative paths in it resolve against the config's directory, so copy `configs/tsa/` next to it. Add the server certificate and key (readable by the service user) and the CA that issues collector certificates: your own PKI (`dev-pki` is for demos).
4. `sudo -u evidencestore evidencestore init -config /etc/evidencestore/evidencestore.json`. It prints the store's public key: collectors pin it as `store_key`, auditors pass it to `esverify -store-key`.
5. `cp configs/systemd/evidencestore.service /etc/systemd/system/ && systemctl enable --now evidencestore`. The unit sees the file system read-only apart from its own directories (`ProtectSystem=strict`): a `file://` `replica.url` or `witness.url` has to be added to `ReadWritePaths`. Operator commands talk to the admin socket, which belongs to the service user: `sudo -u evidencestore evidencestore status -config /etc/evidencestore/evidencestore.json`.

**A collector host**: one service per source. Create the user (`useradd --system --no-create-home --shell /usr/sbin/nologin escollect`); the unit adds it to group `adm`, which reads `/var/log` on Debian and Ubuntu. For each source put its certificate and `/etc/escollect/<source>.json` (from [`configs/collector.example.json`](configs/collector.example.json), with `spool_dir` set to `/var/lib/escollect/<source>`), then `cp configs/systemd/escollect@.service /etc/systemd/system/ && systemctl enable --now escollect@<source>`.

There is no container image yet.

## Documentation

- [Configuration](docs/configuration.md): the store and the collector, values refused at start, upgrading.
- [Keys and retention](docs/keys.md): month keys, their backup and the roots mirror, destruction.
- [Copy, restore and the witness](docs/copy-and-witness.md): the remote copy, `restore`, the witness of the chain heads.
- [Bundles over a window of time](docs/bundles.md): everything received in a window, for one source or for all, and the collector's promise.
- [Gateway journals (Pipelock)](docs/pipelock.md): the flight recorder of an AI agent gateway, checked at intake.
- [Monitoring](docs/monitoring.md): what to alert on.
- [Known limitations](docs/limitations.md), [How it was tested](docs/testing.md), [release notes](docs/releases/).

## What is proven, and what is not

Proven offline:

- these exact bytes were received from this source;
- they have not been altered since;
- they entered the chain between the two time-stamps T1 and T2;
- with the collector's promise (`esverify -promise`): the store signed for this very record at intake, and no TSA time-stamp taken more than a minute after its receive time lies before the record in the chain;
- with the record key: the body as received (`esverify -body FILE` writes it out byte for byte, so the original log can be rebuilt from the store); the key is bound to the record's digest, so the store cannot show two auditors two different bodies;
- for gateway journals: the body is the gateway's own entry, and a checkpoint signed by the gateway covers it — when that signature was checked by the store with the pinned `gateway_key` or by you with `-gateway-key`. A gateway record whose bundle lacks the gateway part does not verify;
- with `-heads DIR`: the chain in the bundle agrees with every head a witness holds for that part of the chain; a second version of the chain elsewhere is named in the report (see [Witness of the chain heads](docs/copy-and-witness.md#witness-of-the-chain-heads));
- with a bundle over a window of time (`evidencestore proof -source S -from FROM -to TO`, or `-window` for every source): every record the store put into its chain between two TSA time-stamps is in the bundle, so a record received in the window cannot be kept from the auditor unless the store holds it back past the window, and then the deadline the store promised the collector for it is missed and `esverify -promise` shows it (see [Bundles over a window of time](docs/bundles.md)). The window is by the store's receive time, which the collector checks against its own clock to within a minute, and that clock may run up to a minute ahead: this holds for records the collector delivered more than two minutes before the window ends.

T2 is required: a bundle without a time-stamp after the record only carries the store's own signature, and whoever holds `sign.key` can make up a record with any date. `esverify` rejects such a bundle unless told `-allow-no-tsa`. The verdict is printed first and last, and control characters in the body are escaped, so a body cannot paint a false verdict on the auditor's screen.

Not proven:

- that the content is true: a lying source is recorded faithfully;
- anything before the record reached the store;
- anything about records the source never wrote;
- from a single-record bundle, that you were given every record: it proves that one record only. A bundle over a window of time proves the whole window, by the store's receive time, not by the time written in the lines;
- from a one-source bundle, that the source tails are true: they are the store's own statements, written when it took the time-stamps, and an understated one shows in a window bundle or in the hidden record's own bundle;
- that a bundle over a window of time was built from the chain as it was then: a rewrite after the lower time-stamp needs fresh time-stamps after it. A T2 more than an hour after the window is a sign of that (the store takes a time-stamp at least once an hour); a rewrite made sooner is caught only by a witness, with `-heads` and the check of when the witness received the head (see [Witness of the chain heads](docs/copy-and-witness.md#witness-of-the-chain-heads)).

Root on the store host can delete or rewrite the store's files, and whoever holds `sign.key` can sign a second version of the chain. That leaves traces: a rewritten chain gets only fresh time-stamps, the collectors hold signed promises for the original records (`esverify -promise` shows a replaced one), and a witness or a remote copy kept out of that administrator's reach still holds the original signed heads. The traces help only someone who checks them: `esverify -heads` compares a bundle with a witness's heads, nothing compares the collectors' promises by itself, and nothing can prevent the rewrite. Keep the store, its remote copy and the sources under different administrators where you can. With one administrator for everything, only the time-stamps and a witness that administrator does not control stand against them. The pilot cryptography (AES-256-GCM from the Go standard library, root keys in files) is not certified. The design keeps a plug-in point for an HSM.

## How it was tested

The test gate with the race detector runs on every push. 578 bugs were injected one at a time, and every one of them makes a test fail. Randomized simulations of crashes, clocks, the collector and a dishonest store owner ran thousands of scenarios each; on the code of v0.3.0 none failed. The store ran a night on real logs and a live Pipelock, and the witness and the copy were tried on S3 with Object Lock. Numbers, dates and commands: [docs/testing.md](docs/testing.md). Every finding of the code review, how it was reproduced and how it was fixed: [docs/dev/FINDINGS.md](docs/dev/FINDINGS.md), in Russian.

## Known limitations

Each with its cause, in [docs/limitations.md](docs/limitations.md): a file the collector never saw, a file closed after a minute of quiet, long lines, `copytruncate` rotation, the collector epoch is not a secret, gateway receipts inside entries, a gap event lost in a crash, an unreachable key backup at restart, approvals recorded but not enforced, bulk proof export, a stalled `keys.backup_dir`, receive times shifted by up to two minutes, a held-back record shown only by the collector's promise, the heartbeat of a stopped collector, indexes in memory, the witness check by number, the witness queue in memory, the witness following the copy, file-only input, failure paths checked only by reading.

## Development

GitHub Actions runs the same gate on every push to master and every pull request (`.github/workflows/ci.yml`). A `v*` tag also builds the release binaries with `scripts/release.sh`, attests where they were built and publishes the release with notes from `docs/releases/`.

```sh
go build ./... && go vet ./... && go test -race ./...
scripts/release.sh dist               # release binaries and SHA256SUMS
ES_BIN=/usr/local/bin scripts/demo.sh # the demo on installed binaries instead of a fresh build
python3 scripts/mutate.py keyring     # mutation testing: every injected bug must fail a test
                                      # sets: keyring, evlog, tsa, store, edge, auditchain, gateway, config, ship
```

The simulations and how to replay a failing scenario: [docs/testing.md](docs/testing.md#simulations).

Code comments, commit messages and the notes in [`docs/dev/`](docs/dev/) are in Russian: a code map, the design decisions and open questions, and the log of every finding of the code review. Everything a user of the product sees is in English.

## License

Apache License 2.0, see [`LICENSE`](LICENSE).
