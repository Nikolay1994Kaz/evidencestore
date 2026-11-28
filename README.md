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

<p align="center"><b>Logs that cannot be cleaned up: every line kept on another machine, with a proof anyone can check offline.</b></p>

Whoever controls a machine controls its log: an intruder deletes their lines from `auth.log`, an administrator or an AI agent edits away what it did. evidencestore keeps every line where they cannot reach it, and for any line gives a proof bundle that `esverify` checks offline, without trusting the store.

```sh
docker run --rm ghcr.io/nikolay1994kaz/evidencestore
```

About a second once the image is pulled: inside the container a collector sends three lines of `auth.log` to a store, an intruder deletes one of them from the file, and the store gives it back with a proof. What it prints, abridged:

```
== an intruder removes the line with their address from auth.log
== the store gives record 2 as a proof bundle, and esverify checks it offline
VERIFIED
  ✔ the links are chained by hash with no gaps — 5 links
  ✔ the head is signed with the store key — head 8
  ✔ a TSA time-stamp over the chain after the record (not later than T2)
Body:
Nov 24 09:14:37 web-1 sshd[840]: Accepted password for root from 203.0.113.7 port 40112

== one byte of the bundle changed: esverify refuses it
  ✘ the chain leaf describes this very record — the digest in the leaf does not match the record bytes
NOT VERIFIED
```

**[Quick start](docs/quick-start.md)** · **[Install](#install)** · **[What is proven](#what-is-proven-and-what-is-not)** · **[How it works](docs/how-it-works.md)** · **[Releases](https://github.com/Nikolay1994Kaz/evidencestore/releases)**

## Why

A log is evidence only while nobody who could have done the thing can edit it. On an ordinary server that is never true: root can rewrite `auth.log`, the administrator of the log server can rewrite its copy, and nobody outside can tell. evidencestore is for the moments when the log has to stand up against the people who had access:

- **After a break-in.** The intruder with root cleaned `auth.log` and the shell history. Every line was already in the store before they deleted it, and the time-stamps show when it arrived.
- **Administrators and contractors with full rights.** Someone with root edits the log to hide a mistake, or worse. The store sits on another machine, and witnesses catch even its own administrator rewriting history.
- **AI agents with access to your systems.** The gateway between the agent and your tools records every step out of the agent's reach ([Gateway receipts](docs/receipts.md)); on PostgreSQL, an agent's transaction can be undone from what the store holds ([PostgreSQL](docs/postgres.md)).
- **An audit or a dispute.** Hand the auditor or the other side a bundle for one line or a whole day. They check it offline with an open-source tool, without access to your systems and without trusting you.
- **Data you must delete.** After the retention period, destroy a month's key: the lines are gone from every copy, while the proof that they existed and never changed stays.

**Why not the SIEM or a log server?** They keep a copy, but whoever runs them can change it, and nothing in that copy proves to an outsider that it is complete and unchanged. evidencestore sits next to them: it takes the same stream and adds the proof.

## Features

- **Deleted lines come back.** The store keeps every line byte for byte on another machine, and a verified bundle gives it back exactly as the source sent it.
- **Proof, not trust.** One changed byte fails the check. The auditor needs the bundle, the store's public key and the root of the time-stamp authority, and no access to the store.
- **Nothing left out.** A bundle over a window of time proves that it holds every line the store received in that window ([Bundles](docs/bundles.md)).
- **The store's own administrator is checked too.** Signed chain heads go to witnesses out of that administrator's reach, and a rewritten history contradicts what they hold ([Witnesses](docs/copy-and-witness.md)).
- **Time from a third party.** RFC 3161 time-stamps from before and after every line, from any service: DigiCert, the NCA of Kazakhstan.
- **Forgetting on schedule.** Destroying a month's key makes that month's lines unreadable in every copy, while the proofs that they existed stay valid ([Keys and retention](docs/keys.md)).
- **Undo for an AI agent on PostgreSQL.** The agent works through an MCP server with limits; the collector reads the database's own log, keeps the agent's transactions whole, and an operator undoes one in two commands ([PostgreSQL](docs/postgres.md)).
- **Any line-based log.** System and application logs, a copy of the SIEM stream, the journal of an AI agent gateway such as [Pipelock](docs/pipelock.md), a PostgreSQL database by logical replication.

## Install

In Docker, on the store's host:

```sh
curl -fsSLO https://raw.githubusercontent.com/Nikolay1994Kaz/evidencestore/v0.7.2/deploy/docker/store/compose.yaml
ES_HOST=logs.example.com docker compose up -d
docker compose exec -T store add-collector web1 > web1.tgz
```

Then on each host with a log, with its bundle copied there: `tar -xzf web1.tgz && cd web1 && docker compose up -d`. The details: [In Docker](docs/install.md#in-docker).

- **On hosts with systemd**: [Installing on hosts](docs/install.md).
- **Binaries**: [Releases](https://github.com/Nikolay1994Kaz/evidencestore/releases), for Linux (amd64, arm64), with `esverify` also for macOS and Windows. Check them with `sha256sum -c SHA256SUMS --ignore-missing` and `gh attestation verify FILE --repo Nikolay1994Kaz/evidencestore`.
- **With Go** 1.25.4 or newer: `go install github.com/Nikolay1994Kaz/evidencestore/cmd/...@latest`.

## Run it yourself

The store on a log of your own, on one machine and without Docker, from `evidencestore dev-setup` to `VERIFIED`: [Quick start, step 2](docs/quick-start.md#step-2-the-store-on-a-log-of-your-own).

## What is proven, and what is not

| Who could cheat | What shows it | What the auditor brings |
|---|---|---|
| Someone on the source host edits or deletes log lines | the store holds every line as it received it, byte for byte, and TSA time-stamps from before and after bound when it entered the chain | the bundle, the store key, the TSA root |
| Someone changes a record inside the store | the record no longer matches its leaf, its Merkle path or the signed head | the same |
| The store leaves a record out of its answer | a bundle over a window of time holds every record the store put into its chain in that window; a record held back past the window misses the deadline the store promised the collector | `-from` and `-to`, the collector's promise with `-promise` |
| The store's administrator rewrites the chain and signs it again | the new chain has only fresh time-stamps and contradicts the heads that witnesses and collectors hold | `-witness-key` or `-heads` |
| The TSA's key is stolen and its certificate revoked | a second TSA or a witness shows that the time-stamp existed before the revocation | `-tsa-crl`, the root of the second TSA or `-witness-key` |
| The operator hands the auditor a store key that is not the organization's | a seal of the organization's X.509 certificate on the store key | `-seal-trust` and `-seal-subject` |

Not proven:

- that the content is true: a lying source is recorded faithfully;
- anything before a line reached the store, or about lines the source never wrote;
- from a bundle for a single line, that you were given every line;
- by the store alone, that it was not rewritten: root on its host can do that, and only the traces it leaves against time-stamps, collectors and witnesses show it.

Every claim with its conditions, and the exit codes of `esverify`: [docs/what-is-proven.md](docs/what-is-proven.md).

## How it was tested

The test gate with the race detector and the Docker installation run on every push; 650 injected bugs each made a test fail on the code of v0.4.0, a set since grown to 1,322; randomized simulations of crashes, clocks, the collector and a dishonest store owner found no failure. Numbers, dates and commands: [docs/testing.md](docs/testing.md); every finding of the code review: [docs/dev/FINDINGS.md](docs/dev/FINDINGS.md), in Russian.

## Known limitations

About thirty-five, each with its cause: [docs/limitations.md](docs/limitations.md). Before a pilot: what the store holds of an AI agent is only what the gateway wrote, so the gateway's key and its receipts must be out of the agent's reach ([the trust boundary](docs/postgres.md#the-trust-boundary)); the collector reads files and PostgreSQL only; the two approvals of a key destruction are recorded but not enforced; indexes are kept in memory; the cryptography is not certified.

## Documentation

- [Quick start](docs/quick-start.md) · [How it works](docs/how-it-works.md) · [What is proven](docs/what-is-proven.md)
- [Installing](docs/install.md) (in Docker, on hosts) · [Configuration](docs/configuration.md) · [Monitoring](docs/monitoring.md)
- [Keys and retention](docs/keys.md) · [Copy, restore and the witness](docs/copy-and-witness.md) · [Bundles over a window of time](docs/bundles.md)
- [Gateway receipts](docs/receipts.md) · [Pipelock](docs/pipelock.md) · [Purchases made by AI agents](docs/purchases.md) · [PostgreSQL and an MCP server](docs/postgres.md)
- [Known limitations](docs/limitations.md) · [How it was tested](docs/testing.md) · [Development](docs/development.md) · [Release notes](docs/releases/)

## License

Apache License 2.0, see [`LICENSE`](LICENSE).
