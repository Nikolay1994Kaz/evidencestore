# Installing on hosts

[← README](../README.md)

The store, the collector and the witness run on Linux (amd64, arm64) as systemd services. Where to get the binaries and how to check them: [README, Install](../README.md#install). A first try on one machine, without any of this: [README, Run it yourself](../README.md#run-it-yourself).

## A store host

With the unit file from [`configs/systemd/`](../configs/systemd):

1. Create the service user and its directories: `useradd --system --home-dir /var/lib/evidencestore --shell /usr/sbin/nologin evidencestore`, then `install -d -o evidencestore -g evidencestore -m 0700 /var/lib/evidencestore /var/lib/evidencestore-roots`.
2. Put `keys.backup_dir` and `keys.roots_mirror_dir` on other disks, better on another machine, and create those directories for the same user before `init`, with the disks mounted. Use a directory on the mounted disk, not the mount point itself: an empty mount point is there even when nothing is mounted on it. Neither `init` nor the store creates these directories, since a missing one looks like an unmounted disk: `init` refuses to run, and the store reports every copy there as failed until the directory is back (`evidencestore_keyring_backup_pending` and `evidencestore_sign_key_backup_pending` for `keys.backup_dir`, `evidencestore_keyring_roots_unreachable` for `keys.roots_mirror_dir`).
3. Put the config into `/etc/evidencestore/evidencestore.json`, starting from [`configs/evidencestore.example.json`](../configs/evidencestore.example.json). Relative paths in it resolve against the config's directory, so copy `configs/tsa/` next to it. Add the server certificate and key (readable by the service user) and the CA that issues collector certificates: your own PKI (`dev-pki` is for demos).
4. `sudo -u evidencestore evidencestore init -config /etc/evidencestore/evidencestore.json`. It prints the store's public key: collectors pin it as `store_key`, auditors pass it to `esverify -store-key`.
5. `cp configs/systemd/evidencestore.service /etc/systemd/system/ && systemctl enable --now evidencestore`. The unit sees the file system read-only apart from its own directories (`ProtectSystem=strict`): a `file://` `replica.url` or `witness.url` has to be added to `ReadWritePaths`. Operator commands talk to the admin socket, which belongs to the service user: `sudo -u evidencestore evidencestore status -config /etc/evidencestore/evidencestore.json`.

## A collector host

One service per source, or one for several with a `sources` list ([Configuration](configuration.md#collector)). Create the user (`useradd --system --no-create-home --shell /usr/sbin/nologin escollect`); the unit adds it to group `adm`, which reads `/var/log` on Debian and Ubuntu. For each source put its certificate and `/etc/escollect/<source>.json` (from [`configs/collector.example.json`](../configs/collector.example.json), with `spool_dir` set to `/var/lib/escollect/<source>`), then `cp configs/systemd/escollect@.service /etc/systemd/system/ && systemctl enable --now escollect@<source>`.

## A witness host

It is run by someone other than the store's administrator: `useradd --system --home-dir /var/lib/eswitness --shell /usr/sbin/nologin eswitness`, `install -d -o eswitness -g eswitness -m 0700 /var/lib/eswitness`, the config in `/etc/eswitness/eswitness.json` from [`configs/eswitness.example.json`](../configs/eswitness.example.json) with each store's public key, then `sudo -u eswitness eswitness init -config /etc/eswitness/eswitness.json`: it prints the verifier key for the store's `witness.cosigners` and for auditors. Then `cp configs/systemd/eswitness.service /etc/systemd/system/ && systemctl enable --now eswitness` ([Cosigning witnesses](copy-and-witness.md#cosigning-witnesses-c2sp)).

## In Docker

The store on one host and a collector on each host whose log it keeps, from the image `ghcr.io/nikolay1994kaz/evidencestore` (published from v0.7.0). The store makes a CA for its collectors and issues each one a bundle with its certificate, key, config and compose file. Docker and Docker Compose on every host, nothing else.

On the store's host:

```sh
curl -fsSLO https://raw.githubusercontent.com/Nikolay1994Kaz/evidencestore/v0.7.2/deploy/docker/store/compose.yaml
ES_HOST=logs.example.com docker compose up -d
docker compose exec -T store add-collector web1 > web1.tgz
```

Copy `web1.tgz` to web1, and there:

```sh
tar -xzf web1.tgz && cd web1 && docker compose up -d
```

- `ES_HOST` is the name or address the collectors reach the store by; several, comma-separated, all go into the server certificate, and the first one into the collectors' configs. They need port 8443. It is read at the first start only.
- Time-stamps, also chosen at the first start: DigiCert by default, `ES_TSA=nca` for the NCA of Kazakhstan, `ES_TSA=local` for the demo TSA built into the store (a trial without internet).
- Next to `compose.yaml`: `config/` (`evidencestore.json`, the server certificate, `store.pub`, the collectors' CA with its key in `config/ca/`), `data/`, `roots/`, `backup/` and `roots-mirror/`. Put the last two on other disks, better on other machines, with `ES_BACKUP_DIR` and `ES_ROOTS_MIRROR_DIR` set before the first start ([Keys and retention](keys.md)). Do not copy the whole directory somewhere: `roots/` must have no copy apart from its mirror, or a destroyed key can still be opened.
- `add-collector NAME` issues the collector's certificate under the store's CA, pins its fingerprint (`cert_sha256`) in the config, writes the bundle to standard output (`ca.crt`, the certificate and its key, `collector.json`, `compose.yaml`) and restarts the store's `serve` inside the container so it accepts the new source. The key exists only in the bundle. The collector reads `/var/log/auth.log`; another log: `-file PATH` (on Red Hat and its kin, `/var/log/secure`), and its directory is mounted read-only. Also `-content-type` and `-retention-months`; `-T` keeps Docker from giving the command a terminal, which would break the archive.
- The collector keeps its spool in the volume `spool`, with the lines the store has not signed for yet and the installation's epoch. Removing it (`docker compose down -v`) makes a new installation, which the store refuses until the operator runs `evidencestore sources bind` ([Configuration](configuration.md#collector)).
- Both containers run as root without capabilities and with a read-only root file system; the collector gets one capability, `DAC_READ_SEARCH`, to read the log and its key. On the store's host the files under `config/`, `data/` and the rest belong to root.
- Operator commands go through the container and find the config themselves: `docker compose exec store evidencestore status`, likewise `proof`, `stamp` and `keys`. For an auditor: `docker compose exec -T store evidencestore proof -source web1 -seq 1 -dek > bundle.json`, checked with `esverify -proof bundle.json -store-key "$(cat config/store.pub)" -tsa-trust` and the two files under `config/tsa/digicert/`.
- The collectors' certificates are valid for two years and the CA for ten; no command renews them yet. A collector gets one source; several logs on one host are several bundles.
- `scripts/docker-check.sh` runs all of this on one Docker host, the collector as a separate project reaching the store by the host's address, through to `esverify`; CI runs it on every push and on the published image of every release.

A PostgreSQL source and the MCP server for an agent: [PostgreSQL and an MCP server](postgres.md). A trial of all of it in Docker on one machine: [`compose.yaml`](../compose.yaml) ([Try it in Docker](postgres.md#try-it-in-docker)).
