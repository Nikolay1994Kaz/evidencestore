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

One service per source. Create the user (`useradd --system --no-create-home --shell /usr/sbin/nologin escollect`); the unit adds it to group `adm`, which reads `/var/log` on Debian and Ubuntu. For each source put its certificate and `/etc/escollect/<source>.json` (from [`configs/collector.example.json`](../configs/collector.example.json), with `spool_dir` set to `/var/lib/escollect/<source>`), then `cp configs/systemd/escollect@.service /etc/systemd/system/ && systemctl enable --now escollect@<source>`.

## A witness host

It is run by someone other than the store's administrator: `useradd --system --home-dir /var/lib/eswitness --shell /usr/sbin/nologin eswitness`, `install -d -o eswitness -g eswitness -m 0700 /var/lib/eswitness`, the config in `/etc/eswitness/eswitness.json` from [`configs/eswitness.example.json`](../configs/eswitness.example.json) with each store's public key, then `sudo -u eswitness eswitness init -config /etc/eswitness/eswitness.json`: it prints the verifier key for the store's `witness.cosigners` and for auditors. Then `cp configs/systemd/eswitness.service /etc/systemd/system/ && systemctl enable --now eswitness` ([Cosigning witnesses](copy-and-witness.md#cosigning-witnesses-c2sp)).

There is no container image yet.
