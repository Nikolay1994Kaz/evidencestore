# Quick start

[← README](../README.md)

## Step 1. Try it in Docker

With nothing but Docker:

```sh
docker run --rm ghcr.io/nikolay1994kaz/evidencestore
```

Inside the container a collector sends three lines of a practice `auth.log` to a store, an intruder deletes the line with their address from the file, and the store gives that line back as a proof bundle. `esverify` checks the bundle offline and prints `VERIFIED` with the deleted line as its body; the same bundle with one byte changed gives `NOT VERIFIED`. It takes about a second, and nothing leaves the container.

## Step 2. The store on a log of your own

The same by hand, on one Linux machine and a log of your own. You need `evidencestore`, `escollect` and `esverify` on your `PATH`: from a release ([Install](../README.md#install)), or `go install ./cmd/...` in the clone.

`dev-setup` prepares a new or empty directory for a try: demo certificates, both configs with the store's public key pinned in the collector's, and `init`. Time-stamps come from a demo TSA built into the store, so nothing leaves the machine. `-log FILE` points the collector at a log of your own, and `-port` moves the store off port 8443:

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

Start the store in a second terminal and leave it running. Its warnings that `keys.backup_dir` is not set and, two minutes later, that the collector of `app` is lost are fine for a try:

```sh
cd ~/es-try && evidencestore serve -config store.json
```

Back in the first terminal, write a line into `app.log` and send it (with `-log`, skip the `echo`: record 1 is the first line of your log). With `-once` the collector sends what the file holds and exits; as a service it follows the file:

```sh
cd ~/es-try
echo "$(date -Is) user=alice action=login" >> app.log
escollect -config collector.json -once
```

Now a proof of record 1, checked the way an auditor does it. A bundle verifies only once a time-stamp lies over the chain after its record: the store takes one every 10 minutes, and `stamp` takes one now. `-dek` adds the key of this one record, so `esverify` also prints the body:

```sh
evidencestore stamp -config store.json
evidencestore proof -config store.json -source app -seq 1 -dek -out proof.json
evidencestore tsa-root -config store.json -out tsa-root.crt
esverify -proof proof.json -store-key store.pub -tsa-trust tsa-root.crt
```

`esverify` ends with `VERIFIED` (exit code 0), and `evidencestore status -config store.json` shows what the store holds. A real installation also needs certificates from your own PKI, a real TSA, key backups on other disks and the store on another machine than its sources: [Installing on hosts](install.md). To start over, stop the store and remove `~/es-try`.

## Step 3. The store and its collectors on your hosts

The store on its own host and a collector on each host with a log, in Docker: [In Docker](install.md#in-docker). With systemd: [Installing on hosts](install.md).

## More demos

The demos run on Linux with bash, python3 and Go 1.25.4 or newer (the Pipelock one also needs curl, the purchase one openssl, the PostgreSQL one PostgreSQL 14 or newer). With binaries from a release, `ES_BIN=/usr/local/bin` runs them without Go ([Install](../README.md#install)).

```sh
git clone https://github.com/Nikolay1994Kaz/evidencestore && cd evidencestore
scripts/demo.sh                    # builds everything, runs a full scenario offline
DEMO_TSA=digicert scripts/demo.sh  # same, time-stamps from the public DigiCert TSA
DEMO_TSA=nca scripts/demo.sh       # same, time-stamps from the NCA of Kazakhstan
scripts/demo-intruder.sh           # an intruder cleans auth.log; every deleted line comes back from the store
PIPELOCK_BIN=$(which pipelock) scripts/demo-pipelock.sh  # a real Pipelock gateway (docs/pipelock.md)
scripts/demo-purchase.sh           # an AI agent makes three purchases, signed by its platform; one comes out as a bundle, the others stay closed
experiments/pg-undo/run.sh         # an AI agent on PostgreSQL through the MCP server, a person's edit, alerts, limits and an undo
```

`scripts/demo.sh` runs these steps:

1. Issues demo certificates and starts the store.
2. Ships three log lines through the collector.
3. Verifies a proof with `esverify`.
4. Shows that a one-byte forgery is caught.
5. Destroys the month key (a single approval is refused) and shows that the proof still verifies while the body is gone.

`scripts/demo-intruder.sh` plays an intrusion on a web server: an intruder logs in as root and removes every line with their address from a practice `auth.log` (inside the demo directory; nothing on the host is touched). The script pulls the records of that source out of the store and verifies each one offline: the four deleted lines come back byte for byte, and the time-stamps show they were in the store before the file was rewritten. Last, it asks for the whole session of web-1 as one bundle, which would not verify with any line left out (this waits two minutes for the time-stamps that close the window).

PostgreSQL with an MCP server for an AI agent, in Docker on one machine: [Try it in Docker](postgres.md#try-it-in-docker).
