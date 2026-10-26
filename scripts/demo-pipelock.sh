#!/usr/bin/env bash
# Демо с настоящим гейтвеем: Pipelock → escollect → evidencestore → esverify.
#
#   1. Pipelock с бортовым журналом и подписанными контрольными точками;
#      «агент» просит то, что Pipelock блокирует на месте (метаданные облака,
#      ключ AWS в URL, loopback), поэтому наружу не уходит ни один запрос;
#   2. сборщик читает шарды журнала по маске, хранилище при приёме проверяет
#      хэш каждой записи, сцепку и подписи контрольных точек ключом гейтвея;
#   3. пакет доказательств по записи журнала проверяется офлайн своим ключом
#      гейтвея: тело — та самая запись, её накрывает подписанная точка;
#   4. запись, изменённая после записи на диск гейтвея, ловится при приёме.
#
#   PIPELOCK_BIN=/path/to/pipelock scripts/demo-pipelock.sh
#   (go install github.com/luckyPipewrench/pipelock/cmd/pipelock@v1.5.1-0.20261002230022-3e868ac5d5b6
#    — коммит тега v3.6.0: путь модуля Pipelock без /v3, и @v3.6.0 Go не берёт)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PIPELOCK_BIN:?PIPELOCK_BIN must point to a pipelock binary (v3.6.0: go install github.com/luckyPipewrench/pipelock/cmd/pipelock@v1.5.1-0.20261002230022-3e868ac5d5b6)}"
WORK=${WORK:-$(mktemp -d)}
BIN=${ES_BIN:-$WORK/bin} # ES_BIN — готовые бинарники (например, из релиза) вместо сборки
PORT=${PORT:-18444}
mkdir -p "$BIN"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

step "build"
if [ -n "${ES_BIN:-}" ]; then "$BIN/evidencestore" version; else go build -o "$BIN/" ./cmd/...; fi
"$PIPELOCK_BIN" version | head -1

step "Pipelock: the journal signing key"
# Pipelock живёт в своём каталоге: настройки пользователя не трогаются.
PL=$WORK/pipelock
mkdir -p "$PL"/{home,keys,recorder}
chmod 700 "$PL/keys"
export HOME=$PL/home XDG_CONFIG_HOME=$PL/home/.config XDG_DATA_HOME=$PL/home/.local/share \
  XDG_STATE_HOME=$PL/home/.local/state XDG_CACHE_HOME=$PL/home/.cache PIPELOCK_HOME=$PL/home/.pipelock
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy SENTRY_DSN || true
"$PIPELOCK_BIN" signing key generate --purpose receipt-signing --out "$PL/keys/signing.json" >/dev/null
"$PIPELOCK_BIN" signing pubkey --key-file "$PL/keys/signing.json" --out "$PL/keys/signing.pub" >/dev/null
GW_KEY=$(tr -d '[:space:]' <"$PL/keys/signing.pub")
echo "gateway public key: $GW_KEY"

step "store: source agent-gw of type pipelock/recorder with the pinned gateway key"
"$BIN/evidencestore" dev-pki -out "$WORK/pki" -source agent-gw >/dev/null
cat >"$WORK/evidencestore.json" <<EOF
{
  "data_dir": "data",
  "roots_dir": "roots",
  "listen": "127.0.0.1:$PORT",
  "tls": {"cert": "pki/server.crt", "key": "pki/server.key", "client_ca": "pki/ca.crt"},
  "chain": {"tick": "200ms", "promise_mmd": "10s"},
  "tsa": {"url": "local", "every": "1h"},
  "demo": true,
  "keys": {"min_wait": "1s", "backup_dir": "keyring-backup", "roots_mirror_dir": "roots-mirror"},
  "sources": [
    {"name": "agent-gw", "content_type": "pipelock/recorder", "gateway_key": "$GW_KEY", "retention_months": 36}
  ]
}
EOF
CFG=$WORK/evidencestore.json
mkdir -p "$WORK/keyring-backup" "$WORK/roots-mirror" # в работе — другие диски; init их не создаёт
STORE_KEY=$("$BIN/evidencestore" init -config "$CFG" | tail -1)
"$BIN/evidencestore" serve -config "$CFG" 2>"$WORK/server.log" &
SERVER=$!
PIPELOCK=
trap 'kill $SERVER ${PIPELOCK:+$PIPELOCK} 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -S "$WORK/data/admin.sock" ] && break; sleep 0.1; done
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null

step "Pipelock at work: the agent asks for forbidden things, the gateway blocks them and writes its journal"
PL_PORT=$(free_port)
cat >"$PL/pipelock.yaml" <<EOF
version: 1
mode: balanced
fetch_proxy:
  listen: "127.0.0.1:$PL_PORT"
  timeout_seconds: 10
sentry:
  enabled: false
flight_recorder:
  enabled: true
  dir: "$PL/recorder"
  signing_key_path: "$PL/keys/signing.json"
  redact: true
  sign_checkpoints: true
  checkpoint_interval: 3
  max_entries_per_file: 6
  completeness:
    heartbeat_interval: "2s"
EOF
"$PIPELOCK_BIN" run --config "$PL/pipelock.yaml" >"$PL/pipelock.log" 2>&1 &
PIPELOCK=$!
for _ in $(seq 100); do curl -sf --max-time 1 "http://127.0.0.1:$PL_PORT/health" >/dev/null 2>&1 && break; sleep 0.1; done
for url in "http://169.254.169.254/latest/meta-data/" "https://example.com/?aws=AKIAZ7Q3XR5TLMNP2WVB" \
  "http://127.0.0.1:1/private" "http://169.254.169.254/latest/user-data"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -G --data-urlencode "url=$url" "http://127.0.0.1:$PL_PORT/fetch" || true)
  echo "agent: $url → HTTP $code"
done
sleep 3 # пара сердцебиений
kill -TERM "$PIPELOCK"
wait "$PIPELOCK" 2>/dev/null || true
PIPELOCK=
ls "$PL/recorder"/evidence-*.jsonl | sed "s|$PL/recorder/|  shard: |"

step "the collector delivers every shard under the mask, in order"
cat >"$WORK/collector.json" <<EOF
{
  "server": "https://127.0.0.1:$PORT",
  "ca": "pki/ca.crt", "cert": "pki/agent-gw.crt", "key": "pki/agent-gw.key",
  "store_key": "$STORE_KEY",
  "spool_dir": "spool", "glob": "pipelock/recorder/evidence-*.jsonl", "from_start": true
}
EOF
"$BIN/escollect" -config "$WORK/collector.json" -once
TOTAL=$(cat "$PL/recorder"/evidence-*.jsonl | wc -l)
echo "journal lines: $TOTAL"

step "proof bundle for journal record #3 with its record key"
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null
"$BIN/evidencestore" proof -config "$CFG" -source agent-gw -seq 3 -dek -out "$WORK/proof-3.json"
"$BIN/evidencestore" tsa-root -config "$CFG" -out "$WORK/tsa-root.crt"

step "auditor: esverify offline with their own copy of the gateway key"
"$BIN/esverify" -proof "$WORK/proof-3.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -gateway-key "$GW_KEY" | grep -v '^  "'

step "an entry changed after the gateway wrote it: the store catches it at intake"
python3 - "$PL/recorder" "$WORK/forged.jsonl" <<'PY'
import glob, json, sys
first = sorted(glob.glob(sys.argv[1] + "/evidence-*-0.jsonl"))[0]
lines = open(first).read().splitlines()
e = json.loads(lines[1])
lines[1] = lines[1].replace(json.dumps(e["summary"])[1:-1], (json.dumps(e["summary"])[1:-1]).upper(), 1)
open(sys.argv[2], "w").write(lines[1] + "\n")
PY
cat >"$WORK/collector-forged.json" <<EOF
{
  "server": "https://127.0.0.1:$PORT",
  "ca": "pki/ca.crt", "cert": "pki/agent-gw.crt", "key": "pki/agent-gw.key",
  "store_key": "$STORE_KEY",
  "spool_dir": "spool-forged", "file": "forged.jsonl", "from_start": true
}
EOF
# Тот же сборщик (та же установка — его эпоха), только файл другой:
# хранилище закрепило источник за установкой из шага выше, чужую не пустит.
mkdir -p "$WORK/spool-forged"
cp "$WORK/spool/epoch.json" "$WORK/spool-forged/epoch.json"
"$BIN/escollect" -config "$WORK/collector-forged.json" -once
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null
FORGED=$((TOTAL + 1))
"$BIN/evidencestore" proof -config "$CFG" -source agent-gw -seq "$FORGED" -dek -out "$WORK/proof-forged.json"
if "$BIN/esverify" -proof "$WORK/proof-forged.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -gateway-key "$GW_KEY" >"$WORK/forged-report.txt"; then
  echo "ERROR: the altered entry passed verification"; exit 1
fi
grep -E "✘|chaining|hash" "$WORK/forged-report.txt" | head -4
echo ">>> alteration caught: the entry is kept as it came, and the intake verdict says what is wrong with it"

step "metrics"
grep -E '"(records|log_failure|orphan_roots)"' <("$BIN/evidencestore" status -config "$CFG") || true
echo
echo "work directory: $WORK"
