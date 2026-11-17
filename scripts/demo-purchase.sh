#!/usr/bin/env bash
# Демо «покупки ИИ-агента»: один агент покупает для трёх клиентов через один
# журнал, а спор — об одной покупке (docs/purchases.md).
#
#   1. хранилище «на своей машине», сборщик «у платформы агента»: агент дописывает
#      в журнал по строке JSON на каждый шаг покупки, в каждой строке — purchase_id;
#      у источника subject_field = purchase_id; мандат в строке подписан ключом
#      клиента (компактный JWS, ES256 — подписывает openssl);
#   2. три покупки вперемешку: p-1001 и p-1002 доходят до доставки, p-1003 клиент
#      отменяет;
#   3. спор о p-1002: пакет по субъекту — её шесть строк открыты, одиннадцать
#      строк двух других покупок закрыты; esverify проверяет пакет офлайн;
#   4. отчёт по покупке (scripts/purchase-report.py): мандат, агент, корзина,
#      уведомление, оплата, доставка и сверки строк между собой; подпись мандата
#      проверяется ключом клиента, и корзина сверяется с подписанными условиями;
#      с чужим ключом подпись не сходится;
#   5. подделки: байт в корзине и вынутое из пакета уведомление — оба пакета
#      проверку не проходят, отчёт по ним не печатается.
#
# Хранилище здесь ничего не знает о покупках: это пакет по субъекту (DECISIONS,
# п. 32) и соглашение о строках журнала. Подписи внутри строк оно не проверяет:
# мандат хранится байт в байт, а его подпись проверяет отчёт, вне хранилища.
# Кроме bash и python3 демо нужен openssl.
#
#   scripts/demo-purchase.sh
#   ES_BIN=/path/to/bin scripts/demo-purchase.sh # готовые бинарники вместо сборки
#   WORK=/tmp/es-purchase scripts/demo-purchase.sh
set -euo pipefail
cd "$(dirname "$0")/.."
REPORT=$(pwd)/scripts/purchase-report.py
WORK=${WORK:-$(mktemp -d)}
BIN=${ES_BIN:-$WORK/bin} # ES_BIN — готовые бинарники (например, из релиза) вместо сборки
PORT=${PORT:-18447}
mkdir -p "$BIN"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
command -v openssl >/dev/null || { echo "ERROR: this demo signs the mandates with openssl, and it is not installed"; exit 1; }

step "build"
if [ -n "${ES_BIN:-}" ]; then "$BIN/evidencestore" version; else go build -o "$BIN/" ./cmd/...; fi

step "the store on its own host, a collector at the agent platform (source shop-agent)"
"$BIN/evidencestore" dev-pki -out "$WORK/pki" -source shop-agent >/dev/null
cat >"$WORK/evidencestore.json" <<EOF
{
  "data_dir": "data",
  "roots_dir": "roots",
  "listen": "127.0.0.1:$PORT",
  "tls": {"cert": "pki/server.crt", "key": "pki/server.key", "client_ca": "pki/ca.crt"},
  "chain": {"tick": "200ms", "promise_mmd": "1m"},
  "tsa": {"url": "local", "every": "1h"},
  "demo": true,
  "keys": {"min_wait": "1s", "backup_dir": "keyring-backup", "roots_mirror_dir": "roots-mirror"},
  "sources": [
    {"name": "shop-agent", "content_type": "purchase-events", "subject_field": "purchase_id", "retention_months": 24}
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
"$BIN/evidencestore" tsa-root -config "$CFG" -out "$WORK/tsa-root.crt" >/dev/null 2>&1
TSA_TRUST=$WORK/tsa-root.crt

# Платформа агента — каталог стенда; сборщик работает всё время, как служба.
LOG=$WORK/agent/purchases.jsonl
mkdir -p "$(dirname "$LOG")"
: >"$LOG"
cat >"$WORK/collector.json" <<EOF
{
  "server": "https://127.0.0.1:$PORT",
  "ca": "pki/ca.crt", "cert": "pki/shop-agent.crt", "key": "pki/shop-agent.key",
  "store_key": "$STORE_KEY",
  "spool_dir": "spool", "file": "agent/purchases.jsonl", "from_start": true, "flush_every": "200ms"
}
EOF
"$BIN/escollect" -config "$WORK/collector.json" 2>"$WORK/collector.log" &
COLLECTOR=$!
echo "store: 127.0.0.1:$PORT; collector: following the agent's log purchases.jsonl; subject_field: purchase_id"

# Клиенты: у каждого свой ключ P-256 — им подписан мандат; открытый ключ — у проверяющего.
mkdir -p "$WORK/customers"
for c in c-7731 c-2204 c-9050; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/customers/$c.key" 2>/dev/null
  openssl ec -in "$WORK/customers/$c.key" -pubout -out "$WORK/customers/$c.pub" 2>/dev/null
done

# Агент: одна строка JSON на шаг покупки (docs/purchases.md, «What the agent writes»).
cat >"$WORK/agent.py" <<'PY'
import base64, json, subprocess, sys
from datetime import datetime, timedelta, timezone

pid, event, keys = sys.argv[1], sys.argv[2], sys.argv[3]


def sign(claims, key):
    """Мандат как компактный JWS с ES256 (RFC 7515): подписывает openssl ключом клиента."""
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "ES256", "kid": claims["customer"] + "-device-1"}, separators=(",", ":")).encode())
    body = b64(json.dumps(claims, ensure_ascii=False, separators=(",", ":")).encode())
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key], input=f"{head}.{body}".encode(), capture_output=True, check=True).stdout
    # DER SEQUENCE { INTEGER r, INTEGER s } → r ‖ s по 32 байта (RFC 7518, 3.4)
    r, rest = der[4:4 + der[3]], der[4 + der[3]:]
    s = rest[2:2 + rest[1]]
    return f"{head}.{body}." + b64(int.from_bytes(r, "big").to_bytes(32, "big") + int.from_bytes(s, "big").to_bytes(32, "big"))


now = datetime.now(timezone.utc)
ts = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
P = {
    "p-1001": dict(customer="c-7731", ask="coffee beans, 1 kg", cap=15000, merchants=["beans.example"], merchant="beans.example",
                   items=[dict(sku="BE-ETH-1000", name="Ethiopia Guji, 1 kg", qty=1, price=12400)]),
    "p-1002": dict(customer="c-2204", ask="running shoes, size 43", cap=60000, merchants=["sport.example", "run.example"], merchant="sport.example",
                   items=[dict(sku="RR5-43", name="Road Runner 5, size 43", qty=1, price=54990)]),
    "p-1003": dict(customer="c-9050", ask="wireless headphones", cap=40000, merchants=["audio.example"], merchant="audio.example",
                   items=[dict(sku="WH-700", name="WH-700 headphones", qty=1, price=38500)]),
    "p-1004": dict(customer="c-7731", ask="paper filters, 100 pcs", cap=3000, merchants=["beans.example"], merchant="beans.example",
                   items=[dict(sku="PF-100", name="Paper filters, 100 pcs", qty=1, price=1900)]),
}[pid]
total = sum(i["qty"] * i["price"] for i in P["items"])
e = {"purchase_id": pid, "event": event, "at": ts(now)}
if event == "mandate":
    # Клиент подписывает то же, что агент пишет в строку: покупку, себя, поручение и его рамки.
    e.update(customer=P["customer"], instruction=P["ask"],
             scope=dict(price_cap=P["cap"], currency="KZT", merchants=P["merchants"], expires=ts(now + timedelta(days=7))))
    e["credential"] = sign({k: e[k] for k in ("purchase_id", "customer", "instruction", "scope")}, f"{keys}/{P['customer']}.key")
elif event == "agent_verified":
    e.update(agent_id="agent.shop-assistant.example", key_id="k-2026-11", checked_by=P["merchant"], result="ok")
elif event == "cart":
    e.update(merchant=P["merchant"], items=P["items"], total=total, currency="KZT")
elif event == "notification":
    e.update(channel="push", cancel_until=ts(now + timedelta(minutes=30)))
elif event == "cancel":
    e.update(by="customer", channel="app")
elif event == "payment":
    e.update(amount=total, currency="KZT", method="network token", token_ref="tok-" + pid[2:], authentication="3DS: passed", network_ref="nr-" + pid[2:])
elif event == "delivery":
    e.update(carrier="post.example", tracking="TRK" + pid[2:] + "KZ", status="delivered")
print(json.dumps(e, ensure_ascii=False, separators=(",", ":")))
PY

# max_seq — последний номер источника, принятый хранилищем.
max_seq() {
  "$BIN/evidencestore" status -config "$CFG" |
    python3 -I -c 'import json,sys; print(next((s["max_seq"] for s in json.load(sys.stdin)["sources"] if s["name"]=="shop-agent"), 0))'
}
wait_seq() {
  for _ in $(seq 150); do [ "$(max_seq)" -ge "$1" ] && return 0; sleep 0.2; done
  echo "ERROR: the store did not get record $1 from shop-agent"
  exit 1
}
# steps "p-1001 mandate" "p-1002 cart" … — шаги агента подряд, по строке на шаг.
steps() { for s in "$@"; do python3 -I "$WORK/agent.py" $s "$WORK/customers" >>"$LOG"; done; }

# Начало окна для пакета в конце: больше чем через секунду после метки T1 —
# тогда нижняя метка окна она (DECISIONS, п. 27, 28). Первая строка — заметно
# позже начала окна: время приёма может отставать от часов хоста до секунды.
sleep 1.2
FROM=$(date -u +%FT%T.%NZ)
sleep 1.5

step "the agent buys for three customers at once: one log, the lines of three purchases interleaved"
steps "p-1001 mandate" "p-1002 mandate" "p-1001 agent_verified" "p-1003 mandate"
sleep 1
steps "p-1002 agent_verified" "p-1001 cart" "p-1002 cart" "p-1003 agent_verified"
sleep 1
steps "p-1001 notification" "p-1002 notification" "p-1003 cart" "p-1001 payment"
sleep 1
steps "p-1003 notification" "p-1002 payment" "p-1003 cancel" "p-1001 delivery" "p-1002 delivery"
wait_seq 17
python3 -I - "$LOG" <<'PY'
import json, sys
for n, line in enumerate(open(sys.argv[1]), 1):
    e = json.loads(line)
    print(f"{n:>3}  {e['purchase_id']}  {e['event']}")
PY
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # метка: все три покупки в цепи
sleep 1
TO=$(date -u +%FT%T.%NZ)

step "weeks later the customer of p-1002 disputes the charge; the platform asks the store for that purchase alone"
echo "window (receive time): $FROM – $TO"
echo "(a window is closed by a time-stamp taken more than two minutes after its end, and the bundle ends at the source"
echo " tails of the time-stamp after that one: two minutes pass, the agent goes on buying)"
sleep 135 # две минуты и запас
steps "p-1004 mandate"
wait_seq 18
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # метка больше чем через две минуты после окна — закрывающая
steps "p-1004 agent_verified"
wait_seq 19
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # её хвосты — верхний край пакета по источнику
"$BIN/evidencestore" proof -config "$CFG" -source shop-agent -subject p-1002 -from "$FROM" -to "$TO" -out "$WORK/p-1002.json"

step "the other side verifies the bundle offline: esverify, the store's pinned key, the TSA root"
"$BIN/esverify" -proof "$WORK/p-1002.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -bodies "$WORK/p-1002" |
  sed '/^What this bundle does not prove:/,$d' # вердикт, источник, субъект и проверки; заметки esverify — в docs/bundles.md
python3 -I - "$WORK/p-1002" <<'PY'
import json, os, sys
d = sys.argv[1]
ids = [json.load(open(os.path.join(d, f)))["purchase_id"] for f in os.listdir(d)]
if len(ids) != 6 or set(ids) != {"p-1002"}:
    sys.exit(f"ERROR: expected the 6 lines of p-1002 and nothing else, got {sorted(ids)}")
print("bodies written out: 6, every one a line of p-1002; the 11 lines of p-1001 and p-1003 came encrypted and without keys")
PY

step "the purchase as a report: printed only for a bundle esverify accepts; the mandate is checked with the customer's public key"
python3 -I "$REPORT" -proof "$WORK/p-1002.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -purchase p-1002 -esverify "$BIN/esverify" \
  -mandate-key "$WORK/customers/c-2204.pub"

step "the same report with another customer's key: the mandate's signature does not verify"
python3 -I "$REPORT" -proof "$WORK/p-1002.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -purchase p-1002 -esverify "$BIN/esverify" \
  -mandate-key "$WORK/customers/c-7731.pub" >"$WORK/report-other-key.txt"
grep -E 'signed mandate:|key you gave|comparisons disagree' "$WORK/report-other-key.txt"
grep -q 'does NOT verify' "$WORK/report-other-key.txt" || { echo "ERROR: the mandate verified under another customer's key"; exit 1; }

step "forgery 1: one byte of the cart is changed; forgery 2: the notification is taken out of the bundle"
python3 -I - "$WORK/p-1002.json" "$WORK/forged-cart.json" "$WORK/forged-dropped.json" <<'PY'
import base64, copy, json, struct, sys
b = json.load(open(sys.argv[1]))
# Номер записи — в заголовке улики: version(1) | seq(8) | …
seq = lambda r: struct.unpack(">Q", base64.b64decode(r["evidence"])[1:9])[0] if r.get("evidence") else None
f = copy.deepcopy(b)
for r in f["records"]:
    if seq(r) == 7:  # корзина p-1002
        ev = bytearray(base64.b64decode(r["evidence"]))
        ev[-20] ^= 0x01
        r["evidence"] = base64.b64encode(bytes(ev)).decode()
json.dump(f, open(sys.argv[2], "w"))
f = copy.deepcopy(b)
f["records"] = [r for r in f["records"] if seq(r) != 10]  # уведомление p-1002
json.dump(f, open(sys.argv[3], "w"))
PY
for f in forged-cart forged-dropped; do
  if python3 -I "$REPORT" -proof "$WORK/$f.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -purchase p-1002 -esverify "$BIN/esverify" \
    -mandate-key "$WORK/customers/c-2204.pub"; then
    echo "ERROR: $f passed verification"
    exit 1
  else
    echo ">>> $f caught (exit code $?)"
  fi
done

step "what this does not cover"
echo "- the lines are the platform's word: a step it never wrote is not in the store, and a false line is recorded faithfully;"
echo "- the store checks no signature inside a line: the report checks the mandate's, outside the store, and whose key"
echo "  signed it is for the auditor to establish; an AP2 SD-JWT with disclosures and key binding is not parsed;"
echo "- which lines belong to p-1002 rests on the label the store set at intake, from the purchase_id in each line;"
echo "- the bundle carries every record of the source in the window, so it grows with the source, not with the purchase;"
echo "- who pays in the dispute is decided by the rules of the payment method, not by the bundle."
echo
echo "work directory: $WORK"
