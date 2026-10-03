#!/usr/bin/env bash
# Демо evidencestore на настоящих бинарниках, без интернета:
#
#   1. учебный УЦ, хранилище, сборщик; строки журнала АБС доезжают по mTLS;
#   2. пакет доказательств проходит офлайн-проверку (esverify);
#   3. подделал улику — проверка поймала;
#   4. уничтожил ключ месяца (два подтверждения, срок ожидания) — тело
#      больше не прочитать, а доказательство существования и неизменности
#      по-прежнему проходит.
#
# Метки времени ставит встроенная демо-служба (tsa.url = "local"). Чтобы
# заверять у НУЦ РК, в конфиге: "url": "http://tsp.pki.gov.kz" и "trust":
# configs/tsa/nca-kz/*.cer.
#
#   WORK=/tmp/es-demo scripts/demo.sh     # каталог стенда (по умолчанию mktemp)
#   DEMO_TSA=nca scripts/demo.sh          # метки у настоящей TSA НУЦ РК (нужен интернет)
#   DEMO_TSA=digicert scripts/demo.sh     # метки у публичной TSA DigiCert (нужен интернет)
set -euo pipefail
cd "$(dirname "$0")/.."
WORK=${WORK:-$(mktemp -d)}
BIN=$WORK/bin
PORT=${PORT:-18443}
mkdir -p "$BIN"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "сборка"
go build -o "$BIN/" ./cmd/...

step "учебный УЦ: сертификат сервера и сборщика abs-core"
"$BIN/evidencestore" dev-pki -out "$WORK/pki" -source abs-core

TSA_JSON='"url": "local", "every": "1h"'
case "${DEMO_TSA:-}" in
nca)
  NCA=$(pwd)/configs/tsa/nca-kz
  TSA_JSON="\"url\": \"http://tsp.pki.gov.kz\", \"every\": \"1h\", \"trust\": [\"$NCA/root_rsa_2020.cer\", \"$NCA/nca_rsa_2022.cer\"]"
  ;;
digicert)
  DC=$(pwd)/configs/tsa/digicert
  TSA_JSON="\"url\": \"http://timestamp.digicert.com\", \"every\": \"1h\", \"trust\": [\"$DC/DigiCertTrustedRootG4.crt\", \"$DC/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt\"]"
  ;;
esac

cat >"$WORK/evidencestore.json" <<EOF
{
  "data_dir": "data",
  "roots_dir": "roots",
  "listen": "127.0.0.1:$PORT",
  "tls": {"cert": "pki/server.crt", "key": "pki/server.key", "client_ca": "pki/ca.crt"},
  "chain": {"tick": "200ms", "promise_mmd": "10s"},
  "tsa": {$TSA_JSON},
  "keys": {"min_wait": "1s", "backup_dir": "keyring-backup", "roots_mirror_dir": "roots-mirror"},
  "sources": [
    {"name": "abs-core", "content_type": "syslog", "retention_months": 36, "expect_every": "1h"}
  ]
}
EOF
CFG=$WORK/evidencestore.json

step "init: кейринг под корнем, ключ подписи хранилища"
"$BIN/evidencestore" init -config "$CFG" | tee "$WORK/init.txt"
STORE_KEY=$(tail -1 "$WORK/init.txt")

step "serve"
"$BIN/evidencestore" serve -config "$CFG" 2>"$WORK/server.log" &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -S "$WORK/data/admin.sock" ] && break; sleep 0.1; done

step "метка времени до приёма: она станет нижней границей T1 для улик"
"$BIN/evidencestore" stamp -config "$CFG"

step "сборщик дочитывает журнал АБС и доставляет строки"
cat >"$WORK/abs-audit.log" <<'EOF'
2026-10-03T09:00:01Z user=teller7 action=login ip=10.0.4.17
2026-10-03T09:02:44Z user=teller7 action=transfer from=KZ01 to=KZ02 amount=1500000 KZT
2026-10-03T09:03:10Z user=admin action=grant role=superuser to=teller7
EOF
cat >"$WORK/collector.json" <<EOF
{
  "server": "https://127.0.0.1:$PORT",
  "ca": "pki/ca.crt", "cert": "pki/abs-core.crt", "key": "pki/abs-core.key",
  "store_key": "$STORE_KEY",
  "spool_dir": "spool", "file": "abs-audit.log", "from_start": true
}
EOF
"$BIN/escollect" -config "$WORK/collector.json" -once
echo "обещания хранилища у сборщика для номеров: $("$BIN/escollect" -config "$WORK/collector.json" -promises)"

step "метка времени над головой цепи, пакет доказательств по улике №2 с ключом записи"
"$BIN/evidencestore" stamp -config "$CFG"
"$BIN/evidencestore" proof -config "$CFG" -source abs-core -seq 2 -dek -out "$WORK/proof-2.json"
case "${DEMO_TSA:-}" in
nca) TSA_TRUST="$NCA/root_rsa_2020.cer,$NCA/nca_rsa_2022.cer" ;;
digicert) TSA_TRUST="$DC/DigiCertTrustedRootG4.crt,$DC/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt" ;;
*)
  "$BIN/evidencestore" tsa-root -config "$CFG" -out "$WORK/tsa-root.crt"
  TSA_TRUST="$WORK/tsa-root.crt"
  ;;
esac
grep '"seq":2,' "$WORK/spool/promises.jsonl" >"$WORK/promise-2.json"

step "проверяющий: esverify офлайн, с обещанием, полученным сборщиком при приёме"
"$BIN/esverify" -proof "$WORK/proof-2.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -promise "$WORK/promise-2.json"

step "подделка: в предъявленной улике изменён один байт"
python3 - "$WORK/proof-2.json" "$WORK/forged-2.json" <<'PY'
import base64, json, sys
b = json.load(open(sys.argv[1]))
ev = bytearray(base64.b64decode(b["evidence"]))
ev[-20] ^= 0x01
b["evidence"] = base64.b64encode(bytes(ev)).decode()
json.dump(b, open(sys.argv[2], "w"))
PY
if "$BIN/esverify" -proof "$WORK/forged-2.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST"; then
  echo "ОШИБКА: подделка прошла проверку"; exit 1
else
  echo ">>> подделка поймана (код выхода $?)"
fi

MONTH=$(date -u +%Y-%m)
step "стирание по сроку: месяц abs-core/$MONTH — закрыть, заявка двух людей, ожидание, уничтожение"
# Текущий месяц закрывается только с -force: приём от источника встанет до
# конца месяца. В жизни по сроку уничтожают прошлые месяцы (keys due).
"$BIN/evidencestore" keys deactivate -config "$CFG" -scope "abs-core/$MONTH" -force >/dev/null
if "$BIN/evidencestore" keys schedule -config "$CFG" -scope "abs-core/$MONTH" -approve operator -wait 1s 2>&1; then
  echo "ОШИБКА: хватило одного подтверждения"; exit 1
fi
"$BIN/evidencestore" keys schedule -config "$CFG" -scope "abs-core/$MONTH" -approve operator -approve security -wait 1s
sleep 1.5
"$BIN/evidencestore" keys complete -config "$CFG"
"$BIN/evidencestore" stamp -config "$CFG"

step "после уничтожения: ключ записи не выдаётся, тело не прочитать, доказательство проходит"
"$BIN/evidencestore" proof -config "$CFG" -source abs-core -seq 2 -dek -out "$WORK/proof-2-erased.json"
"$BIN/esverify" -proof "$WORK/proof-2-erased.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST"

step "старый пакет с ключом записи: тело вскрывается ключом, выданным ДО стирания"
echo "(ключ записи, однажды выданный проверяющему, у него и остаётся — это предел, а не дыра)"
"$BIN/esverify" -proof "$WORK/proof-2.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" | head -3

step "сводка хранилища"
"$BIN/evidencestore" status -config "$CFG"
echo
echo "стенд: $WORK"
