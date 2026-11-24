#!/bin/sh
# Проба одной командой, без Go и клона (команда образа по умолчанию):
#
#   docker run --rm ghcr.io/nikolay1994kaz/evidencestore
#
# Внутри контейнера: хранилище (dev-setup, встроенная демо-TSA), сборщик и
# auth.log. Сборщик отправляет три строки, злоумышленник стирает из файла
# строку со своим адресом, хранилище отдаёт её пакетом, esverify проверяет его
# офлайн (VERIFIED, тело — стёртая строка); пакет с одним изменённым байтом —
# NOT VERIFIED. Всё — во временном каталоге контейнера, наружу ничего.
set -eu

if [ -t 1 ]; then
	b=$(printf '\033[1m') n=$(printf '\033[0m')
else
	b='' n=''
fi
step() { printf '\n%s== %s%s\n' "$b" "$*" "$n"; }

W=$(mktemp -d)
cd "$W"
pid=
trap '[ -z "$pid" ] || kill "$pid" 2>/dev/null || true' EXIT

cat >auth.log <<'EOF'
Nov 24 09:12:01 web-1 sshd[812]: Accepted publickey for alice from 198.51.100.23 port 52344
Nov 24 09:14:37 web-1 sshd[840]: Accepted password for root from 203.0.113.7 port 40112
Nov 24 09:15:02 web-1 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
EOF

step "a store and a collector for web-1 (demo certificates, the demo TSA built into the store)"
evidencestore dev-setup -dir es -source web-1 -log "$W/auth.log" >/dev/null
cd es
evidencestore serve -config store.json >serve.log 2>&1 &
pid=$!
i=0
until evidencestore status -config store.json >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -gt 100 ]; then
		cat serve.log >&2
		exit 1
	fi
	sleep 0.1
done

step "the collector sends auth.log to the store, line by line"
escollect -config collector.json -once 2>/dev/null
cat ../auth.log

step "an intruder removes the line with their address from auth.log"
sed -i '/203\.0\.113\.7/d' ../auth.log
cat ../auth.log

step "the store gives record 2 as a proof bundle, and esverify checks it offline"
evidencestore stamp -config store.json >/dev/null
evidencestore proof -config store.json -source web-1 -seq 2 -dek -out proof.json 2>/dev/null
evidencestore tsa-root -config store.json -out tsa-root.crt 2>/dev/null
esverify -proof proof.json -store-key store.pub -tsa-trust tsa-root.crt

step "one byte of the bundle changed: esverify refuses it"
# Знак base64 за 30 до конца записи — в зашифрованном теле, как ev[-20] в demo.sh.
awk '/"evidence": "/ && !done { v = index($0, "\"evidence\": \"") + 13; e = index(substr($0, v), "\""); i = v + e - 30; c = substr($0, i, 1); r = (c == "A") ? "B" : "A"; $0 = substr($0, 1, i - 1) r substr($0, i + 1); done = 1 } { print }' proof.json >forged.json
if esverify -proof forged.json -store-key store.pub -tsa-trust tsa-root.crt >forged.txt 2>&1; then
	echo "try: the forged bundle passed" >&2
	exit 1
fi
grep -m 1 '✘' forged.txt || true
tail -n 1 forged.txt

printf '\n%sThe deleted line came back from the store, and a changed byte is caught.%s\n' "$b" "$n"
echo "Install the store and its collectors on your hosts: https://github.com/Nikolay1994Kaz/evidencestore/blob/master/docs/install.md#in-docker"
