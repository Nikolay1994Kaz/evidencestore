#!/usr/bin/env bash
# Установка в Docker на две машины — по шагам docs/install.md («In Docker»),
# на одном хосте Docker: хранилище (deploy/docker/store/compose.yaml) и
# сборщик из архива add-source — отдельным проектом compose, к хранилищу —
# через адрес хоста, как с другой машины. Строка лога доходит, пакет по ней
# проходит esverify (VERIFIED). Сначала — проба образа без команды (try.sh).
#
#   scripts/docker-check.sh                  образ из исходников (корневой Dockerfile)
#   scripts/docker-check.sh IMAGE            готовый образ, например выпуска
#
# Метки — встроенной службы хранилища (ES_TSA=local): проверке не нужен интернет.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(pwd)

image=${1:-}
if [ -z "$image" ]; then
	image=evidencestore:docker-check
	docker build -q -t "$image" . >/dev/null
fi
export ES_IMAGE=$image

echo "== the try: docker run --rm IMAGE"
try=$(docker run --rm "$image") || { echo "$try" >&2; echo "docker-check: the try failed" >&2; exit 1; }
echo "$try" | grep -q '^Nov 24 09:14:37 web-1 sshd\[840\]: Accepted password for root from 203.0.113.7' || { echo "$try" >&2; echo "docker-check: the try did not bring the deleted line back" >&2; exit 1; }
echo "$try" | grep -q '^NOT VERIFIED$' || { echo "$try" >&2; echo "docker-check: the try did not catch the forgery" >&2; exit 1; }

# Адрес хоста из сети контейнеров: по нему сборщик идёт к хранилищу, как к
# хосту хранилища с другой машины.
host=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')

w=$(mktemp -d)
cleanup() {
	(cd "$w/collector/web1" 2>/dev/null && docker compose down -v -t 2 >/dev/null 2>&1) || true
	(cd "$w/store" && docker compose down -t 2 >/dev/null 2>&1) || true
	# Файлы хранилища — root контейнера: удаляет их контейнер.
	docker run --rm -v "$w:/w" --entrypoint sh "$image" -c 'rm -rf /w/* /w/.[!.]*' >/dev/null 2>&1 || true
	rmdir "$w" 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p "$w/store" "$w/collector" "$w/logs"
printf 'first line\n' >"$w/logs/app.log"

echo "== store host: docker compose up (ES_HOST=$host)"
cp deploy/docker/store/compose.yaml "$w/store/"
cd "$w/store"
ES_HOST=$host ES_TSA=local docker compose up -d --wait >/dev/null

echo "== a collector: add-collector (the store restarts serve by itself)"
docker compose exec -T store add-collector web1 -file "$w/logs/app.log" >web1.tgz
# Ещё раз тот же источник — отказ, конфиг не меняется.
before=$(cat config/evidencestore.json)
if docker compose exec -T store add-collector web1 >/dev/null 2>&1; then
	echo "docker-check: add-collector issued web1 twice" >&2
	exit 1
fi
[ "$before" = "$(cat config/evidencestore.json)" ] || { echo "docker-check: a refused add-collector changed the config" >&2; exit 1; }
# Закрытый ключ сборщика — только в архиве.
if docker compose exec -T store sh -c 'find / -name "web1.key" -not -path "/proc/*" 2>/dev/null' | grep -q .; then
	echo "docker-check: web1.key is on the store's host" >&2
	exit 1
fi

echo "== collector host: tar -xzf web1.tgz && docker compose up"
cp web1.tgz "$w/collector/"
cd "$w/collector"
tar -xzf web1.tgz
cd web1
docker compose up -d >/dev/null
printf 'second line\n' >>"$w/logs/app.log"

cd "$w/store"
status() { docker compose exec -T store evidencestore status; }
for _ in $(seq 60); do
	if status | grep -q '"max_seq": 2'; then
		break
	fi
	sleep 1
done
status | grep -q '"max_seq": 2' || {
	echo "docker-check: the store did not get both lines" >&2
	(cd "$w/collector/web1" && docker compose logs collector | tail -20) >&2
	exit 1
}

echo "== an auditor: proof and esverify"
docker compose exec -T store evidencestore stamp >/dev/null
docker compose exec -T store evidencestore proof -source web1 -seq 2 -dek >bundle.json
docker compose exec -T store evidencestore tsa-root -out /tmp/tsa-root.crt >/dev/null 2>&1
docker compose exec -T store cat /tmp/tsa-root.crt >tsa-root.crt
out=$(docker run --rm -v "$w/store:/w:ro" "$image" esverify -proof /w/bundle.json -store-key "$(cat config/store.pub)" -tsa-trust /w/tsa-root.crt) || {
	echo "$out" >&2
	exit 1
}
echo "$out" | grep -q '^second line$' || { echo "$out" >&2; echo "docker-check: the body is not the log line" >&2; exit 1; }
echo "$out" | tail -n 1
cd "$repo"
echo "docker-check: ok"
