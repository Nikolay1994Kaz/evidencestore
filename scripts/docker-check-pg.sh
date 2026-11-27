#!/usr/bin/env bash
# Проба Postgres в Docker (корневой compose.yaml, docs/postgres.md, «Try it in
# Docker») — с нуля и до отката, как её прошли руками 24.11:
#
#   1. docker compose up: база, хранилище, сборщик, первый запуск;
#   2. агент через MCP-сервер меняет 5 строк — транзакция дошла до хранилища;
#   3. esundo check и apply по пакету из хранилища — строки как были;
#   4. правка мимо сервера (суперпользователь) — отпечаток в журнале сборщика
#      (пачка уходит через минуту, PackWait);
#   5. DROP TABLE через MCP — отказ до выполнения, таблица цела;
#   6. прямое подключение агента (agent.txt) — изменить ничего нельзя.
#
#   scripts/docker-check-pg.sh            образ собирается из этого дерева
#   PG_VERSION=14 scripts/docker-check-pg.sh
#
# Работает во временной копии дерева и под своим именем проекта compose: проба,
# поднятая в клоне, не трогается. Около двух минут, из них минута — пачка.
set -euo pipefail
cd "$(dirname "$0")/.."

w=$(mktemp -d)
export COMPOSE_PROJECT_NAME=es-pg-check
# Копия дерева — с неотслеженными, но не игнорируемыми файлами: проверяется то,
# что лежит в дереве сейчас, а ./state клона не трогается.
git ls-files -co --exclude-standard -z | tar --null -T - -cf - | tar -xf - -C "$w"
cd "$w"

cleanup() {
	docker compose down -v -t 3 >/dev/null 2>&1 || true
	# ./state принадлежит пользователям контейнеров: удаляет его контейнер.
	docker run --rm -v "$w:/w" alpine:3.22 rm -rf /w/state >/dev/null 2>&1 || true
	rm -rf "$w"
}
trap cleanup EXIT

fail() {
	echo "docker-check-pg: $*" >&2
	docker compose logs --tail 30 collector store >&2 || true
	exit 1
}
sql() { docker compose exec -T db sh -c "PGPASSWORD=\$(cat /run/es/postgres-password) psql -h 127.0.0.1 -U postgres -d shop -Atc \"$1\""; }
status() { docker compose exec -T store evidencestore status -config /state/store/store.json; }
records() { status | tr -d ' \n' | grep -o "\"name\":\"$1\",[^}]*" | grep -o '"records":[0-9]*' | cut -d: -f2; }
# mcp — вызовы инструментов MCP-сервера одним сеансом, как у клиента: ответы — строки JSON-RPC.
mcp() {
	{
		printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"docker-check-pg","version":"1"}}}' \
			'{"jsonrpc":"2.0","method":"notifications/initialized"}' "$@"
		sleep 3
	} | docker compose run --rm -T --no-deps esmcp 2>/dev/null
}
waitfor() { # описание, секунд, команда…
	local what=$1 n=$2
	shift 2
	for _ in $(seq "$n"); do
		if "$@"; then return 0; fi
		sleep 1
	done
	fail "$what"
}

echo "== docker compose up (PostgreSQL ${PG_VERSION:-17})"
docker compose up -d --wait >/dev/null 2>&1 || fail "docker compose up"
before=$(sql "select string_agg(id || ':' || balance, ' ' order by id) from accounts where id <= 5")

echo "== the agent changes 5 rows through the MCP server"
out=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute","arguments":{"sql":"UPDATE accounts SET balance = 0 WHERE id <= 5"}}}')
xid=$(echo "$out" | grep -o '\\"xid\\":\\"[0-9]*' | grep -o '[0-9]*$' | head -n 1)
[ -n "$xid" ] && echo "$out" | grep -q '\\"outcome\\":\\"committed\\"' || { echo "$out" >&2; fail "the action did not commit"; }
[ "$(sql "select count(*) from accounts where id <= 5 and balance = 0")" = 5 ] || fail "the action did not change the rows"
in_store() { [ "$(records pg-agent)" -ge 1 ] 2>/dev/null; }
waitfor "transaction $xid did not reach the store" 30 in_store
echo "   transaction $xid is in the store"

echo "== esundo check and apply, from the bundle the store gives"
docker compose exec -T store esundo check -config /state/store/undo.json -xid "$xid" >check.txt 2>&1 || { cat check.txt >&2; fail "esundo check"; }
grep -q 'to apply 5, already as before 0, conflicts 0' check.txt || { cat check.txt >&2; fail "the plan is not 5 rows to restore"; }
docker compose exec -T store esundo apply -config /state/store/undo.json -plan "undo-$xid.json" -by docker-check -reason "docker-check-pg" >apply.txt 2>&1 || { cat apply.txt >&2; fail "esundo apply"; }
grep -q 'every row is as it was before the transaction' apply.txt || { cat apply.txt >&2; fail "the undo did not check the rows"; }
[ "$(sql "select string_agg(id || ':' || balance, ' ' order by id) from accounts where id <= 5")" = "$before" ] || fail "the rows are not as before"
echo "   the rows are as before: $before"

echo "== a change made past the server is kept as a fingerprint (within a minute)"
[ "$(sql "with d as (delete from orders where id > 40 returning 1) select count(*) from d")" = 10 ] || fail "the direct delete"
fingerprint() { docker compose exec -T store cat /state/pg-index/index.jsonl | grep -q '"kind":"fingerprint".*"changes":10'; }
waitfor "the direct delete did not reach the store as a fingerprint" 120 fingerprint
echo "   fingerprint of 10 changes in the collector's index"

echo "== DROP TABLE through the MCP server is refused before it runs"
out=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute","arguments":{"sql":"DROP TABLE orders"}}}')
echo "$out" | grep -q 'failed and was rolled back: the statement was not taken, nothing ran' || { echo "$out" >&2; fail "DROP was not refused"; }
[ "$(sql "select count(*) from orders")" = 40 ] || fail "the orders table changed"

echo "== the agent's own connection (agent.txt) changes nothing"
dsn=$(docker run --rm -v "$w/state:/s:ro" --entrypoint cat evidencestore:local /s/agent.txt)
if docker compose exec -T db psql "$dsn" -c "update accounts set balance = 1 where id = 7" >agent.txt.out 2>&1; then
	fail "the agent's connection changed a row"
fi
grep -q 'permission denied' agent.txt.out || { cat agent.txt.out >&2; fail "the agent's connection failed, but not by permission"; }

echo "docker-check-pg: ok"
