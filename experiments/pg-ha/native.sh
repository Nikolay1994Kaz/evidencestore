#!/usr/bin/env bash
# Слот сборщика на реплике средствами самого PostgreSQL 17 (без Patroni):
# слот с failover, sync_replication_slots на реплике, synchronized_standby_slots
# на основной. Основную убивают под нагрузкой агента, реплику поднимают в
# основные (pg_ctl promote), адрес ведёт HAProxy (вторая база — запасной
# сервер). Ожидаемое: слот на новой основной есть, каждое зафиксированное
# действие — в базе и у сборщика целиком, тревог gap и db-rewound нет.
#
#   experiments/pg-ha/native.sh              около 3 минут
#   WORK=/tmp/pg-native …   KEEP=1 …
#
# Нужны: Go, Docker, psql, python3; образ стенда собирает run.sh или этот
# сценарий. Порты на 127.0.0.1: 55100 (база через HAProxy), 18743 (хранилище).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE/../.."
WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
BIN=${ES_BIN:-$WORK/bin}
PORT=${PORT:-18743}
PG_VERSION=${PG_VERSION:-17}
IMAGE=es-pgha:$PG_VERSION
NAME=${PGNATIVE_NAME:-es-pgnative}
export PGHA_PASSWORD=${PGHA_PASSWORD:-stand}
export PGPASSWORD=$PGHA_PASSWORD
PGPORT=${PGNATIVE_PORT:-55100}
export PGHA_PSQL="host=127.0.0.1 port=$PGPORT user=postgres dbname=shop"
. "$HERE/lib.sh"

down() {
  docker rm -f "$NAME-a" "$NAME-b" "$NAME-haproxy" >/dev/null 2>&1 || true
  docker network rm "$NAME" >/dev/null 2>&1 || true
}
cleanup() {
  kill "${SERVER:-}" "${COLLECT:-}" "${LOAD:-}" 2>/dev/null || true
  [ -n "${KEEP:-}" ] || down
}
trap cleanup EXIT
on() { local c=$1; shift; docker exec -u postgres "$NAME-$c" psql -U postgres -d shop -X -At -v ON_ERROR_STOP=1 "$@"; }

step "сборка и две базы PostgreSQL $PG_VERSION: основная (pga) и реплика (pgb), адрес — HAProxy"
build_bins
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -q -t "$IMAGE" --build-arg PG_VERSION="$PG_VERSION" "$HERE" >/dev/null
down
docker network create "$NAME" >/dev/null
# Настройки обеих баз одинаковы: после переключения роли меняются.
PGOPTS=(-c wal_level=logical -c max_slot_wal_keep_size=2GB -c hot_standby_feedback=on -c sync_replication_slots=on)
docker run -d --name "$NAME-a" --network "$NAME" --network-alias pga -e POSTGRES_PASSWORD="$PGHA_PASSWORD" -e POSTGRES_DB=shop "$IMAGE" postgres "${PGOPTS[@]}" >/dev/null
for _ in $(seq 60); do docker exec "$NAME-a" pg_isready -h 127.0.0.1 -U postgres -d shop >/dev/null 2>&1 && break; sleep 1; done
docker exec -u postgres "$NAME-a" sh -c 'echo "host replication all all scram-sha-256" >>"$PGDATA/pg_hba.conf"'
# synchronized_standby_slots — логические потоки слотов с failover не уходят
# дальше того, что получила реплика: сборщик не окажется впереди неё. Через
# ALTER SYSTEM, а не в командной строке базы: после переключения его придётся
# менять, а командная строка сильнее.
on a -q -c "select pg_create_physical_replication_slot('standby1')" -c "alter system set synchronized_standby_slots = 'standby1'" -c "select pg_reload_conf()" >/dev/null
# Реплики ещё нет: её имя HAProxy узнает у DNS сети позже (resolvers, init-addr none).
cat >"$WORK/haproxy.cfg" <<'EOF'
resolvers docker
    nameserver dns 127.0.0.11:53
    hold valid 1s
defaults
    mode tcp
    timeout connect 3s
    timeout client 1h
    timeout server 1h
listen primary
    bind *:5000
    default-server inter 1s fall 2 rise 1 on-marked-down shutdown-sessions init-addr last,libc,none resolvers docker
    server a pga:5432 check
    server b pgb:5432 check backup
EOF
chmod 644 "$WORK/haproxy.cfg"
docker run -d --name "$NAME-haproxy" --network "$NAME" -p "127.0.0.1:$PGPORT:5000" -v "$WORK/haproxy.cfg:/etc/haproxy.cfg:ro" "$IMAGE" haproxy -f /etc/haproxy.cfg -db >/dev/null
wait_sql
demo_tables
store_and_collector

step "слот сборщика — с failover, до первого запуска сборщика; реплика синхронизирует слоты"
on a -q -c "select pg_create_logical_replication_slot('evidence_tap', 'pgoutput', false, false, true)" >/dev/null
# Реплика: копия основной; dbname в primary_conninfo — без него слоты не синхронизируются.
docker run -d --name "$NAME-b" --network "$NAME" --network-alias pgb -e PGPASSWORD="$PGHA_PASSWORD" --user postgres "$IMAGE" sh -c "
  pg_basebackup -d 'host=pga user=postgres dbname=shop' -D \"\$PGDATA\" -R -S standby1 -X stream &&
  chmod 700 \"\$PGDATA\" && exec postgres ${PGOPTS[*]}" >/dev/null
# Слот заведён раньше, чем создана реплика: ему нужен журнал старше её начала,
# и PostgreSQL не считает копию слота готовой («Synchronization could lead to
# data loss»), пока сборщик не дочитает за это место и слот не сдвинется.
# Поэтому сначала — сборщик и действия агента, потом — ждать готовности.
mcp_config mcp-direct.json "$PGPORT" 60s
start_collector
grep -q 'replication slot created' collect.log && die "сборщик завёл слот сам: без failover он не синхронизируется"
synced() { [ "$(on b -c "select synced and failover and not temporary from pg_replication_slots where slot_name = 'evidence_tap'" 2>/dev/null)" = t ]; }
load_start ledger-warm.jsonl 29000
for _ in $(seq 180); do synced && break; sleep 1; done
load_stop
synced || die "слот не синхронизирован на реплику: $(docker logs --tail 3 "$NAME-b" 2>&1)"
# Фиксация ждёт реплику: аварийное переключение не теряет зафиксированного.
on a -q -c "alter system set synchronous_standby_names = '*'" -c "select pg_reload_conf()" >/dev/null
for _ in $(seq 30); do [ "$(on a -c "select count(*) from pg_stat_replication where sync_state = 'sync'")" = 1 ] && break; sleep 1; done
on b -c "select 'реплика: слот ' || slot_name || ', synced ' || synced || ', failover ' || failover || ', temporary ' || temporary from pg_replication_slots where slot_name = 'evidence_tap'"
echo "сборщик читает слот, который завели с failover"

step "основную убивают под нагрузкой агента, реплику поднимают в основные"
load_start ledger-native.jsonl 30000
sleep 6
docker kill "$NAME-a" >/dev/null
docker exec -u postgres "$NAME-b" pg_ctl promote -D /var/lib/postgresql/data >/dev/null
# У новой основной реплики пока нет, а synchronized_standby_slots называет
# слот прежней: пока его не убрать, она не отдаёт изменения слотам с failover
# («Logical replication is waiting on the standby…»), и сборщик молча ничего
# не получает. Это шаг того, кто переключает кластер.
docker exec -u postgres "$NAME-b" psql -U postgres -X -q -c "alter system set synchronized_standby_slots = ''" -c "select pg_reload_conf()" >/dev/null
for _ in $(seq 60); do [ "$(psqlp -c "select pg_is_in_recovery()" 2>/dev/null)" = f ] && break; sleep 1; done
[ "$(psqlp -c "select pg_is_in_recovery()")" = f ] || die "адрес не ведёт к новой основной"
sleep 25
load_stop
psqlp -c "select 'новая основная: слот ' || slot_name || ', failover ' || failover || ', занят ' || active from pg_replication_slots where slot_name = 'evidence_tap'"
grep 'switched over to another server' collect.log | tail -1 | grep -o 'timeline=.*' || die "сборщик не узнал чистое переключение: $(tail -3 collect.log)"
settle_collector
verify ledger-native.jsonl fingerprint=0 alert:gap=0 alert:db-rewound=0

step "итог"
echo "PostgreSQL $PG_VERSION, слот с failover: после переключения слот на новой основной, записи не потеряны и не лежат отпечатками"
echo "стенд: $WORK"
