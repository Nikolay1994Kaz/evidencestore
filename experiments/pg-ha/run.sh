#!/usr/bin/env bash
# Стенд «кластер клиента»: esmcp и сборщик в среде, где базой управляет не
# evidencestore, — два узла PostgreSQL под Patroni, HAProxy как адрес основной
# базы, PgBouncer по сессиям и по транзакциям (compose.yaml). Проверяет три
# вещи, каждый шаг — с ожидаемым итогом, расхождение — ненулевой код выхода:
#
#   1. esmcp через пулер: без "pooler": true сервер не входит; с ним — все
#      проверки pool_check.py в обоих режимах пула;
#   2. сборщик переживает переключение кластера: плановое (patronictl
#      switchover) и аварийное (основную убивают) под нагрузкой агента — каждое
#      зафиксированное действие в базе и у сборщика целиком, тревог gap и
#      db-rewound нет; в конце — то же без постоянного слота: потеря видна
#      (тревога gap);
#   3. основная пропадает посреди действия агента (midaction.py): до COMMIT —
#      «откатилось», на COMMIT — «неизвестно» и тревога commit-unknown;
#      напрямую и через пул по транзакциям.
#
#   experiments/pg-ha/run.sh                 всё, около 12 минут
#   WORK=/tmp/pg-ha experiments/pg-ha/run.sh каталог стенда (по умолчанию mktemp)
#   KEEP=1 …                                 не гасить кластер в конце
#   PG_VERSION=17 …                          версия PostgreSQL образа (17 и новее)
#
# Нужны: Go, Docker с compose, psql, python3. Порты — только на 127.0.0.1:
# 55000 (основная через HAProxy), 56432 и 56433 (PgBouncer), 18643 (хранилище).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE/../.."
WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
BIN=${ES_BIN:-$WORK/bin}
PORT=${PORT:-18643}
export PG_VERSION=${PG_VERSION:-17}
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-es-pgha}
export PGHA_PASSWORD=${PGHA_PASSWORD:-stand}
export PGPASSWORD=$PGHA_PASSWORD
PGPORT=${PGHA_PORT:-55000}
SESSIONPORT=${PGHA_SESSION_PORT:-56432}
TXPORT=${PGHA_TX_PORT:-56433}
export PGHA_PSQL="host=127.0.0.1 port=$PGPORT user=postgres dbname=shop"
DC=(docker compose -f "$HERE/compose.yaml")

. "$HERE/lib.sh"

members() { for n in pg1 pg2; do "${DC[@]}" exec -T $n patronictl -c /etc/patroni.yml list -f json 2>/dev/null && return; done; echo '[]'; }
leader() { members | python3 -I -c 'import json,sys; print(([m["Member"] for m in json.load(sys.stdin) if m["Role"]=="Leader" and m["State"]=="running"] or [""])[0])'; }
other() { [ "$1" = pg1 ] && echo pg2 || echo pg1; }
# settled: основная есть, вторая — реплика (синхронная, если так настроено) и догоняет.
settled() { members | python3 -I -c 'import json,sys; m=json.load(sys.stdin); sys.exit(0 if len(m)==2 and any(x["Role"]=="Leader" and x["State"]=="running" for x in m) and any(x["Role"] in ("Replica","Sync Standby") and x["State"]=="streaming" for x in m) else 1)'; }
wait_settled() { for _ in $(seq 120); do settled && return 0; sleep 1; done; die "кластер не собрался: $(members)"; }
pctl() { "${DC[@]}" exec -T "$(leader)" patronictl -c /etc/patroni.yml "$@"; }
cleanup() {
  kill "${SERVER:-}" "${COLLECT:-}" "${LOAD:-}" 2>/dev/null || true
  [ -n "${KEEP:-}" ] || "${DC[@]}" down -v -t 3 >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------- стенд

step "сборка: бинарники и образ стенда (PostgreSQL $PG_VERSION, Patroni, etcd, HAProxy, PgBouncer из пакетов)"
build_bins
"${DC[@]}" build -q >/dev/null
"${DC[@]}" down -v -t 3 >/dev/null 2>&1 || true
"${DC[@]}" up -d >/dev/null 2>&1
wait_settled
wait_sql
"${DC[@]}" exec -T pg1 sh -c 'patroni --version; pgbouncer --version | head -1; haproxy -v | head -1; postgres --version'
echo "основная: $(leader)"

step "база shop, хранилище, сборщик: адрес базы у всех — адрес кластера (HAProxy), не узел"
psql "host=127.0.0.1 port=$PGPORT user=postgres dbname=postgres" -X -qAt -v ON_ERROR_STOP=1 -c "create database shop"
demo_tables
store_and_collector
mcp_config mcp-direct.json "$PGPORT" 60s
mcp_config mcp-session.json "$SESSIONPORT" 5s pooler
mcp_config mcp-tx.json "$TXPORT" 5s pooler
mcp_config mcp-tx-long.json "$TXPORT" 60s pooler
mcp_config mcp-tx-nopooler.json "$TXPORT" 5s

step "Patroni: слот сборщика — постоянный (slots в настройках кластера), реплика — синхронная"
# Слот объявлен до первого запуска сборщика: Patroni заводит его сам на
# основной и держит копию на реплике. Синхронная реплика — чтобы аварийное
# переключение не теряло зафиксированного: без неё последние транзакции
# теряет сам кластер, и сборщик честно скажет db-rewound.
pctl edit-config es --force -s 'slots={"evidence_tap":{"type":"logical","database":"shop","plugin":"pgoutput"}}' -s synchronous_mode=true >/dev/null
slot_on_replica() { "${DC[@]}" exec -T "$(other "$(leader)")" psql -U postgres -d shop -X -Atc "select count(*) from pg_replication_slots where slot_name = 'evidence_tap' and slot_type = 'logical'" 2>/dev/null | grep -qx 1; }
for _ in $(seq 60); do slot_on_replica && break; sleep 1; done
slot_on_replica || die "Patroni не скопировал слот на реплику"
wait_settled
start_collector
grep -q 'replication slot created' collect.log && die "сборщик завёл слот сам: Patroni должен был завести его раньше"
echo "слот evidence_tap: на основной и на реплике; сборщик читает его через адрес кластера"

# ---------------------------------------------------------------- 1. пулер

step "1. esmcp через PgBouncer без \"pooler\": true — сервер не входит"
out=$(printf '%s\n' 'query {"sql":"select 1"}' | python3 -I "$HERE/mcp_session.py" "$BIN/esmcp" mcp-tx-nopooler.json mcp.log) || true
echo "$out" | cut -c1-200
echo "$out" | grep -q 'unsupported startup parameter' || die "ожидался отказ пулера по параметру входа"

for mode in session tx; do
  step "1. esmcp через PgBouncer, пул по $([ $mode = tx ] && echo транзакциям || echo сессиям), \"pooler\": true"
  python3 -I "$HERE/pool_check.py" "$BIN/esmcp" "mcp-$mode.json" >"pool-$mode.txt" 2>&1 || { cat "pool-$mode.txt"; die "проверки пулера ($mode) не сошлись"; }
  grep -c '^ok ' "pool-$mode.txt" | sed 's/$/ проверок сошлись/'
done

# ---------------------------------------------------------------- 2. сборщик и переключение

step "2. плановое переключение (patronictl switchover) под нагрузкой агента"
wait_settled; L=$(leader)
load_start ledger-switchover.jsonl 10000
sleep 5
pctl switchover es --leader "$L" --candidate "$(other "$L")" --force >/dev/null
for _ in $(seq 60); do [ "$(leader)" = "$(other "$L")" ] && break; sleep 1; done
[ "$(leader)" = "$(other "$L")" ] || die "переключение не состоялось"
sleep 25
load_stop
echo "основная: $L → $(leader)"
grep 'switched over to another server' collect.log | tail -1 | grep -o 'timeline=.*' || die "сборщик не узнал чистое переключение"
settle_collector
verify ledger-switchover.jsonl fingerprint=0 unknown=0 alert:gap=0 alert:db-rewound=0

step "2. аварийное переключение: основную убивают под нагрузкой"
wait_settled; L=$(leader)
load_start ledger-failover.jsonl 20000
sleep 5
docker kill "$COMPOSE_PROJECT_NAME-$L-1" >/dev/null
for _ in $(seq 90); do [ "$(leader)" = "$(other "$L")" ] && break; sleep 1; done
[ "$(leader)" = "$(other "$L")" ] || die "реплика не стала основной"
sleep 20
load_stop
"${DC[@]}" start "$L" >/dev/null 2>&1
echo "основная: $L (убита) → $(leader)"
settle_collector
verify ledger-failover.jsonl fingerprint=0 alert:gap=0 alert:db-rewound=0
wait_settled

# ---------------------------------------------------------------- 3. обрыв посреди действия

pctl edit-config es --force -s synchronous_mode_strict=true >/dev/null
sleep 8
n=500
for via in direct tx-long; do
  for scenario in sql frozen commit link; do
    n=$((n + 1))
    step "3. основная пропадает посреди действия: $scenario, $([ $via = direct ] && echo напрямую || echo 'через пул по транзакциям')"
    python3 -I "$HERE/midaction.py" "$BIN/esmcp" "mcp-$via.json" "$scenario" "$n" | tee -a midaction.jsonl | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print({k: d[k] for k in ("told","took","in_db","leader_was","leader_now")}); print("  ", d["text"][:200])' || die "сценарий $scenario ($via) не сошёлся: $(tail -1 midaction.jsonl)"
  done
done
pctl edit-config es --force -s synchronous_mode_strict=false >/dev/null
for _ in $(seq 30); do [ "$(alerts commit-unknown)" = 4 ] && break; sleep 1; done
[ "$(alerts commit-unknown)" = 4 ] || die "тревог commit-unknown $(alerts commit-unknown), а действий с исходом «неизвестно» — 4"
echo "тревог commit-unknown: 4 — по одной на действие с исходом «неизвестно»"
# Действия «неизвестно», которые база всё же зафиксировала, у сборщика — целиком, с действием шлюза.
python3 -I - midaction.jsonl pg-index/index.jsonl <<'PY' || die "транзакция с исходом «неизвестно» у сборщика не целиком"
import json, re, sys
idx = {}
for l in open(sys.argv[2]):
    r = json.loads(l)
    idx[str(r["xid"])] = r
n = 0
for l in open(sys.argv[1]):
    r = json.loads(l)
    if r["told"] == "unknown" and r["in_db"]:
        xid = re.search(r"transaction (\d+)", r["text"]).group(1)
        e = idx.get(xid)
        if not e or e.get("kind") or not e.get("action"):
            sys.exit(f"transaction {xid}: {e}")
        n += 1
print(f"зафиксированных базой действий с исходом «неизвестно»: {n} — у сборщика все целиком, с действием шлюза")
PY
[ "$(alerts gap)" = 0 ] && [ "$(alerts db-rewound)" = 0 ] || die "тревоги gap $(alerts gap), db-rewound $(alerts db-rewound) — ожидалось 0 и 0"
echo "за все переключения: тревог gap 0, db-rewound 0"

# ---------------------------------------------------------------- без постоянного слота

step "без постоянного слота в Patroni: слота на новой основной нет — потеря видна (тревога gap)"
wait_settled
pctl edit-config es --force -s slots=null >/dev/null
gone_on_replica() { "${DC[@]}" exec -T "$(other "$(leader)")" psql -U postgres -d shop -X -Atc "select count(*) from pg_replication_slots where slot_name = 'evidence_tap'" 2>/dev/null | grep -qx 0; }
for _ in $(seq 60); do gone_on_replica && break; sleep 1; done
gone_on_replica || die "копия слота на реплике осталась"
L=$(leader)
pctl switchover es --leader "$L" --candidate "$(other "$L")" --force >/dev/null
for _ in $(seq 90); do [ "$(alerts gap)" = 1 ] && break; sleep 1; done
[ "$(alerts gap)" = 1 ] || die "тревоги gap нет"
grep '"kind":"gap"' pg-index/alerts.jsonl | python3 -I -c 'import json,sys; print(json.loads(sys.stdin.readline())["signals"][0]["detail"])'

step "итог"
echo "esmcp через PgBouncer (по сессиям и по транзакциям), переключения кластера под нагрузкой и обрывы посреди действия — сошлись"
echo "стенд: $WORK"
