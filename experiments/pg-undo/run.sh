#!/usr/bin/env bash
# Сценарий «аудит + откат» на живом Postgres, на частях этой ветки:
#
#   ИИ-агент → esmcp (MCP-сервер): запрос идёт ролью агента, в транзакции — отметка действия
#   Postgres: триггер пишет в журнал роль сессии; права роли — то, что агенту можно
#     → espgtap: логическая репликация (pgoutput), только транзакции агента и отката,
#                сжатые части в journal.jsonl, тревоги
#     → escollect → evidencestore: источник с "subject_field": "xid"   (хранилище не изменено)
#     → пакеты записей транзакции → esverify → esundo: обратные операции, сверка с базой,
#                одна транзакция отката; сам откат тоже ложится в журнал
#   Откат делают двое: оператор командой esundo и сам агент инструментом MCP undo_apply.
#
# Что происходит: агент делает хорошее действие и плохое (обнуляет треть счетов,
# удаляет заказы, удаляет счёт, портит документ в 1,5 МБ). Человек после него
# правит несколько строк руками, одну — между сверкой и откатом. Откат плохого
# действия возвращает всё, кроме тронутого человеком. По дороге: агенту отказано
# в TRUNCATE, DROP и подделке отметки; транзакция в обход MCP поднимает тревогу.
# Каждый шаг сверяется с ожидаемым: расхождение — ненулевой код выхода.
#
#   WORK=/tmp/pg-undo experiments/pg-undo/run.sh   # каталог стенда (по умолчанию mktemp)
#   ES_BIN=/path/to/bin …                          # готовые бинарники этой ветки вместо сборки
#   WINDOW=1 …                                     # ещё и пакет по окну времени: +2,5 минуты
#   ROWS=450000 …                                  # замер объёма: счетов ROWS
#   PGBIN=/usr/lib/postgresql/16/bin …             # где initdb, pg_ctl, psql
#
# Нужны: Go (сборка), PostgreSQL 14+ (плагин pgoutput встроен), python3.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE/../.."
WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
BIN=${ES_BIN:-$WORK/bin}
PORT=${PORT:-18443}
PGPORT=${PGPORT:-55432}
ROWS=${ROWS:-2000}
WINDOW=${WINDOW:-0}
SRC=pg-agent
mkdir -p "$BIN"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { echo "ОШИБКА: $*" >&2; exit 1; }
now() { date +%s.%N; }
since() { python3 -I -c 'import sys; print(f"{float(sys.argv[2]) - float(sys.argv[1]):.2f}")' "$1" "$(now)"; }
size() { du -sb "$@" 2>/dev/null | awk '{s += $1} END {print s + 0}'; }
field() { python3 -I -c 'import json,sys; v=json.loads(sys.argv[1])[sys.argv[2]]; print(v if isinstance(v, (str, int)) else json.dumps(v))' "$1" "$2"; }

# ---------------------------------------------------------------- стенд

step "сборка"
if [ -n "${ES_BIN:-}" ]; then "$BIN/evidencestore" version; else go build -o "$BIN/" ./cmd/...; fi
for b in evidencestore escollect esverify espgtap esmcp esundo; do [ -x "$BIN/$b" ] || die "нет $BIN/$b"; done

if [ -z "${PGBIN:-}" ]; then
  PGBIN=$(pg_config --bindir 2>/dev/null || true)
  [ -x "$PGBIN/initdb" ] || PGBIN=$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)
fi
for t in initdb pg_ctl psql; do [ -x "$PGBIN/$t" ] || die "нет $t в '$PGBIN': задайте PGBIN"; done

# Postgres под root не запускается: тогда — от пользователя postgres.
AS_PG=()
if [ "$(id -u)" = 0 ]; then
  id postgres >/dev/null 2>&1 || die "запуск от root, а пользователя postgres нет"
  AS_PG=(runuser -u postgres --)
  chmod 755 "$WORK"
fi
as_pg() { ${AS_PG[@]+"${AS_PG[@]}"} "$@"; }
mkdir -p "$WORK/pg" "$WORK/sock"
[ ${#AS_PG[@]} -eq 0 ] || chown postgres "$WORK/pg" "$WORK/sock"

cleanup() {
  kill "${SERVER:-}" "${TAP:-}" "${COLLECT:-}" "${COLLECT_MCP:-}" 2>/dev/null || true
  as_pg "$PGBIN/pg_ctl" -D "$WORK/pg" -m fast stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "Postgres: wal_level=logical, предел журнала для слота"
as_pg "$PGBIN/initdb" -D "$WORK/pg" -A trust -U postgres --no-sync >/dev/null
cat >>"$WORK/pg/postgresql.conf" <<EOF
listen_addresses = ''
unix_socket_directories = '$WORK/sock'
unix_socket_permissions = 0700
port = $PGPORT
wal_level = logical
max_slot_wal_keep_size = 2GB
EOF
as_pg "$PGBIN/pg_ctl" -D "$WORK/pg" -l "$WORK/pg/server.log" -w start >/dev/null
PGCONN=(-h "$WORK/sock" -p "$PGPORT")
OWNER=("$PGBIN/psql" "${PGCONN[@]}" -U postgres -X -v ON_ERROR_STOP=1 -d shop)
"$PGBIN/psql" "${PGCONN[@]}" -U postgres -X -qAt -v ON_ERROR_STOP=1 -d postgres -c "create database shop"
"${OWNER[@]}" -Atc "select version()" | cut -d' ' -f1-2

"${OWNER[@]}" -q -v rows="$ROWS" <<'SQL'
create table accounts (
  id int primary key, owner text not null, balance numeric(14,2) not null,
  note text, profile text, updated_at timestamptz not null default now());
create table orders (
  id bigint primary key, account_id int not null references accounts(id),
  item text not null, paid boolean not null default false);
create table docs (id int primary key, body text);
insert into accounts (id, owner, balance, note, profile)
  select g, 'client-' || g, 1000 + g,
         case when g % 7 = 0 then null else 'it''s a "vip" #' || g end,
         -- у каждого 500-го — 12,8 КБ в поле: значение уходит в TOAST
         case when g % 500 = 10 then (select string_agg(md5(random()::text || g || i), '') from generate_series(1, 400) i) end
  from generate_series(1, :rows) g;
insert into orders select g, 1 + (g * 7) % :rows, 'item ' || g, g % 2 = 0 from generate_series(1, :rows / 2) g;
insert into orders values (:rows + 1, 5, 'gift', true), (:rows + 2, 5, 'gift wrap', false);
insert into docs values (1, 'contract'), (2, 'note');
create schema snap;
SQL
echo "accounts: $ROWS строк, orders: $((ROWS / 2 + 2))"

step "настройка базы: роль агента, отметка «кто», публикация (espgtap -setup-sql)"
mkdir -p "$WORK/pgtap" "$WORK/mcp"
cat >"$WORK/pgtap.json" <<EOF
{
  "dsn": "host=$WORK/sock port=$PGPORT user=evidence_tap dbname=shop",
  "dir": "pgtap",
  "roles": ["agent_bot"],
  "tables": ["public.accounts", "public.orders", "public.docs"],
  "alert_rows": 500,
  "require_action": true,
  "canaries": [{"table": "public.accounts", "column": "id", "value": "3"}],
  "status_every": "1s"
}
EOF
"$BIN/espgtap" -config "$WORK/pgtap.json" -setup-sql >"$WORK/setup.sql"
PGOPTIONS='-c client_min_messages=warning' "${OWNER[@]}" -q -f "$WORK/setup.sql"
grep -c . "$WORK/setup.sql" | sed 's/$/ строк SQL: права роли agent_bot, триггер отметки на трёх таблицах, публикация, роль сборщика/'
"$BIN/espgtap" -config "$WORK/pgtap.json" 2>"$WORK/pgtap.log" &
TAP=$!
for _ in $(seq 100); do grep -q 'msg=streaming' "$WORK/pgtap.log" 2>/dev/null && break; sleep 0.1; done
grep -q 'msg=streaming' "$WORK/pgtap.log" || die "espgtap не начал читать журнал: $(cat "$WORK/pgtap.log")"

# mcp ИНСТРУМЕНТ JSON: вызов инструмента так, как его делает агент (stdio, ревизия MCP 2026-07-28).
mcp() { python3 -I "$HERE/mcp_call.py" "$BIN/esmcp" "$WORK/mcp.json" "$1" "$2" 2>>"$WORK/mcp.log"; }
sql_arg() { python3 -I -c 'import json,sys; print(json.dumps({"sql": sys.stdin.read(), "reason": sys.argv[1]}))' "$1"; }

step "хранилище: источники $SRC (метка субъекта — xid) и agent-mcp (квитанции, метка — action_id)"
"$BIN/evidencestore" dev-pki -out "$WORK/pki" -source "$SRC" -source agent-mcp >/dev/null
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
    {"name": "$SRC", "content_type": "pg/espgtap-v1", "subject_field": "xid", "retention_months": 1, "expect_every": "1h"},
    {"name": "agent-mcp", "content_type": "mcp/receipt-v1", "subject_field": "action_id", "retention_months": 12, "expect_every": "1h"}
  ]
}
EOF
CFG=$WORK/evidencestore.json
mkdir -p "$WORK/keyring-backup" "$WORK/roots-mirror"
"$BIN/evidencestore" init -config "$CFG" >"$WORK/init.txt"
STORE_KEY=$(tail -1 "$WORK/init.txt")
"$BIN/evidencestore" serve -config "$CFG" 2>"$WORK/server.log" &
SERVER=$!
for _ in $(seq 50); do [ -S "$WORK/data/admin.sock" ] && break; sleep 0.1; done
for s in "$SRC:pgtap/journal.jsonl" "agent-mcp:mcp/receipts.jsonl"; do
  cat >"$WORK/collector-${s%%:*}.json" <<EOF
{
  "server": "https://127.0.0.1:$PORT",
  "ca": "pki/ca.crt", "cert": "pki/${s%%:*}.crt", "key": "pki/${s%%:*}.key",
  "store_key": "$STORE_KEY",
  "spool_dir": "spool-${s%%:*}", "file": "${s##*:}", "from_start": true, "flush_every": "200ms"
}
EOF
done
# Сборщики хранилища работают постоянно, как в жизни: строка журнала уезжает сама.
touch "$WORK/pgtap/journal.jsonl" "$WORK/mcp/receipts.jsonl"
"$BIN/escollect" -config "$WORK/collector-$SRC.json" 2>"$WORK/collect.log" &
COLLECT=$!
"$BIN/escollect" -config "$WORK/collector-agent-mcp.json" 2>"$WORK/collect-mcp.log" &
COLLECT_MCP=$!
# MCP-сервер агента. Секция undo — как ему достать до-образы из хранилища и
# чем их проверить: ключ хранилища и доверие к меткам времени заданы здесь.
cat >"$WORK/mcp.json" <<EOF
{
  "dsn": "host=$WORK/sock port=$PGPORT user=agent_bot dbname=shop",
  "agent": "support-bot",
  "receipts": "mcp/receipts.jsonl",
  "undo": {
    "index": "pgtap/index.jsonl",
    "stamp": ["$BIN/evidencestore", "stamp", "-config", "$CFG"],
    "proof": ["$BIN/evidencestore", "proof", "-config", "$CFG", "-source", "$SRC", "-dek"],
    "verify": ["$BIN/esverify", "-store-key", "$STORE_KEY", "-tsa-trust", "$WORK/tsa-root.crt"]
  }
}
EOF
"$BIN/evidencestore" tsa-root -config "$CFG" -out "$WORK/tsa-root.crt" >/dev/null 2>&1

INDEX=$WORK/pgtap/index.jsonl
ALERTS=$WORK/pgtap/alerts.jsonl
# wait_tx XID: дождаться, пока сборщик допишет транзакцию в журнал (строка индекса).
wait_tx() {
  for _ in $(seq 6000); do grep -q "^{\"xid\":$1," "$INDEX" 2>/dev/null && return 0; sleep 0.1; done
  die "транзакция $1 не дошла до журнала сборщика: $(tail -3 "$WORK/pgtap.log")"
}
entry() { grep "^{\"xid\":$1," "$INDEX" | tail -1; }
max_seq() {
  "$BIN/evidencestore" status -config "$CFG" |
    python3 -I -c 'import json,sys; print(next((s["max_seq"] for s in json.load(sys.stdin)["sources"] if s["name"]==sys.argv[1]), 0))' "$1"
}
# shipped ИСТОЧНИК ФАЙЛ: дождаться, пока хранилище примет все строки файла.
shipped() {
  local want
  want=$(wc -l <"$2")
  for _ in $(seq 3000); do [ "$(max_seq "$1")" -ge "$want" ] && return 0; sleep 0.1; done
  die "хранилище не получило записи источника $1: есть $(max_seq "$1"), ждали $want"
}
ship() { shipped "$SRC" "$WORK/pgtap/journal.jsonl"; }
ship_receipts() { shipped agent-mcp "$WORK/mcp/receipts.jsonl"; }
OPDSN="host=$WORK/sock port=$PGPORT user=postgres dbname=shop"
stamp() { "$BIN/evidencestore" stamp -config "$CFG" >/dev/null; }
alerts() { [ -s "$ALERTS" ] && python3 -I -c 'import json,sys; print(" ".join(sorted({json.loads(l)["kind"] for l in open(sys.argv[1]) if json.loads(l)["xid"] == int(sys.argv[2])})))' "$ALERTS" "$1" || true; }
# owner_tx: транзакция владельца (человека) из stdin, печатает её xid.
owner_tx() {
  local body
  body=$(cat)
  PGAPPNAME=human "${OWNER[@]}" -qAt <<SQL | tail -1
begin;
select pg_current_xact_id()::text as xid \gset
$body
commit;
\echo :xid
SQL
}
# fetch XID DIR: записи транзакции пакетами одной записи — готовы сразу после
# метки времени, окно ждать не надо. Номера записей — из индекса сборщика
# (строка журнала = запись источника); что это части именно этой транзакции и
# что они все, проверяет esundo по самим телам.
fetch() {
  local e first last n
  e=$(entry "$1"); first=$(field "$e" first_line); last=$(field "$e" last_line)
  mkdir -p "$2/bodies" "$2/bundles"
  for n in $(seq "$first" "$last"); do
    "$BIN/evidencestore" proof -config "$CFG" -source "$SRC" -seq "$n" -dek -out "$2/bundles/$n.json" >/dev/null 2>&1 || die "пакет записи $n не выдан"
    "$BIN/esverify" -proof "$2/bundles/$n.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -body "$2/bodies/$SRC-$n" >"$2/bundles/$n.txt" 2>&1 ||
      die "запись $n не прошла проверку: $2/bundles/$n.txt"
  done
  echo "$((last - first + 1))"
}

stamp # нижняя граница времени (T1) для всего, что придёт дальше
sleep 1.2
FROM=$(date -u +%FT%T.%NZ)
sleep 1.5

# ---------------------------------------------------------------- агент

step "действие агента через MCP (хорошее): перевод 100.50 со счёта 1 на счёт 2"
R=$(sql_arg "client asked to move funds" <<'SQL' | { mcp execute "$(cat)" || die "действие не прошло"; }
update accounts set balance = balance - 100.50 where id = 1;
update accounts set balance = balance + 100.50 where id = 2;
SQL
)
echo "$R"
GOOD=$(field "$R" xid)
wait_tx "$GOOD"
echo "чтение через MCP: $(mcp query '{"sql": "select id, balance from accounts where id in (1, 2) order by id"}')"

step "что агенту нельзя: права роли в базе, а не разбор текста запроса"
for q in "truncate accounts" "drop table orders" "alter table accounts disable trigger evidence_who" \
  "select pg_logical_emit_message(true, 'evidence/who', '{\"role\":\"postgres\"}')"; do
  if out=$(mcp execute "$(sql_arg "" <<<"$q")"); then die "агенту удалось: $q"; fi
  echo "$q → $(grep -o 'postgres: [^(]*' <<<"$out" | head -1)"
done
[ "$(grep -c '"outcome":"failed"' "$WORK/mcp/receipts.jsonl")" = 4 ] || die "ждали четыре квитанции с исходом failed"
echo "все четыре попытки остались в квитанциях с исходом failed"

step "агент в обход MCP: прямое подключение своей ролью"
BEFORE_ALERTS=$(wc -l <"$ALERTS" 2>/dev/null || echo 0)
PGAPPNAME=some-script "$PGBIN/psql" "${PGCONN[@]}" -U agent_bot -X -q -d shop -c "update accounts set note = 'direct write' where id = 12"
BYPASS=$("${OWNER[@]}" -Atc "select xmin from accounts where id = 12")
wait_tx "$BYPASS"
echo "транзакция $BYPASS записана и без MCP (отметку ставит база): $(field "$(entry "$BYPASS")" who)"
[ "$(alerts "$BYPASS")" = "no-action" ] || die "ждали тревогу no-action, получили: $(alerts "$BYPASS")"
echo "тревога: no-action — у транзакции роли агента нет отметки действия"
# Снимок «как было до плохого действия» — только чтобы в конце сверить итог.
"${OWNER[@]}" -q -c "create table snap.accounts as table accounts" -c "create table snap.orders as table orders" -c "create table snap.docs as table docs"

step "действие агента через MCP (плохое): «закрыть неактивные счета»"
E0=$(size "$WORK/data/evidence"); C0=$(size "$WORK/data/chain"); J0=$(stat -c %s "$WORK/pgtap/journal.jsonl")
T=$(now)
R=$(sql_arg "close inactive accounts" <<SQL | { mcp execute "$(cat)" || die "действие не прошло"; }
update accounts set balance = 0, note = 'closed by support-bot' where id % 3 = 0;
delete from orders where not paid and account_id <> 5;
insert into orders values ($((ROWS + 3)), 1, 'refund', true);
update accounts set note = 'flagged' where id = 3;
delete from orders where account_id = 5;
delete from accounts where id = 5;
update docs set body = (select string_agg(md5(random()::text), '') from generate_series(1, 47000)) where id = 1;
SQL
)
T_TX=$(since "$T")
T_ACTION=$(now)
BAD=$(field "$R" xid)
BAD_ACTION=$(field "$R" action_id)
echo "действие $BAD_ACTION, транзакция $BAD, в базе за $T_TX с"
T=$(now)
wait_tx "$BAD"
T_TAP=$(since "$T")
T=$(now)
ship
T_SHIP=$(since "$T")
ship_receipts
BAD_ENTRY=$(entry "$BAD")
CHANGES=$(field "$BAD_ENTRY" changes)
PARTS=$(($(field "$BAD_ENTRY" last_line) - $(field "$BAD_ENTRY" first_line) + 1))
J1=$(stat -c %s "$WORK/pgtap/journal.jsonl")
echo "изменений строк $CHANGES; в журнале сборщика $PARTS записей, $(((J1 - J0) / 1024)) КБ; сборщик — $T_TAP с, доставка в хранилище — $T_SHIP с"
"${OWNER[@]}" -At -F ' ' -c "select 'счетов с нулём:', count(*) from accounts where balance = 0" -c "select 'заказов осталось:', count(*) from orders" -c "select 'документ 1, байт:', length(body) from docs where id = 1"
[ "$(alerts "$BAD")" = "canary mass-change" ] || die "ждали тревоги canary и mass-change, получили: $(alerts "$BAD")"
echo "тревоги: mass-change (изменений не меньше 500) и canary (тронута строка-ловушка accounts id=3)"
sleep 0.5
E1=$(size "$WORK/data/evidence"); C1=$(size "$WORK/data/chain")
TO=$(date -u +%FT%T.%NZ)

step "человек после агента: правит счёт 6, заново заводит удалённый заказ 1, удаляет заказ-возврат, правит счёт 1"
LINES_BEFORE=$(wc -l <"$INDEX")
owner_tx >/dev/null <<SQL
update accounts set balance = 777.00, note = 'fixed by a human' where id = 6;
insert into orders values (1, 8, 're-entered by a human', false);
delete from orders where id = $((ROWS + 3));
update accounts set note = 'called the client' where id = 1;
SQL
sleep 1.5
[ "$(wc -l <"$INDEX")" = "$LINES_BEFORE" ] || die "транзакция владельца попала в журнал до-образов"
echo "транзакции владельца в журнал до-образов не идут: транзакций в индексе по-прежнему $LINES_BEFORE"

# ---------------------------------------------------------------- до-образы и откат

step "до-образы действия $BAD_ACTION из хранилища: пакеты записей, проверка esverify"
U=$WORK/undo
T=$(now)
stamp
N=$(fetch "$BAD" "$U")
T_FETCH=$(since "$T")
echo "записей $N, каждая VERIFIED; выдача и проверка — $T_FETCH с; от действия агента прошло $(since "$T_ACTION") с"
BUNDLE_BYTES=$(size "$U/bundles")

step "оператор, esundo check: план отката и сверка с базой — что сейчас на месте каждой строки"
T=$(now)
"$BIN/esundo" check -bodies "$U/bodies" -xid "$BAD" -dsn "$OPDSN" -out "$U/plan.json" | tee "$U/check.txt"
T_CHECK=$(since "$T")
grep -q "action $BAD_ACTION: agent support-bot" "$U/check.txt" || die "в до-образах нет отметки действия $BAD_ACTION"
grep -q 'already as before 1, conflicts 2$' "$U/check.txt" || die "ждали два конфликта (счёт 6 и заказ 1) и один шаг «уже сделано» (заказ-возврат человек удалил сам)"

step "гонка: между сверкой и откатом человек правит ещё одну строку (счёт 9)"
state() { "${OWNER[@]}" -At -F ' ' -c "select (select count(*) from accounts where balance = 0), 'счетов с нулём,', (select count(*) from orders), 'заказов'"; }
BEFORE=$(state)
owner_tx >/dev/null <<<"update accounts set note = 'late human edit' where id = 9;"
RC=0
"$BIN/esundo" apply -plan "$U/plan.json" -dsn "$OPDSN" -by nikolay -reason "action $BAD_ACTION closed live accounts" >"$U/race.txt" 2>&1 || RC=$?
[ "$RC" = 3 ] || die "ждали отказ с кодом 3 (строка изменилась после сверки), получили $RC: $(cat "$U/race.txt")"
cat "$U/race.txt"
[ "$(state)" = "$BEFORE" ] || die "сорванный откат что-то применил: было $BEFORE, стало $(state)"
echo "откат не применён вовсе: по-прежнему $BEFORE. Сверка заново:"
"$BIN/esundo" check -bodies "$U/bodies" -xid "$BAD" -dsn "$OPDSN" -out "$U/plan.json" -show 0 | grep '^checked' | tee "$U/check.txt"
grep -q 'conflicts 3$' "$U/check.txt" || die "после правки счёта 9 ждали три конфликта"

step "оператор, esundo apply: одна транзакция"
T=$(now)
"$BIN/esundo" apply -plan "$U/plan.json" -dsn "$OPDSN" -by nikolay -reason "action $BAD_ACTION closed live accounts" | tee "$U/apply.txt"
T_APPLY=$(since "$T")
UNDO=$(sed -n 's/.* in transaction //p' "$U/apply.txt")
[ -n "$UNDO" ] || die "откат не применился"
echo "применён за $T_APPLY с; от действия агента до возврата данных — $(since "$T_ACTION") с"

step "итог: база против снимка до плохого действия"
"${OWNER[@]}" -At -F ' ' >"$U/diff.txt" <<'SQL'
select 'accounts', id from ((table accounts except table snap.accounts) union (table snap.accounts except table accounts)) d group by id
union all
select 'orders', id from ((table orders except table snap.orders) union (table snap.orders except table orders)) d group by id
union all
select 'docs', id from ((table docs except table snap.docs) union (table snap.docs except table docs)) d group by id
order by 1, 2;
SQL
cat "$U/diff.txt"
[ "$(tr '\n' ';' <"$U/diff.txt")" = "accounts 1;accounts 6;accounts 9;orders 1;" ] || die "отличаться должны только счета 1, 6 и 9 (правки человека) и заказ 1 (заведён человеком)"
echo "отличаются от снимка только четыре строки, которые после агента тронул человек; документ в 1,5 МБ вернулся"

step "повторная сверка: применять нечего"
"$BIN/esundo" check -bodies "$U/bodies" -xid "$BAD" -dsn "$OPDSN" -show 0 | grep '^checked' | tee "$U/check2.txt"
grep -q 'to apply 0,' "$U/check2.txt" || die "вторая сверка нашла, что применять"

step "сам откат — тоже транзакция в журнале: кто, что и почему откатил"
wait_tx "$UNDO"
ship
stamp
mkdir -p "$WORK/undo-tx"
fetch "$UNDO" "$WORK/undo-tx" >/dev/null
"$BIN/esundo" check -bodies "$WORK/undo-tx/bodies" -xid "$UNDO" >"$WORK/undo-tx/plan.txt"
head -2 "$WORK/undo-tx/plan.txt" | cut -c1-230
grep -q "\"undoes_xid\":\"$BAD\"" "$WORK/undo-tx/plan.txt" || die "в записи отката нет ссылки на транзакцию $BAD"

step "квитанция действия из источника agent-mcp: что агент просил"
ship_receipts
stamp
RSEQ=$(grep -n "\"action_id\":\"$BAD_ACTION\"" "$WORK/mcp/receipts.jsonl" | cut -d: -f1)
"$BIN/evidencestore" proof -config "$CFG" -source agent-mcp -seq "$RSEQ" -dek -out "$WORK/receipt.json" >/dev/null 2>&1 || die "пакет квитанции не выдан"
"$BIN/esverify" -proof "$WORK/receipt.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -body "$WORK/receipt.txt" >/dev/null 2>&1 || die "квитанция не прошла проверку"
python3 -I - "$WORK/receipt.txt" "$BAD_ACTION" "$BAD" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
assert r["action_id"] == sys.argv[2] and r["xid"] == sys.argv[3] and r["outcome"] == "committed", r
print(f"VERIFIED: действие {r['action_id']}, агент {r['agent']}, транзакция {r['xid']}, причина «{r['reason']}», запрос на {len(r['sql'])} байт")
PY

# ---------------------------------------------------------------- откат через MCP

step "агент ошибается ещё раз и откатывает себя сам: инструменты MCP undo_preview и undo_apply"
R=$(mcp execute "$(sql_arg "double the bonus" <<<"update accounts set balance = balance * 2 where id between 100 and 199")") || die "действие не прошло"
ACT2=$(field "$R" action_id); XID2=$(field "$R" xid)
T_ACTION2=$(now)
echo "действие $ACT2, транзакция $XID2: балансы ста счетов удвоены"
"${OWNER[@]}" -qc "update accounts set note = 'human touched 150' where id = 150"
P=$(mcp undo_preview "{\"action_id\": \"$ACT2\"}") || die "undo_preview: $P"
python3 -I "$HERE/preview_check.py" "$P"
A=$(mcp undo_apply "{\"action_id\": \"$ACT2\", \"reason\": \"bonus applied twice\"}") || die "undo_apply: $A"
UNDO2=$(field "$A" undo_xid)
echo "undo_apply: возвращено $(field "$A" applied) строк транзакцией $UNDO2, действие отката $(field "$A" undo_action_id); от ошибки до возврата — $(since "$T_ACTION2") с"
[ "$("${OWNER[@]}" -Atc "select count(*) from accounts a join snap.accounts s using (id) where a.id between 100 and 199 and a.balance <> s.balance")" = 1 ] ||
  die "после отката через MCP отличаться от снимка должен только счёт 150 (его правил человек)"
wait_tx "$UNDO2"
E=$(entry "$UNDO2")
[ "$(alerts "$UNDO2")" = "" ] || die "откат через MCP поднял тревогу: $(alerts "$UNDO2")"
echo "в журнале сборщика откат — транзакция роли $(python3 -I -c 'import json,sys; e=json.loads(sys.argv[1]); print(e["who"]["role"], "с отметкой отката действия", e["undo"]["info"]["undoes_action"])' "$E")"
grep -q "\"tool\":\"undo_apply\".*\"undoes\":\"$ACT2\"" "$WORK/mcp/receipts.jsonl" || die "нет квитанции отката"

# ---------------------------------------------------------------- окно времени

if [ "$WINDOW" = 1 ]; then
  step "пакет по окну времени (доказывает, что записей транзакции больше нет): ждём 135 с"
  sleep 135
  tick() { wait_tx "$(field "$(mcp execute "$(sql_arg tick <<<"update docs set body = '$1' where id = 2")")" xid)"; ship; }
  tick "tick 1"
  stamp # закрывающая метка
  tick "tick 2"
  stamp # её хвосты источников — верхний край пакета
  W=$WORK/window
  mkdir -p "$W"
  "$BIN/evidencestore" proof -config "$CFG" -source "$SRC" -subject "$BAD" -from "$FROM" -to "$TO" -out "$W/bundle.json" >/dev/null 2>&1 || die "пакет по окну не выдан"
  "$BIN/esverify" -proof "$W/bundle.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -json >"$W/report.json"
  "$BIN/esverify" -proof "$W/bundle.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -bodies "$W/bodies" >"$W/esverify.txt" 2>&1
  grep -q '^VERIFIED' "$W/esverify.txt" || die "пакет по окну не прошёл проверку"
  "$BIN/esundo" check -bodies "$W/bodies" -xid "$BAD" -dsn "$OPDSN" -out "$W/plan.json" >/dev/null
  python3 -I - "$U/plan.json" "$W/plan.json" "$W/report.json" "$(stat -c %s "$W/bundle.json")" <<'PY'
import json, sys
a, b, rep = (json.load(open(p)) for p in sys.argv[1:4])
assert a["steps"] == b["steps"] and a["changes"] == b["changes"], "планы по пакетам записей и по окну разошлись"
s = rep["subject"]
assert s["unlabeled"] == 0 and s["opened"] == s["records"], s
print(f"VERIFIED: в окне записей источника {rep['records_in_window']}, этой транзакции {s['records']} (открыто {s['opened']}), чужих закрытых {s['others_closed']}, без метки {s['unlabeled']}")
print(f"план из пакета по окну совпал с планом из пакетов записей: {len(a['steps'])} шагов; пакет — {int(sys.argv[4]) // 1024} КБ")
PY
fi

# ---------------------------------------------------------------- числа

step "объём плохого действия"
TABLES=$("${OWNER[@]}" -Atc "select pg_total_relation_size('accounts') + pg_total_relation_size('orders') + pg_total_relation_size('docs')")
python3 -I - "$CHANGES" "$((J1 - J0))" "$((E1 - E0))" "$((C1 - C0))" "$BUNDLE_BYTES" "$T_TAP" "$T_SHIP" "$T_FETCH" "$T_CHECK" "$T_APPLY" "$TABLES" "$PARTS" <<'PY'
import sys
ch, journal, ev, chain, bundles, tap, ship, fetch, check, apply, tables, parts = [float(x) for x in sys.argv[1:]]
print(f"изменений строк: {int(ch)}, записей хранилища: {int(parts)}")
print(f"журнал сборщика: {journal/1024:.0f} КБ ({journal/ch:.0f} байт на изменение)")
print(f"хранилище, журнал улик: +{ev/1024:.0f} КБ ({ev/ch:.0f} байт на изменение); цепь: +{chain/1024:.1f} КБ")
print(f"сборщик: {tap:.2f} с; доставка в хранилище: {ship:.2f} с")
print(f"пакеты записей: {bundles/1024:.0f} КБ; выдача и проверка: {fetch:.2f} с")
print(f"сверка с базой: {check:.2f} с; применение отката: {apply:.2f} с")
print(f"для масштаба: три таблицы целиком, с индексами, — {tables/1024:.0f} КБ; действие заняло в хранилище {(ev+chain)/tables:.2f} такого объёма")
PY
kill "$TAP" 2>/dev/null; wait "$TAP" 2>/dev/null || true
grep -o 'msg=stopped.*' "$WORK/pgtap.log" | sed 's/^msg=stopped/сборщик за прогон:/'
echo
echo "каталог стенда: $WORK"
