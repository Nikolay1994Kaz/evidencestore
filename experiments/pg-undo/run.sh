#!/usr/bin/env bash
# Сценарий «аудит + откат» на живом Postgres, на частях этой ветки:
#
#   ИИ-агент → esmcp (MCP-сервер): запрос идёт ролью агента, в транзакции — отметка действия
#   Postgres: триггер пишет в журнал роль сессии; права роли — то, что агенту можно
#     → escollect, источник "postgres": логическая репликация (pgoutput), только транзакции
#                агента и отката, сжатые части прямо в буфер сборщика, тревоги
#     → evidencestore: источник с "subject_field": "xid"   (хранилище не изменено)
#     → пакеты записей транзакции → esverify → esundo: обратные операции, сверка с базой,
#                одна транзакция отката; сам откат тоже ложится в хранилище
#   Сборщик один: тот же процесс escollect вторым источником читает файл квитанций MCP.
#   Тревоги сборщик несёт людям сам: Telegram, Slack-совместимый веб-хук, свой адрес в JSON
#   (здесь все три — местный приёмник hook_server.py). В тревоге — готовая команда отката.
#   У MCP-сервера — предел строк на действие: больше — откат до фиксации и тревога.
#   Там же — таймер на запрос агента (отмена на сервере базы), предел действий в минуту и
#   строк за окно (счёт по файлу квитанций). У сборщика — страница /metrics.
#   Откат делают двое: оператор командой esundo и сам агент инструментом MCP undo_apply.
#
# Что происходит: агент делает хорошее действие и плохое (обнуляет треть счетов,
# удаляет заказы, удаляет счёт, портит документ в 1,5 МБ). Человек после него
# правит несколько строк руками, одну — между сверкой и откатом. Откат плохого
# действия возвращает всё, кроме тронутого человеком. По дороге: агенту отказано
# в TRUNCATE, DROP и подделке отметки; транзакция в обход MCP поднимает тревогу.
# В конце сборщик убивают (kill -9) и перезапускают базу: записи не теряются и
# не двоятся, сборщик подключается к базе сам.
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
HOOKPORT=${HOOKPORT:-$((PORT + 1))}
METRICSPORT=${METRICSPORT:-$((PORT + 2))}
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
for b in evidencestore escollect esverify esmcp esundo; do [ -x "$BIN/$b" ] || die "нет $BIN/$b"; done

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
  kill "${SERVER:-}" "${COLLECT:-}" "${HOOK:-}" 2>/dev/null || true
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
-- PostgreSQL 14 и старше дают PUBLIC право CREATE на схеме public; роль агента
-- с ним -setup-sql не берёт (свои функции заслонили бы системные, P-242).
revoke create on schema public from public;
SQL
echo "accounts: $ROWS строк, orders: $((ROWS / 2 + 2))"

# mcp ИНСТРУМЕНТ JSON: вызов инструмента так, как его делает агент (stdio, ревизия MCP 2026-07-28).
mcp() { python3 -I "$HERE/mcp_call.py" "$BIN/esmcp" "$WORK/mcp.json" "$1" "$2" 2>>"$WORK/mcp.log"; }
sql_arg() { python3 -I -c 'import json,sys; print(json.dumps({"sql": sys.stdin.read(), "reason": sys.argv[1]}))' "$1"; }
# stmts_arg ПРИЧИНА: команды со стандартного ввода, по одной на строку («;» в конце строки — не часть команды) → {"statements": […]}.
stmts_arg() { python3 -I -c 'import json,sys; print(json.dumps({"statements": [l.strip().rstrip(";").rstrip() for l in sys.stdin if l.strip()], "reason": sys.argv[1]}))' "$1"; }

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
    {"name": "$SRC", "content_type": "pg/before-images-v1", "subject_field": "xid", "retention_months": 1, "expect_every": "1h"},
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

step "сборщик: один escollect, два источника — журнал базы и файл квитанций MCP"
# Общее (сервер, УЦ, ключ хранилища) — наверху; у источника свои сертификат,
# буфер и вход. Раздел "postgres" — он же вход для -setup-sql.
mkdir -p "$WORK/mcp"
cat >"$WORK/collector.json" <<EOF
{
  "server": "https://127.0.0.1:$PORT",
  "ca": "pki/ca.crt",
  "store_key": "$STORE_KEY",
  "flush_every": "200ms",
  "metrics_listen": "127.0.0.1:$METRICSPORT",
  "sources": [
    {"cert": "pki/$SRC.crt", "key": "pki/$SRC.key", "spool_dir": "spool-$SRC",
     "postgres": {
       "dsn": "host=$WORK/sock port=$PGPORT user=evidence_tap dbname=shop",
       "dir": "pg-index",
       "mcp_roles": ["esmcp_bot"],
       "roles": ["agent_bot"],
       "undo_roles": ["undo_op"],
       "tables": ["public.accounts", "public.orders", "public.docs"],
       "alert_rows": 500,
       "require_action": true,
       "canaries": [{"table": "public.accounts", "column": "id", "value": "3"}],
       "status_every": "1s",
       "down_after": "1s",
       "notify": {
         "undo_hint": "$BIN/esundo check -config $WORK/undo.json -xid {xid}",
         "to": [
           {"type": "telegram", "url": "http://127.0.0.1:$HOOKPORT", "token": "123456:DEMO-TOKEN", "chat": "-1001234567890"},
           {"type": "slack", "url": "http://127.0.0.1:$HOOKPORT/services/T0/B0/DEMO"},
           {"type": "json", "url": "http://127.0.0.1:$HOOKPORT/alerts"}
         ]}}},
    {"cert": "pki/agent-mcp.crt", "key": "pki/agent-mcp.key", "spool_dir": "spool-agent-mcp",
     "file": "mcp/receipts.jsonl", "from_start": true}
  ]
}
EOF
"$BIN/escollect" -config "$WORK/collector.json" -setup-sql >"$WORK/setup.sql"
PGOPTIONS='-c client_min_messages=warning' "${OWNER[@]}" -q -f "$WORK/setup.sql"
grep -c . "$WORK/setup.sql" | sed 's/$/ строк SQL (escollect -setup-sql): роли сервера esmcp_bot (запись), агента agent_bot (чтение) и отката undo_op, триггер отметки на трёх таблицах, публикация, роль сборщика/'
touch "$WORK/mcp/receipts.jsonl"
# Получатель тревог: местный приёмник вместо Telegram, Slack и своего адреса.
HOOKS=$WORK/hooks.jsonl
: >"$HOOKS"
python3 -I "$HERE/hook_server.py" "$HOOKPORT" "$HOOKS" &
HOOK=$!
# hooked ПУТЬ СЛОВО: дождаться сообщения по этому пути со словом в тексте, напечатать текст.
hooked() {
  for _ in $(seq 150); do
    if python3 -I - "$HOOKS" "$1" "$2" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    m = json.loads(line)
    if sys.argv[2] in m["path"] and sys.argv[3] in m["body"].get("text", ""):
        print(m["body"]["text"])
        sys.exit(0)
sys.exit(1)
PY
    then return 0; fi
    sleep 0.1
  done
  die "тревога со словом «$2» не пришла на $1: $(tail -2 "$WORK/collect.log")"
}
# Сборщик работает постоянно, как в жизни: запись уезжает сама.
start_collector() {
  "$BIN/escollect" -config "$WORK/collector.json" 2>>"$WORK/collect.log" &
  COLLECT=$!
}
start_collector
for _ in $(seq 100); do grep -q 'msg="reading the database log"' "$WORK/collect.log" 2>/dev/null && break; sleep 0.1; done
grep -q 'msg="reading the database log"' "$WORK/collect.log" || die "сборщик не начал читать журнал базы: $(cat "$WORK/collect.log")"
ls "$WORK" | grep -c '^spool-' | sed 's/$/ буфера, процесс один; отдельной программы для базы и файла-посредника между ними нет/'
# MCP-сервер агента. Секция undo — как ему достать до-образы из хранилища и
# чем их проверить: ключ хранилища и доверие к меткам времени заданы здесь.
cat >"$WORK/mcp.json" <<EOF
{
  "dsn": "host=$WORK/sock port=$PGPORT user=esmcp_bot dbname=shop",
  "agent": "support-bot",
  "receipts": "mcp/receipts.jsonl",
  "action_row_limit": $ROWS,
  "undo": {
    "index": "pg-index/index.jsonl",
    "stamp": ["$BIN/evidencestore", "stamp", "-config", "$CFG"],
    "proof": ["$BIN/evidencestore", "proof", "-config", "$CFG", "-source", "$SRC", "-dek"],
    "verify": ["$BIN/esverify", "-store-key", "$STORE_KEY", "-tsa-trust", "$WORK/tsa-root.crt"]
  }
}
EOF
"$BIN/evidencestore" tsa-root -config "$CFG" -out "$WORK/tsa-root.crt" >/dev/null 2>&1
# Второй агент — со строгими пределами: секунда на запрос, четыре действия в
# минуту, 50 строк за десять минут. Квитанции — в тот же файл.
cat >"$WORK/mcp-strict.json" <<EOF
{
  "dsn": "host=$WORK/sock port=$PGPORT user=esmcp_bot dbname=shop",
  "agent": "batch-bot",
  "receipts": "mcp/receipts.jsonl",
  "statement_timeout": "1s",
  "actions_per_minute": 4,
  "window_rows": 50,
  "window": "10m"
}
EOF
mcp_strict() { python3 -I "$HERE/mcp_call.py" "$BIN/esmcp" "$WORK/mcp-strict.json" "$1" "$2" 2>>"$WORK/mcp.log"; }
# Настройки оператора для esundo: база и то, как достать записи из хранилища.
# Оператор откатывает ролью отката: не владелец и не суперпользователь (DECISIONS, п. 39).
OPDSN="host=$WORK/sock port=$PGPORT user=undo_op dbname=shop"
cat >"$WORK/undo.json" <<EOF
{
  "dsn": "$OPDSN",
  "index": "pg-index/index.jsonl",
  "stamp": ["$BIN/evidencestore", "stamp", "-config", "$CFG"],
  "proof": ["$BIN/evidencestore", "proof", "-config", "$CFG", "-source", "$SRC", "-dek"],
  "verify": ["$BIN/esverify", "-store-key", "$STORE_KEY", "-tsa-trust", "$WORK/tsa-root.crt"]
}
EOF
# Настройки с паролями ролей сервера и отката — только владельцу файла: агент (и пользователь ОС
# postgres, чьими правами база читает файлы) их не прочтёт (DECISIONS, п. 39; R1-2, T-6).
chmod 600 "$WORK/mcp.json" "$WORK/mcp-strict.json" "$WORK/undo.json"

INDEX=$WORK/pg-index/index.jsonl
ALERTS=$WORK/pg-index/alerts.jsonl
# wait_tx XID: дождаться, пока сборщик прочитает транзакцию (строка справочника).
wait_tx() {
  for _ in $(seq 6000); do grep -q "^{\"xid\":$1," "$INDEX" 2>/dev/null && return 0; sleep 0.1; done
  die "транзакция $1 не дошла до сборщика: $(tail -3 "$WORK/collect.log")"
}
entry() { grep "^{\"xid\":$1," "$INDEX" | tail -1; }
max_seq() {
  "$BIN/evidencestore" status -config "$CFG" |
    python3 -I -c 'import json,sys; print(next((s["max_seq"] for s in json.load(sys.stdin)["sources"] if s["name"]==sys.argv[1]), 0))' "$1"
}
# shipped ИСТОЧНИК НОМЕР: дождаться, пока хранилище примет запись с этим номером.
shipped() {
  for _ in $(seq 3000); do [ "$(max_seq "$1")" -ge "$2" ] && return 0; sleep 0.1; done
  die "хранилище не получило записи источника $1: есть $(max_seq "$1"), ждали $2"
}
# ship: всё, что сборщик прочитал из базы, — в хранилище. Номера записей
# транзакции сборщик пишет в справочник сам: это номера, под которыми он их шлёт.
ship() { shipped "$SRC" "$(field "$(tail -1 "$INDEX")" last_seq)"; }
# Квитанции — обычный файл, читается с начала: номер записи = номер строки.
ship_receipts() { shipped agent-mcp "$(wc -l <"$WORK/mcp/receipts.jsonl")"; }
stamp() { "$BIN/evidencestore" stamp -config "$CFG" >/dev/null; }
alerts() { [ -s "$ALERTS" ] && python3 -I -c 'import json,sys; print(" ".join(sorted({s["kind"] for e in map(json.loads, open(sys.argv[1])) if e.get("xid") == int(sys.argv[2]) for s in e["signals"]})))' "$ALERTS" "$1" || true; }
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
# метки времени, окно ждать не надо. Номера записей — из справочника сборщика;
# что это части именно этой транзакции и что они все, проверяет esundo по
# самим телам.
fetch() {
  local e first last n
  e=$(entry "$1"); first=$(field "$e" first_seq); last=$(field "$e" last_seq)
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
R=$(stmts_arg "client asked to move funds" <<'SQL' | { mcp execute "$(cat)" || die "действие не прошло"; }
update accounts set balance = balance - 100.50 where id = 1;
update accounts set balance = balance + 100.50 where id = 2;
SQL
)
echo "$R"
GOOD=$(field "$R" xid)
wait_tx "$GOOD"
echo "чтение через MCP: $(mcp query '{"sql": "select id, balance from accounts where id in (1, 2) order by id"}')"

step "что агенту нельзя: в базу идут только SELECT, INSERT, UPDATE, DELETE, MERGE (решает грамматика базы), остальное — права роли"
for q in "truncate accounts" "drop table orders" "alter table accounts disable trigger evidence_who" \
  "select pg_logical_emit_message(true, 'evidence/who', '{\"role\":\"postgres\"}')" \
  "select pg_terminate_backend(pid) from pg_stat_activity where usename = 'esmcp_bot'"; do
  if out=$(mcp execute "$(sql_arg "" <<<"$q")"); then die "агенту удалось: $q"; fi
  echo "$q → $(grep -o 'postgres: [^(]*' <<<"$out" | head -1)"
done
[ "$(grep -c '"outcome":"failed"' "$WORK/mcp/receipts.jsonl")" = 5 ] || die "ждали пять квитанций с исходом failed"
echo "все пять попыток остались в квитанциях с исходом failed; три первые база отвергла при разборе, подделку отметки и обрыв сеансов сервера — правами роли"

step "агент сам закрывает транзакцию сервера: BEGIN … COMMIT, COMMIT в списке команд, чтение с COMMIT"
DOCS=$("${OWNER[@]}" -Atc "select md5(string_agg(id || coalesce(body, ''), ',' order by id)) from docs")
for a in "$(sql_arg "" <<<"begin; delete from docs; commit;")" "$(printf '%s\n' "delete from docs" "commit" | stmts_arg "")" \
  "$(sql_arg "" <<<"commit; update docs set body = 'x' where id = 2")" "$(printf '%s\n' "update docs set body = 'x' where id = 2" "end" | stmts_arg "")"; do
  if out=$(mcp execute "$a"); then die "агенту удалось: $a"; fi
  grep -q "was not taken, nothing ran" <<<"$out" || die "ждали отказ до исполнения: $out"
  echo "$(tr -d '\n' <<<"$a" | cut -c1-90) → $(grep -o 'postgres: [^(]*' <<<"$out" | head -1)"
done
if out=$(mcp query "$(sql_arg "" <<<"commit; insert into docs values (99, 'q')")"); then die "чтение с COMMIT прошло: $out"; fi
grep -q "takes one SELECT" <<<"$out" || die "ждали отказ чтению: $out"
[ "$("${OWNER[@]}" -Atc "select md5(string_agg(id || coalesce(body, ''), ',' order by id)) from docs")" = "$DOCS" ] || die "таблица docs изменилась"
echo "ни одна команда не исполнилась, docs не тронута: транзакцию ведёт сервер, команды агента идут в PREPARE"

step "агент в обход MCP: своя роль agent_bot — только чтение, сервер — другая роль"
AGENT=("$PGBIN/psql" "${PGCONN[@]}" -U agent_bot -X -q -d shop)
"${AGENT[@]}" -Atc "select count(*) from accounts" | sed 's/$/ счетов агент читает своей ролью/'
# Сеанс сервера на время проверки: держит его отдельный esmcp (stdio открыт, пока ждёт sleep).
( sleep 3 | "$BIN/esmcp" -config "$WORK/mcp.json" >/dev/null 2>&1 ) &
HOLD=$!
for _ in $(seq 50); do
  SERVER_PID=$("${OWNER[@]}" -Atc "select pid from pg_stat_activity where usename = 'esmcp_bot' limit 1")
  [ -n "$SERVER_PID" ] && break; sleep 0.05
done
[ -n "$SERVER_PID" ] || die "сеанс esmcp в базе не появился"
for a in "update accounts set note = 'direct write' where id = 12" \
         "select evidence.mark_action('{\"action_id\": \"forged\"}')" \
         "select pg_terminate_backend($SERVER_PID)" \
         "alter role esmcp_bot set statement_timeout = 1"; do
  if out=$("${AGENT[@]}" -c "$a" 2>&1); then die "агенту удалось: $a"; fi
  echo "$(cut -c1-70 <<<"$a") → $(grep -o 'ERROR: .*' <<<"$out" | head -1)"
done
wait "$HOLD"
[ "$("${OWNER[@]}" -Atc "select note from accounts where id = 12")" != "direct write" ] || die "агент записал мимо сервера"
echo "ни записи, ни отметки, ни обрыва сеансов сервера, ни его настроек: граница — роли базы (п. 39)"

# Снимок «как было до плохого действия» — только чтобы в конце сверить итог.
"${OWNER[@]}" -q -c "create table snap.accounts as table accounts" -c "create table snap.orders as table orders" -c "create table snap.docs as table docs"

step "действие агента через MCP (плохое): «закрыть неактивные счета»"
E0=$(size "$WORK/data/evidence"); C0=$(size "$WORK/data/chain")
T=$(now)
R=$(stmts_arg "close inactive accounts" <<SQL | { mcp execute "$(cat)" || die "действие не прошло"; }
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
PARTS=$(($(field "$BAD_ENTRY" last_seq) - $(field "$BAD_ENTRY" first_seq) + 1))
echo "изменений строк $CHANGES, записей $PARTS; в буфере сборщика через $T_TAP с после фиксации, в хранилище — ещё через $T_SHIP с"
"${OWNER[@]}" -At -F ' ' -c "select 'счетов с нулём:', count(*) from accounts where balance = 0" -c "select 'заказов осталось:', count(*) from orders" -c "select 'документ 1, байт:', length(body) from docs where id = 1"
[ "$(alerts "$BAD")" = "canary mass-change" ] || die "ждали тревоги canary и mass-change, получили: $(alerts "$BAD")"
[ "$(grep -c "\"xid\":$BAD," "$ALERTS")" = 1 ] || die "на транзакцию $BAD должна быть одна строка тревоги"
echo "тревоги mass-change (изменений не меньше 500) и canary (тронута строка-ловушка accounts id=3) — одним сообщением."
ALERT_TEXT=$(hooked /services/T0/B0/DEMO "agent transaction $BAD")
echo "Как оно пришло в Slack-совместимый веб-хук (через $(since "$T_ACTION") с после действия):"
sed 's/^/    /' <<<"$ALERT_TEXT"
grep -q "action: $BAD_ACTION, agent support-bot" <<<"$ALERT_TEXT" || die "в тревоге нет действия $BAD_ACTION"
[ "$(grep -c '• canary' <<<"$ALERT_TEXT")" = 1 ] || die "ловушка в сообщении должна быть названа один раз"
hooked /bot123456:DEMO-TOKEN/sendMessage "agent transaction $BAD" >/dev/null
hooked /alerts "agent transaction $BAD" >/dev/null
# Команда отката — прямо из текста тревоги.
UNDO_CMD=$(sed -n 's/^undo preview: //p' <<<"$ALERT_TEXT")
[ -n "$UNDO_CMD" ] || die "в тревоге нет команды отката"
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
[ "$(wc -l <"$INDEX")" = "$LINES_BEFORE" ] || die "транзакция владельца попала в записи до-образов"
echo "транзакции владельца в хранилище не идут: транзакций в справочнике по-прежнему $LINES_BEFORE"

# ---------------------------------------------------------------- до-образы и откат

step "до-образы действия $BAD_ACTION из хранилища: пакеты записей, проверка esverify"
U=$WORK/undo
T=$(now)
stamp
N=$(fetch "$BAD" "$U")
T_FETCH=$(since "$T")
echo "записей $N, каждая VERIFIED; выдача и проверка — $T_FETCH с; от действия агента прошло $(since "$T_ACTION") с"
BUNDLE_BYTES=$(size "$U/bundles")

step "оператор выполняет команду из тревоги: записи из хранилища, план отката, сверка с базой"
echo "\$ $UNDO_CMD -out plan.json"
T=$(now)
# shellcheck disable=SC2086
$UNDO_CMD -out "$U/plan.json" >"$U/check.txt"
T_CHECK=$(since "$T")
cat "$U/check.txt"
grep -q "^fetched from the store and verified: $N records" "$U/check.txt" || die "esundo не достал записи из хранилища сам"
grep -q "^to apply it: $BIN/esundo apply -config $WORK/undo.json -plan $U/plan.json" "$U/check.txt" || die "esundo не подсказал команду применения"
grep -q "action $BAD_ACTION: agent support-bot" "$U/check.txt" || die "в до-образах нет отметки действия $BAD_ACTION"
grep -q 'already as before 1, conflicts 2$' "$U/check.txt" || die "ждали два конфликта (счёт 6 и заказ 1) и один шаг «уже сделано» (заказ-возврат человек удалил сам)"

step "гонка: между сверкой и откатом человек правит ещё одну строку (счёт 9)"
state() { "${OWNER[@]}" -At -F ' ' -c "select (select count(*) from accounts where balance = 0), 'счетов с нулём,', (select count(*) from orders), 'заказов'"; }
BEFORE=$(state)
owner_tx >/dev/null <<<"update accounts set note = 'late human edit' where id = 9;"
RC=0
"$BIN/esundo" apply -config "$WORK/undo.json" -plan "$U/plan.json" -by nikolay -reason "action $BAD_ACTION closed live accounts" >"$U/race.txt" 2>&1 || RC=$?
[ "$RC" = 3 ] || die "ждали отказ с кодом 3 (строка изменилась после сверки), получили $RC: $(cat "$U/race.txt")"
cat "$U/race.txt"
[ "$(state)" = "$BEFORE" ] || die "сорванный откат что-то применил: было $BEFORE, стало $(state)"
echo "откат не применён вовсе: по-прежнему $BEFORE. Сверка заново:"
"$BIN/esundo" check -config "$WORK/undo.json" -xid "$BAD" -out "$U/plan.json" -show 0 >"$U/check.txt"
grep '^checked against' "$U/check.txt"
grep -q 'conflicts 3$' "$U/check.txt" || die "после правки счёта 9 ждали три конфликта"

step "оператор, esundo apply: одна транзакция"
T=$(now)
"$BIN/esundo" apply -config "$WORK/undo.json" -plan "$U/plan.json" -by nikolay -reason "action $BAD_ACTION closed live accounts" | tee "$U/apply.txt"
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

step "сам откат — тоже запись в хранилище: кто, что и почему откатил"
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
echo "в справочнике сборщика откат — транзакция роли $(python3 -I -c 'import json,sys; e=json.loads(sys.argv[1]); print(e["who"]["role"], "с отметкой отката действия", e["undo"]["info"]["undoes_action"])' "$E")"
grep -q "\"tool\":\"undo_apply\".*\"undoes\":\"$ACT2\"" "$WORK/mcp/receipts.jsonl" || die "нет квитанции отката"

# ---------------------------------------------------------------- окно времени

if [ "$WINDOW" = 1 ]; then
  step "пакет по окну времени (доказывает, что записей транзакции больше нет): ждём 135 с"
  sleep 135
  wtick() { wait_tx "$(field "$(mcp execute "$(sql_arg tick <<<"update docs set body = '$1' where id = 2")")" xid)"; ship; }
  wtick "tick 1"
  stamp # закрывающая метка
  wtick "tick 2"
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

# ---------------------------------------------------------------- предохранитель

step "предохранитель: агент хочет изменить больше строк, чем разрешено одному действию ($ROWS)"
NOTES=$("${OWNER[@]}" -Atc "select md5(string_agg(coalesce(note, '') || id, ',' order by id)) from accounts")
INDEX_BEFORE=$(wc -l <"$INDEX")
if R=$(mcp execute "$(printf '%s\n' "update accounts set note = 'normalized'" "update orders set item = upper(item)" | stmts_arg "normalize everything")"); then die "действие сверх предела прошло: $R"; fi
cut -c1-250 <<<"$R"
grep -q "was refused and rolled back, nothing changed" <<<"$R" || die "ждали отказ"
[ "$("${OWNER[@]}" -Atc "select md5(string_agg(coalesce(note, '') || id, ',' order by id)) from accounts")" = "$NOTES" ] || die "отказанное действие изменило строки"
grep -q '"outcome":"refused"' "$WORK/mcp/receipts.jsonl" || die "нет квитанции с исходом refused"
REFUSED=$(hooked /services/T0/B0/DEMO "• refused:")
sed 's/^/    /' <<<"$REFUSED"
grep -q 'reason given: "normalize everything"' <<<"$REFUSED" || die "в тревоге об отказе нет причины действия"
[ "$(wc -l <"$INDEX")" = "$INDEX_BEFORE" ] || die "отказанное действие попало в хранилище как транзакция"
echo "в базе ничего не изменилось, записей в хранилище нет; люди узнали из тревоги, квитанция — с исходом refused"

# ---------------------------------------------------------------- таймер и частота

step "таймер: запрос агента идёт дольше секунды (и сам снимает себе таймаут базы)"
T=$(now)
if R=$(mcp_strict execute "$(printf '%s\n' "select set_config('statement_timeout', '0', true)" "select set_config('lock_timeout', '0', true)" "select pg_sleep(30)" | stmts_arg "heavy report")"); then die "зависший запрос прошёл: $R"; fi
cut -c1-200 <<<"$R"
grep -q "ran longer than 1s and was cancelled" <<<"$R" || die "ждали отмену по таймеру"
TOOK=$(since "$T")
python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) < 10 else 1)' "$TOOK" || die "отмена заняла $TOOK с"
[ "$("${OWNER[@]}" -Atc "select count(*) from pg_stat_activity where application_name = 'esmcp/batch-bot' and state = 'active'")" = 0 ] ||
  die "запрос агента всё ещё идёт на сервере базы"
echo "отменён через $TOOK с; на сервере базы запрос не идёт: set_config в запросе агента таймер MCP-сервера не снимает"
hooked /alerts "ran longer than 1s" | sed -n '2p' | sed 's/^/    /'

step "строки за окно: агент дробит большое изменение на части (предел — 50 строк за 10 минут)"
for part in 1 2; do
  R=$(mcp_strict execute "$(sql_arg "part $part of a big change" <<<"update accounts set note = 'part $part' where id between $((part * 100)) and $((part * 100 + 19))")") || die "часть $part не прошла: $R"
done
echo "две части по 20 строк прошли"
if R=$(mcp_strict execute "$(sql_arg "part 3 of a big change" <<<"update accounts set note = 'part 3' where id between 300 and 319")"); then die "третья часть прошла: $R"; fi
cut -c1-230 <<<"$R"
grep -q "would have changed 60 rows in the last 10m0s, and the limit is 50" <<<"$R" || die "ждали отказ по строкам за окно"
[ "$("${OWNER[@]}" -Atc "select count(*) from accounts where note = 'part 3'")" = 0 ] || die "третья часть изменила строки"
hooked /alerts "would have changed 60 rows in 10m0s" | sed -n '2p' | sed 's/^/    /'

step "частота: пятое действие за минуту (предел — четыре), потом ещё одно"
if R=$(mcp_strict execute "$(sql_arg "again" <<<"update accounts set note = 'again' where id = 400")"); then die "пятое действие за минуту прошло: $R"; fi
cut -c1-230 <<<"$R"
grep -q "4 actions in the last minute, and the limit is 4" <<<"$R" || die "ждали отказ по частоте"
if R=$(mcp_strict execute "$(sql_arg "and again" <<<"update accounts set note = 'again' where id = 400")"); then die "шестое действие за минуту прошло: $R"; fi
[ "$("${OWNER[@]}" -Atc "select count(*) from accounts where note = 'again'")" = 0 ] || die "отказанное действие изменило строки"
[ "$(grep -c '"agent":"batch-bot".*"cause":"rate"' "$WORK/mcp/receipts.jsonl")" = 2 ] || die "в квитанциях должны быть оба отказа по частоте"
hooked /alerts "refuses the agent's actions" | sed -n '2p' | sed 's/^/    /'
sleep 1
[ "$(grep -c "refuses the agent's actions" "$ALERTS")" = 1 ] || die "тревога о частоте должна быть одна, а не на каждый отказ"
echo "оба отказа — в квитанциях, тревога людям — одна; счёт шёл по файлу квитанций: каждое действие — новый сеанс сервера"

# ---------------------------------------------------------------- показатели

step "страница показателей сборщика (/metrics): оба источника, слот, очередь тревог"
python3 -I - "http://127.0.0.1:$METRICSPORT/metrics" >"$WORK/metrics.txt" <<'PY'
import sys, urllib.request
sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=5).read().decode())
PY
grep -E '^escollect_(spool_pending_records|acked_seq|postgres_connected|postgres_slot_retained_bytes|postgres_slot_limit_bytes|postgres_slot_lag_bytes|alerts_waiting)' "$WORK/metrics.txt" | sed 's/^/    /'
for want in "escollect_up{source=\"$SRC\"} 1" 'escollect_up{source="agent-mcp"} 1' "escollect_postgres_connected{source=\"$SRC\"} 1" \
  "escollect_postgres_slot_retained_bytes{source=\"$SRC\"} " "escollect_postgres_slot_limit_bytes{source=\"$SRC\"} 2.147483648e+09" \
  "escollect_alerts_waiting{source=\"$SRC\",target=\"telegram\"} 0" "escollect_spool_pending_records{source=\"$SRC\"} 0"; do
  grep -qF "$want" "$WORK/metrics.txt" || die "на странице показателей нет: $want"
done

# ---------------------------------------------------------------- живучесть

step "сборщик убит (kill -9), пока агент работает; потом перезапущена база"
tick() { field "$(mcp execute "$(sql_arg "$1" <<<"update docs set body = '$1' where id = 2")")" xid; }
X1=$(tick "before the kill"); wait_tx "$X1"
kill -9 "$COLLECT"; wait "$COLLECT" 2>/dev/null || true
X2=$(tick "while the collector is dead")
X3=$(tick "still dead")
# Сначала разовый проход (-once): дочитать, что накопилось, отправить и выйти.
"$BIN/escollect" -config "$WORK/collector.json" -once 2>>"$WORK/collect.log" >"$WORK/once.txt" || die "escollect -once: $(tail -3 "$WORK/collect.log")"
sed 's/^/escollect -once → /' "$WORK/once.txt"
grep -q "^$SRC: read 2 new records, .* pending 0$" "$WORK/once.txt" || die "разовый проход должен был дочитать из базы две транзакции"
start_collector
wait_tx "$X2"; wait_tx "$X3"; ship
echo "транзакции $X2 и $X3, сделанные без сборщика, дочитаны из журнала базы; сборщик снова работает постоянно"
as_pg "$PGBIN/pg_ctl" -D "$WORK/pg" -l "$WORK/pg/server.log" -m fast -w restart >/dev/null
X4=$(tick "after the database restart")
wait_tx "$X4"; ship
kill -0 "$COLLECT" 2>/dev/null || die "сборщик не пережил перезапуск базы: $(tail -3 "$WORK/collect.log")"
hooked /alerts "• db-down:" | cut -c1-150 | sed 's/^/    /'
hooked /alerts "• db-up:" | sed 's/^/    /' 
grep -q 'msg="the database connection is down' "$WORK/collect.log" || die "сборщик не заметил обрыва соединения с базой"
echo "база перезапущена: сборщик не остановился, подключился сам и прочитал транзакцию $X4"
# Ни потерь, ни повторов: каждая транзакция в справочнике один раз, номера её
# записей идут сразу за предыдущей, и хранилище держит ровно столько записей.
python3 -I - "$INDEX" "$(max_seq "$SRC")" "$X1" "$X2" "$X3" "$X4" <<'PY'
import json, sys
entries = [json.loads(l) for l in open(sys.argv[1])]
want = [int(x) for x in sys.argv[3:]]
tail = [e for e in entries if e["xid"] in want]
assert [e["xid"] for e in tail] == want, f"в справочнике {[e['xid'] for e in tail]}, ждали {want}"
for a, b in zip(entries, entries[1:]):
    assert b["first_seq"] == a["last_seq"] + 1, f"между транзакциями {a['xid']} и {b['xid']} номера записей идут не подряд"
assert entries[-1]["last_seq"] == int(sys.argv[2]), f"в хранилище {sys.argv[2]} записей, по справочнику {entries[-1]['last_seq']}"
print(f"транзакций в справочнике {len(entries)}, записей в хранилище {sys.argv[2]}: каждая один раз, номера подряд, пропусков нет")
PY
stamp
mkdir -p "$WORK/after-kill"
fetch "$X3" "$WORK/after-kill" >/dev/null
"$BIN/esundo" check -bodies "$WORK/after-kill/bodies" -xid "$X3" >"$WORK/after-kill/plan.txt"
head -1 "$WORK/after-kill/plan.txt" | cut -c1-160

# ---------------------------------------------------------------- числа

step "объём плохого действия"
TABLES=$("${OWNER[@]}" -Atc "select pg_total_relation_size('accounts') + pg_total_relation_size('orders') + pg_total_relation_size('docs')")
python3 -I - "$CHANGES" "$((E1 - E0))" "$((C1 - C0))" "$BUNDLE_BYTES" "$T_TAP" "$T_SHIP" "$T_FETCH" "$T_CHECK" "$T_APPLY" "$TABLES" "$PARTS" <<'PY'
import sys
ch, ev, chain, bundles, tap, ship, fetch, check, apply, tables, parts = [float(x) for x in sys.argv[1:]]
print(f"изменений строк: {int(ch)}, записей хранилища: {int(parts)}")
print(f"хранилище, журнал улик: +{ev/1024:.0f} КБ ({ev/ch:.0f} байт на изменение); цепь: +{chain/1024:.1f} КБ")
print(f"от фиксации в базе до буфера сборщика: {tap:.2f} с; оттуда до хранилища: {ship:.2f} с")
print(f"пакеты записей: {bundles/1024:.0f} КБ; выдача и проверка: {fetch:.2f} с")
print(f"сверка с базой: {check:.2f} с; применение отката: {apply:.2f} с")
print(f"для масштаба: три таблицы целиком, с индексами, — {tables/1024:.0f} КБ; действие заняло в хранилище {(ev+chain)/tables:.2f} такого объёма")
PY
kill "$COLLECT" 2>/dev/null; wait "$COLLECT" 2>/dev/null || true
grep -o 'msg="database input closed".*' "$WORK/collect.log" | tail -1 | sed 's/^msg="database input closed"/вход «postgres» с последнего запуска:/'
echo
echo "каталог стенда: $WORK"
