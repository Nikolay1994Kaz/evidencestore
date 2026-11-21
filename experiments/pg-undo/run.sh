#!/usr/bin/env bash
# Опыт «аудит + откат» на живом Postgres. Хранилище не меняется ни строкой:
#
#   Postgres (wal_level=logical, REPLICA IDENTITY FULL)
#     → pg_recvlogical + wal2json: каждое изменение строки — строка JSON в файле
#     → escollect читает файл как обычный журнал
#     → evidencestore: источник с "subject_field": "xid" — метка записи = номер транзакции
#     → proof -subject <xid>: все до-образы одной транзакции одним проверяемым пакетом
#     → esverify -bodies → undo.py: обратные операции, сверка с базой, одна транзакция отката
#
# Сценарий: агент делает хорошее действие (№41) и плохое (№42: обнуляет треть
# счетов, удаляет заказы, удаляет счёт). После него человек успевает поправить
# несколько строк руками, одну — между сверкой и откатом. Откат №42 возвращает
# всё, кроме тронутого человеком, и сам ложится в журнал. Затем края: строка
# больше предела записи, TRUNCATE, DROP TABLE; в конце — уничтожение ключа месяца.
# Каждый шаг сверяется с ожидаемым: расхождение — ненулевой код выхода.
#
#   WORK=/tmp/pg-undo experiments/pg-undo/run.sh   # каталог стенда (по умолчанию mktemp)
#   ES_BIN=/path/to/bin …                          # готовые бинарники (релиз) вместо сборки
#   ROWS=300000 EDGES=0 …                          # замер объёма: счетов ROWS, без краёв
#   PGBIN=/usr/lib/postgresql/16/bin …             # где initdb, pg_ctl, psql, pg_recvlogical
#
# Нужны: PostgreSQL с плагином wal2json (Debian/Ubuntu: postgresql-16-wal2json), python3.
# Идёт около трёх минут: окно пакета закрывает метка времени, взятая больше чем
# через две минуты после его конца (docs/bundles.md).
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
EDGES=${EDGES:-1}
SRC=pg-agent
mkdir -p "$BIN"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { echo "ОШИБКА: $*" >&2; exit 1; }
now() { date +%s.%N; }
since() { python3 -I -c 'import sys; print(f"{float(sys.argv[2]) - float(sys.argv[1]):.2f}")' "$1" "$(now)"; }
size() { du -sb "$@" 2>/dev/null | awk '{s += $1} END {print s + 0}'; }

# ---------------------------------------------------------------- стенд

step "сборка"
if [ -n "${ES_BIN:-}" ]; then "$BIN/evidencestore" version; else go build -o "$BIN/" ./cmd/...; fi

if [ -z "${PGBIN:-}" ]; then
  PGBIN=$(pg_config --bindir 2>/dev/null || true)
  [ -x "$PGBIN/initdb" ] || PGBIN=$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)
fi
for t in initdb pg_ctl psql pg_recvlogical pg_config; do [ -x "$PGBIN/$t" ] || die "нет $t в '$PGBIN': задайте PGBIN"; done
[ -e "$("$PGBIN/pg_config" --pkglibdir)/wal2json.so" ] || die "нет плагина wal2json (Debian/Ubuntu: apt install postgresql-16-wal2json)"

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
  kill "${SERVER:-}" "${RECV:-}" 2>/dev/null || true
  as_pg "$PGBIN/pg_ctl" -D "$WORK/pg" -m fast stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "Postgres: wal_level=logical, слот с плагином wal2json"
as_pg "$PGBIN/initdb" -D "$WORK/pg" -A trust -U postgres --no-sync >/dev/null
cat >>"$WORK/pg/postgresql.conf" <<EOF
listen_addresses = ''
unix_socket_directories = '$WORK/sock'
unix_socket_permissions = 0700
port = $PGPORT
wal_level = logical
EOF
as_pg "$PGBIN/pg_ctl" -D "$WORK/pg" -l "$WORK/pg/server.log" -w start >/dev/null
PGCONN=(-h "$WORK/sock" -p "$PGPORT" -U postgres)
PSQL=("$PGBIN/psql" "${PGCONN[@]}" -X -v ON_ERROR_STOP=1 -d shop)
"$PGBIN/psql" "${PGCONN[@]}" -X -qAt -v ON_ERROR_STOP=1 -d postgres -c "create database shop"
"${PSQL[@]}" -Atc "select version()" | cut -d' ' -f1-2
# Сборки с настройкой output_plugin_libraries (у Ubuntu 16.15 она есть) пускают
# плагином только названные библиотеки; wal2json в списке по умолчанию нет.
if [ "$("${PSQL[@]}" -Atc "select count(*) from pg_settings where name = 'output_plugin_libraries'")" = 1 ]; then
  "${PSQL[@]}" -qAtc "alter system set output_plugin_libraries = pgoutput, test_decoding, wal2json" -c "select pg_reload_conf()" >/dev/null
  sleep 0.5
  echo "output_plugin_libraries: $("${PSQL[@]}" -Atc "show output_plugin_libraries")"
fi

"${PSQL[@]}" -q -v rows="$ROWS" <<'SQL'
create table accounts (
  id int primary key, owner text not null, balance numeric(14,2) not null,
  note text, profile text, updated_at timestamptz not null default now());
create table orders (
  id bigint primary key, account_id int not null references accounts(id),
  item text not null, paid boolean not null default false);
create table docs (id int primary key, body text);
create table scratch_a (id int primary key, v text);
create table scratch_b (id int primary key, v text);
-- Без этого в журнал идёт только ключ старой строки, и возвращать нечего.
alter table accounts replica identity full;
alter table orders replica identity full;
alter table docs replica identity full;
alter table scratch_a replica identity full;
alter table scratch_b replica identity full;
insert into accounts (id, owner, balance, note, profile)
  select g, 'client-' || g, 1000 + g,
         case when g % 7 = 0 then null else 'it''s a "vip" #' || g end,
         -- у каждого 500-го — 12,8 КБ в поле: значение уходит в TOAST
         case when g % 500 = 10 then (select string_agg(md5(random()::text || g || i), '') from generate_series(1, 400) i) end
  from generate_series(1, :rows) g;
insert into orders select g, 1 + (g * 7) % :rows, 'item ' || g, g % 2 = 0 from generate_series(1, :rows / 2) g;
insert into orders values (:rows + 1, 5, 'gift', true), (:rows + 2, 5, 'gift wrap', false);
insert into docs values (1, 'contract'), (2, 'note');
insert into scratch_a select g, 'a' || g from generate_series(1, 50) g;
insert into scratch_b select g, 'b' || g from generate_series(1, 50) g;
create schema snap;
SQL
echo "accounts: $ROWS строк, orders: $((ROWS / 2 + 2))"

WAL=$WORK/wal.jsonl
"$PGBIN/pg_recvlogical" "${PGCONN[@]}" -d shop --slot agent_undo --create-slot -P wal2json
# format-version=2 — строка JSON на изменение; include-xids — номер транзакции в
# каждой строке (по нему хранилище ставит метку); include-pk — чем адресовать строку.
"$PGBIN/pg_recvlogical" "${PGCONN[@]}" -d shop --slot agent_undo --start -f "$WAL" \
  -o format-version=2 -o include-xids=true -o include-pk=true -o include-timestamp=true \
  -o filter-tables='snap.*' --fsync-interval=1 --status-interval=1 2>"$WORK/recv.log" &
RECV=$!

step "хранилище: источник $SRC, метка субъекта — поле xid"
"$BIN/evidencestore" dev-pki -out "$WORK/pki" -source "$SRC" >/dev/null
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
    {"name": "$SRC", "content_type": "pg/wal2json-v2", "subject_field": "xid", "retention_months": 1, "expect_every": "1h"}
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
cat >"$WORK/collector.json" <<EOF
{
  "server": "https://127.0.0.1:$PORT",
  "ca": "pki/ca.crt", "cert": "pki/$SRC.crt", "key": "pki/$SRC.key",
  "store_key": "$STORE_KEY",
  "spool_dir": "spool", "file": "wal.jsonl", "from_start": true
}
EOF
"$BIN/evidencestore" tsa-root -config "$CFG" -out "$WORK/tsa-root.crt" >/dev/null 2>&1

# tx: транзакция из stdin, печатает её xid. С именем действия — «через прокси
# агента»: прокси кладёт в транзакцию отметку, и она едет в журнал под тем же
# xid. Ни роли, ни application_name в WAL нет — без отметки журнал не знает, чья транзакция.
tx() {
  local mark="" body
  body=$(cat)
  [ -z "${1:-}" ] || mark="select pg_logical_emit_message(true, 'agent', '{\"agent\":\"support-bot\",\"action_id\":\"$1\",\"tool\":\"sql.execute\"}') \\gset m_"
  PGAPPNAME="session-of-${1:-human}" "${PSQL[@]}" -qAt <<SQL | tail -1
begin;
$mark
select pg_current_xact_id()::text as xid \gset
$body
commit;
\echo :xid
SQL
}
# ship: дождаться конца транзакции в файле wal2json и отдать файл сборщику.
ship() {
  for _ in $(seq 6000); do
    grep -q "^{\"action\":\"C\",\"xid\":$1," "$WAL" 2>/dev/null && [ -z "$(tail -c1 "$WAL")" ] && break
    sleep 0.1
  done
  grep -q "^{\"action\":\"C\",\"xid\":$1," "$WAL" || die "транзакция $1 не дошла до файла wal2json: $(cat "$WORK/recv.log")"
  "$BIN/escollect" -config "$WORK/collector.json" -once 2>&1 | tail -1
}
stamp() { "$BIN/evidencestore" stamp -config "$CFG" >/dev/null; }
max_seq() {
  "$BIN/evidencestore" status -config "$CFG" |
    python3 -I -c 'import json,sys; print(next((s["max_seq"] for s in json.load(sys.stdin)["sources"] if s["name"]==sys.argv[1]), 0))' "$SRC"
}
lines_of() { grep -c "\"xid\":$1[,}]" "$WAL" || true; }
bytes_of() { grep "\"xid\":$1[,}]" "$WAL" | wc -c; }
# bundle XID FROM TO DIR: пакет по транзакции, проверка, тела и отчёт в DIR.
bundle() {
  mkdir -p "$4"
  "$BIN/evidencestore" proof -config "$CFG" -source "$SRC" -subject "$1" -from "$2" -to "$3" -out "$4/bundle.json" >"$4/proof.txt" 2>&1 || die "пакет не выдан: $(cat "$4/proof.txt")"
  "$BIN/esverify" -proof "$4/bundle.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -json >"$4/report.json"
  "$BIN/esverify" -proof "$4/bundle.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -bodies "$4/bodies" >"$4/esverify.txt" 2>&1
}
report() {
  python3 -I - "$1/report.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
s = d["subject"]
print(f"отчёт esverify: пакет {'прошёл' if d['valid'] else 'НЕ прошёл'} проверку; записей источника в окне {d['records_in_window']}: "
      f"этой транзакции {s['records']} (открыто {s['opened']}), чужих закрытых {s['others_closed']}, без метки {s['unlabeled']}")
PY
}

stamp # нижняя граница времени (T1) для всего, что придёт дальше
sleep 1.2
FROM=$(date -u +%FT%T.%NZ)
sleep 1.5

# ---------------------------------------------------------------- действия агента

step "действие агента №41 (хорошее): перевод 100.50 со счёта 1 на счёт 2"
GOOD=$(tx 41 <<'SQL'
update accounts set balance = balance - 100.50 where id = 1;
update accounts set balance = balance + 100.50 where id = 2;
SQL
)
ship "$GOOD"
echo "xid $GOOD"
# Снимок «как было до плохого действия» — только чтобы в конце сверить итог.
# (В журнал схема snap не идёт: filter-tables.)
"${PSQL[@]}" -q -c "create table snap.accounts as table accounts" -c "create table snap.orders as table orders"

step "действие агента №42 (плохое): «закрыть неактивные счета»"
E0=$(size "$WORK/data/evidence"); C0=$(size "$WORK/data/chain"); W0=$(stat -c %s "$WAL")
T=$(now)
BAD=$(tx 42 <<SQL
update accounts set balance = 0, note = 'closed by support-bot' where id % 3 = 0;
delete from orders where not paid and account_id <> 5;
insert into orders values ($((ROWS + 3)), 1, 'refund', true);
update accounts set note = 'flagged' where id = 3;
delete from orders where account_id = 5;
delete from accounts where id = 5;
SQL
)
T_TX=$(since "$T")
T=$(now)
ship "$BAD"
T_SHIP=$(since "$T")
BAD_LINES=$(lines_of "$BAD"); BAD_BYTES=$(bytes_of "$BAD")
echo "xid $BAD: транзакция $T_TX с; в журнале wal2json $BAD_LINES строк, $BAD_BYTES байт; до хранилища доехало за $T_SHIP с"
"${PSQL[@]}" -At -F ' ' -c "select 'счетов с нулём:', count(*) from accounts where balance = 0" -c "select 'заказов осталось:', count(*) from orders"
# Сессия агента шла под application_name = session-of-42. В журнале его нет:
[ "$(grep -c 'session-of-' "$WAL" || true)" = 0 ] || die "application_name нашёлся в журнале wal2json"
echo "application_name сессии (session-of-42) в журнале не встречается ни разу: чья транзакция, говорит только отметка"
sleep 0.5
E1=$(size "$WORK/data/evidence"); C1=$(size "$WORK/data/chain")
TO=$(date -u +%FT%T.%NZ)

if [ "$EDGES" = 1 ]; then
  step "края (своё окно): TRUNCATE, DROP TABLE, строка в 1,5 МБ"
  sleep 1.5
  EFROM=$(date -u +%FT%T.%NZ)
  sleep 1.5
  X_TRUNC=$(tx 43 <<<"truncate scratch_a;")
  X_DROP=$(tx 44 <<<"drop table scratch_b;")
  X_BIG=$(tx 45 <<'SQL'
update docs set body = (select string_agg(md5(random()::text), '') from generate_series(1, 47000)) where id = 1;
update docs set body = 'short' where id = 2;
SQL
  )
  ship "$X_BIG"
  echo "xid: TRUNCATE $X_TRUNC, DROP TABLE $X_DROP, большая строка $X_BIG"
  sleep 0.5
  ETO=$(date -u +%FT%T.%NZ)
fi

step "человек после агента: правит счёт 6, заново заводит удалённый заказ 1, удаляет заказ-возврат, правит счёт 1"
HUMAN=$(tx "" <<SQL
update accounts set balance = 777.00, note = 'fixed by a human' where id = 6;
insert into orders values (1, 8, 're-entered by a human', false);
delete from orders where id = $((ROWS + 3));
update accounts set note = 'called the client' where id = 1;
SQL
)
ship "$HUMAN"
echo "xid $HUMAN (отметки агента в ней нет)"

step "ждём 135 с: окно закрывает метка времени, взятая больше чем через две минуты после его конца"
sleep 135
ship "$(tx "" <<<"update docs set body = 'tick 1' where id = 2;")" >/dev/null
stamp # закрывающая метка
ship "$(tx "" <<<"update docs set body = 'tick 2' where id = 2;")" >/dev/null
stamp # её хвосты источников — верхний край пакета

# ---------------------------------------------------------------- пакет и откат

step "пакет по транзакции $BAD: хранилище открывает только её записи, esverify проверяет офлайн"
U=$WORK/undo
T=$(now)
bundle "$BAD" "$FROM" "$TO" "$U"
T_BUNDLE=$(since "$T")
grep -E '✔|✘' "$U/esverify.txt" || true
grep -q '^VERIFIED' "$U/esverify.txt" || die "пакет не прошёл проверку: $U/esverify.txt"
report "$U"
echo "от конца окна до проверенного пакета прошло $(python3 -I -c 'import sys,datetime as d; f=lambda s: d.datetime.fromisoformat(s[:26]+"+00:00"); print(int((d.datetime.now(d.timezone.utc)-f(sys.argv[1])).total_seconds()))' "$TO") с"
BUNDLE_BYTES=$(stat -c %s "$U/bundle.json")
[ "$(ls "$U/bodies" | wc -l)" = "$BAD_LINES" ] || die "тел $(ls "$U/bodies" | wc -l), а строк транзакции в журнале $BAD_LINES"

step "план отката: обратные операции в обратном порядке"
python3 -I "$HERE/undo.py" plan -bodies "$U/bodies" -xid "$BAD" -report "$U/report.json" -out "$U" | tee "$U/plan.txt"
grep -q 'отметка агента: .*"action_id":"42"' "$U/plan.txt" || die "отметка агента не доехала вместе с транзакцией"
[ "$(sed -n 's/.*чужих закрытых \([0-9]*\),.*/\1/p' <<<"$(report "$U")")" -gt 0 ] || die "в окне ждали чужие записи, закрытые в пакете"

step "сверка с базой: что сейчас на месте каждой строки"
T=$(now)
"${PSQL[@]}" -f "$U/check.sql" >"$U/check.tsv"
python3 -I "$HERE/undo.py" sql -plan "$U" -check "$U/check.tsv" -by "nikolay" -reason "action 42 closed live accounts" | tee "$U/sql.txt"
T_CHECK=$(since "$T")
grep -q 'конфликтов 2$' "$U/sql.txt" || die "ждали два конфликта (счёт 6 и заказ 1)"
grep -q 'уже в нужном виде 1,' "$U/sql.txt" || die "ждали один шаг «уже сделано» (заказ-возврат человек удалил сам)"

step "гонка: между сверкой и откатом человек правит ещё одну строку (счёт 9)"
state() { "${PSQL[@]}" -At -F ' ' -c "select (select count(*) from accounts where balance = 0), 'счетов с нулём,', (select count(*) from orders), 'заказов'"; }
BEFORE=$(state)
tx "" <<<"update accounts set note = 'late human edit' where id = 9;" >/dev/null
if "${PSQL[@]}" -f "$U/undo.sql" >"$U/race.txt" 2>&1; then die "откат прошёл поверх строки, изменённой после сверки"; fi
grep -m1 -o 'undo: .*' "$U/race.txt" || die "откат упал не на своей проверке: $(cat "$U/race.txt")"
[ "$(state)" = "$BEFORE" ] || die "сорванный откат что-то применил: было $BEFORE, стало $(state)"
echo "откат не применён вовсе: по-прежнему $BEFORE. Сверка заново:"
"${PSQL[@]}" -f "$U/check.sql" >"$U/check.tsv"
python3 -I "$HERE/undo.py" sql -plan "$U" -check "$U/check.tsv" -by "nikolay" -reason "action 42 closed live accounts" -show 0 | tee "$U/sql.txt"
grep -q 'конфликтов 3$' "$U/sql.txt" || die "после правки счёта 9 ждали три конфликта"

step "откат: одна транзакция"
T=$(now)
UNDO=$("${PSQL[@]}" -f "$U/undo.sql" | sed -n 's/^undo_xid=//p')
T_APPLY=$(since "$T")
[ -n "$UNDO" ] || die "откат не применился"
echo "применён за $T_APPLY с, xid отката $UNDO"

step "итог: база против снимка до действия №42"
"${PSQL[@]}" -At -F ' ' >"$U/diff.txt" <<'SQL'
select 'accounts', id from ((table accounts except table snap.accounts) union (table snap.accounts except table accounts)) d group by id
union all
select 'orders', id from ((table orders except table snap.orders) union (table snap.orders except table orders)) d group by id
order by 1, 2;
SQL
cat "$U/diff.txt"
[ "$(tr '\n' ';' <"$U/diff.txt")" = "accounts 1;accounts 6;accounts 9;orders 1;" ] || die "отличаться должны только счета 1, 6 и 9 (правки человека) и заказ 1 (заведён человеком)"
echo "отличаются от снимка только четыре строки, которые после агента тронул человек: откат их не перезаписал"

step "повторный откат: применять нечего"
"${PSQL[@]}" -f "$U/check.sql" >"$U/check2.tsv"
python3 -I "$HERE/undo.py" sql -plan "$U" -check "$U/check2.tsv" | tee "$U/sql2.txt"
grep -q 'применить 0,' "$U/sql2.txt" || die "второй откат нашёл, что применять"

step "сам откат — тоже транзакция: её записи легли в то же хранилище"
ship "$UNDO"
stamp
# Отметка отката — вторая строка транзакции; последняя запись источника — её C.
MARK_SEQ=$(($(max_seq) - $(lines_of "$UNDO") + 2))
"$BIN/evidencestore" proof -config "$CFG" -source "$SRC" -seq "$MARK_SEQ" -dek -out "$U/undo-mark.json" >/dev/null 2>&1
"$BIN/esverify" -proof "$U/undo-mark.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -body "$U/undo-mark.txt" >"$U/undo-mark.esverify.txt" 2>&1 ||
  die "пакет записи $MARK_SEQ не прошёл проверку: $U/undo-mark.esverify.txt"
grep -q '"prefix":"undo"' "$U/undo-mark.txt" || die "запись $MARK_SEQ — не отметка отката"
python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); print("запись", sys.argv[2], "— транзакция", r["xid"], "отметка:", r["content"])' "$U/undo-mark.txt" "$MARK_SEQ"

# ---------------------------------------------------------------- края

if [ "$EDGES" = 1 ]; then
  edge() { # edge ИМЯ XID [ключи undo.py]: пакет по транзакции и что из него выходит у undo.py
    local d=$WORK/edge-$1 rc=0
    [ -e "$d/bundle.json" ] || { bundle "$2" "$EFROM" "$ETO" "$d"; report "$d"; }
    python3 -I "$HERE/undo.py" plan -bodies "$d/bodies" -xid "$2" -report "$d/report.json" -out "$d" "${@:3}" >"$d/plan.txt" 2>&1 || rc=$?
    cat "$d/plan.txt"
    echo "(код выхода undo.py: $rc)"
    EDGE_RC=$rc
  }
  bodies() { # тела пакета по порядку номеров, начало каждой строки
    local n
    for n in $(ls "$1" | sed 's/.*-//' | sort -n); do cut -c1-160 "$1/$SRC-$n"; done
  }
  step "край 1: строка 1,5 МБ — длиннее предела записи (1 МиБ)"
  edge big "$X_BIG"
  [ "$EDGE_RC" = 2 ] || die "ждали отказ: в окне записи без метки"
  echo "строк транзакции в журнале wal2json: $(lines_of "$X_BIG"); самая длинная — $(grep "\"xid\":$X_BIG[,}]" "$WAL" | awk '{ if (length($0) > m) m = length($0) } END { print m }') байт"
  echo "-- то же с -allow-unlabeled: план строится, но правки большой строки в нём нет"
  edge big "$X_BIG" -allow-unlabeled
  grep -q 'public.docs: правок 1$' "$WORK/edge-big/plan.txt" || die "транзакция правила две строки docs, в плане ждали одну: большая в пакет не попадает"
  # Записи без метки — ничьи: пока они в окне, undo.py отказывает любой транзакции этого окна.
  step "край 2: TRUNCATE — в журнале одна строка без данных"
  edge truncate "$X_TRUNC" -allow-unlabeled
  [ "$EDGE_RC" = 2 ] && grep -q TRUNCATE "$WORK/edge-truncate/plan.txt" || die "ждали отказ из-за TRUNCATE"
  bodies "$WORK/edge-truncate/bodies"
  step "край 3: DROP TABLE — в журнале только начало и конец транзакции"
  edge drop "$X_DROP" -allow-unlabeled
  grep -q 'обратных шагов 0:' "$WORK/edge-drop/plan.txt" || die "ждали пустой план: DROP TABLE в журнал не попадает"
  [ "$(ls "$WORK/edge-drop/bodies" | wc -l)" = 3 ] || die "у DROP TABLE ждали три записи: начало, отметка, конец"
  bodies "$WORK/edge-drop/bodies"
fi

# ---------------------------------------------------------------- срок хранения

step "срок хранения: ключ месяца уничтожен (два подтверждения, срок ожидания)"
MONTH=$(date -u +%Y-%m)
D0=$(size "$WORK/data/evidence")
"$BIN/evidencestore" keys deactivate -config "$CFG" -scope "$SRC/$MONTH" -force >/dev/null
"$BIN/evidencestore" keys schedule -config "$CFG" -scope "$SRC/$MONTH" -approve operator -approve security -wait 1s >/dev/null
sleep 2.1
"$BIN/evidencestore" keys complete -config "$CFG" >/dev/null
stamp
D1=$(size "$WORK/data/evidence")
mkdir -p "$WORK/erased"
"$BIN/evidencestore" proof -config "$CFG" -source "$SRC" -subject "$BAD" -from "$FROM" -to "$TO" -out "$WORK/erased/bundle.json" >/dev/null 2>&1
"$BIN/esverify" -proof "$WORK/erased/bundle.json" -store-key "$STORE_KEY" -tsa-trust "$WORK/tsa-root.crt" -bodies "$WORK/erased/bodies" >"$WORK/erased/esverify.txt" 2>&1 || true
grep -q '^VERIFIED' "$WORK/erased/esverify.txt" || die "пакет после уничтожения ключа не прошёл проверку"
[ "$(ls "$WORK/erased/bodies" 2>/dev/null | wc -l)" = 0 ] || die "после уничтожения ключа тела открылись"
echo "тот же пакет по транзакции $BAD проходит проверку, но тел в нём нет: до-образы больше не прочитать, откат невозможен"
echo "журнал улик на диске: было $((D0 / 1024)) КБ, стало $((D1 / 1024)) КБ — уничтожение ключа места не освобождает"

# ---------------------------------------------------------------- числа

step "объём действия №42"
CHANGES=$((BAD_LINES - 3))
TABLES=$("${PSQL[@]}" -Atc "select pg_total_relation_size('accounts') + pg_total_relation_size('orders')")
python3 -I - "$CHANGES" "$BAD_BYTES" "$((E1 - E0))" "$((C1 - C0))" "$BUNDLE_BYTES" "$T_SHIP" "$T_BUNDLE" "$T_CHECK" "$T_APPLY" "$TABLES" "$(stat -c %s "$U/undo.sql")" <<'PY'
import sys
ch, wal, ev, chain, bundle, ship, tb, tc, ta, tables, usql = [float(x) for x in sys.argv[1:]]
print(f"изменений строк: {int(ch)}")
print(f"журнал wal2json: {wal/1024:.0f} КБ ({wal/ch:.0f} байт на изменение)")
print(f"хранилище, журнал улик: +{ev/1024:.0f} КБ ({ev/ch:.0f} байт на изменение); цепь: +{chain/1024:.0f} КБ ({chain/ch:.0f} байт)")
print(f"доставка сборщиком: {ship:.2f} с ({ch/max(ship, 0.01):.0f} записей/с)")
print(f"пакет: {bundle/1024:.0f} КБ; выдача и две проверки esverify: {tb:.2f} с")
print(f"сверка с базой: {tc:.2f} с; undo.sql: {usql/1024:.0f} КБ; применение: {ta:.2f} с")
print(f"для масштаба: обе таблицы целиком, с индексами, — {tables/1024:.0f} КБ; одно действие агента заняло в хранилище {(ev+chain)/tables:.1f} такого объёма")
PY
echo
echo "каталог стенда: $WORK"
