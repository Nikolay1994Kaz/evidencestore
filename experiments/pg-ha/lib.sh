# Общее для сценариев стенда (run.sh, native.sh): хранилище, сборщик, настройки
# esmcp, нагрузка и сверка. Подключается через «.»; ждёт переменные HERE (этот
# каталог), WORK, BIN, PORT (хранилище), PGPORT (адрес основной базы),
# PGHA_PASSWORD и PGHA_PSQL (строка psql к базе shop суперпользователем).

# Вход в базу — не дольше пяти секунд: первое соединение после переключения
# балансировщик может принять и оставить без ответа (README, «Что нашлось»).
export PGCONNECT_TIMEOUT=5

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { echo "ОШИБКА: $*" >&2; exit 1; }
psqlp() { psql "$PGHA_PSQL" -X -At -v ON_ERROR_STOP=1 "$@"; }
wait_sql() { for _ in $(seq 90); do psql "${PGHA_PSQL/dbname=shop/dbname=postgres}" -X -Atc "select 1" >/dev/null 2>&1 && return 0; sleep 1; done; die "основная база не отвечает по своему адресу"; }
# alerts ВИД: сколько тревог этого вида поднял сборщик.
alerts() { python3 -I -c 'import json,sys; print(sum(1 for l in open(sys.argv[1]) for s in json.loads(l).get("signals", []) if s["kind"] == sys.argv[2]))' "$WORK/pg-index/alerts.jsonl" "$1" 2>/dev/null || echo 0; }

build_bins() {
  if [ -n "${ES_BIN:-}" ]; then "$BIN/evidencestore" version; else mkdir -p "$BIN"; go build -o "$BIN/" ./cmd/...; fi
}

# demo_tables: таблицы стенда в базе shop.
demo_tables() {
  psqlp -q <<'SQL'
create table accounts (id int primary key, owner text not null, balance numeric(14,2) not null, note text);
create table orders (id bigint primary key, account_id int not null references accounts(id), item text not null);
insert into accounts select g, 'client-' || g, 1000 + g, 'n' from generate_series(1, 2000) g;
insert into orders select g, 1 + (g * 7) % 2000, 'item ' || g from generate_series(1, 1000) g;
revoke create on schema public from public;
SQL
}

# store_and_collector: хранилище (запущено), настройки сборщика и роли в базе
# (escollect -setup-sql). Адрес базы у сборщика — PGPORT на 127.0.0.1.
store_and_collector() {
  cd "$WORK"
  mkdir -p mcp undo mcp-head undo-head keyring-backup roots-mirror
  MCPPUB=$("$BIN/esreceipt" keygen -key mcp/esmcp.key)
  UNDOPUB=$("$BIN/esreceipt" keygen -key undo/esundo.key)
  "$BIN/evidencestore" dev-pki -out pki -source pg-agent -source agent-mcp -source undo-op >/dev/null
  cat >evidencestore.json <<EOF
{
  "data_dir": "data", "roots_dir": "roots", "listen": "127.0.0.1:$PORT",
  "tls": {"cert": "pki/server.crt", "key": "pki/server.key", "client_ca": "pki/ca.crt"},
  "chain": {"tick": "200ms", "promise_mmd": "1m"},
  "tsa": {"url": "local", "every": "1h"}, "demo": true,
  "keys": {"min_wait": "1s", "backup_dir": "keyring-backup", "roots_mirror_dir": "roots-mirror"},
  "sources": [
    {"name": "pg-agent", "content_type": "pg/before-images-v1", "subject_field": "xid", "retention_months": 1, "expect_every": "1h"},
    {"name": "agent-mcp", "content_type": "receipt/v2", "gateway_key": "$MCPPUB", "subject_field": "action", "retention_months": 12, "expect_every": "1h"},
    {"name": "undo-op", "content_type": "receipt/v2", "gateway_key": "$UNDOPUB", "subject_field": "action", "retention_months": 12, "expect_every": "1h"}
  ]
}
EOF
  "$BIN/evidencestore" init -config evidencestore.json >init.txt
  STORE_KEY=$(tail -1 init.txt)
  "$BIN/evidencestore" serve -config evidencestore.json 2>server.log &
  SERVER=$!
  for _ in $(seq 50); do [ -S data/admin.sock ] && break; sleep 0.1; done
  cat >collector.json <<EOF
{
  "server": "https://127.0.0.1:$PORT", "ca": "pki/ca.crt", "store_key": "$STORE_KEY", "flush_every": "200ms",
  "sources": [
    {"cert": "pki/pg-agent.crt", "key": "pki/pg-agent.key", "spool_dir": "spool-pg-agent",
     "postgres": {
       "dsn": "host=127.0.0.1 port=$PGPORT user=evidence_tap dbname=shop password=$PGHA_PASSWORD",
       "dir": "pg-index",
       "mcp_roles": ["esmcp_bot"], "roles": ["agent_bot"], "undo_roles": ["undo_op"],
       "tables": ["public.accounts", "public.orders"],
       "receipts": {"files": ["mcp/receipts.jsonl", "undo/receipts.jsonl"], "gateway_keys": ["$MCPPUB", "$UNDOPUB"], "source": "pg-agent"},
       "alert_rows": 500, "status_every": "1s", "down_after": "1s"}},
    {"cert": "pki/agent-mcp.crt", "key": "pki/agent-mcp.key", "spool_dir": "spool-agent-mcp", "file": "mcp/receipts.jsonl", "from_start": true},
    {"cert": "pki/undo-op.crt", "key": "pki/undo-op.key", "spool_dir": "spool-undo-op", "file": "undo/receipts.jsonl", "from_start": true}
  ]
}
EOF
  "$BIN/escollect" -config collector.json -setup-sql >setup.sql
  PGOPTIONS='-c client_min_messages=warning' psqlp -q -f setup.sql
  psqlp -q -c "alter role evidence_tap password '$PGHA_PASSWORD'; alter role esmcp_bot password '$PGHA_PASSWORD'; alter role undo_op password '$PGHA_PASSWORD'; alter role agent_bot password '$PGHA_PASSWORD'"
  touch mcp/receipts.jsonl undo/receipts.jsonl
}

# mcp_config ФАЙЛ ПОРТ ТАЙМАУТ [pooler]: настройки esmcp на этот адрес.
mcp_config() {
  local pooler=
  [ -z "${4:-}" ] || pooler='"pooler": true,'
  cat >"$1" <<EOF
{
  "dsn": "host=127.0.0.1 port=$2 user=esmcp_bot dbname=shop password=$PGHA_PASSWORD",
  $pooler
  "agent": "support-bot", "receipts": "mcp/receipts.jsonl", "key": "mcp/esmcp.key", "head": "mcp-head/esmcp.head",
  "pg_source": "pg-agent", "action_row_limit": 500, "statement_timeout": "$3", "lock_timeout": "2s"
}
EOF
}

# start_collector: сборщик работает постоянно; ждёт, пока он начнёт читать журнал базы.
start_collector() {
  "$BIN/escollect" -config collector.json 2>>collect.log &
  COLLECT=$!
  for _ in $(seq 100); do grep -q 'msg="reading the database log"' collect.log 2>/dev/null && return 0; sleep 0.1; done
  die "сборщик не начал читать журнал базы: $(cat collect.log)"
}

# load_start ЖУРНАЛ ПЕРВЫЙ_N; load_stop: агент под нагрузкой — действие каждые 0,1 с (mcp-direct.json).
load_start() { rm -f stop; python3 -I "$HERE/load.py" "$BIN/esmcp" mcp-direct.json "$1" stop "$2" 0.1 & LOAD=$!; }
load_stop() { touch stop; wait "$LOAD" 2>/dev/null || true; LOAD=; }
# verify ЖУРНАЛ ожидания…: сверка журнала агента с базой и справочником сборщика.
verify() {
  local l=$1
  shift
  python3 -I "$HERE/verify.py" "$PGHA_PSQL" pg-index "$l" --expect "$@" | tee "$l.verify" |
    python3 -I -c 'import json,sys; d=json.load(sys.stdin); print({k: d[k] for k in ("actions","committed","failed","unknown","in_db","whole","fingerprint")})'
}
# Пачка отпечатков уходит в буфер через минуту: столько же ждёт сверка, чтобы
# «отпечатков нет» значило «нет», а не «ещё не дошли».
settle_collector() { sleep 65; }
