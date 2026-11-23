#!/bin/sh
# Первый запуск docker compose: сертификаты, ключ хранилища, настройки всех
# программ и пароли ролей базы — в ./state. Второй запуск ничего не трогает.
#
# Это проба на одной машине, как evidencestore dev-setup: демонстрационный УЦ,
# метки времени от встроенной службы хранилища. Настоящая установка —
# docs/install.md: свой УЦ, настоящая служба меток, хранилище на другой машине.
#
# Кому что (каталог — только тому контейнеру, которому он нужен):
#   store/      хранилище: серверный сертификат, ключи, данные; undo.json для esundo
#   collector/  сборщик: сертификаты источников, буфер, пароль роли сборщика
#   mcp/        MCP-сервер: пароль роли сервера
#   pg-index/   справочник и тревоги сборщика (сборщик пишет, esundo читает)
#   receipts/   квитанции MCP (сервер пишет, сборщик читает)
#   db/         пароль суперпользователя базы; setup/ — SQL настройки базы
#   agent.txt   подключение для агента напрямую: только чтение
set -eu
S=${ES_STATE:-/state}
UID_ES=${ES_UID:-10001}

if [ -f "$S/.done" ]; then
	echo "es-init: $S is set up already; to start over: docker compose down -v && rm -rf ./state"
	exit 0
fi
if [ -n "$(ls -A "$S" 2>/dev/null)" ]; then
	echo "es-init: $S is not empty, but not set up either (an earlier first start broke off): remove ./state and start again" >&2
	exit 1
fi
umask 077
for d in pki store collector mcp pg-index receipts db setup; do mkdir -p "$S/$d"; done

# Пароль: 32 шестнадцатеричных знака — без кавычек в строке подключения.
pw() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }
PW_PG=$(pw); PW_TAP=$(pw); PW_MCP=$(pw); PW_UNDO=$(pw); PW_AGENT=$(pw)

evidencestore dev-pki -out "$S/pki" -host store -host localhost -source pg-agent -source agent-mcp >/dev/null
cp "$S/pki/ca.crt" "$S/pki/server.crt" "$S/pki/server.key" "$S/store/"
cp "$S/pki/ca.crt" "$S/pki/pg-agent.crt" "$S/pki/pg-agent.key" "$S/pki/agent-mcp.crt" "$S/pki/agent-mcp.key" "$S/collector/"

cat >"$S/store/store.json" <<EOF
{
  "data_dir": "data",
  "roots_dir": "roots",
  "listen": "0.0.0.0:8443",
  "tls": {"cert": "server.crt", "key": "server.key", "client_ca": "ca.crt"},
  "tsa": {"url": "local"},
  "sources": [
    {"name": "pg-agent", "content_type": "pg/before-images-v1", "subject_field": "xid", "retention_months": 1, "expect_every": "1h"},
    {"name": "agent-mcp", "content_type": "mcp/receipt-v1", "subject_field": "action_id", "retention_months": 12, "expect_every": "1h"}
  ]
}
EOF
evidencestore init -config "$S/store/store.json" >"$S/store/init.txt"
KEY=$(tail -n 1 "$S/store/init.txt")

cat >"$S/collector/collector.json" <<EOF
{
  "server": "https://store:8443",
  "ca": "ca.crt",
  "store_key": "$KEY",
  "sources": [
    {"cert": "pg-agent.crt", "key": "pg-agent.key", "spool_dir": "spool-pg-agent",
     "postgres": {
       "dsn": "host=db user=evidence_tap dbname=shop password=$PW_TAP",
       "dir": "/state/pg-index",
       "mcp_roles": ["esmcp_bot"],
       "roles": ["agent_bot"],
       "undo_roles": ["undo_op"],
       "tables": ["public.accounts", "public.orders"],
       "alert_rows": 500,
       "require_action": true}},
    {"cert": "agent-mcp.crt", "key": "agent-mcp.key", "spool_dir": "spool-agent-mcp",
     "file": "/state/receipts/receipts.jsonl", "from_start": true}
  ]
}
EOF
touch "$S/receipts/receipts.jsonl"

# Тревоги — в /state/pg-index/alerts.jsonl и в журнал сборщика. Людям — раздел
# "notify" у входа "postgres" (Telegram, Slack, свой адрес), с командой отката
# "undo_hint": "docker compose exec store esundo check -config /state/store/undo.json -xid {xid}".

# SQL настройки базы и пароли ролей, которые он заводит: применяет db-setup.
{
	escollect -config "$S/collector/collector.json" -setup-sql
	echo "ALTER ROLE evidence_tap PASSWORD '$PW_TAP';"
	echo "ALTER ROLE esmcp_bot PASSWORD '$PW_MCP';"
	echo "ALTER ROLE undo_op PASSWORD '$PW_UNDO';"
	echo "ALTER ROLE agent_bot PASSWORD '$PW_AGENT';"
} >"$S/setup/setup.sql"
printf '%s' "$PW_PG" >"$S/setup/postgres-password"
# Базе пароль нужен её пользователем (postgres, не root): файл — на чтение всем
# в каталоге, который монтируется только ей.
printf '%s' "$PW_PG" >"$S/db/postgres-password"
chmod 755 "$S/db"
chmod 444 "$S/db/postgres-password"

cat >"$S/mcp/mcp.json" <<EOF
{
  "dsn": "host=db user=esmcp_bot dbname=shop password=$PW_MCP",
  "agent": "agent",
  "receipts": "/state/receipts/receipts.jsonl"
}
EOF

# esundo — в контейнере хранилища: пакеты записей ему выдаёт само хранилище,
# корень службы меток (tsa-root.crt) пишет es-store при запуске.
cat >"$S/store/undo.json" <<EOF
{
  "dsn": "host=db user=undo_op dbname=shop password=$PW_UNDO",
  "index": "/state/pg-index/index.jsonl",
  "stamp": ["evidencestore", "stamp", "-config", "/state/store/store.json"],
  "proof": ["evidencestore", "proof", "-config", "/state/store/store.json", "-source", "pg-agent", "-dek"],
  "verify": ["esverify", "-store-key", "$KEY", "-tsa-trust", "/state/store/tsa-root.crt"]
}
EOF

printf 'host=db user=agent_bot dbname=shop password=%s\n' "$PW_AGENT" >"$S/agent.txt"

chown -R "$UID_ES:$UID_ES" "$S/store" "$S/collector" "$S/mcp" "$S/pg-index" "$S/receipts" "$S/agent.txt"
chmod 711 "$S"
touch "$S/.done"
echo "es-init: set up in ./state; the store key: $KEY"
