#!/bin/sh
# Запуск docker compose. Первый: сертификаты, ключ хранилища, настройки всех
# программ, ключи шлюзов и пароли ролей базы — в ./state, пароль
# суперпользователя базы — в томе dbsecret. Каждый: SQL настройки базы этой
# версии (escollect -setup-sql) — db-setup применяет его, и после обновления
# образа права ролей в базе — той же версии, что сборщик (заход 2, R1-5).
#
# Это проба на одной машине, как evidencestore dev-setup: демонстрационный УЦ,
# метки времени от встроенной службы хранилища. Настоящая установка —
# docs/install.md: свой УЦ, настоящая служба меток, хранилище на другой машине.
#
# Кому что (каталог — только тому контейнеру, которому он нужен):
#   store/      хранилище: серверный сертификат, ключи, данные; undo.json и ключ esundo
#   collector/  сборщик: сертификаты источников, буфер, пароль роли сборщика
#   mcp/        MCP-сервер: пароль роли сервера, ключ шлюза esmcp (только чтение)
#   mcp-head/   MCP-сервер: голова цепочки его квитанций — состояние шлюза, как
#               ключ, а не файла квитанций (docs/receipts.md)
#   pg-index/   справочник и тревоги сборщика (сборщик пишет, esundo читает)
#   receipts/   квитанции MCP (сервер пишет, сборщик читает)
#   undo-receipts/ квитанции откатов (esundo пишет, сборщик читает)
#   setup/      SQL настройки базы и пароли ролей для него (только root)
#   agent.txt   подключение для агента напрямую: только чтение
# Пароль суперпользователя базы — не в ./state, а в томе dbsecret: каталог
# хоста с uid 999 читал бы пользователь хоста с тем же uid (заход 2, R1-10).
set -eu
S=${ES_STATE:-/state}
UID_ES=${ES_UID:-10001}

D=${ES_DBSECRET:-/dbsecret}

# setup_sql — SQL настройки базы этой версии и пароли ролей (каждый запуск).
setup_sql() {
	umask 077
	{
		escollect -config "$S/collector/collector.json" -setup-sql
		cat "$S/setup/passwords.sql"
	} >"$S/setup/setup.sql.new"
	mv "$S/setup/setup.sql.new" "$S/setup/setup.sql"
}

# upgrade — то, чего нет в ./state, заведённом прежней версией (каждый запуск).
upgrade() {
	# Голова цепочки квитанций esmcp — состояние шлюза рядом с ключом, а
	# каталог ключа смонтирован только для чтения: свой каталог (2026-11).
	# Владелец и права — каждый раз: сеанс esmcp, запущенный до этого init
	# (docker compose run после git pull), оставляет Docker'у создать каталог
	# самому — root:root 0755, и шлюз туда не пишет (R1-6 третьего захода).
	mkdir -p "$S/mcp-head"
	chown "$UID_ES:$UID_ES" "$S/mcp-head"
	chmod 700 "$S/mcp-head"
	if [ -f "$S/mcp/mcp.json" ] && ! grep -q '"head"' "$S/mcp/mcp.json"; then
		# Ключ "head" — сразу за первой «{»: так JSON остаётся верным при любой
		# раскладке остальных строк.
		awk 'done != 1 && /\{/ { sub(/\{/, "{\n  \"head\": \"/state/mcp-head/esmcp.head\","); done = 1 } { print }' "$S/mcp/mcp.json" >"$S/mcp/mcp.json.new"
		cat "$S/mcp/mcp.json.new" >"$S/mcp/mcp.json" # тот же файл: владелец и права — прежние
		rm -f "$S/mcp/mcp.json.new"
	fi
}

if [ -f "$S/.done" ]; then
	upgrade
	setup_sql
	echo "es-init: $S is set up already (the database setup SQL is renewed); to start over: docker compose down -v && rm -rf ./state"
	exit 0
fi
if [ -n "$(ls -A "$S" 2>/dev/null)" ]; then
	echo "es-init: $S is not empty, but not set up either (an earlier first start broke off): remove ./state and start again" >&2
	exit 1
fi
umask 077
for d in pki store collector mcp mcp-head pg-index receipts undo-receipts setup; do mkdir -p "$S/$d"; done

# Пароль: 32 шестнадцатеричных знака — без кавычек в строке подключения.
pw() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }
PW_PG=$(pw); PW_TAP=$(pw); PW_MCP=$(pw); PW_UNDO=$(pw); PW_AGENT=$(pw)

evidencestore dev-pki -out "$S/pki" -host store -host localhost -source pg-agent -source agent-mcp -source undo-op >/dev/null
cp "$S/pki/ca.crt" "$S/pki/server.crt" "$S/pki/server.key" "$S/store/"
cp "$S/pki/ca.crt" "$S/pki/pg-agent.crt" "$S/pki/pg-agent.key" "$S/pki/agent-mcp.crt" "$S/pki/agent-mcp.key" "$S/pki/undo-op.crt" "$S/pki/undo-op.key" "$S/collector/"

# Ключи шлюзов: esmcp и esundo подписывают каждый свои квитанции; «чья
# транзакция» сборщик берёт из них, а не из базы (DECISIONS, п. 42).
MCPPUB=$(esreceipt keygen -key "$S/mcp/esmcp.key")
UNDOPUB=$(esreceipt keygen -key "$S/store/esundo.key")

cat >"$S/store/store.json" <<EOF
{
  "data_dir": "data",
  "roots_dir": "roots",
  "listen": "0.0.0.0:8443",
  "tls": {"cert": "server.crt", "key": "server.key", "client_ca": "ca.crt"},
  "tsa": {"url": "local"},
  "sources": [
    {"name": "pg-agent", "content_type": "pg/before-images-v1", "subject_field": "xid", "retention_months": 1, "expect_every": "1h"},
    {"name": "agent-mcp", "content_type": "receipt/v1", "gateway_key": "$MCPPUB", "subject_field": "action", "retention_months": 12, "expect_every": "1h"},
    {"name": "undo-op", "content_type": "receipt/v1", "gateway_key": "$UNDOPUB", "subject_field": "action", "retention_months": 12}
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
       "receipts": {"files": ["/state/receipts/receipts.jsonl", "/state/undo-receipts/receipts.jsonl"],
                    "gateway_keys": ["$MCPPUB", "$UNDOPUB"], "source": "pg-agent"},
       "alert_rows": 500}},
    {"cert": "agent-mcp.crt", "key": "agent-mcp.key", "spool_dir": "spool-agent-mcp",
     "file": "/state/receipts/receipts.jsonl", "from_start": true},
    {"cert": "undo-op.crt", "key": "undo-op.key", "spool_dir": "spool-undo-op",
     "file": "/state/undo-receipts/receipts.jsonl", "from_start": true}
  ]
}
EOF
touch "$S/receipts/receipts.jsonl" "$S/undo-receipts/receipts.jsonl"

# Тревоги — в /state/pg-index/alerts.jsonl и в журнал сборщика. Людям — раздел
# "notify" у входа "postgres" (Telegram, Slack, свой адрес), с командой отката
# "undo_hint": "docker compose exec store esundo check -config /state/store/undo.json -xid {xid}".

# Пароли ролей, которые заводит SQL настройки: применяет db-setup.
{
	echo "ALTER ROLE evidence_tap PASSWORD '$PW_TAP';"
	echo "ALTER ROLE esmcp_bot PASSWORD '$PW_MCP';"
	echo "ALTER ROLE undo_op PASSWORD '$PW_UNDO';"
	echo "ALTER ROLE agent_bot PASSWORD '$PW_AGENT';"
} >"$S/setup/passwords.sql"
printf '%s' "$PW_PG" >"$S/setup/postgres-password"
# Базе пароль нужен её пользователем: postgres образа postgres (Debian), uid 999.
# Файл — только ему (R1-5, R2-3), в томе, а не в каталоге хоста.
mkdir -p "$D"
printf '%s' "$PW_PG" >"$D/postgres-password"
chown "${PG_UID:-999}:${PG_UID:-999}" "$D/postgres-password"
chmod 400 "$D/postgres-password"

cat >"$S/mcp/mcp.json" <<EOF
{
  "dsn": "host=db user=esmcp_bot dbname=shop password=$PW_MCP",
  "agent": "agent",
  "receipts": "/state/receipts/receipts.jsonl",
  "key": "/state/mcp/esmcp.key",
  "head": "/state/mcp-head/esmcp.head",
  "pg_source": "pg-agent"
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
  "verify": ["esverify", "-store-key", "$KEY", "-tsa-trust", "/state/store/tsa-root.crt"],
  "receipts": "/state/undo-receipts/receipts.jsonl",
  "key": "/state/store/esundo.key",
  "pg_source": "pg-agent"
}
EOF

printf 'host=db user=agent_bot dbname=shop password=%s\n' "$PW_AGENT" >"$S/agent.txt"

chown -R "$UID_ES:$UID_ES" "$S/store" "$S/collector" "$S/mcp" "$S/mcp-head" "$S/pg-index" "$S/receipts" "$S/undo-receipts" "$S/agent.txt"
chmod 711 "$S"
setup_sql
touch "$S/.done"
echo "es-init: set up in ./state; the store key: $KEY"
