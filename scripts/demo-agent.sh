#!/usr/bin/env bash
# Демо «агент и его журнал»: каждый вызов инструмента ИИ-агента уходит в
# хранилище раньше, чем выполнится, и строку, стёртую из журнала агента,
# проверяющий получает обратно.
#
#   1. хранилище «на своей машине» и сборщик рядом с агентом: сборщик следит
#      за tool-calls.jsonl, куда хук агента (PreToolUse у Claude Code, одна
#      строка jq) пишет каждый вызов инструмента до его выполнения;
#   2. две сессии агента: обычная задача и задача, в которой агент копирует
#      файл с клиентами в outbox/;
#   3. строку про копирование стирают из журнала (прав агента на это хватает);
#   4. расследование: каждая строка — из хранилища, проверена esverify офлайн;
#      стёртая видна, у каждой время приёма между метками TSA;
#   5. пакет по субъекту (subject_field — session_id): всё, что сделала вторая
#      сессия, без пропусков, а вызовы первой остаются закрытыми.
#
#   scripts/demo-agent.sh                      # записанные сессии: хуку подаются вызовы в том виде, в каком их подаёт Claude Code
#   DEMO_AGENT=claude scripts/demo-agent.sh    # настоящий Claude Code без интерфейса (claude в PATH; тратит токены)
#   DEMO_TSA=digicert scripts/demo-agent.sh    # метки у публичной TSA DigiCert (нужен интернет)
#   ES_BIN=/path/to/bin scripts/demo-agent.sh  # готовые бинарники вместо сборки
set -euo pipefail
cd "$(dirname "$0")/.."
WORK=${WORK:-$(mktemp -d)}
BIN=${ES_BIN:-$WORK/bin} # ES_BIN — готовые бинарники (например, из релиза) вместо сборки
PORT=${PORT:-18446}
AGENT=${DEMO_AGENT:-replay}
mkdir -p "$BIN"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

command -v jq >/dev/null || { echo "ERROR: the agent's hook in this demo is a jq one-liner: install jq"; exit 1; }
case "$AGENT" in
replay) ;;
claude) command -v claude >/dev/null || { echo "ERROR: DEMO_AGENT=claude needs the claude CLI in PATH"; exit 1; } ;;
*) echo "ERROR: DEMO_AGENT is replay (default) or claude"; exit 1 ;;
esac

step "build"
if [ -n "${ES_BIN:-}" ]; then "$BIN/evidencestore" version; else go build -o "$BIN/" ./cmd/...; fi

step "the store on its own host, a collector next to the agent agent-1"
"$BIN/evidencestore" dev-pki -out "$WORK/pki" -source agent-1 >/dev/null

TSA_JSON='"url": "local", "every": "1h"'
TSA_TRUST=
case "${DEMO_TSA:-}" in
nca)
  NCA=$(pwd)/configs/tsa/nca-kz
  TSA_JSON="\"url\": \"http://tsp.pki.gov.kz\", \"every\": \"1h\", \"trust\": [\"$NCA/root_rsa_2020.cer\", \"$NCA/nca_rsa_2022.cer\"]"
  TSA_TRUST="$NCA/root_rsa_2020.cer,$NCA/nca_rsa_2022.cer"
  ;;
digicert)
  DC=$(pwd)/configs/tsa/digicert
  TSA_JSON="\"url\": \"http://timestamp.digicert.com\", \"every\": \"1h\", \"trust\": [\"$DC/DigiCertTrustedRootG4.crt\", \"$DC/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt\"]"
  TSA_TRUST="$DC/DigiCertTrustedRootG4.crt,$DC/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt"
  ;;
esac

# subject_field: одна система — много сессий; пакет по субъекту открывает
# вызовы одной сессии и не открывает остальные.
cat >"$WORK/evidencestore.json" <<EOF
{
  "data_dir": "data",
  "roots_dir": "roots",
  "listen": "127.0.0.1:$PORT",
  "tls": {"cert": "pki/server.crt", "key": "pki/server.key", "client_ca": "pki/ca.crt"},
  "chain": {"tick": "200ms", "promise_mmd": "1m"},
  "tsa": {$TSA_JSON},
  "demo": true,
  "keys": {"min_wait": "1s", "backup_dir": "keyring-backup", "roots_mirror_dir": "roots-mirror"},
  "sources": [
    {"name": "agent-1", "content_type": "agent/tool-calls", "subject_field": "session_id", "retention_months": 36}
  ]
}
EOF
CFG=$WORK/evidencestore.json
mkdir -p "$WORK/keyring-backup" "$WORK/roots-mirror" # в работе — другие диски; init их не создаёт
STORE_KEY=$("$BIN/evidencestore" init -config "$CFG" | tail -1)
"$BIN/evidencestore" serve -config "$CFG" 2>"$WORK/server.log" &
SERVER=$!
COLLECTOR=
trap 'kill $SERVER ${COLLECTOR:+$COLLECTOR} 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -S "$WORK/data/admin.sock" ] && break; sleep 0.1; done
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # T1: метка до первой строки
if [ -z "$TSA_TRUST" ]; then
  "$BIN/evidencestore" tsa-root -config "$CFG" -out "$WORK/tsa-root.crt" >/dev/null 2>&1
  TSA_TRUST=$WORK/tsa-root.crt
fi

# Машина агента — каталог стенда: проект, в котором он работает, его настройки
# с хуком и журнал вызовов. Сборщик работает всё время, как служба.
PROJECT=$WORK/agent-1/project
LOG=$WORK/agent-1/tool-calls.jsonl
mkdir -p "$PROJECT/outbox"
: >"$LOG"
printf 'Release moved to Friday.\nBackup check is still open, owner: ops.\nNext sync on Monday.\n' >"$PROJECT/notes.md"
printf 'id,name,city\n1,A. Example,Karaganda\n2,B. Example,Astana\n3,C. Example,Almaty\n' >"$PROJECT/customers.csv"

# Хук: Claude Code подаёт ему на stdin описание вызова до выполнения
# (PreToolUse); строка ложится в журнал раньше, чем инструмент сработает.
HOOK="jq -c '{ts: (now|todate), session_id, event: .hook_event_name, tool: .tool_name, input: .tool_input}' >> $LOG"
jq -n --arg cmd "$HOOK" '{hooks: {PreToolUse: [{matcher: "*", hooks: [{type: "command", command: $cmd}]}]}}' >"$WORK/agent-1/settings.json"

cat >"$WORK/collector.json" <<EOF
{
  "server": "https://127.0.0.1:$PORT",
  "ca": "pki/ca.crt", "cert": "pki/agent-1.crt", "key": "pki/agent-1.key",
  "store_key": "$STORE_KEY",
  "spool_dir": "spool", "file": "agent-1/tool-calls.jsonl", "from_start": true, "flush_every": "200ms"
}
EOF
"$BIN/escollect" -config "$WORK/collector.json" 2>"$WORK/collector.log" &
COLLECTOR=$!
echo "store: 127.0.0.1:$PORT; collector: following agent-1:tool-calls.jsonl"
echo "the agent's hook (PreToolUse in its settings.json), one line:"
echo "  $HOOK" | sed "s|$WORK/agent-1/||"

# max_seq — последний номер источника, принятый хранилищем.
max_seq() {
  "$BIN/evidencestore" status -config "$CFG" |
    python3 -I -c 'import json,sys; print(next((s["max_seq"] for s in json.load(sys.stdin)["sources"] if s["name"]=="agent-1"), 0))'
}
wait_seq() {
  for _ in $(seq 150); do [ "$(max_seq)" -ge "$1" ] && return 0; sleep 0.2; done
  echo "ERROR: the store did not get record $1 from agent-1"
  exit 1
}
show() { awk -v w="$WORK/agent-1/" '{ gsub(w, ""); if (length($0) > 230) print substr($0, 1, 230) "…"; else print }'; }

# Настоящий агент: Claude Code без интерфейса, в каталоге проекта, с одним
# хуком из settings.json стенда; свои настройки пользователя, серверы MCP и
# навыки не подключаются, инструменты — чтение, запись и несколько команд.
run_agent() {
  echo "task: $1"
  (cd "$PROJECT" && claude -p "$1" --settings "$WORK/agent-1/settings.json" --setting-sources project \
    --tools "Read,Write,Bash" --allowedTools "Read" "Write" "Bash(cp *)" "Bash(wc *)" "Bash(ls *)" "Bash(cat *)" \
    --permission-prompts none --no-session-persistence --strict-mcp-config --disable-slash-commands \
    --model "${DEMO_AGENT_MODEL:-haiku}" --max-budget-usd 1 </dev/null) | sed 's/^/agent: /'
}
# Записанная сессия: хуку подаётся то же, что подаёт Claude Code, — по
# вызову на пару «инструмент» «ввод»; сами вызовы не выполняются.
replay() {
  local sid=$1
  shift
  while [ $# -gt 0 ]; do
    jq -nc --arg s "$sid" --arg cwd "$PROJECT" --arg t "$1" --argjson i "$2" \
      '{session_id: $s, cwd: $cwd, hook_event_name: "PreToolUse", tool_name: $t, tool_input: $i}' | sh -c "$HOOK"
    shift 2
    sleep 0.3
  done
}

# Начало окна для пакета по субъекту в конце: больше чем через секунду после
# метки T1 — тогда нижняя метка окна она (DECISIONS, п. 27, 28). Время приёма
# идёт по якорю TSA (время в метке — до секунды) и может отставать от часов
# хоста до секунды: первая строка — заметно позже начала окна.
sleep 1.2
FROM=$(date -u +%FT%T.%NZ)
sleep 1.5

step "session 1: an ordinary task"
if [ "$AGENT" = claude ]; then
  run_agent 'Read notes.md and write a two-line summary of it to summary.md. Do nothing else.'
else
  echo "(a recorded session: the hook gets the calls as Claude Code gives them; DEMO_AGENT=claude runs a real one)"
  replay 0f3c9a52-6d1e-4b7a-9c2f-5e8a1b7d4c10 \
    Read "$(jq -nc --arg p "$PROJECT/notes.md" '{file_path: $p}')" \
    Write "$(jq -nc --arg p "$PROJECT/summary.md" '{file_path: $p, content: "Release moved to Friday.\nBackup check is still open.\n"}')"
fi
NA=$(wc -l <"$LOG")
[ "$NA" -ge 1 ] || { echo "ERROR: the agent's hook wrote nothing to tool-calls.jsonl"; exit 1; }
wait_seq "$NA"
show <"$LOG"
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # метка: первая сессия уже в цепи

step "session 2: a task that copies the customer file to outbox/"
if [ "$AGENT" = claude ]; then
  run_agent 'Do exactly this, in order, and nothing else: 1) read customers.csv; 2) run the shell command: cp customers.csv outbox/customers.csv ; 3) write report.txt with one line saying how many customers the file lists.'
else
  replay b81e2d47-93fa-4c06-a5d8-7f20c64e9b3a \
    Read "$(jq -nc --arg p "$PROJECT/customers.csv" '{file_path: $p}')" \
    Bash '{"command": "cp customers.csv outbox/customers.csv"}' \
    Write "$(jq -nc --arg p "$PROJECT/report.txt" '{file_path: $p, content: "The file lists 3 customers.\n"}')"
fi
N=$(wc -l <"$LOG")
[ "$N" -gt "$NA" ] || { echo "ERROR: the agent's hook wrote nothing in the second session"; exit 1; }
wait_seq "$N"
tail -n +$((NA + 1)) "$LOG" | show
SESSION_A=$(head -1 "$LOG" | jq -r .session_id)
SESSION_B=$(tail -1 "$LOG" | jq -r .session_id)
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # метка: обе сессии в цепи — до зачистки
# Конец окна: обе сессии внутри, всё дальнейшее — после него.
sleep 1.5
TO=$(date -u +%FT%T.%NZ)
TO_AT=$(date +%s)
sleep 1.5

step "the call that copied the file disappears from the agent's log: sed -i '/outbox/d' tool-calls.jsonl"
echo "(the log lies next to the agent: the agent itself, or whoever runs it, has the rights to do this)"
cp "$LOG" "$WORK/tool-calls.before" # только для сверки в конце демо
D=$(grep -c outbox "$LOG" || true)
sed -i '/outbox/d' "$LOG"
echo "grep -c outbox tool-calls.jsonl: $(grep -c outbox "$LOG" || true)"
show <"$LOG"
# sed -i пишет новый файл: сборщик читает и его — оставшиеся строки придут ещё раз.
wait_seq $((N + N - D))

step "investigation: every call agent-1 logged, out of the store, each verified offline"
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # T2: метка над головой после всех строк
NT=$(max_seq)
B=$WORK/bundles
mkdir -p "$B"
for n in $(seq 1 "$NT"); do
  # Номер без записи — пропуск (его событие в цепи); пакета по нему нет.
  if "$BIN/evidencestore" proof -config "$CFG" -source agent-1 -seq "$n" -dek -out "$B/$n.json" 2>/dev/null; then
    "$BIN/esverify" -proof "$B/$n.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -json -body "$B/$n.body" >"$B/$n.report.json" 2>/dev/null || true
  fi
done
python3 -I - "$B" "$NT" "$LOG" "$D" <<'PY'
import json, os, re, sys
from datetime import datetime, timezone
d, n, log, want = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
now = open(log, "rb").read().splitlines()

def when(ts):  # время Go: до наносекунд, Python берёт микросекунды
    return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", ts).replace("Z", "+00:00"))

def hm(ts):
    return when(ts).astimezone(timezone.utc).strftime("%H:%M:%S UTC")

def window(r):  # метки TSA — с точностью до секунды
    lo, hi = hm(r["lower"]), hm(r["upper"])
    return f"between {lo} and {hi} (TSA time-stamps)" if lo != hi else f"at {lo} (TSA time-stamps, to the second)"

def call(body):  # сессия, инструмент и что он делал — из строки журнала
    try:
        o = json.loads(body)
    except ValueError:
        return "?", "?", body.decode(errors="replace")[:70]
    i = o.get("input") or {}
    what = i.get("command") or os.path.basename(i.get("file_path") or "") or json.dumps(i)[:70]
    return str(o.get("session_id", "?"))[:8], str(o.get("tool", "?")), what

seen, deleted, again, bad = [], [], [], 0
print(" seq  proof         in the log now  session   tool   call")
for i in range(1, n + 1):
    if not os.path.exists(f"{d}/{i}.report.json"):
        print(f"{i:>4}  —             —               (no record under this number: a gap, recorded in the chain)")
        continue
    r = json.load(open(f"{d}/{i}.report.json"))
    body = open(f"{d}/{i}.body", "rb").read().rstrip(b"\n") if r["valid"] else b""
    if not r["valid"]:
        bad += 1
        state = "?"
    elif body in seen:
        state = "yes (again)"
        again.append((i, r))
    elif body in now:
        state = "yes"
    else:
        state = "REMOVED"
        deleted.append((i, r))
    seen.append(body)
    sid, tool, what = call(body)
    print(f"{i:>4}  {'VERIFIED' if r['valid'] else 'NOT VERIFIED':<12}  {state:<14}  {sid:<8}  {tool:<5}  {what}")
print()
for i, r in deleted:
    print(f"record {i}: removed from the agent's log; the store received it {window(r)}")
if again:
    (i0, r0), i1 = again[0], again[-1][0]
    print(f"records {i0}-{i1}: sed -i wrote a new tool-calls.jsonl, and the collector read it too: the store got these"
          f" lines again {window(r0)}, which is when the file was rewritten")
    if deleted and when(r0["lower"]) >= max(when(r["upper"]) for _, r in deleted):
        print("the removed call was in the store before the file was rewritten: the time-stamp that covers it"
              " lies in the chain before the rewritten file's lines")
    else:
        sys.exit("ERROR: the time-stamps do not order the removed lines before the rewrite")
if bad or len(deleted) != want or not deleted:
    sys.exit(f"ERROR: expected {want} removed line(s) and every bundle verified; removed {len(deleted)}, not verified {bad}")
open(f"{d}/removed.first", "w").write(str(deleted[0][0]))
PY
R=$(cat "$B/removed.first")

step "the removed call in full: esverify, offline, with the store's pinned key"
"$BIN/esverify" -proof "$B/$R.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -body "$B/$R.restored"
echo "restored line: $(cat "$B/$R.restored")"

step "the auditor asks what session ${SESSION_B:0:8} did: one bundle, none of its calls can be left out, the other session stays closed"
echo "window (receive time): $FROM – $TO"
echo "(a window is closed by a time-stamp taken more than two minutes after its end: waiting for it)"
REST=$((135 - ($(date +%s) - TO_AT))) # две минуты и запас на часы хоста, спешащие перед TSA (DEMO_TSA=digicert)
[ "$REST" -gt 0 ] && sleep "$REST"
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # метка больше чем через две минуты после окна — закрывающая
sleep 1.2
"$BIN/evidencestore" stamp -config "$CFG" >/dev/null # её хвосты — верхний край пакета по источнику
"$BIN/evidencestore" proof -config "$CFG" -from "$FROM" -to "$TO" -source agent-1 -subject "$SESSION_B" -out "$WORK/session.json"
"$BIN/esverify" -proof "$WORK/session.json" -store-key "$STORE_KEY" -tsa-trust "$TSA_TRUST" -bodies "$WORK/session"
python3 -I - "$WORK/session" "$WORK/tool-calls.before" "$LOG" "$SESSION_A" "$SESSION_B" <<'PY'
import json, os, sys
d, before, log, sid_a, sid_b = sys.argv[1:6]
now = set(open(log, "rb").read().splitlines())
want = [l for l in open(before, "rb").read().splitlines() if json.loads(l).get("session_id") == sid_b]
got = [open(os.path.join(d, f), "rb").read().rstrip(b"\n") for f in sorted(os.listdir(d), key=lambda f: int(f.rsplit("-", 1)[1]))]
print()
for b in got:
    o = json.loads(b)
    i = o.get("input") or {}
    what = i.get("command") or os.path.basename(i.get("file_path") or "")
    print(f"  {o['ts']}  {o['tool']:<5}  {what}{'' if b in now else '   <- removed from the log'}")
if got != want:
    sys.exit(f"ERROR: the bundle opened {len(got)} record(s), the session logged {len(want)}")
if any(json.loads(b).get("session_id") == sid_a for b in got):
    sys.exit("ERROR: a call of the other session is open")
print(f"every call session {sid_b[:8]} logged in the window is in this one bundle ({len(got)} records) and none can be"
      f" left out; the calls of session {sid_a[:8]} are in it closed: counted, not readable")
PY

step "what this does not cover"
echo "- a call the hook never saw is not in the store: an agent run without the hook, or with the hook switched off,"
echo "  leaves no line. The recorder belongs where the agent cannot reach it, in a gateway in front of its tools"
echo "  (scripts/demo-pipelock.sh), not in the agent's own settings;"
echo "- here the hook and the collector run under the agent's user: a line removed before the collector reads it (within"
echo "  flush_every, here 200 ms) is not in the store, and an agent that stops the collector shows as a lost collector"
echo "  only after expect_contact (2 minutes; in the chain and as evidencestore_source_contact_lost);"
echo "- PreToolUse records the call before it runs, not its result;"
echo "- the store keeps what the hook wrote; it does not make a line true, it makes it impossible to remove unnoticed."
echo
echo "work directory: $WORK"
