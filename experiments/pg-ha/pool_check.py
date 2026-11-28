#!/usr/bin/env python3
"""pool_check.py — esmcp через пулер соединений: два сеанса агента на один
конфиг (в нём "pooler": true), вызовы вперемешку.

    pool_check.py ESMCP CONFIG

Проверяет то, что в режиме пула по транзакциям ломалось или могло сломаться:
действия подряд (подготовленные команды остаются на соединении базы), то,
что SQL агента оставляет сеансу (настройки, рекомендательный замок), вид
текста значений и таймауты без параметров входа, отказы (DDL, предел строк,
таймаут с отменой запроса через пулер), действия двух сеансов одновременно.
Код 1 — хотя бы одна проверка не сошлась.
"""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_session import Session  # noqa: E402

BIN, CFG = sys.argv[1], sys.argv[2]
bad = 0
def check(name, cond, detail=""):
    global bad
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else "  :: " + str(detail)[:400]))
    bad += not cond
a, b = Session(BIN, CFG, CFG + ".log"), Session(BIN, CFG, CFG + ".log")
ok, t = a.call("query", {"sql": "select count(*) from accounts"}); check("query", ok and '"2000"' in t, t)
for i in range(6):
    s = (a, b)[i % 2]
    ok, t = s.call("execute", {"sql": f"update accounts set note = 'p{i}' where id = {10+i}", "reason": "pool"}); check(f"execute {i}", ok and "committed" in t, t)
ok, t = a.call("execute", {"statements": ["update accounts set note = 'm1' where id = 20", "update accounts set note = 'm2' where id = 21"], "reason": "multi"}); check("two statements", ok, t)
# то, что агент пытается оставить соединению базы
ok, t = a.call("execute", {"sql": "select set_config('search_path', 'pg_temp', false), set_config('statement_timeout', '1', false), set_config('DateStyle', 'German', false), pg_advisory_lock(42)", "reason": "leftovers"}); check("leftovers commit", ok, t)
for i in range(4):
    s = (b, a)[i % 2]
    ok, t = s.call("query", {"sql": "select current_setting('search_path'), current_setting('statement_timeout'), current_setting('DateStyle'), current_setting('extra_float_digits'), current_setting('array_nulls'), current_setting('IntervalStyle'), (select count(*) from pg_locks where locktype = 'advisory' and pid = pg_backend_pid()), (select count(*) from pg_prepared_statements), current_setting('application_name'), current_setting('idle_in_transaction_session_timeout'), current_setting('lock_timeout'), current_user::text, pg_backend_pid()"})
    r = json.loads(t)["rows"][0] if ok else None
    check(f"session clean after leftovers {i}", ok and r[0] == '"$user", public' and r[1] == "10s" and r[2] == "ISO, YMD" and r[3] == "3" and r[4] == "on" and r[5] == "postgres" and r[6] == "0" and r[7] == "1" and r[8] == "esmcp/support-bot" and r[9] == "5min" and r[10] == "2s" and r[11] == "esmcp_bot", t)
    ok, t = s.call("execute", {"sql": "update accounts set note = 'after' where id = 30", "reason": "after leftovers"}); check(f"execute after leftovers {i}", ok, t)
# замок сеанса, пережив ROLLBACK, не остаётся (чтение откатывается)
ok, t = a.call("query", {"sql": "select pg_advisory_lock(43)"}); check("advisory lock in a read", ok, t)
ok, t = b.call("query", {"sql": "select count(*) from pg_locks where locktype = 'advisory'"}); check("no advisory lock left", ok and '"0"' in t, t)
# отказы: DDL, предел строк, таймаут
ok, t = a.call("execute", {"sql": "drop table orders", "reason": "x"}); check("DROP refused", not ok and "was not taken" in t, t)
ok, t = a.call("execute", {"sql": "update accounts set note = 'big'", "reason": "x"}); check("row limit", not ok and "refused" in t and "500" in t, t)
ok, t = b.call("query", {"sql": "select count(*) from accounts where note = 'big'"}); check("row limit rolled back", ok and '"0"' in t, t)
t0 = time.time(); ok, t = a.call("execute", {"sql": "update accounts set note = (select 'slow' from pg_sleep(30)) where id = 40", "reason": "slow"}); el = time.time() - t0
check("timeout", not ok and "longer than 5s" in t and el < 9, (el, t))
ok, t = a.call("execute", {"sql": "update accounts set note = 'after-timeout' where id = 40", "reason": "x"}); check("execute after timeout", ok, t)
ok, t = b.call("query", {"sql": "select count(*) from pg_stat_activity where usename = 'esmcp_bot' and state <> 'idle'"}); check("nothing left running", ok and '"1"' in t, t)
# ошибка команды и следующее действие
ok, t = a.call("execute", {"sql": "update accounts set balance = 1/0 where id = 1", "reason": "x"}); check("statement error", not ok and "division by zero" in t, t)
ok, t = a.call("execute", {"sql": "update accounts set note = 'after-error' where id = 41", "reason": "x"}); check("execute after error", ok, t)
# два сеанса одновременно
def burst(s, base, out):
    for i in range(15):
        ok, t = s.call("execute", {"sql": f"update accounts set note = 'c' where id = {base+i}", "reason": "concurrent"}); out.append((ok, t))
ra, rb = [], []
ta, tb = threading.Thread(target=burst, args=(a, 100, ra)), threading.Thread(target=burst, args=(b, 200, rb)); ta.start(); tb.start(); ta.join(); tb.join()
check("30 concurrent actions", all(ok for ok, _ in ra + rb), [t for ok, t in ra + rb if not ok][:2])
ok, t = a.call("actions", {}); check("actions", ok, t)
a.close(); b.close()
print("FAILED" if bad else "all ok"); sys.exit(1 if bad else 0)
