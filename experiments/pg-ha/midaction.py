#!/usr/bin/env python3
"""midaction.py — основная база пропадает посреди действия агента.

    midaction.py ESMCP CONFIG СЦЕНАРИЙ N

Сценарии (кластер стенда: Patroni, синхронная реплика, строгий режим —
COMMIT ждёт реплику):
  sql      основную убивают, пока идёт SQL агента (до COMMIT);
  frozen   основная замирает без единого пакета (docker pause), пока идёт SQL;
  commit   основную убивают, пока COMMIT ждёт реплику: зафиксировано ли —
           не узнать (на стенде транзакция обычно доезжает до реплики и
           остаётся на новой основной: журнал уже был в её сокете);
  link     связь рвётся, пока COMMIT ждёт реплику, а база жива: агенту —
           «неизвестно», транзакция потом фиксируется;
  silent   основная замирает без единого пакета, пока COMMIT ждёт реплику
           (для адреса без балансировщика: рвать соединение некому).
Действие — UPDATE accounts SET note = 'mid-N' WHERE id = N. Печатает JSON:
что ответили агенту, сколько ждал, что в базе после переключения.
Код 1 — ответ агенту противоречит базе или не тот, что должен быть.
"""
import json
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_session import Session  # noqa: E402

PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "es-pgha")
PSQL = os.environ.get("PGHA_PSQL", "host=127.0.0.1 port=55000 user=postgres dbname=shop")


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)


def members():
    for node in ("pg1", "pg2"):
        p = docker("compose", "-p", PROJECT, "exec", "-T", node, "patronictl", "-c", "/etc/patroni.yml", "list", "-f", "json")
        if p.returncode == 0 and p.stdout.strip().startswith("["):
            return json.loads(p.stdout)
    return []


def leader():
    return next((m["Member"] for m in members() if m["Role"] == "Leader"), "")


def replica(of):
    return "pg2" if of == "pg1" else "pg1"


def sql(q, tries=90):
    for _ in range(tries):
        p = subprocess.run(["psql", PSQL, "-X", "-Atc", q], capture_output=True, text=True)
        if p.returncode == 0:
            return p.stdout.strip()
        time.sleep(1)
    raise RuntimeError(f"psql: {p.stderr}")


def wait_cluster():
    """Основная есть, реплика догоняет синхронно."""
    for _ in range(120):
        m = members()
        if any(x["Role"] == "Leader" and x["State"] == "running" for x in m) and any(x["Role"] == "Sync Standby" and x["State"] == "streaming" for x in m):
            return
        time.sleep(1)
    raise RuntimeError(f"the cluster did not settle: {members()}")


def main():
    binary, config, scenario, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    wait_cluster()
    lead = leader()
    rep = replica(lead)
    s = Session(binary, config, config + ".log")
    ok, text = s.call("query", {"sql": "select 1"})  # соединение открыто до события
    assert ok, text
    stmt = f"update accounts set note = 'mid-{n}' where id = {n}"
    if scenario in ("sql", "frozen"):
        stmt = f"update accounts set note = (select 'mid-{n}' from pg_sleep(20)) where id = {n}"
    if scenario in ("commit", "link", "silent"):
        docker("pause", f"{PROJECT}-{rep}-1")  # COMMIT теперь ждёт реплику
    res = {}

    def act():
        t0 = time.time()
        res["ok"], res["text"] = s.call("execute", {"sql": stmt, "reason": scenario})
        res["took"] = round(time.time() - t0, 1)

    t = threading.Thread(target=act)
    t.start()
    time.sleep(3)
    if scenario == "sql" or scenario == "commit":
        docker("kill", f"{PROJECT}-{lead}-1")
    elif scenario in ("frozen", "silent"):
        docker("pause", f"{PROJECT}-{lead}-1")
    elif scenario == "link":
        docker("compose", "-p", PROJECT, "restart", "-t", "1", "haproxy")
    t.join(timeout=240)
    if t.is_alive():
        res = {"ok": False, "text": "the call did not return in 240s", "took": 240}
    # Кластер — в строй: замершие — отмереть, убитые — запустить.
    if scenario in ("commit", "link", "silent"):
        docker("unpause", f"{PROJECT}-{rep}-1")
    if scenario in ("frozen", "silent"):
        time.sleep(25)  # ключ основной истекает, реплика становится основной
        docker("unpause", f"{PROJECT}-{lead}-1")
    if scenario in ("sql", "commit"):
        for _ in range(60):  # реплика становится основной, когда истекает ключ убитой
            if leader() == rep:
                break
            time.sleep(1)
        docker("compose", "-p", PROJECT, "start", lead)
    wait_cluster()
    note = sql(f"select note from accounts where id = {n}")
    in_db = note == f"mid-{n}"
    told = "committed" if res["ok"] else "unknown" if "may have been committed" in res["text"] else "failed"
    want = {"sql": ("failed", False), "frozen": ("failed", False), "commit": ("unknown", None), "link": ("unknown", True), "silent": ("unknown", None)}[scenario]
    bad = []
    if told != want[0]:
        bad.append(f"the agent was told {told!r}, expected {want[0]!r}")
    if want[1] is not None and in_db != want[1]:
        bad.append(f"the change is {'in' if in_db else 'not in'} the database")
    if told == "failed" and in_db or told == "committed" and not in_db:
        bad.append("the answer contradicts the database")
    print(json.dumps({"scenario": scenario, "n": n, "told": told, "took": res["took"], "in_db": in_db, "leader_was": lead, "leader_now": leader(),
                      "text": res["text"][:300], "bad": bad}))
    try:
        s.close()
    except Exception:
        pass
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
