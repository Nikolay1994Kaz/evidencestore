#!/usr/bin/env python3
"""verify.py — сверка после прогона: что агенту ответили (журналы load.py),
что в базе (строки 'load-N' и номер транзакции, которая их вставила) и что у
сборщика (index.jsonl: транзакция целиком, с действием шлюза, или отпечатком).

    verify.py DSN-для-psql КАТАЛОГ-pg-index ЖУРНАЛ... [--expect ключ=число ...]

Печатает сводку JSON. Код 1 — нарушено то, что должно держаться всегда:
  - действие, про которое агенту сказано «committed», есть в базе;
  - действие, про которое сказано «failed and was rolled back», в базе нет;
  - каждая строка базы — от действия из журнала, и транзакция та же;
  - каждая транзакция базы дошла до сборщика (целиком или отпечатком);
и то, что названо в --expect (например whole=120 fingerprint=0 unknown=0).
"""
import json
import subprocess
import sys


def main():
    args = sys.argv[1:]
    expect = {}
    if "--expect" in args:
        i = args.index("--expect")
        expect = {k: int(v) for k, v in (a.split("=") for a in args[i + 1:])}
        args = args[:i]
    dsn, index_dir, ledgers = args[0], args[1], args[2:]
    told = {}
    for path in ledgers:
        for line in open(path):
            r = json.loads(line)
            told[r["n"]] = r
    out = subprocess.run(["psql", dsn, "-X", "-Atc", "select id, xmin from orders where item like 'load-%'"],
                         capture_output=True, text=True, check=True).stdout
    in_db = {int(a): b for a, b in (line.split("|") for line in out.splitlines())}
    # Только строки этого прогона: номера — между первым и последним из журналов.
    in_db = {n: x for n, x in in_db.items() if told and min(told) <= n <= max(told)}
    whole, finger = {}, set()
    for line in open(index_dir + "/index.jsonl"):
        r = json.loads(line)
        if r.get("kind") == "fingerprint":
            finger.add(str(r["xid"]))
        else:
            whole[str(r["xid"])] = (r.get("action") or {}).get("id", "")
    alerts = {}
    try:
        for line in open(index_dir + "/alerts.jsonl"):
            for s in json.loads(line).get("signals", []):
                alerts[s["kind"]] = alerts.get(s["kind"], 0) + 1
    except FileNotFoundError:
        pass
    s = {"actions": len(told), "committed": 0, "failed": 0, "unknown": 0, "unknown_in_db": 0,
         "committed_not_in_db": [], "failed_in_db": [], "db_not_in_ledger": [], "xid_mismatch": [],
         "whole": 0, "fingerprint": 0, "not_collected": [], "alerts": alerts}
    for n, r in sorted(told.items()):
        s[r["told"]] += 1
        if r["told"] == "committed" and n not in in_db:
            s["committed_not_in_db"].append(n)
        if r["told"] == "failed" and n in in_db:
            s["failed_in_db"].append(n)
        if r["told"] == "unknown" and n in in_db:
            s["unknown_in_db"] += 1
        if n in in_db and r.get("xid") and r["xid"] != in_db[n]:
            s["xid_mismatch"].append(n)
    for n, xid in sorted(in_db.items()):
        if n not in told:
            s["db_not_in_ledger"].append(n)
        if xid in whole:
            s["whole"] += 1
        elif xid in finger:
            s["fingerprint"] += 1
        else:
            s["not_collected"].append(n)
    bad = [k for k in ("committed_not_in_db", "failed_in_db", "db_not_in_ledger", "xid_mismatch", "not_collected") if s[k]]
    for k, v in expect.items():
        got = s["alerts"].get(k[6:], 0) if k.startswith("alert:") else s[k]
        if got != v:
            bad.append(f"{k}: expected {v}, got {got}")
    s["in_db"] = len(in_db)
    print(json.dumps(s))
    if bad:
        print("verify: FAILED:", "; ".join(bad), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
