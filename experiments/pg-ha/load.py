#!/usr/bin/env python3
"""load.py — агент под нагрузкой: действие за действием через esmcp, пока нет
файла-стопа. Каждое действие вставляет одну строку orders с номером N и меткой
'load-N' и больше не повторяется: что агенту ответили про N — в журнале
(строка JSON на действие), а что стало с N на самом деле, потом сверяет
verify.py.

    load.py ESMCP CONFIG ЖУРНАЛ СТОП-ФАЙЛ ПЕРВЫЙ_N [ПАУЗА_С] [SQL-ШАБЛОН с {n}]
"""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_session import Session  # noqa: E402


def main():
    binary, config, ledger, stop, n = sys.argv[1:6]
    pause = float(sys.argv[6]) if len(sys.argv) > 6 else 0.05
    template = sys.argv[7] if len(sys.argv) > 7 else "insert into orders values ({n}, 1, 'load-{n}')"
    n = int(n)
    s = Session(binary, config, ledger + ".esmcp.log")
    with open(ledger, "a", buffering=1) as out:
        while not os.path.exists(stop):
            t0 = time.time()
            ok, text = s.call("execute", {"sql": template.format(n=n), "reason": "load"})
            rec = {"n": n, "t0": round(t0, 3), "took": round(time.time() - t0, 3), "ok": ok, "text": text}
            if ok:
                rec["told"], rec["xid"] = "committed", json.loads(text)["xid"]
            elif "may have been committed" in text:
                rec["told"] = "unknown"
                m = re.search(r"transaction (\d+)", text)
                rec["xid"] = m.group(1) if m else ""
            else:
                rec["told"] = "failed"
            out.write(json.dumps(rec) + "\n")
            n += 1
            time.sleep(pause)
    s.close()


if __name__ == "__main__":
    main()
