#!/usr/bin/env python3
"""preview_check.py — сверка ответа undo_preview в сценарии run.sh: из ста строк
действия девяносто девять годны к возврату, одна (счёт 150) — конфликт."""
import json
import sys

p = json.loads(sys.argv[1])
c = p["conflicts"][0] if p["conflicts"] else {}
if p["to_apply"] != 99 or p["conflicts_total"] != 1 or c.get("key") != "id=150" or c.get("state") != "changed":
    sys.exit(f"preview_check: ждали 99 строк к возврату и конфликт по счёту 150, получили: {sys.argv[1]}")
b = next(col for col in c["columns"] if col["name"] == "balance")
print(f"undo_preview: вернуть {p['to_apply']} строк; конфликт {c['table']} ({c['key']}): {c['why']}; "
      f"balance был {b["was"]}, действие оставило {b["left"]}, сейчас {b["now"]}")
