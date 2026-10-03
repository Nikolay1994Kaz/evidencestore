#!/usr/bin/env python3
"""Мутационная проверка тестов: портит код по одному месту и ждёт, что
тесты упадут. Выживший мутант = свойство, которое тесты не стерегут.

    python3 scripts/mutate.py keyring          # все мутации пакета
    python3 scripts/mutate.py keyring M1a M6   # только выбранные

Мутация — точная замена строки; если строка не нашлась ровно один раз,
скрипт падает: значит, код поменялся и мутацию надо обновить.
Компиляционная ошибка мутанта засчитывается как «не собрался», а не как
«пойман»: такой мутант ничего не говорит о тестах.
"""
import json, pathlib, signal, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SETS = ROOT / "scripts" / "mutations"

def leftovers():
    """Мутанты, оставшиеся в дереве после убитого прогона."""
    found = []
    for spec_path in SETS.glob("*.json"):
        for m in json.loads(spec_path.read_text(encoding="utf-8"))["mutations"]:
            src = (ROOT / m["file"]).read_text(encoding="utf-8")
            if m["new"] and m["new"] in src and m["old"] not in src:
                found.append(f'{spec_path.name}: {m["name"]} в {m["file"]}')
    return found


def run(pkg, only):
    left = leftovers()
    if left:
        sys.exit("в дереве остался мутант — сначала верни код:\n  " + "\n  ".join(left))
    spec = json.loads((SETS / f"{pkg}.json").read_text(encoding="utf-8"))
    caught = survived = broken = 0
    for m in spec["mutations"]:
        name = m["name"]
        if only and not any(name.startswith(o + " ") for o in only):
            continue
        path = ROOT / m["file"]
        src = path.read_text(encoding="utf-8")
        if src.count(m["old"]) != 1:
            sys.exit(f"{name}: строка найдена {src.count(m['old'])} раз — обнови мутацию")
        path.write_text(src.replace(m["old"], m["new"]), encoding="utf-8")
        # Убьют скрипт сигналом — код вернётся: finally при SIGTERM не сработал бы.
        restore = lambda *_: (path.write_text(src, encoding="utf-8"), sys.exit(130))
        signal.signal(signal.SIGTERM, restore)
        signal.signal(signal.SIGINT, restore)
        try:
            vet = subprocess.run(["go", "vet"] + spec["packages"], cwd=ROOT, capture_output=True, text=True)
            if vet.returncode != 0 and ("undefined" in vet.stderr or "declared and not used" in vet.stderr or "cannot use" in vet.stderr):
                broken += 1
                print(f"НЕ СОБРАЛСЯ {name}")
                continue
            r = subprocess.run(["go", "test", "-race", "-count=1"] + spec["packages"],
                               cwd=ROOT, capture_output=True, text=True, timeout=600)
        finally:
            path.write_text(src, encoding="utf-8")
        if r.returncode != 0:
            caught += 1
            fails = [l.strip() for l in (r.stdout + r.stderr).splitlines()
                     if l.startswith("--- FAIL") or "DATA RACE" in l or l.startswith("panic:")]
            print(f"пойман     {name}: {', '.join(dict.fromkeys(fails))[:140]}")
        else:
            survived += 1
            print(f"ВЫЖИЛ      {name}")
    print(f"итого: поймано {caught}, выжило {survived}, не собралось {broken}")
    return survived == 0 and broken == 0

if __name__ == "__main__":
    ok = run(sys.argv[1], sys.argv[2:])
    sys.exit(0 if ok else 1)
