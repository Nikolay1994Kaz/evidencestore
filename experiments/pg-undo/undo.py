#!/usr/bin/env python3
"""undo.py — обратные операции для одной транзакции Postgres по до-образам из хранилища улик.

Вход — каталог тел записей, который пишет `esverify -bodies DIR` (пакет по
субъекту, субъект — номер транзакции xid) или `esverify -body` по одной записи.
Тела — строки журнала espgtap (internal/pgtap):

    {"xid":751,"part":1,"last":true,"gz":"<base64>"}

Поля gz частей 1..k, склеенные по порядку, — один поток gzip со строками JSON:
H заголовок (кто, отметки действия), R таблица (колонки, типы, первичный ключ),
I/U/D изменения со старой и новой строкой, T — TRUNCATE, C — итог.

    undo.py plan -bodies DIR -xid N [-report FILE] -out DIR
        разобрать транзакцию, написать DIR/plan.json и DIR/check.sql
    undo.py sql -plan DIR -check FILE [-by КТО] [-reason ЗАЧЕМ]
        по ответу базы на check.sql написать DIR/undo.sql

Сам скрипт в базу не ходит: check.sql и undo.sql исполняет psql. Откат — одна
транзакция; каждая группа шагов проверяет, что изменила ровно столько строк,
сколько обещала, иначе вся транзакция отменяется.

Коды выхода: 0 — готово, 1 — неверный вызов или ввод, 2 — откат построить
нельзя (TRUNCATE, неполные образы, транзакция не вся), 3 — база ответила не то.
"""
import argparse
import base64
import gzip
import json
import os
import secrets
import sys


class Refused(Exception):
    """Откат построить нельзя: причина — в сообщении."""


def fail(msg, code=1):
    print(f"undo: {msg}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------- разбор тел


def load_bodies(directory):
    """Тела в порядке номеров записей: [(seq, часть)]. Имя файла — <источник>-<номер>."""
    out = []
    for name in os.listdir(directory):
        try:
            seq = int(name.rsplit("-", 1)[1])
        except (IndexError, ValueError):
            raise Refused(f"в каталоге тел лишний файл {name!r}")
        with open(os.path.join(directory, name), "rb") as f:
            raw = f.read()
        try:
            part = json.loads(raw)
        except ValueError as e:
            raise Refused(f"запись {seq} — не JSON ({e}): это не строка журнала espgtap")
        if not isinstance(part, dict) or not {"xid", "part", "last", "gz"} <= part.keys():
            raise Refused(f"запись {seq} — не строка журнала espgtap")
        out.append((seq, part))
    out.sort(key=lambda p: p[0])
    return out


def transaction(parts, xid):
    """Строки потока одной транзакции из её частей.

    После перезапуска сборщика транзакция может лежать в журнале дважды (первый
    раз оборванной): берётся последний целый набор частей 1..k с "last": true.
    resent — была ли пересылка.
    """
    run, whole, runs = [], None, 0
    for seq, p in parts:
        if p["xid"] != xid:
            raise Refused(f"запись {seq} — транзакции {p['xid']}, а не {xid}: тела не той транзакции")
        if p["part"] == 1:
            run, runs = [], runs + 1
        if p["part"] != len(run) + 1:
            raise Refused(f"запись {seq}: часть {p['part']} после части {len(run)} — части транзакции не все")
        run.append(p)
        if p["last"]:
            whole, run = run, []
    if whole is None:
        raise Refused("нет последней части транзакции: она ещё не доехала целиком")
    try:
        stream = gzip.decompress(b"".join(base64.b64decode(p["gz"], validate=True) for p in whole))
        lines = [json.loads(l) for l in stream.split(b"\n") if l]
    except (ValueError, OSError, EOFError) as e:
        raise Refused(f"поток транзакции не читается: {e}")
    if len(lines) < 2 or lines[0].get("t") != "H" or lines[-1].get("t") != "C":
        raise Refused("поток транзакции не идёт от заголовка до итога")
    if lines[0].get("v") != 1 or lines[0].get("xid") != xid:
        raise Refused(f"заголовок потока: версия {lines[0].get('v')}, транзакция {lines[0].get('xid')}")
    return lines, runs > 1


class Row:
    """Одна строка таблицы за транзакцию: какой была до и какой стала после."""

    def __init__(self, table, old, n):
        self.table = table
        self.old = old  # None — строки до транзакции не было
        self.new = None  # None — строки после транзакции нет
        self.first = n
        self.touches = 0


def build_plan(parts, xid):
    lines, resent = transaction(parts, xid)
    head = lines[0]
    rels, tables = {}, {}  # номер таблицы в потоке -> имя; имя -> описание
    truncated, counts = [], {}
    live, dead, order = {}, {}, []
    markers = [{"prefix": "evidence/action", "content": a} for a in head.get("actions") or []]

    def image(seq, name, t, vals):
        if len(vals) != len(t["columns"]):
            raise Refused(f"{name}: в изменении {seq} значений {len(vals)}, а колонок {len(t['columns'])}")
        for c, v in zip(t["columns"], vals):
            if v is not None and not isinstance(v, str):
                raise Refused(f"{name}.{c}: значение в журнале не текстом ({v}): такое опыт не возвращает")
        return dict(zip(t["columns"], vals))

    n = 0
    for r in lines[1:-1]:
        a = r.get("t")
        if a == "R":
            name = f'{r["schema"]}.{r["table"]}'
            if not r["pk"]:
                raise Refused(f"{name}: у таблицы нет первичного ключа — строку нечем адресовать")
            if r["identity"] != "f":
                raise Refused(f"{name}: таблица не REPLICA IDENTITY FULL — старых строк в журнале нет")
            t = {"schema": r["schema"], "table": r["table"], "pk": r["pk"],
                 "columns": sorted(r["columns"]), "types": dict(zip(r["columns"], r["types"])), "order": r["columns"]}
            if name in tables and {k: tables[name][k] for k in ("pk", "columns", "types")} != {k: t[k] for k in ("pk", "columns", "types")}:
                raise Refused(f"{name}: таблицу изменили посреди транзакции (DDL): такое опыт не разбирает")
            rels[r["id"]], tables[name] = name, t
            continue
        if a == "M":
            markers.append({"prefix": r.get("prefix"), "content": r.get("content")})
            continue
        if a == "T":
            truncated += r["tables"]
            continue
        if a not in ("I", "U", "D"):
            raise Refused(f"строка потока вида {a!r} этому скрипту незнакома")
        n += 1
        name = rels.get(r["r"])
        if name is None:
            raise Refused(f"изменение {n} — таблицы {r['r']}, которой в потоке нет")
        t = tables[name]
        if r.get("partial"):
            raise Refused(f"{name}: старая строка в изменении {n} неполная. Целиком она пишется только при REPLICA IDENTITY FULL")
        by_order = dict(t, columns=t["order"])
        old = image(n, name, by_order, r["old"]) if a in ("U", "D") else None
        new = image(n, name, by_order, r["new"]) if a in ("I", "U") else None
        counts[(name, a)] = counts.get((name, a), 0) + 1
        key = lambda img: (name,) + tuple(img[c] for c in t["pk"])

        if a == "I":
            k = key(new)
            if k in live:
                raise Refused(f"{name}: изменение {n} вставляет строку поверх живой — журнал не сходится")
            row = dead.pop(k, None)
            if row is None:
                row = Row(name, None, n)
                order.append(row)
        elif a == "U":
            ko, k = key(old), key(new)
            row = live.pop(ko, None)
            if row is None:
                row = Row(name, old, n)
                order.append(row)
            elif row.new != old:
                raise Refused(f"{name}: изменение {n} правит не тот образ строки, что оставило прежнее")
            if k != ko and (k in live or k in dead):
                raise Refused(f"{name}: изменение {n} переносит строку на ключ, занятый в этой же транзакции: такое опыт не разбирает")
        else:
            k = key(old)
            row = live.pop(k, None)
            if row is None:
                row = Row(name, old, n)
                order.append(row)
            elif row.new != old:
                raise Refused(f"{name}: изменение {n} удаляет не тот образ строки, что оставило прежнее")
            if k in dead:
                raise Refused(f"{name}: ключ изменения {n} в этой транзакции удалён дважды разными строками: такое опыт не разбирает")
        row.new = new
        row.touches += 1
        (dead if a == "D" else live)[k] = row

    if lines[-1].get("changes") != n:
        raise Refused(f"итог потока называет {lines[-1].get('changes')} изменений, а в потоке их {n}: журнал транзакции не весь")
    if truncated:
        raise Refused(
            "транзакция сделала TRUNCATE " + ", ".join(sorted(set(truncated))) + ": строк в журнале нет, "
            "до-образов не существует, построчный откат невозможен (нужна резервная копия)"
        )
    for t in tables.values():
        del t["order"]

    # Обратный порядок: что транзакция тронула последним, возвращается первым
    # (удалил детей, потом родителя — вернуть родителя, потом детей).
    steps, noop = [], 0
    for row in reversed(order):
        if row.old == row.new:
            noop += 1  # вставил и удалил, или вернул прежние значения сам
            continue
        op = "delete" if row.old is None else "insert" if row.new is None else "update"
        steps.append({"step": len(steps) + 1, "op": op, "table": row.table, "old": row.old, "new": row.new, "touches": row.touches})
    return {
        "xid": str(xid), "records": len(parts), "resent": resent, "who": head.get("who"), "undo": head.get("undo"),
        "markers": markers, "noop": noop, "changes": n,
        "counts": [{"table": t, "action": a, "lines": c} for (t, a), c in sorted(counts.items())],
        "tables": tables, "steps": steps,
    }


def text(v):
    """Значение из ответа базы (to_jsonb) текстом; None — NULL."""
    if v is None:
        return None
    if v is True:
        return "t"  # как PostgreSQL пишет boolean текстом — так он лежит и в журнале
    if v is False:
        return "f"
    if isinstance(v, str):
        return v
    return json.dumps(v, ensure_ascii=False)


def check_report(report, xid, bodies):
    """Отчёт esverify -json о пакете: тот ли пакет и все ли записи транзакции в нём открыты."""
    s = report.get("subject") or {}
    if not report.get("valid"):
        raise Refused("пакет не прошёл проверку esverify")
    if report.get("kind") != "source" or s.get("field") != "xid" or s.get("value") != str(xid):  # пакет по субъекту
        raise Refused(f"пакет не по транзакции {xid}: субъект {s.get('field')}={s.get('value')}")
    if s.get("opened") != bodies or s.get("keyless") or s.get("unbound") or s.get("no_label"):
        raise Refused(
            f"не все записи транзакции открыты: тел {bodies}, в отчёте открыто {s.get('opened')} из {s.get('records')}, "
            f"без ключа {s.get('keyless')}, под меткой месяцев без открытых тел {s.get('unbound')}, в закрытых месяцах {s.get('no_label')}"
        )
    return s.get("unlabeled") or 0


# ---------------------------------------------------------------- SQL


def lit(v):
    return "NULL" if v is None else "'" + v.replace("'", "''") + "'"


def ident(name):
    return '"' + name.replace('"', '""') + '"'


def groups(steps):
    """Соседние шаги одного вида над одной таблицей — одной командой."""
    out = []
    for s in steps:
        if out and out[-1][0]["table"] == s["table"] and out[-1][0]["op"] == s["op"]:
            out[-1].append(s)
        else:
            out.append([s])
    return out


class Group:
    """Группа шагов как список VALUES: step, новый образ (n0..), старый образ (o0..)."""

    def __init__(self, tables, steps):
        self.steps = steps
        self.op = steps[0]["op"]
        t = tables[steps[0]["table"]]
        self.name = steps[0]["table"]
        self.rel = ident(t["schema"]) + "." + ident(t["table"])
        self.cols = t["columns"]
        self.types = t["types"]
        self.pk = [self.cols.index(c) for c in t["pk"]]
        # Какие образы нужны: правке — оба, возврату удалённой — старый, уборке вставленной — новый.
        self.sides = {"update": ["n", "o"], "insert": ["o"], "delete": ["n"]}[self.op]

    def values(self):
        names = ["step"] + [f"{s}{i}" for s in self.sides for i in range(len(self.cols))]
        rows = []
        for n, st in enumerate(self.steps):
            cells = [str(st["step"])]
            for s in self.sides:
                img = st["new"] if s == "n" else st["old"]
                for c in self.cols:
                    # Тип — в первой строке: остальные Postgres приводит к нему сам.
                    cells.append(lit(img[c]) + (f"::{self.types[c]}" if n == 0 else ""))
            rows.append("(" + ", ".join(cells) + ")")
        return "(VALUES\n  " + ",\n  ".join(rows) + "\n) AS w(" + ", ".join(names) + ")"

    def join(self, side):
        return " AND ".join(f"t.{ident(self.cols[i])} = w.{side}{i}" for i in self.pk)

    def same(self, side):
        return " AND ".join(f"t.{ident(c)} IS NOT DISTINCT FROM w.{side}{i}" for i, c in enumerate(self.cols))

    def missing(self):
        return f"t.{ident(self.cols[self.pk[0]])} IS NULL"


HEADER = "\\set QUIET on\n\\set ON_ERROR_STOP on\nSET standard_conforming_strings = on;\n"


def check_sql(plan):
    """Запрос к базе: что сейчас на месте каждой строки. Ответ — строки «шаг, статус, сведения»."""
    out = [HEADER, "\\pset tuples_only on\n\\pset format unaligned\n\\pset fieldsep '\\t'\n"]
    for name, t in sorted(plan["tables"].items()):
        if t["columns"] is None:
            continue
        reg = f"to_regclass({lit(ident(t['schema']) + '.' + ident(t['table']))})"
        now = f"(SELECT array_agg(attname::text ORDER BY attname::text) FROM pg_attribute WHERE attrelid = {reg} AND attnum > 0 AND NOT attisdropped)"
        want = "ARRAY[" + ", ".join(lit(c) for c in t["columns"]) + "]::text[]"
        out.append(
            f"SELECT 0, CASE WHEN {reg} IS NULL THEN 'error-gone' WHEN {now} = {want} THEN 'ok' ELSE 'error-columns' END, {lit(name)};\n"
        )
    for steps in groups(plan["steps"]):
        g = Group(plan["tables"], steps)
        if g.op == "update":
            taken = (
                f"(({', '.join(f'w.o{i}' for i in g.pk)}) IS DISTINCT FROM ({', '.join(f'w.n{i}' for i in g.pk)})"
                f" AND EXISTS (SELECT 1 FROM {g.rel} x WHERE "
                + " AND ".join(f"x.{ident(g.cols[i])} = w.o{i}" for i in g.pk) + "))"
            )
            status = (
                f"CASE WHEN {g.missing()} THEN 'gone' WHEN {taken} THEN 'key-taken' WHEN {g.same('n')} THEN 'ok'"
                f" WHEN {g.same('o')} THEN 'done' ELSE 'changed' END"
            )
            differs = f"NOT ({g.missing()}) AND NOT ({g.same('n')}) AND NOT ({g.same('o')})"
            side = "n"
        elif g.op == "insert":
            status = f"CASE WHEN {g.missing()} THEN 'ok' WHEN {g.same('o')} THEN 'done' ELSE 'exists' END"
            differs = f"NOT ({g.missing()}) AND NOT ({g.same('o')})"
            side = "o"
        else:
            status = f"CASE WHEN {g.missing()} THEN 'done' WHEN {g.same('n')} THEN 'ok' ELSE 'changed' END"
            differs = f"NOT ({g.missing()}) AND NOT ({g.same('n')})"
            side = "n"
        out.append(
            f"SELECT w.step, {status}, CASE WHEN {differs} THEN to_jsonb(t)::text END\n"
            f"FROM {g.values()}\nLEFT JOIN {g.rel} t ON {g.join(side)}\nORDER BY 1;\n"
        )
    return "".join(out)


def undo_sql(plan, ok, marker):
    """Одна транзакция отката по шагам из ok. Каждая группа сверяет число изменённых строк."""
    body = []
    for steps in groups([s for s in plan["steps"] if s["step"] in ok]):
        g = Group(plan["tables"], steps)
        n = len(steps)
        span = f"{steps[0]['step']}–{steps[-1]['step']}"
        cols = ", ".join(ident(c) for c in g.cols)
        if g.op == "insert":
            what = f"вернуть удалённые строки в {g.name}"
            stmt = f"INSERT INTO {g.rel} ({cols})\n  SELECT {', '.join(f'w.o{i}' for i in range(len(g.cols)))}\n  FROM {g.values()}"
        elif g.op == "delete":
            what = f"убрать вставленные строки из {g.name}"
            stmt = f"DELETE FROM {g.rel} t\n  USING {g.values()}\n  WHERE {g.join('n')} AND {g.same('n')}"
        else:
            what = f"вернуть прежние значения в {g.name}"
            sets = ", ".join(f"{ident(c)} = w.o{i}" for i, c in enumerate(g.cols))
            stmt = f"UPDATE {g.rel} t SET {sets}\n  FROM {g.values()}\n  WHERE {g.join('n')} AND {g.same('n')}"
        body.append((f"шаги {span}: {what} ({n})", stmt, n, g.name.replace("'", "''").replace("%", "%%")))
    tag = "$undo_" + secrets.token_hex(6) + "$"
    text_all = "".join(stmt for _, stmt, _, _ in body) + marker
    if tag in text_all:
        raise Refused("метка блока встретилась в данных: запустите ещё раз")
    out = [HEADER, "BEGIN;\n"]
    out.append(f"SELECT pg_logical_emit_message(true, 'evidence/undo', {lit(marker)}) IS NOT NULL AS marked, pg_current_xact_id()::text AS undo_xid \\gset\n")
    for title, stmt, n, name in body:
        out.append(
            f"-- {title}\nDO {tag}\nDECLARE undo_rows_ bigint;\nBEGIN\n  {stmt};\n  GET DIAGNOSTICS undo_rows_ = ROW_COUNT;\n"
            f"  IF undo_rows_ <> {n} THEN\n    RAISE EXCEPTION 'undo: {name}: expected % rows, the statement touched %: a row changed after the check; nothing is applied', {n}, undo_rows_;\n"
            f"  END IF;\nEND {tag};\n"
        )
    out.append("COMMIT;\n\\echo undo_xid=:undo_xid\n")
    return "".join(out)


# ---------------------------------------------------------------- команды


def key_text(plan, step):
    t = plan["tables"][step["table"]]
    img = step["new"] if step["op"] != "insert" else step["old"]
    return ", ".join(f"{c}={img[c]}" for c in t["pk"])


def cmd_plan(a):
    try:
        recs = load_bodies(a.bodies)
        unlabeled = 0
        if a.report:
            with open(a.report) as f:
                unlabeled = check_report(json.load(f), a.xid, len(recs))
        if unlabeled and not a.allow_unlabeled:
            raise Refused(
                f"записей без метки субъекта в окне пакета: {unlabeled}. Чьи они, пакет не говорит, и если среди них "
                "есть части этой транзакции, откат был бы неполным (-allow-unlabeled — строить всё равно)"
            )
        plan = build_plan(recs, a.xid)
    except Refused as e:
        fail(f"отказ: {e}", 2)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "plan.json"), "w") as f:
        json.dump(plan, f, ensure_ascii=False)
    with open(os.path.join(a.out, "check.sql"), "w") as f:
        f.write(check_sql(plan))
    print(f"транзакция {a.xid}: записей хранилища {plan['records']}, изменений строк {plan['changes']}" + (" (журнал пересылал её заново)" if plan["resent"] else ""))
    if plan["who"]:
        print(f"  кто: роль {plan['who'].get('role')}, сессия {plan['who'].get('app')!r}")
    if plan["undo"]:
        print(f"  это транзакция отката: {json.dumps(plan['undo'], ensure_ascii=False)}")
    actions = [m["content"] for m in plan["markers"] if m["prefix"] == "evidence/action"]
    for m in actions:
        info = m.get("info") or {}
        print(f"  действие {info.get('action_id')}: агент {info.get('agent')}, инструмент {info.get('tool')}, причина: {info.get('reason') or '—'}")
    if plan["who"] and not actions:
        print("  отметки действия нет: транзакция пришла в базу в обход MCP-сервера")
    names = {"I": "вставок", "U": "правок", "D": "удалений"}
    for c in plan["counts"]:
        print(f"  {c['table']}: {names[c['action']]} {c['lines']}")
    by = {}
    for s in plan["steps"]:
        by[s["op"]] = by.get(s["op"], 0) + 1
    twice = sum(1 for s in plan["steps"] if s["touches"] > 1)
    print(
        f"  обратных шагов {len(plan['steps'])}: вернуть значения {by.get('update', 0)}, вернуть удалённые {by.get('insert', 0)}, "
        f"убрать вставленные {by.get('delete', 0)}; строк, тронутых больше раза, {twice}; без итогового изменения {plan['noop']}"
    )
    if not plan["steps"]:
        print("  откатывать нечего: изменений строк в этой транзакции нет")


STATUS = {
    "gone": "строки уже нет",
    "changed": "строку изменили после транзакции",
    "exists": "под этим ключом снова есть строка",
    "key-taken": "прежний ключ занят другой строкой",
}


def cmd_sql(a):
    with open(os.path.join(a.plan, "plan.json")) as f:
        plan = json.load(f)
    answer = {}
    with open(a.check) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t", 2)
            if not parts[0].isdigit() or len(parts) < 2:
                fail(f"строка ответа базы не разобрана: {line[:80]!r}", 3)
            step, status, info = int(parts[0]), parts[1], parts[2] if len(parts) > 2 else ""
            if step == 0:
                if status != "ok":
                    why = "таблицы больше нет" if status == "error-gone" else "колонки таблицы теперь другие, чем в журнале"
                    fail(f"отказ: {info}: {why}. Откат по образам строк не подходит к такой таблице", 3)
                continue
            answer[step] = (status, info)
    missing = [s["step"] for s in plan["steps"] if s["step"] not in answer]
    if missing:
        fail(f"база не ответила про шаги {missing[:5]}…: check.sql исполнен не весь", 3)
    ok = {n for n, (st, _) in answer.items() if st == "ok"}
    done = [n for n, (st, _) in answer.items() if st == "done"]
    conflicts = [s for s in plan["steps"] if answer[s["step"]][0] in STATUS]
    print(f"шагов {len(plan['steps'])}: применить {len(ok)}, уже в нужном виде {len(done)}, конфликтов {len(conflicts)}")
    for s in conflicts[: a.show]:
        status, now = answer[s["step"]]
        t = plan["tables"][s["table"]]
        print(f"  КОНФЛИКТ, шаг {s['step']}: {s['table']} ({key_text(plan, s)}) — {STATUS[status]}")
        short = lambda v: "NULL" if v is None else "«" + (v if len(v) <= 60 else v[:57] + "…") + "»"
        whole = lambda img: ", ".join(f"{c}={short(text(img.get(c)))}" for c in t["columns"])
        cur = json.loads(now, parse_float=str, parse_int=str) if now else None
        if s["op"] == "update":
            for c in t["columns"]:
                if s["old"][c] != s["new"][c]:
                    here = f", сейчас {short(text(cur.get(c)))}" if cur else ""
                    print(f"      {c}: было {short(s['old'][c])}, транзакция оставила {short(s['new'][c])}{here}")
        elif s["op"] == "insert":
            print(f"      транзакция удалила: {whole(s['old'])}")
            print(f"      сейчас под ключом:  {whole(cur)}")
        else:
            print(f"      транзакция вставила: {whole(s['new'])}")
            print(f"      сейчас:              {whole(cur)}")
    if len(conflicts) > a.show:
        print(f"  … и ещё {len(conflicts) - a.show}")
    if conflicts:
        print("  конфликтные строки откат не трогает: решить про каждую должен человек")
    if not ok:
        print("применять нечего: undo.sql не написан")
        return
    marker = json.dumps({
        "undoes_xid": plan["xid"], "by": a.by, "reason": a.reason, "steps_applied": len(ok),
        "steps_already_done": len(done), "conflicts_left": [s["step"] for s in conflicts][:200],
    }, ensure_ascii=False)
    try:
        sql = undo_sql(plan, ok, marker)
    except Refused as e:
        fail(f"отказ: {e}", 2)
    path = os.path.join(a.plan, "undo.sql")
    with open(path, "w") as f:
        f.write(sql)
    print(f"написан {path}: одна транзакция, {len(ok)} шагов")


def main():
    p = argparse.ArgumentParser(description="Обратные операции для одной транзакции Postgres по до-образам из хранилища улик (опыт).")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("plan", help="разобрать транзакцию: plan.json и check.sql")
    a.add_argument("-bodies", required=True, help="каталог тел от esverify -bodies")
    a.add_argument("-xid", required=True, type=int, help="номер транзакции")
    a.add_argument("-report", help="отчёт esverify -json о том же пакете: сверка, что открыты все записи транзакции")
    a.add_argument("-allow-unlabeled", action="store_true", help="строить план, даже если в окне есть записи без метки")
    a.add_argument("-out", required=True, help="каталог для plan.json и check.sql")
    a.set_defaults(fn=cmd_plan)
    b = sub.add_parser("sql", help="по ответу базы на check.sql написать undo.sql")
    b.add_argument("-plan", required=True, help="каталог с plan.json")
    b.add_argument("-check", required=True, help="вывод psql -f check.sql")
    b.add_argument("-by", default="operator", help="кто откатывает (ляжет в журнал)")
    b.add_argument("-reason", default="", help="почему (ляжет в журнал)")
    b.add_argument("-show", type=int, default=10, help="сколько конфликтов показать")
    b.set_defaults(fn=cmd_sql)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
