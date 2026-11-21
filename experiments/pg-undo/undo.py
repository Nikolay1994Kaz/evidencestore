#!/usr/bin/env python3
"""undo.py — обратные операции для одной транзакции Postgres по до-образам из хранилища улик.

ОПЫТ, НЕ ПРОДУКТ (см. README.md рядом). Вход — каталог тел, который пишет
`esverify -bodies DIR` из проверенного пакета по субъекту, где субъект —
номер транзакции (xid). Каждое тело — одна строка wal2json format-version 2:

    B  начало транзакции          M  сообщение (отметка агента)
    I  вставка: columns           U  правка: columns (новое) + identity (старое)
    D  удаление: identity         T  TRUNCATE: строк нет
    C  конец транзакции

Старый образ строки целиком есть только у таблиц с REPLICA IDENTITY FULL.

    undo.py plan -bodies DIR -xid N [-report FILE] -out DIR
        разобрать транзакцию, написать DIR/plan.json и DIR/check.sql
    undo.py sql -plan DIR -check FILE [-by КТО] [-reason ЗАЧЕМ]
        по ответу базы на check.sql написать DIR/undo.sql

Сам скрипт в базу не ходит: check.sql и undo.sql исполняет psql. Откат — одна
транзакция; каждая группа шагов проверяет, что изменила ровно столько строк,
сколько обещала, иначе вся транзакция отменяется.

Коды выхода: 0 — готово, 1 — неверный вызов или ввод, 2 — откат построить
нельзя (TRUNCATE, неполные образы, пакет не тот), 3 — база ответила не то.
"""
import argparse
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
    """Тела в порядке номеров записей: [(seq, запись)]. Имя файла — <источник>-<номер>."""
    out = []
    for name in os.listdir(directory):
        try:
            seq = int(name.rsplit("-", 1)[1])
        except (IndexError, ValueError):
            raise Refused(f"в каталоге тел лишний файл {name!r}")
        with open(os.path.join(directory, name), "rb") as f:
            raw = f.read()
        try:
            # Числа — как записаны: 800.00 остаётся "800.00", а не float.
            rec = json.loads(raw, parse_float=str, parse_int=str)
        except ValueError as e:
            raise Refused(f"запись {seq} — не JSON ({e}): это не строка wal2json")
        if not isinstance(rec, dict) or "action" not in rec:
            raise Refused(f"запись {seq} — не строка wal2json format-version 2")
        out.append((seq, rec))
    out.sort(key=lambda p: p[0])
    return out


def text(v):
    """Значение колонки текстом, как его примет Postgres с приведением к типу; None — NULL."""
    if v is None:
        return None
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return v
    return json.dumps(v, ensure_ascii=False)  # wal2json так не пишет, но пусть будет видно


def image(cols):
    return {c["name"]: text(c.get("value")) for c in cols}


def transaction(recs, xid):
    """Строки одной транзакции между B и C.

    pg_recvlogical после сбоя шлёт транзакцию заново с подтверждённой позиции,
    и в файле она тогда лежит дважды (первый раз, возможно, оборванной).
    Берётся последняя пара B..C; resent — была ли пересылка.
    """
    for seq, r in recs:
        if r.get("xid") != str(xid):
            raise Refused(f"запись {seq} — транзакции {r.get('xid')}, а не {xid}: пакет не по этому субъекту")
    begins = [i for i, (_, r) in enumerate(recs) if r["action"] == "B"]
    if not begins:
        raise Refused("нет строки начала транзакции (B): записи транзакции не все")
    tail = recs[begins[-1]:]
    if tail[-1][1]["action"] != "C":
        raise Refused("нет строки конца транзакции (C): она ещё не доехала целиком, или окно пакета её режет")
    inner = tail[1:-1]
    if any(r["action"] in ("B", "C") for _, r in inner):
        raise Refused("строки B и C идут не парой: журнал транзакции повреждён")
    return inner, len(begins) > 1


class Row:
    """Одна строка таблицы за транзакцию: какой была до и какой стала после."""

    def __init__(self, table, old, seq):
        self.table = table
        self.old = old  # None — строки до транзакции не было
        self.new = None  # None — строки после транзакции нет
        self.first_seq = seq
        self.last_seq = seq
        self.touches = 0


def build_plan(recs, xid):
    inner, resent = transaction(recs, xid)
    tables = {}  # "схема.таблица" -> описание
    markers, truncated = [], []
    counts = {}  # (таблица, действие) -> сколько строк журнала
    live, dead, order = {}, {}, []

    def table_of(seq, r, full_images):
        name = f'{r["schema"]}.{r["table"]}'
        pk = [p["name"] for p in r.get("pk", [])]
        if not pk:
            raise Refused(f"{name}: в записи {seq} нет первичного ключа — строку нечем адресовать")
        types = {}
        for c in r.get("columns", []) + r.get("identity", []):
            types[c["name"]] = c["type"]
        t = tables.setdefault(name, {"schema": r["schema"], "table": r["table"], "pk": pk, "types": {}, "columns": None})
        if t["pk"] != pk:
            raise Refused(f"{name}: первичный ключ в записях транзакции разный")
        t["types"].update(types)
        for img in full_images:
            cols = sorted(img)
            if t["columns"] is None:
                t["columns"] = cols
            elif t["columns"] != cols:
                raise Refused(
                    f"{name}: образы строк в записи {seq} неполные (колонки {cols}, раньше {t['columns']}). "
                    "Старый образ целиком пишется только при REPLICA IDENTITY FULL"
                )
        return name, pk

    for seq, r in inner:
        a = r["action"]
        if a == "M":
            markers.append({"prefix": r.get("prefix"), "content": r.get("content"), "seq": seq})
            continue
        if a == "T":
            truncated.append(f'{r["schema"]}.{r["table"]}')
            continue
        if a not in ("I", "U", "D"):
            raise Refused(f"запись {seq}: действие {a!r} этому скрипту незнакомо")
        old = image(r["identity"]) if a in ("U", "D") else None
        new = image(r["columns"]) if a in ("I", "U") else None
        if a == "U":
            # Нетронутое значение, вынесенное в TOAST, в новый образ не попадает: оно равно старому.
            new = {**old, **new}
        name, pk = table_of(seq, r, [i for i in (old, new) if i is not None])
        counts[(name, a)] = counts.get((name, a), 0) + 1
        key = lambda img: (name,) + tuple(img[c] for c in pk)

        if a == "I":
            k = key(new)
            if k in live:
                raise Refused(f"{name}: запись {seq} вставляет строку поверх живой — журнал не сходится")
            row = dead.pop(k, None)
            if row is None:
                row = Row(name, None, seq)
                order.append(row)
        elif a == "U":
            ko, k = key(old), key(new)
            row = live.pop(ko, None)
            if row is None:
                row = Row(name, old, seq)
                order.append(row)
            elif row.new != old:
                raise Refused(f"{name}: запись {seq} правит не тот образ строки, что оставила прежняя запись")
            if k != ko and (k in live or k in dead):
                raise Refused(f"{name}: запись {seq} переносит строку на ключ, занятый в этой же транзакции: такое опыт не разбирает")
        else:
            k = key(old)
            row = live.pop(k, None)
            if row is None:
                row = Row(name, old, seq)
                order.append(row)
            elif row.new != old:
                raise Refused(f"{name}: запись {seq} удаляет не тот образ строки, что оставила прежняя запись")
            if k in dead:
                raise Refused(f"{name}: ключ записи {seq} в этой транзакции удалён дважды разными строками: такое опыт не разбирает")
        row.new = new
        row.last_seq = seq
        row.touches += 1
        (dead if a == "D" else live)[k] = row

    if truncated:
        raise Refused(
            "транзакция сделала TRUNCATE " + ", ".join(sorted(set(truncated))) + ": строк в журнале нет, "
            "до-образов не существует, построчный откат невозможен (нужна резервная копия)"
        )

    # Обратный порядок: что транзакция тронула последним, возвращается первым
    # (удалил детей, потом родителя — вернуть родителя, потом детей).
    steps, noop = [], 0
    for row in reversed(order):
        if row.old == row.new:
            noop += 1  # вставил и удалил, или вернул прежние значения сам
            continue
        op = "delete" if row.old is None else "insert" if row.new is None else "update"
        steps.append({
            "step": len(steps) + 1, "op": op, "table": row.table, "old": row.old, "new": row.new,
            "touches": row.touches, "first_seq": row.first_seq, "last_seq": row.last_seq,
        })
    return {
        "xid": str(xid), "records": len(recs), "resent": resent, "markers": markers, "noop": noop,
        "counts": [{"table": t, "action": a, "lines": n} for (t, a), n in sorted(counts.items())],
        "tables": tables, "steps": steps,
    }


def check_report(report, xid, bodies):
    """Отчёт esverify -json о пакете: тот ли пакет и все ли записи транзакции в нём открыты."""
    s = report.get("subject") or {}
    if not report.get("valid"):
        raise Refused("пакет не прошёл проверку esverify")
    if report.get("kind") != "source" or s.get("field") != "xid" or s.get("value") != str(xid):
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
    out.append(f"SELECT pg_logical_emit_message(true, 'undo', {lit(marker)}) IS NOT NULL AS marked, pg_current_xact_id()::text AS undo_xid \\gset\n")
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
                f"записей без метки субъекта в окне пакета: {unlabeled}. Строка журнала длиннее предела записи режется "
                "на куски без метки, и до-образ такой строки в пакет транзакции не попадает. Откат был бы неполным "
                "(-allow-unlabeled — строить всё равно)"
            )
        plan = build_plan(recs, a.xid)
    except Refused as e:
        fail(f"отказ: {e}", 2)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "plan.json"), "w") as f:
        json.dump(plan, f, ensure_ascii=False)
    with open(os.path.join(a.out, "check.sql"), "w") as f:
        f.write(check_sql(plan))
    print(f"транзакция {a.xid}: записей в пакете {plan['records']}" + (" (журнал пересылал её заново)" if plan["resent"] else ""))
    agent = [m for m in plan["markers"] if m["prefix"] == "agent"]
    for m in agent:
        print(f"  отметка агента: {m['content']}")
    if not agent:
        print("  отметки агента нет: журнал не говорит, чья это транзакция")
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
        print("  откатывать нечего: изменений строк этой транзакции в журнале нет. Это не значит, что она ничего")
        print("  не сделала: DROP TABLE и остальной DDL в журнал wal2json не попадают вовсе")


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
