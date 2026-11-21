#!/usr/bin/env python3
"""Проверки разбора транзакции в undo.py: python3 -I test_undo.py (без базы и хранилища)."""
import base64
import gzip
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import undo  # noqa: E402

XID = 7
REL = {"t": "R", "id": 1, "schema": "public", "table": "t", "identity": "f", "columns": ["id", "v"], "types": ["integer", "text"], "pk": ["id"]}


def rel(rid, table, **kw):
    return dict(REL, id=rid, table=table, **kw)


def ch(action, old=None, new=None, r=1, **kw):
    line = {"t": action, "r": r, **kw}
    if old is not None:
        line["old"] = old
    if new is not None:
        line["new"] = new
    return line


def parts(lines, size=10**9, xid=XID, header=None, count=None):
    """Поток транзакции, как его пишет espgtap, порезанный на части по size сжатых байт."""
    n = sum(1 for l in lines if l["t"] in "IUD")
    head = {"t": "H", "v": 1, "xid": xid, "who": {"role": "agent", "app": "x"}, **(header or {})}
    stream = [head, *lines, {"t": "C", "changes": n if count is None else count}]
    gz = gzip.compress("".join(json.dumps(l) + "\n" for l in stream).encode())
    cut = [gz[i:i + size] for i in range(0, len(gz), size)]
    return [(100 + i, {"xid": xid, "part": i + 1, "last": i == len(cut) - 1, "gz": base64.b64encode(c).decode()}) for i, c in enumerate(cut)]


def plan(*lines, **kw):
    return undo.build_plan(parts(list(lines), **kw), XID)


class Plan(unittest.TestCase):
    def test_reverse_order_parent_before_children(self):
        p = plan(rel(1, "child"), ch("D", old=["1", "c"]), rel(2, "parent"), ch("D", old=["9", "p"], r=2))
        self.assertEqual([(s["op"], s["table"]) for s in p["steps"]], [("insert", "public.parent"), ("insert", "public.child")])

    def test_row_touched_twice_is_one_step(self):
        p = plan(REL, ch("U", old=["1", "a"], new=["1", "b"]), ch("U", old=["1", "b"], new=["1", "c"]))
        (s,) = p["steps"]
        self.assertEqual((s["op"], s["old"]["v"], s["new"]["v"], s["touches"]), ("update", "a", "c", 2))

    def test_insert_then_delete_is_nothing(self):
        p = plan(REL, ch("I", new=["1", "a"]), ch("D", old=["1", "a"]))
        self.assertEqual((p["steps"], p["noop"]), ([], 1))

    def test_insert_then_update_removes_the_final_row(self):
        (s,) = plan(REL, ch("I", new=["1", "a"]), ch("U", old=["1", "a"], new=["1", "b"]))["steps"]
        self.assertEqual((s["op"], s["old"], s["new"]["v"]), ("delete", None, "b"))

    def test_update_then_delete_restores_the_first_image(self):
        (s,) = plan(REL, ch("U", old=["1", "a"], new=["1", "b"]), ch("D", old=["1", "b"]))["steps"]
        self.assertEqual((s["op"], s["old"]["v"], s["new"]), ("insert", "a", None))

    def test_delete_then_insert_same_key_is_an_update(self):
        (s,) = plan(REL, ch("D", old=["1", "a"]), ch("I", new=["1", "z"]))["steps"]
        self.assertEqual((s["op"], s["old"]["v"], s["new"]["v"]), ("update", "a", "z"))

    def test_key_change_is_followed(self):
        (s,) = plan(REL, ch("U", old=["1", "a"], new=["2", "a"]), ch("U", old=["2", "a"], new=["2", "b"]))["steps"]
        self.assertEqual((s["old"], s["new"]), ({"id": "1", "v": "a"}, {"id": "2", "v": "b"}))

    def test_null_and_types_survive(self):
        p = plan(REL, ch("U", old=["1", None], new=["1", "b"]))
        self.assertEqual(p["steps"][0]["old"], {"id": "1", "v": None})
        self.assertEqual(p["tables"]["public.t"]["types"], {"id": "integer", "v": "text"})

    def test_markers(self):
        p = plan(REL, ch("I", new=["1", "a"]), header={"actions": [{"role": "agent", "info": {"action_id": "42"}}]})
        self.assertEqual(p["markers"][0]["content"]["info"]["action_id"], "42")
        self.assertEqual(p["who"]["role"], "agent")

    def test_many_parts_and_a_resent_transaction(self):
        lines = [REL] + [ch("I", new=[str(i), "x" * 50]) for i in range(200)]
        ps = parts(lines, size=64)
        self.assertGreater(len(ps), 5)
        self.assertEqual(len(undo.build_plan(ps, XID)["steps"]), 200)
        # Первая копия оборвана на третьей части, потом транзакция целиком.
        p = undo.build_plan(ps[:3] + ps, XID)
        self.assertTrue(p["resent"])
        self.assertEqual(len(p["steps"]), 200)
        # Без любой части — отказ.
        for drop in range(len(ps)):
            with self.assertRaises(undo.Refused):
                undo.build_plan(ps[:drop] + ps[drop + 1:], XID)

    def test_refusals(self):
        up = ch("U", old=["1", "a"], new=["1", "b"])
        cases = {
            "TRUNCATE": dict(lines=[REL, {"t": "T", "tables": ["public.t"]}]),
            "REPLICA IDENTITY FULL": dict(lines=[rel(1, "t", identity="d"), up]),
            "неполная": dict(lines=[REL, ch("U", new=["1", "b"], partial=True)]),
            "нет первичного ключа": dict(lines=[rel(1, "t", pk=[]), up]),
            "а не 7": dict(lines=[REL, up], xid=8),
            "не тот образ": dict(lines=[REL, up, ch("U", old=["1", "x"], new=["1", "c"])]),
            "не текстом": dict(lines=[REL, ch("U", old=["1", "a"], new=["1", {"b64": "AA=="}])]),
            "журнал транзакции не весь": dict(lines=[REL, up], count=2),
            "которой в потоке нет": dict(lines=[ch("I", new=["1", "a"], r=9)]),
        }
        for want, kw in cases.items():
            with self.assertRaises(undo.Refused, msg=want) as e:
                undo.build_plan(parts(kw.pop("lines"), **kw), XID)
            self.assertIn(want, str(e.exception))


class Sql(unittest.TestCase):
    def test_literals(self):
        self.assertEqual(undo.lit("it's"), "'it''s'")
        self.assertEqual(undo.lit(None), "NULL")
        self.assertEqual(undo.ident('a"b'), '"a""b"')

    def test_first_row_carries_the_types(self):
        p = plan(REL, ch("D", old=["1", "a"]), ch("D", old=["2", None]))
        v = undo.Group(p["tables"], p["steps"]).values()
        self.assertIn("(1, '2'::integer, NULL::text)", v)
        self.assertIn("(2, '1', 'a')", v)

    def test_undo_applies_only_the_steps_named(self):
        p = plan(REL, ch("U", old=["1", "a"], new=["1", "b"]), ch("U", old=["2", "a"], new=["2", "b"]))
        sql = undo.undo_sql(p, {2}, "{}")
        self.assertIn("IF undo_rows_ <> 1 THEN", sql)
        self.assertIn("'evidence/undo'", sql)
        self.assertEqual(sql.count("::integer"), 2)  # одна строка VALUES: новый и старый образ


if __name__ == "__main__":
    unittest.main()
