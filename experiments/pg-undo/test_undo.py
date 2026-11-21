#!/usr/bin/env python3
"""Проверки разбора транзакции в undo.py: python3 -I test_undo.py (без базы и хранилища)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import undo  # noqa: E402

XID = "7"
TYPES = {"id": "integer", "v": "text", "big": "text"}


def cols(img):
    return [{"name": k, "type": TYPES[k], "value": v} for k, v in img.items()]


def line(action, table=None, old=None, new=None):
    r = {"action": action, "xid": XID}
    if table:
        r.update(schema="public", table=table, pk=[{"name": "id", "type": "integer"}])
    if new is not None:
        r["columns"] = cols(new)
    if old is not None:
        r["identity"] = cols(old)
    return r


def plan(*lines):
    return undo.build_plan(list(enumerate(lines, 1)), 7)


def row(i, v):
    return {"id": str(i), "v": v}


class Plan(unittest.TestCase):
    def test_reverse_order_parent_before_children(self):
        p = plan(line("B"), line("D", "child", old=row(1, "c")), line("D", "parent", old=row(9, "p")), line("C"))
        self.assertEqual([(s["op"], s["table"]) for s in p["steps"]], [("insert", "public.parent"), ("insert", "public.child")])

    def test_row_touched_twice_is_one_step(self):
        p = plan(line("B"), line("U", "t", old=row(1, "a"), new=row(1, "b")), line("U", "t", old=row(1, "b"), new=row(1, "c")), line("C"))
        (s,) = p["steps"]
        self.assertEqual((s["op"], s["old"]["v"], s["new"]["v"], s["touches"]), ("update", "a", "c", 2))

    def test_insert_then_delete_is_nothing(self):
        p = plan(line("B"), line("I", "t", new=row(1, "a")), line("D", "t", old=row(1, "a")), line("C"))
        self.assertEqual((p["steps"], p["noop"]), ([], 1))

    def test_insert_then_update_removes_the_final_row(self):
        p = plan(line("B"), line("I", "t", new=row(1, "a")), line("U", "t", old=row(1, "a"), new=row(1, "b")), line("C"))
        (s,) = p["steps"]
        self.assertEqual((s["op"], s["old"], s["new"]["v"]), ("delete", None, "b"))

    def test_update_then_delete_restores_the_first_image(self):
        p = plan(line("B"), line("U", "t", old=row(1, "a"), new=row(1, "b")), line("D", "t", old=row(1, "b")), line("C"))
        (s,) = p["steps"]
        self.assertEqual((s["op"], s["old"]["v"], s["new"]), ("insert", "a", None))

    def test_delete_then_insert_same_key_is_an_update(self):
        p = plan(line("B"), line("D", "t", old=row(1, "a")), line("I", "t", new=row(1, "z")), line("C"))
        (s,) = p["steps"]
        self.assertEqual((s["op"], s["old"]["v"], s["new"]["v"]), ("update", "a", "z"))

    def test_key_change_is_followed(self):
        p = plan(line("B"), line("U", "t", old=row(1, "a"), new=row(2, "a")), line("U", "t", old=row(2, "a"), new=row(2, "b")), line("C"))
        (s,) = p["steps"]
        self.assertEqual((s["old"], s["new"]), (row(1, "a"), row(2, "b")))

    def test_resent_transaction_takes_the_last_whole_copy(self):
        u = line("U", "t", old=row(1, "a"), new=row(1, "b"))
        p = plan(line("B"), u, line("B"), u, line("C"))
        self.assertTrue(p["resent"])
        self.assertEqual(len(p["steps"]), 1)

    def test_unchanged_toast_column_comes_from_the_old_image(self):
        old = {"id": "1", "v": "a", "big": "x" * 5000}
        p = plan(line("B"), line("U", "t", old=old, new=row(1, "b")), line("C"))
        self.assertEqual(p["steps"][0]["new"], {"id": "1", "v": "b", "big": "x" * 5000})

    def test_refusals(self):
        cases = {
            "нет строки конца": [line("B"), line("U", "t", old=row(1, "a"), new=row(1, "b"))],
            "нет строки начала": [line("U", "t", old=row(1, "a"), new=row(1, "b")), line("C")],
            "TRUNCATE": [line("B"), line("T", "t"), line("C")],
            # Таблица без REPLICA IDENTITY FULL: в старом образе только ключ.
            "REPLICA IDENTITY FULL": [line("B"), line("U", "t", old={"id": "1"}, new=row(1, "b")), line("C")],
            "а не 7": [line("B"), dict(line("U", "t", old=row(1, "a"), new=row(1, "b")), xid="8"), line("C")],
            "не тот образ": [line("B"), line("U", "t", old=row(1, "a"), new=row(1, "b")), line("U", "t", old=row(1, "x"), new=row(1, "c")), line("C")],
        }
        for want, lines in cases.items():
            with self.assertRaises(undo.Refused, msg=want) as e:
                plan(*lines)
            self.assertIn(want, str(e.exception))


class Sql(unittest.TestCase):
    def test_literals(self):
        self.assertEqual(undo.lit("it's"), "'it''s'")
        self.assertEqual(undo.lit(None), "NULL")
        self.assertEqual(undo.ident('a"b'), '"a""b"')

    def test_first_row_carries_the_types(self):
        p = plan(line("B"), line("D", "t", old=row(1, "a")), line("D", "t", old=row(2, None)), line("C"))
        v = undo.Group(p["tables"], p["steps"]).values()
        self.assertIn("(1, '2'::integer, NULL::text)", v)
        self.assertIn("(2, '1', 'a')", v)

    def test_undo_applies_only_the_steps_named(self):
        p = plan(line("B"), line("U", "t", old=row(1, "a"), new=row(1, "b")), line("U", "t", old=row(2, "a"), new=row(2, "b")), line("C"))
        sql = undo.undo_sql(p, {2}, "{}")
        self.assertIn("IF undo_rows_ <> 1 THEN", sql)
        self.assertEqual(sql.count("::integer"), 2)  # одна строка VALUES: новый и старый образ


if __name__ == "__main__":
    unittest.main()
