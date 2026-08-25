#!/usr/bin/env python3
"""No-model tests for FIND JSON salvage. Parser only — no API."""
from __future__ import annotations

import json
import unittest

from find import extract_json, message_text, test_py_compiles, _salvage_truncated
from expand_board import changed_funcs, prelude_for, slice_class, slice_func


class ExtractJson(unittest.TestCase):
    def test_plain(self):
        obj = extract_json('{"has_bug": false, "test_py": ""}')
        self.assertFalse(obj["has_bug"])

    def test_fenced(self):
        obj = extract_json('```json\n{"has_bug": true, "test_py": "x"}\n```')
        self.assertTrue(obj["has_bug"])

    def test_think_tags(self):
        obj = extract_json('<think>nope</think>\n{"has_bug": true, "test_py": "from subject import f\\nassert 1"}')
        self.assertTrue(obj["has_bug"])

    def test_trailing_junk(self):
        obj = extract_json('{"has_bug": true, "test_py": "a"}\nThanks!')
        self.assertEqual(obj["test_py"], "a")

    def test_unterminated_string_salvage(self):
        raw = '{\n  "has_bug": true,\n  "location": "final return op(actual_value'
        obj = _salvage_truncated(raw)
        self.assertIsNotNone(obj)
        self.assertTrue(obj["has_bug"])

    def test_empty_raises(self):
        with self.assertRaises(json.JSONDecodeError):
            extract_json("")

    def test_unclosed_think_stripped(self):
        with self.assertRaises(json.JSONDecodeError):
            extract_json("<think>all reasoning no json")


class MessageText(unittest.TestCase):
    def test_reasoning_content_fallback(self):
        msg = {"content": "", "reasoning_content": '{"has_bug": false, "test_py": ""}'}
        self.assertIn("has_bug", message_text(msg))

    def test_content_wins_when_present(self):
        msg = {"content": '{"a": 1}', "reasoning_content": '{"a": 2}'}
        self.assertIn('"a": 1', message_text(msg))


class TestPyCompiles(unittest.TestCase):
    def test_ok(self):
        src = "from subject import foo\n\ndef test_x():\n    assert foo(1) == 1\n"
        self.assertIsNone(test_py_compiles(src))

    def test_syntax(self):
        self.assertIn("SyntaxError", test_py_compiles("from subject import foo\n def ("))

    def test_no_assert(self):
        self.assertEqual(test_py_compiles("from subject import foo\n"), "no_assert")


class ExpandSieve(unittest.TestCase):
    def test_hunk_body_def_not_just_header(self):
        patch = """\
diff --git a/lib/ansible/utils/version.py b/lib/ansible/utils/version.py
--- a/lib/ansible/utils/version.py
+++ b/lib/ansible/utils/version.py
@@ -72,14 +72,14 @@ class _Alpha:
 
         raise ValueError
 
-    def __gt__(self, other):
-        return not self.__lt__(other)
-
     def __le__(self, other):
         return self.__lt__(other) or self.__eq__(other)
 
+    def __gt__(self, other):
+        return not self.__le__(other)
+
     def __ge__(self, other):
-        return self.__gt__(other) or self.__eq__(other)
+        return not self.__lt__(other)
"""
        funcs = changed_funcs(patch)
        names = {n for _, n in funcs}
        self.assertIn("__gt__", names)
        self.assertIn("__ge__", names)
        self.assertIn("__le__", names)

    def test_prelude_re_and_ordereddict(self):
        unit = "def f(x):\n    return re.sub(r'a', '', x) or OrderedDict()\n"
        pre = prelude_for(unit)
        self.assertIn("import re", pre)
        self.assertIn("OrderedDict", pre)

    def test_slice_class(self):
        src = "class _Alpha:\n    def __gt__(self, other):\n        return True\n\nclass _Numeric:\n    pass\n"
        body = slice_class(src, "_Alpha")
        self.assertIsNotNone(body)
        self.assertIn("__gt__", body)
        self.assertNotIn("_Numeric", body)

    def test_slice_indented_method(self):
        src = "class Foo:\n    def __gt__(self, other):\n        return True\n    def __ge__(self, other):\n        return False\n"
        body = slice_func(src, "__gt__")
        self.assertIsNotNone(body)
        self.assertTrue(body.startswith("def __gt__"))
        self.assertIn("__gt__", body)
        self.assertNotIn("__ge__", body)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
