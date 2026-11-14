"""归因规则引擎的单元测试。"""

import time
import unittest

from reproverify.model import (
    CATEGORY_ABS_PATH,
    CATEGORY_CODE,
    CATEGORY_LOCALE,
    CATEGORY_MTIME,
    CATEGORY_RANDOM,
)
from reproverify.rules import (
    AbsPathRule,
    BuildContext,
    LocaleRule,
    RandomRule,
    TimestampRule,
    explain_text,
    make_unified_diff,
)


def _ctx(root_a="/tmp/build-a/src", root_b="/tmp/build-b/src"):
    now = time.time()
    return BuildContext(
        root_a=root_a,
        root_b=root_b,
        build_started=now - 60,
        build_finished=now + 60,
        epoch=1_700_000_000,
    )


class AbsPathRuleTests(unittest.TestCase):
    def test_build_root_recognized_high_confidence(self):
        ctx = _ctx()
        a = '{"root": "/tmp/build-a/src/demo_app"}'
        b = '{"root": "/tmp/build-b/src/demo_app"}'
        rule = AbsPathRule(ctx)
        na, _ = rule.normalize(a)
        nb, _ = rule.normalize(b)
        self.assertEqual(na, nb)
        self.assertEqual(rule.confidence, "high")
        self.assertNotIn("/tmp", na)

    def test_generic_posix_path_medium_confidence(self):
        rule = AbsPathRule(_ctx())
        out, samples = rule.normalize("prefix /opt/vendor/lib/libx.so suffix")
        self.assertIn("$PATH", out)
        self.assertTrue(samples)

    def test_relative_path_untouched(self):
        rule = AbsPathRule(_ctx())
        out, _ = rule.normalize("demo_app/core.py")
        self.assertEqual(out, "demo_app/core.py")


class TimestampRuleTests(unittest.TestCase):
    def test_iso_timestamp_in_window(self):
        ctx = _ctx()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        rule = TimestampRule(ctx)
        out, samples = rule.normalize(f"built {now_iso} ok")
        self.assertIn("$TIMESTAMP", out)
        self.assertTrue(samples)

    def test_epoch_in_window(self):
        ctx = _ctx()
        now = int(time.time())
        rule = TimestampRule(ctx)
        out, _ = rule.normalize(f"epoch={now}")
        self.assertIn("$TIMESTAMP", out)

    def test_old_epoch_outside_window_untouched(self):
        rule = TimestampRule(_ctx())
        out, _ = rule.normalize("epoch=1")
        self.assertEqual(out, "epoch=1")

    def test_fixed_epoch_constant_not_flagged(self):
        # 固定的 SOURCE_DATE_EPOCH（2023 年）不在当前构建窗口内
        rule = TimestampRule(_ctx())
        out, _ = rule.normalize(f"epoch=1700000000")
        self.assertNotIn("$TIMESTAMP", out)


class LocaleRuleTests(unittest.TestCase):
    def test_us_grouping_vs_plain(self):
        rule = LocaleRule()
        a, _ = rule.normalize("total 1,234,567.89 usd")
        b, _ = rule.normalize("total 1234567.89 usd")
        self.assertIn("$NUMBER", a)
        self.assertEqual(a, b.replace("1234567.89", "$NUMBER"))

    def test_eu_decimal(self):
        rule = LocaleRule()
        out, _ = rule.normalize("wert 3,1415")
        self.assertIn("$NUMBER", out)

    def test_currency(self):
        rule = LocaleRule()
        out, _ = rule.normalize("amount €99")
        self.assertIn("$AMOUNT", out)


class RandomRuleTests(unittest.TestCase):
    def test_uuid(self):
        rule = RandomRule()
        out, samples = rule.normalize("id=3f2504e0-4f89-11d3-9a0c-0305e82c3301")
        self.assertIn("$UUID", out)
        self.assertEqual(rule.confidence, "high")

    def test_hex_blob(self):
        rule = RandomRule()
        out, _ = rule.normalize("hash=" + "a1" * 24)
        self.assertIn("$HEX", out)

    def test_pointer_address(self):
        rule = RandomRule()
        out, _ = rule.normalize("object at 0x7f8a31c2d4e0")
        self.assertIn("$PTR", out)

    def test_plain_identifier_untouched(self):
        rule = RandomRule()
        out, _ = rule.normalize("reproducibility_guarantee")
        self.assertEqual(out, "reproducibility_guarantee")

    def test_high_entropy_token(self):
        rule = RandomRule()
        out, _ = rule.normalize("token=A9f3Kx27Qp81Lm45Zv")
        self.assertIn("$RANDOM_TOKEN", out)

    def test_b64_digest_starting_with_dash(self):
        # 回归：以 - 开头的 URL-safe base64 摘要必须被识别（RECORD 真实样本）
        rule = RandomRule(high_confidence_only=True)
        a = "x,sha256=-n92HTB1FdqsnjuHQNuKPDPplXV-rh6c0RW1Rze8aHw,32"
        b = "x,sha256=QAf-syGOKX2PNOPqt0xvd6PS2xVaDdD3BnURg_Is5jY,32"
        na, _ = rule.normalize(a)
        nb, _ = rule.normalize(b)
        self.assertEqual(na, nb)
        self.assertIn("$B64DIGEST", na)

    def test_b64_digest_after_comma(self):
        rule = RandomRule(high_confidence_only=True)
        out, _ = rule.normalize(
            "BUILD_METADATA.json,sha256=PP8U6iv_ox5vUPudyCAspxLkLiyepuq5A8WZ73Ihed8,533"
        )
        self.assertIn("$B64DIGEST", out)


class ExplainChainTests(unittest.TestCase):
    def test_fully_explained_mixed_noise(self):
        ctx = _ctx()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        import uuid

        a = (
            f'{{"root": "{ctx.root_a}/x", "t": "{now_iso}", '
            f'"id": "{uuid.uuid4()}", "n": 1000000}}'
        )
        b = (
            f'{{"root": "{ctx.root_b}/x", "t": "{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 5))}", '
            f'"id": "{uuid.uuid4()}", "n": 1,000,000}}'
        )
        expl = explain_text(a, b, ctx)
        self.assertTrue(expl.fully_explained)
        cats = {r.category for r in expl.results}
        self.assertIn(CATEGORY_ABS_PATH, cats)
        self.assertIn(CATEGORY_MTIME, cats)
        self.assertIn(CATEGORY_RANDOM, cats)
        self.assertIn(CATEGORY_LOCALE, cats)

    def test_real_code_diff_not_explained(self):
        ctx = _ctx()
        a = "def add(a, b):\n    return a + b\n"
        b = "def add(a, b):\n    return a - b\n"
        expl = explain_text(a, b, ctx)
        self.assertFalse(expl.fully_explained)
        self.assertEqual(expl.results, [])

    def test_unicode_nfc_nfd_attributed_locale(self):
        ctx = _ctx()
        import unicodedata

        nfd = unicodedata.normalize("NFD", "café")
        nfc = unicodedata.normalize("NFC", "café")
        expl = explain_text(nfc, nfd, ctx)
        self.assertTrue(expl.fully_explained)
        self.assertEqual(expl.results[-1].category, CATEGORY_LOCALE)


class DiffTests(unittest.TestCase):
    def test_unified_diff_contains_hunks(self):
        d = make_unified_diff("a\nx\n", "a\ny\n", "A", "B")
        self.assertIn("-x", d)
        self.assertIn("+y", d)


if __name__ == "__main__":
    unittest.main()
