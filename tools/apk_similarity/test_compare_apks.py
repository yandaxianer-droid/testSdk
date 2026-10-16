"""Unit tests for the APK similarity tool.

Pure-function tests run everywhere. The end-to-end test is skipped unless the
app debug APK has been built (``./gradlew :app:assembleDebug``).
"""

import unittest
from collections import Counter
from pathlib import Path

import compare_apks as cmp
from dex import _build_instruction_size_table, _read_uleb128, _walk_opcodes
from array import array


class MetricTests(unittest.TestCase):
    def test_weighted_jaccard_identical(self):
        c = Counter({"a": 2, "b": 1})
        self.assertEqual(cmp.weighted_jaccard(c, c), 1.0)

    def test_weighted_jaccard_disjoint(self):
        self.assertEqual(
            cmp.weighted_jaccard(Counter({"a": 1}), Counter({"b": 1})), 0.0
        )

    def test_weighted_jaccard_partial(self):
        a = Counter({"x": 2, "y": 1})
        b = Counter({"x": 1, "z": 1})
        # intersection = min counts = 1 ; union = max counts = 2+1+1 = 4
        self.assertAlmostEqual(cmp.weighted_jaccard(a, b), 1 / 4)

    def test_set_jaccard(self):
        self.assertEqual(cmp.set_jaccard({1, 2}, {2, 3}), 1 / 3)
        self.assertEqual(cmp.set_jaccard(set(), set()), 1.0)

    def test_cosine_identical_and_orthogonal(self):
        a = Counter({(1, 2): 3, (2, 3): 1})
        self.assertAlmostEqual(cmp.cosine(a, a), 1.0)
        self.assertEqual(cmp.cosine(Counter({"a": 1}), Counter({"b": 1})), 0.0)

    def test_opcode_ngrams(self):
        self.assertEqual(
            cmp._opcode_ngrams([1, 2, 3, 4], 2),
            [(1, 2), (2, 3), (3, 4)],
        )
        # fewer opcodes than n -> single short gram
        self.assertEqual(cmp._opcode_ngrams([1, 2], 3), [(1, 2)])
        self.assertEqual(cmp._opcode_ngrams([], 3), [])

    def test_fingerprint_ignores_operands_order_sensitivity(self):
        # Same opcodes -> same fingerprint; different order -> different.
        self.assertEqual(
            cmp._method_fingerprint([0x12, 0x0F]),
            cmp._method_fingerprint([0x12, 0x0F]),
        )
        self.assertNotEqual(
            cmp._method_fingerprint([0x12, 0x0F]),
            cmp._method_fingerprint([0x0F, 0x12]),
        )


class DexPrimitiveTests(unittest.TestCase):
    def test_size_table_known_opcodes(self):
        size = _build_instruction_size_table()
        self.assertEqual(size[0x00], 1)   # nop
        self.assertEqual(size[0x12], 1)   # const/4
        self.assertEqual(size[0x14], 3)   # const (31i)
        self.assertEqual(size[0x18], 5)   # const-wide (51l)
        self.assertEqual(size[0x6E], 3)   # invoke-virtual (35c)
        self.assertEqual(size[0x0E], 1)   # return-void

    def test_uleb128(self):
        self.assertEqual(_read_uleb128(bytes([0x00]), 0), (0, 1))
        self.assertEqual(_read_uleb128(bytes([0x7F]), 0), (127, 1))
        self.assertEqual(_read_uleb128(bytes([0x80, 0x01]), 0), (128, 2))
        self.assertEqual(_read_uleb128(bytes([0xE5, 0x8E, 0x26]), 0), (624485, 3))

    def test_walk_skips_nops_and_decodes_lengths(self):
        # const/4 (1u) ; nop (1u) ; const (3u, opcode 0x14) ; return-void (1u)
        units = array("H", [0x0012, 0x0000, 0x0014, 0x0000, 0x0000, 0x000E])
        self.assertEqual(_walk_opcodes(units, 0, len(units)), [0x12, 0x14, 0x0E])

    def test_walk_skips_packed_switch_payload(self):
        # packed-switch (0x2b, 3u) then its payload (ident 0x0100, size=1 ->
        # 4 + 2*1 = 6 units) then return-void.
        units = array(
            "H",
            [0x002B, 0x0000, 0x0000,          # packed-switch
             0x0100, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000,  # payload (6u)
             0x000E],                          # return-void
        )
        self.assertEqual(_walk_opcodes(units, 0, len(units)), [0x2B, 0x0E])


class EndToEndApkTest(unittest.TestCase):
    APK = Path(__file__).resolve().parents[2] / "app/build/outputs/apk/debug/app-debug.apk"

    def test_identical_apk_scores_full_similarity(self):
        if not self.APK.is_file():
            self.skipTest("app-debug.apk not built; run ./gradlew :app:assembleDebug")
        profile = cmp.build_profile(str(self.APK), ngram=4)
        self.assertGreater(profile.method_count, 0)
        report = cmp.compare(profile, profile)
        self.assertEqual(report["overall_similarity"], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
