#!/usr/bin/env python3
"""Compare the code similarity of two Android APKs.

The tool reads the DEX bytecode of each APK and compares them on several
complementary, obfuscation-aware signals:

* method fingerprints - a hash of each method's opcode sequence (operands
  stripped), compared as a weighted multiset Jaccard. Detects methods that are
  identical at the instruction level even when identifiers are renamed.
* opcode n-grams - frequency vectors of opcode n-grams across all methods,
  compared with cosine similarity. Captures *partial* similarity when methods
  are only slightly modified.
* string constants - Jaccard of the string pools. A strong same-origin signal.
* class descriptors - Jaccard of class names (name-based, so sensitive to
  identifier obfuscation; reported separately and weighted lightly).

The script depends only on the Python standard library.

Usage:
    python compare_apks.py app-a.apk app-b.apk
    python compare_apks.py app-a.apk app-b.apk --json report.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dex import DexFile, DexFeatures  # noqa: E402


@dataclass
class ApkProfile:
    path: str
    method_fingerprints: Counter
    opcode_ngrams: Counter
    strings: set
    classes: set
    method_count: int


def _iter_dex_blobs(apk_path: str):
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if name.endswith(".dex") and "/" not in name:
                yield zf.read(name)


def _method_fingerprint(opcodes: List[int]) -> str:
    return hashlib.sha1(bytes(op & 0xFF for op in opcodes)).hexdigest()


def _opcode_ngrams(opcodes: List[int], n: int) -> List[tuple]:
    if len(opcodes) < n:
        return [tuple(opcodes)] if opcodes else []
    return [tuple(opcodes[i : i + n]) for i in range(len(opcodes) - n + 1)]


def build_profile(apk_path: str, ngram: int) -> ApkProfile:
    fingerprints: Counter = Counter()
    ngrams: Counter = Counter()
    strings: set = set()
    classes: set = set()
    method_count = 0

    found_dex = False
    for blob in _iter_dex_blobs(apk_path):
        found_dex = True
        features: DexFeatures = DexFile(blob).parse()
        strings.update(features.strings)
        classes.update(features.class_descriptors)
        for opcodes in features.methods:
            method_count += 1
            fingerprints[_method_fingerprint(opcodes)] += 1
            ngrams.update(_opcode_ngrams(opcodes, ngram))

    if not found_dex:
        raise ValueError(f"{apk_path}: no classes*.dex found in APK")

    return ApkProfile(
        path=apk_path,
        method_fingerprints=fingerprints,
        opcode_ngrams=ngrams,
        strings=strings,
        classes=classes,
        method_count=method_count,
    )


def weighted_jaccard(a: Counter, b: Counter) -> float:
    if not a and not b:
        return 1.0
    intersection = sum((a & b).values())
    union = sum((a | b).values())
    return intersection / union if union else 0.0


def set_jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def cosine(a: Counter, b: Counter) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b.get(k, 0) for k in a)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# Relative importance of each signal in the headline score. Instruction-level
# signals dominate; name-based class overlap is weighted lightly because it is
# the easiest to defeat with obfuscation.
_WEIGHTS = {
    "method_jaccard": 0.45,
    "opcode_ngram_cosine": 0.30,
    "string_jaccard": 0.15,
    "class_jaccard": 0.10,
}


def compare(a: ApkProfile, b: ApkProfile) -> Dict:
    identical_methods = sum((a.method_fingerprints & b.method_fingerprints).values())
    metrics = {
        "method_jaccard": weighted_jaccard(a.method_fingerprints, b.method_fingerprints),
        "opcode_ngram_cosine": cosine(a.opcode_ngrams, b.opcode_ngrams),
        "string_jaccard": set_jaccard(a.strings, b.strings),
        "class_jaccard": set_jaccard(a.classes, b.classes),
    }
    overall = sum(metrics[name] * weight for name, weight in _WEIGHTS.items())

    return {
        "apk_a": a.path,
        "apk_b": b.path,
        "overall_similarity": round(overall, 4),
        "metrics": {k: round(v, 4) for k, v in metrics.items()},
        "weights": _WEIGHTS,
        "details": {
            "methods_a": a.method_count,
            "methods_b": b.method_count,
            "identical_methods": identical_methods,
            "strings_a": len(a.strings),
            "strings_b": len(b.strings),
            "classes_a": len(a.classes),
            "classes_b": len(b.classes),
            "classes_only_in_a": sorted(
                d.decode("utf-8", "replace") for d in (a.classes - b.classes)
            )[:20],
            "classes_only_in_b": sorted(
                d.decode("utf-8", "replace") for d in (b.classes - a.classes)
            )[:20],
        },
    }


def _print_report(report: Dict) -> None:
    pct = lambda x: f"{x * 100:6.2f}%"
    d = report["details"]
    print("=" * 64)
    print("APK code similarity report")
    print("=" * 64)
    print(f"  A: {report['apk_a']}")
    print(f"  B: {report['apk_b']}")
    print("-" * 64)
    m = report["metrics"]
    print(f"  Method fingerprint Jaccard ... {pct(m['method_jaccard'])}")
    print(f"  Opcode n-gram cosine ......... {pct(m['opcode_ngram_cosine'])}")
    print(f"  String-constant Jaccard ...... {pct(m['string_jaccard'])}")
    print(f"  Class-name Jaccard ........... {pct(m['class_jaccard'])}")
    print("-" * 64)
    print(f"  OVERALL SIMILARITY ........... {pct(report['overall_similarity'])}")
    print("-" * 64)
    print(f"  methods:  A={d['methods_a']}  B={d['methods_b']}  "
          f"identical={d['identical_methods']}")
    print(f"  strings:  A={d['strings_a']}  B={d['strings_b']}")
    print(f"  classes:  A={d['classes_a']}  B={d['classes_b']}")
    if d["classes_only_in_a"]:
        print(f"  classes only in A (up to 20): {d['classes_only_in_a']}")
    if d["classes_only_in_b"]:
        print(f"  classes only in B (up to 20): {d['classes_only_in_b']}")
    print("=" * 64)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare the code similarity of two Android APKs."
    )
    parser.add_argument("apk_a", help="path to the first APK")
    parser.add_argument("apk_b", help="path to the second APK")
    parser.add_argument(
        "-n", "--ngram", type=int, default=4,
        help="opcode n-gram size for the cosine metric (default: 4)",
    )
    parser.add_argument(
        "--json", metavar="PATH",
        help="also write the full report as JSON to PATH ('-' for stdout)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="suppress the human-readable report (useful with --json -)",
    )
    args = parser.parse_args(argv)

    for p in (args.apk_a, args.apk_b):
        if not Path(p).is_file():
            parser.error(f"file not found: {p}")
    if args.ngram < 1:
        parser.error("--ngram must be >= 1")

    profile_a = build_profile(args.apk_a, args.ngram)
    profile_b = build_profile(args.apk_b, args.ngram)
    report = compare(profile_a, profile_b)

    if not args.quiet:
        _print_report(report)

    if args.json:
        payload = json.dumps(report, indent=2, ensure_ascii=False)
        if args.json == "-":
            print(payload)
        else:
            Path(args.json).write_text(payload, encoding="utf-8")
            if not args.quiet:
                print(f"JSON report written to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
