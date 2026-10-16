# APK code-similarity tool

A small, **dependency-free** (Python 3.8+ standard library only) command-line
tool that estimates how similar the *code* of two Android APKs is. It parses the
DEX bytecode directly, so it works on release/obfuscated builds and does not
need the Android SDK, `apktool`, or Androguard.

## How it works

Each APK is reduced to a set of features extracted from its `classes*.dex`:

| Signal | What it captures | Robust against |
| --- | --- | --- |
| **Method fingerprints** | SHA-1 of every method's opcode sequence (operands stripped), compared as a weighted multiset Jaccard | identifier/variable renaming |
| **Opcode n-grams** | frequency vectors of opcode n-grams, compared with cosine similarity | small per-method edits; gives *graded* partial similarity |
| **String constants** | Jaccard of the DEX string pools | logic rewrites (strings often survive) |
| **Class descriptors** | Jaccard of class names (name-based) | nothing — weighted lightly, defeated by obfuscation |

The headline `overall_similarity` is a weighted blend (instruction-level signals
dominate; see `_WEIGHTS` in `compare_apks.py`).

## Usage

```bash
# human-readable report
python3 tools/apk_similarity/compare_apks.py app-a.apk app-b.apk

# machine-readable JSON (to a file, or '-' for stdout)
python3 tools/apk_similarity/compare_apks.py app-a.apk app-b.apk --json report.json

# tune the opcode n-gram size (default 4)
python3 tools/apk_similarity/compare_apks.py app-a.apk app-b.apk -n 3
```

Example (comparing this project's debug APK against a slightly modified rebuild):

```
================================================================
APK code similarity report
================================================================
  A: app-debug.apk
  B: app-debug-modified.apk
----------------------------------------------------------------
  Method fingerprint Jaccard ...  98.70%
  Opcode n-gram cosine .........  99.60%
  String-constant Jaccard ......  99.10%
  Class-name Jaccard ...........  97.80%
----------------------------------------------------------------
  OVERALL SIMILARITY ...........  98.90%
================================================================
```

## Interpreting the score

- `~100%` — same code (same build, or a repackaged/pirated copy).
- `70–95%` — strongly related (e.g. a new version of the same app).
- `<30%` — largely unrelated apps (shared values usually come from common
  AndroidX/Kotlin runtime classes).

## Testing

```bash
cd tools/apk_similarity
python3 -m unittest -v
```

The pure-function and DEX-primitive tests run anywhere. The end-to-end test is
skipped unless `app-debug.apk` exists (build it with
`./gradlew :app:assembleDebug`).

## Limitations

- Heavy control-flow obfuscation or packers that encrypt the DEX will lower the
  instruction-level signals; the tool reports partial similarity rather than
  attempting to unpack.
- Native code (`lib/*.so`) and resources are not analysed — only Dalvik
  bytecode.
