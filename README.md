# sanitext

**Defensive Unicode-security text sanitizer.** Paste, commit, or ingested text
can carry invisible attacks that survive human review: bidirectional control
characters that reorder how source *renders* versus how it *executes*
(**Trojan Source, CVE-2021-42574**), zero-width characters used to smuggle or
watermark content, C0/C1 control characters, and **homoglyphs** that spoof
ASCII identifiers, domains, and package names (**Unicode UTS #39**).

sanitext **detects, reports, and strips/normalizes** these — with per-character
offsets, code points, and Unicode names — plus an optional PII/secret redaction
layer on top. The core is **standard-library only**: no network, no model, no
third-party runtime dependencies.

```text
$ sanitext scan trojan.c
Unicode-security findings (2):
    off  codepoint  cat         gc   action      name
     24  U+202E     bidi        Cf   stripped    RIGHT-TO-LEFT OVERRIDE
     34  U+202C     bidi        Cf   stripped    POP DIRECTIONAL FORMATTING
Before/after:
  before: if·access_level·!=·"user··//·Check·"·{
  after : if·access_level·!=·"user·//·Check"·{
Verdict: DANGEROUS  (bidi=2)
$ echo $?
1
```

`scan` exits **nonzero** when dangerous characters are present, so it drops
straight into a pre-commit hook or CI step.

## Why this matters

- **Trojan Source (CVE-2021-42574).** Bidi override/isolate characters
  (U+202A–U+202E, U+2066–U+2069) let an attacker make a code comment or string
  *render* one way while the compiler reads the logical byte order — an
  invisible logic bomb that passes code review. See
  [`docs/TROJAN-SOURCE.md`](docs/TROJAN-SOURCE.md).
- **Zero-width smuggling.** ZWSP/ZWNJ/ZWJ/BOM/word-joiner/soft-hyphen and
  variation selectors break tokens apart (evading naive filters) or watermark
  copied text invisibly.
- **Homoglyph spoofing.** `раypal.com` looks identical to `paypal.com` but the
  first two letters are Cyrillic. Same trick spoofs usernames, package names,
  and code identifiers. See [`docs/CONFUSABLES.md`](docs/CONFUSABLES.md).
- **Control characters.** C0/C1 controls corrupt logs and enable
  terminal-escape injection.

## What it detects

| Category | What | Default action | Standard |
|---|---|---|---|
| `bidi` | LRE/RLE/LRO/RLO/PDF, LRI/RLI/FSI/PDI, LRM/RLM/ALM | **strip** | CVE-2021-42574, UAX #9 |
| `zero_width` | ZWSP, ZWNJ, ZWJ, BOM/ZWNBSP, word joiner, soft hyphen, invisible math ops, Hangul fillers | **strip** | Unicode Cf |
| `invisible` | variation selectors (VS1–VS256), tag chars, other Cf format chars | **strip** | Unicode Cf |
| `control` | C0/C1 controls except `\t \n \r` | **strip** | Unicode Cc |
| `homoglyph` | non-ASCII code points confusable with ASCII/Latin | **normalize** to ASCII skeleton | UTS #39 |
| `pii` / `secret` | email, phone, SSN, IPv4, API keys, tokens | **redact** | (optional layer) |

The `bidi`, `zero_width`, `invisible`, and `control` categories mark text as
**dangerous** (nonzero exit). Homoglyphs are reported and normalized but do not
fail the gate by default (they are common in legitimate prose).

## Install

```bash
pip install -e .                 # core scanner (stdlib only)
pip install -e ".[dev]"          # + pytest
pip install -e ".[openai]"       # + optional LLM re-authoring layer
```

Requires Python **3.10+**. The scanner needs no third-party dependencies.

### Put `sanitext` on your PATH

After `pip install -e .`, the console script `sanitext` is installed. To get a
one-word command from any shell, the repo also ships launchers in `bin/`:

```bash
cp bin/sanitext.cmd bin/sanitext ~/.local/bin/   # Windows .cmd + WSL/bash shim
```

See the [cross-platform section](#cross-platform) for macOS/Linux/Windows and
Docker.

## Usage

```bash
# Scan a file — report findings; exit 1 if dangerous chars are present (CI gate)
sanitext scan path/to/file.txt

# Clean a file — emit sanitized text to stdout
sanitext clean path/to/file.txt

# From stdin
git show HEAD:src/app.py | sanitext scan -

# Machine-readable
sanitext scan file.txt --json
sanitext scan file.txt --sarif        # SARIF 2.1.0 for GitHub code scanning

# Category toggles
sanitext scan file.txt --no-homoglyph --no-pii
sanitext clean file.txt --flag-only-homoglyphs   # report homoglyphs, keep them

# Legacy provider-normalizer (profanity/tone/PII cleanup)
sanitext normalize file.txt --report
```

### JSON output (real)

```console
$ sanitext scan -t "раypal.com" --json
{
  "dangerous": false,
  "counts": { "homoglyph": 2 },
  "clean": "paypal.com",
  "unicode_findings": [
    {
      "offset": 0, "char": "р", "codepoint": "U+0440",
      "name": "CYRILLIC SMALL LETTER ER", "category": "homoglyph",
      "unicode_category": "Ll", "severity": "medium",
      "action": "normalized", "replacement": "p",
      "detail": "confusable with ASCII 'p' (UTS #39)"
    },
    {
      "offset": 1, "char": "а", "codepoint": "U+0430",
      "name": "CYRILLIC SMALL LETTER A", "category": "homoglyph",
      "unicode_category": "Ll", "severity": "medium",
      "action": "normalized", "replacement": "a",
      "detail": "confusable with ASCII 'a' (UTS #39)"
    }
  ],
  "pii_findings": []
}
```

## Library API

```python
from sanitext import scan, clean

result = scan(text)
result.findings        # list[UFinding]: offset, codepoint, name, category, action
result.clean           # sanitized string
result.dangerous       # bool — True if bidi/zero-width/invisible/control found
result.to_dict()       # JSON-ready dict

clean(text)            # -> cleaned string (convenience)
```

Fine-grained control:

```python
from sanitext import scan, ScanOptions, UnicodeScanOptions

opts = ScanOptions(
    unicode=UnicodeScanOptions(homoglyph=True, normalize_homoglyphs=False),
    pii=True,
)
scan(text, opts)
```

SARIF export:

```python
from sanitext import scan
from sanitext.sarif import to_sarif
import json

print(json.dumps(to_sarif(scan(text), artifact_uri="app.py"), indent=2))
```

## Use as a CI gate

```yaml
# .github/workflows/text-hygiene.yml
- run: pip install -e .
- run: |
    git ls-files '*.py' '*.md' | while read f; do
      sanitext scan "$f" || exit 1
    done
```

`sanitext scan` returns exit code **1** when dangerous characters are found,
**0** otherwise — the same pattern works in a `pre-commit` hook.

## Optional PII / secret layer

The scanner reuses the built-in detectors for email, phone, SSN, IPv4, and
common credential shapes (OpenAI/AWS/GitHub/Slack keys, bearer tokens) and
redacts them alongside the Unicode cleanup. Disable with `--no-pii`. Details in
[`docs/PII.md`](docs/PII.md).

## Optional LLM re-authoring

For fluent rephrasing instead of token substitution, an optional layer can call
a **generic, OpenAI-compatible endpoint** (hosted or a local server) — this is
secondary to the offline scanner and needs the `[openai]` extra plus your own
endpoint/key. It never tries to defeat a provider's safety system.

<a name="cross-platform"></a>
## Cross-platform

Pure-Python, stdlib-only core. All file I/O uses UTF-8 with a replacement
fallback (a scanner must tolerate malformed input), and CLI output reconfigures
stdout to UTF-8 with `errors="replace"` so it prints on Windows cp1252 consoles
without crashing.

```bash
# macOS / Linux
./install.sh

# Windows (PowerShell)
./install.ps1

# Make
make install && make test && make demos

# Docker
docker build -t sanitext . && docker run --rm sanitext scan -t "x‮y"
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — modules and data flow
- [`docs/TROJAN-SOURCE.md`](docs/TROJAN-SOURCE.md) — the bidi attack + CVE-2021-42574
- [`docs/CONFUSABLES.md`](docs/CONFUSABLES.md) — UTS #39, the skeleton transform, curated-subset note
- [`docs/PII.md`](docs/PII.md) — the optional PII/secret layer

## Demos & tests

```bash
python demos/run_all.py     # runs 8 offline demos; exits 0
python -m pytest -q         # 149 tests
```

## Threat model (honest scope)

sanitext defends against **text-based Unicode abuse and pattern-matchable
PII/secrets**. It is **not** an antivirus, not a full DLP suite, and homoglyph
coverage is a documented **curated subset** of the Unicode confusables table
(184 explicit mappings plus NFKC folding), not the full ~6000-entry table — see
[`docs/CONFUSABLES.md`](docs/CONFUSABLES.md). PII detection is regex-based and
will miss unusual formats. Treat it as a strong first line, not a guarantee.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** —
see [`LICENSE`](LICENSE) and [`DISCLAIMER.md`](DISCLAIMER.md). Free for
non-commercial use; commercial use requires a separate license.
