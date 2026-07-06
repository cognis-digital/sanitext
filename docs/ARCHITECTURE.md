# Architecture

sanitext is a small, layered, standard-library-only tool. Data flows from raw
text through a per-character Unicode scan, then an optional PII/secret pass, into
structured findings and multiple report renderings.

## Modules

| Module | Responsibility |
|---|---|
| `sanitext/unicode_scan.py` | **Core engine.** Per-character classification (bidi, zero-width, invisible, control, homoglyph); produces `UFinding`s and the cleaned string. |
| `sanitext/bidi.py` | Bidi control tables and Trojan-Source helpers (detect, strip, balance check). |
| `sanitext/confusables.py` | Curated confusables map + UTS #39-style `skeleton()` transform (table + NFKC folding). |
| `sanitext/detectors.py` | PII/secret (and legacy profanity/tone) regex detectors → `Finding`s. |
| `sanitext/core.py` | **Top-level API.** `scan()` / `clean()` compose the Unicode engine with the PII layer into a `ScanResult`. |
| `sanitext/report.py` | Human before/after report (`render_scan`) + legacy policy score (`build`). |
| `sanitext/sarif.py` | SARIF 2.1.0 export for CI / code-scanning dashboards. |
| `sanitext/cli.py` | `scan` / `clean` / `normalize` subcommands; UTF-8 stdio; exit-code gate. |
| `sanitext/sanitizer.py`, `policies.py`, `lexicons.py`, `rewriter.py` | Optional legacy provider-normalizer + optional OpenAI-compatible re-authoring. |

## Data flow

```
raw text
   │
   ▼
unicode_scan.scan_chars()        # 1 classification per code point, priority order:
   │   bidi > zero-width > invisible(VS/tag) > control > Cf-format > homoglyph
   ▼
unicode_scan.clean_text()        # apply each finding's action (strip / normalize / flag)
   │
   ▼
core.scan()                      # optionally run detectors.detect() on the cleaned text
   │                             # and redact pii/secret findings
   ▼
ScanResult(source, clean, unicode_findings, pii_findings)
   │
   ├─► report.render_scan()      # human before/after table
   ├─► ScanResult.to_dict()      # JSON
   └─► sarif.to_sarif()          # SARIF 2.1.0
```

## Classification priority

Each character is classified **exactly once**. A code point that is both a bidi
control and a format character (e.g. U+200E) is owned by the bidi layer; when
bidi scanning is disabled, such a code point is left untouched rather than being
re-scooped by the zero-width/invisible layer. This keeps toggles predictable and
findings non-double-counted.

## Offsets

`UFinding.offset` is a **0-based character index** into the source string.
`sarif.py` translates offsets to 1-based `(line, column)` for viewers while also
emitting `charOffset`/`charLength` in the region for exact addressing.

## Idempotence

`clean(clean(text)) == clean(text)`, and a cleaned string produces no further
dangerous findings. This is enforced by `tests/test_idempotence.py`.

## Dependencies

Core engine, reports, SARIF, and CLI are **standard-library only**. The optional
`[openai]` extra pulls in an OpenAI-compatible SDK solely for the secondary
re-authoring layer; nothing else imports it.
