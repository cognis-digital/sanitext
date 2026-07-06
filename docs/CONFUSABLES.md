# Homoglyphs & confusables (Unicode UTS #39)

## The problem

Different Unicode code points can be visually indistinguishable. `а` (U+0430
CYRILLIC SMALL LETTER A) renders identically to `a` (U+0061 LATIN SMALL LETTER
A). Attackers exploit this to spoof:

- **Domains** — `раypal.com` (Cyrillic `р`, `а`) vs `paypal.com`.
- **Identifiers / usernames** — `аdmin` looks like `admin`.
- **Package names** — a typosquat that is byte-different but pixel-identical.
- **Source-code identifiers** — two "different" variables that read the same.

## Unicode UTS #39 and the skeleton

Unicode Technical Standard #39 (*Unicode Security Mechanisms*) defines
**confusable detection** via a *skeleton* transform: map each string to a
representative form such that two strings are confusable **iff their skeletons
are equal**. The full algorithm uses the Unicode `confusables.txt` data file
(~6000+ mappings).

sanitext ships a **pragmatic, documented approximation**:

1. A **curated table** (`sanitext/confusables.py`, **184 explicit mappings** at
   time of writing) of the code points most relevant to ASCII/Latin spoofing:
   - Cyrillic look-alikes (а е о р с у х Н К М Т В …)
   - Greek look-alikes (ο α Β Ε Η Ρ Τ Χ …)
   - Fullwidth ASCII forms (U+FF01–U+FF5E, the whole block)
   - Selected Latin/IPA look-alikes and punctuation confusables (curly quotes,
     dashes, division/fraction slash, fullwidth `@`/`.`)
2. **NFKC compatibility folding** for anything not in the table. This catches
   the mathematical alphanumeric symbols (`𝐀`→`A`, `𝒂`→`a`), circled and
   parenthesized letters, and fullwidth forms without needing an explicit entry.

`skeleton(text)` applies the table first, then NFKC folding per code point, and
leaves genuinely distinct scripts (e.g. `日本語`) unchanged.

## Honest coverage note

This is **a curated subset plus NFKC folding, not the full UTS #39 confusables
table.** It is tuned for the common ASCII/Latin spoofing cases that matter for
domains, identifiers, and code review. It will not flag every one of the 6000+
Unicode-defined confusable pairs (e.g. rare cross-script pairs outside the
curated set that also don't fold under NFKC). Embedding the complete table with
a build step is tracked as a roadmap item.

## Default behavior

- Homoglyphs are **detected** (offset, code point, Unicode name, ASCII target)
  and **normalized** to their ASCII skeleton in `clean` output.
- A homoglyph alone does **not** mark text as `dangerous` (does not fail the CI
  gate) by default, because non-ASCII letters are common in legitimate prose.
  Use `--flag-only-homoglyphs` to report without rewriting.

## API

```python
from sanitext import confusables

confusables.is_confusable("а")            # True (Cyrillic a)
confusables.target("а")                   # "a"
confusables.skeleton("раypal.com")        # "paypal.com"
confusables.confusable_with_ascii("аpple")  # True: looks like ASCII but isn't
```

## References

- Unicode UTS #39, *Unicode Security Mechanisms*,
  https://www.unicode.org/reports/tr39/
- Unicode `confusables.txt` (Unicode Character Database)
