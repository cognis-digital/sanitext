"""Homoglyph / confusables data and skeleton transform (Unicode UTS #39).

This module provides two things:

1. :data:`CONFUSABLES` -- a curated mapping from confusable (non-ASCII) code
   points to the ASCII/Latin character they visually resemble. This is an
   **honest, curated subset** of the full Unicode confusables table
   (``confusablesSummary.txt`` in the Unicode Character Database, which lists
   ~6000+ mappings). It focuses on the code points most relevant to spoofing
   attacks against ASCII/Latin identifiers, domains, and source code:

     * Cyrillic look-alikes (а е о р с у х ... vs a e o p c y x)
     * Greek look-alikes (ο α ν ρ ... and math omicron)
     * Fullwidth ASCII forms (U+FF01..U+FF5E)
     * A selection of Latin/IPA/accented look-alikes
     * Common punctuation confusables (curly quotes, dashes, division slash)

   Additional coverage is derived at runtime via Unicode NFKC compatibility
   decomposition (see :func:`skeleton`), which folds the mathematical
   alphanumeric symbols (𝐚, 𝒂, 𝔞, ...), fullwidth forms, and many circled /
   parenthesized letters onto their ASCII base without needing an explicit
   table entry.

2. :func:`skeleton` -- a TR39-style "skeleton" transform: map a string to a
   representative form so that two strings are confusable iff their skeletons
   are equal. We combine the curated table with NFKC folding. This is a
   pragmatic approximation of the UTS #39 skeleton algorithm, documented as
   such -- it is deliberately conservative and reproducible.

Reference: Unicode Technical Standard #39, "Unicode Security Mechanisms",
https://www.unicode.org/reports/tr39/ (confusable detection, skeleton).
"""

from __future__ import annotations

import unicodedata

# --- Curated confusable -> ASCII target map --------------------------------
# Each key is a single non-ASCII code point that is visually confusable with
# the ASCII value. Kept explicit (not algorithmic) so the mapping is auditable.
CONFUSABLES: dict[str, str] = {}


def _add(mapping: dict[str, str]) -> None:
    CONFUSABLES.update(mapping)


# Cyrillic letters that look like Latin/ASCII.
_add(
    {
        "а": "a",  # CYRILLIC SMALL A
        "А": "A",  # CYRILLIC CAPITAL A
        "е": "e",  # CYRILLIC SMALL IE
        "Е": "E",  # CYRILLIC CAPITAL IE
        "о": "o",  # CYRILLIC SMALL O
        "О": "O",  # CYRILLIC CAPITAL O
        "р": "p",  # CYRILLIC SMALL ER
        "Р": "P",  # CYRILLIC CAPITAL ER
        "с": "c",  # CYRILLIC SMALL ES
        "С": "C",  # CYRILLIC CAPITAL ES
        "у": "y",  # CYRILLIC SMALL U
        "У": "Y",  # CYRILLIC CAPITAL U
        "х": "x",  # CYRILLIC SMALL HA
        "Х": "X",  # CYRILLIC CAPITAL HA
        "і": "i",  # CYRILLIC SMALL BYELORUSSIAN-UKRAINIAN I
        "І": "I",  # CYRILLIC CAPITAL BYELORUSSIAN-UKRAINIAN I
        "ј": "j",  # CYRILLIC SMALL JE
        "Ј": "J",  # CYRILLIC CAPITAL JE
        "һ": "h",  # CYRILLIC SMALL SHHA
        "Н": "H",  # CYRILLIC CAPITAL EN
        "К": "K",  # CYRILLIC CAPITAL KA
        "М": "M",  # CYRILLIC CAPITAL EM
        "Т": "T",  # CYRILLIC CAPITAL TE
        "В": "B",  # CYRILLIC CAPITAL VE
        "Ѕ": "S",  # CYRILLIC CAPITAL DZE
        "ѕ": "s",  # CYRILLIC SMALL DZE
        "є": "e",  # CYRILLIC SMALL UKRAINIAN IE
        "ґ": "r",  # CYRILLIC SMALL GHE WITH UPTURN (loose)
        "н": "H",  # CYRILLIC SMALL EN (looks like H uppercase-ish)
        "г": "r",  # CYRILLIC SMALL GHE
        "м": "m",  # CYRILLIC SMALL EM
        "т": "t",  # CYRILLIC SMALL TE
        "в": "b",  # CYRILLIC SMALL VE (loose)
        "п": "n",  # CYRILLIC SMALL PE (loose)
    }
)

# Greek letters confusable with Latin/ASCII.
_add(
    {
        "ο": "o",  # GREEK SMALL OMICRON
        "Ο": "O",  # GREEK CAPITAL OMICRON
        "α": "a",  # GREEK SMALL ALPHA
        "Α": "A",  # GREEK CAPITAL ALPHA
        "Β": "B",  # GREEK CAPITAL BETA
        "Ε": "E",  # GREEK CAPITAL EPSILON
        "Η": "H",  # GREEK CAPITAL ETA
        "Ι": "I",  # GREEK CAPITAL IOTA
        "Κ": "K",  # GREEK CAPITAL KAPPA
        "Μ": "M",  # GREEK CAPITAL MU
        "Ν": "N",  # GREEK CAPITAL NU
        "Ρ": "P",  # GREEK CAPITAL RHO
        "Τ": "T",  # GREEK CAPITAL TAU
        "Υ": "Y",  # GREEK CAPITAL UPSILON
        "Χ": "X",  # GREEK CAPITAL CHI
        "Ζ": "Z",  # GREEK CAPITAL ZETA
        "ι": "i",  # GREEK SMALL IOTA (loose)
        "ν": "v",  # GREEK SMALL NU
        "ρ": "p",  # GREEK SMALL RHO
        "υ": "u",  # GREEK SMALL UPSILON (loose)
        "χ": "x",  # GREEK SMALL CHI (loose)
        "κ": "k",  # GREEK SMALL KAPPA
    }
)

# Punctuation / symbol confusables against ASCII punctuation.
_add(
    {
        "‐": "-",  # HYPHEN
        "‑": "-",  # NON-BREAKING HYPHEN
        "‒": "-",  # FIGURE DASH
        "–": "-",  # EN DASH
        "—": "-",  # EM DASH
        "―": "-",  # HORIZONTAL BAR
        "−": "-",  # MINUS SIGN
        "‘": "'",  # LEFT SINGLE QUOTATION MARK
        "’": "'",  # RIGHT SINGLE QUOTATION MARK
        "“": '"',  # LEFT DOUBLE QUOTATION MARK
        "”": '"',  # RIGHT DOUBLE QUOTATION MARK
        "′": "'",  # PRIME
        "″": '"',  # DOUBLE PRIME
        "⁄": "/",  # FRACTION SLASH
        "∕": "/",  # DIVISION SLASH
        "∖": "\\",  # SET MINUS
        "։": ":",  # ARMENIAN FULL STOP (looks like colon)
        "׃": ":",  # HEBREW PUNCTUATION SOF PASUQ (loose)
        "∶": ":",  # RATIO
        "．": ".",  # FULLWIDTH FULL STOP
        "。": ".",  # IDEOGRAPHIC FULL STOP (loose)
        "·": ".",  # MIDDLE DOT (loose)
        "․": ".",  # ONE DOT LEADER
        "＠": "@",  # FULLWIDTH COMMERCIAL AT
        "٪": "%",  # ARABIC PERCENT SIGN (loose)
    }
)

# A few Latin/IPA/other look-alikes.
_add(
    {
        "ı": "i",  # LATIN SMALL DOTLESS I
        "ɩ": "i",  # LATIN SMALL IOTA
        "ɡ": "g",  # LATIN SMALL SCRIPT G
        "ǀ": "l",  # LATIN LETTER DENTAL CLICK (pipe/l)
        "ℓ": "l",  # SCRIPT SMALL L
        "ⅼ": "l",  # SMALL ROMAN NUMERAL FIFTY (loose)
        "ｌ": "l",  # FULLWIDTH covered separately but explicit here
        "İ": "I",  # LATIN CAPITAL I WITH DOT ABOVE
        "ӏ": "l",  # CYRILLIC SMALL PALOCHKA
        "ᴏ": "O",  # LATIN LETTER SMALL CAPITAL O (loose)
        "ո": "n",  # ARMENIAN SMALL VO (loose)
        "ẞ": "S",  # LATIN CAPITAL SHARP S (loose)
    }
)


def _build_fullwidth() -> dict[str, str]:
    """Fullwidth ASCII variants U+FF01..U+FF5E -> ASCII 0x21..0x7E."""
    out: dict[str, str] = {}
    for cp in range(0xFF01, 0xFF5F):
        ascii_cp = cp - 0xFF00 + 0x20
        out[chr(cp)] = chr(ascii_cp)
    return out


_add(_build_fullwidth())


def is_confusable(ch: str) -> bool:
    """Return True if ``ch`` is a single code point in the curated table."""
    return ch in CONFUSABLES


def target(ch: str) -> str | None:
    """Return the ASCII target for a curated confusable, or None."""
    return CONFUSABLES.get(ch)


def _nfkc_fold(ch: str) -> str:
    """Fold a single character via NFKC; if it decomposes to ASCII, use that.

    This catches mathematical alphanumerics (e.g. U+1D400 MATHEMATICAL BOLD
    CAPITAL A -> "A"), circled/parenthesized letters, and fullwidth forms
    without an explicit table entry. Non-ASCII results are returned unchanged
    so the skeleton stays lossless for genuinely distinct scripts.
    """
    folded = unicodedata.normalize("NFKC", ch)
    if folded != ch and all(ord(c) < 128 for c in folded):
        return folded
    return ch


def skeleton(text: str) -> str:
    """Return a confusable *skeleton* of ``text`` (UTS #39-style).

    Two strings are considered confusable when their skeletons are equal. The
    transform, applied per code point:

      1. If the code point is in the curated :data:`CONFUSABLES` table, replace
         it with its ASCII target.
      2. Otherwise, apply NFKC folding; if that yields a pure-ASCII string
         (e.g. mathematical alphanumerics, fullwidth, circled letters), use it.
      3. Otherwise, keep the code point unchanged.

    This is a documented approximation of the full UTS #39 skeleton algorithm,
    sufficient for detecting the common ASCII/Latin spoofing cases.
    """
    out: list[str] = []
    for ch in text:
        mapped = CONFUSABLES.get(ch)
        if mapped is not None:
            out.append(mapped)
            continue
        out.append(_nfkc_fold(ch))
    return "".join(out)


def confusable_with_ascii(text: str) -> bool:
    """True if ``text`` contains non-ASCII chars whose skeleton is ASCII.

    i.e. the string *looks* like ASCII but is not actually ASCII -- the classic
    homoglyph-spoofing condition.
    """
    if all(ord(c) < 128 for c in text):
        return False
    skel = skeleton(text)
    return skel != text and all(ord(c) < 128 for c in skel)
