"""Bidirectional (bidi) control characters and Trojan-Source detection.

The Unicode bidirectional algorithm uses a set of invisible control characters
to override or isolate the display order of text. When these appear inside
source code, code review, commit messages, or chat, they let an attacker make
the *rendered* text differ from the *logical* (compiled/executed) text -- the
"Trojan Source" attack (CVE-2021-42574, Boucher & Anderson, 2021,
https://trojansource.codes/).

A comment such as::

    /* begin admins only */ if (isAdmin) {           # what a reviewer sees

can be reordered on screen while the bytes actually parse as an early
``return`` outside the guard -- an invisible logic bomb that passes review.

sanitext treats **every** bidi formatting character as dangerous by default and
strips it, because none of these characters are needed in normal identifiers,
code, or prose (legitimate right-to-left text renders correctly from the base
paragraph direction without embedded overrides in the vast majority of cases).

References:
  * CVE-2021-42574
  * Unicode Technical Report #9 (UAX #9), the Bidirectional Algorithm
  * "Trojan Source: Invisible Vulnerabilities", Boucher & Anderson, 2021
"""

from __future__ import annotations

import unicodedata

# Explicit bidi formatting characters (all are dangerous in code/identifiers).
# name -> code point.
BIDI_CONTROLS: dict[int, str] = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",  # LRE
    0x202B: "RIGHT-TO-LEFT EMBEDDING",  # RLE
    0x202C: "POP DIRECTIONAL FORMATTING",  # PDF
    0x202D: "LEFT-TO-RIGHT OVERRIDE",  # LRO
    0x202E: "RIGHT-TO-LEFT OVERRIDE",  # RLO
    0x2066: "LEFT-TO-RIGHT ISOLATE",  # LRI
    0x2067: "RIGHT-TO-LEFT ISOLATE",  # RLI
    0x2068: "FIRST STRONG ISOLATE",  # FSI
    0x2069: "POP DIRECTIONAL ISOLATE",  # PDI
    0x200E: "LEFT-TO-RIGHT MARK",  # LRM
    0x200F: "RIGHT-TO-LEFT MARK",  # RLM
    0x061C: "ARABIC LETTER MARK",  # ALM
}

# The subset used to *reorder* text (the Trojan-Source-relevant overrides and
# isolates). Their presence in source code is a strong attack indicator.
BIDI_OVERRIDES: frozenset[int] = frozenset(
    {0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068}
)

# Codes that pop/close a directional scope.
BIDI_POPS: frozenset[int] = frozenset({0x202C, 0x2069})


def is_bidi_control(ch: str) -> bool:
    """True if ``ch`` is a single bidi formatting control character."""
    return len(ch) == 1 and ord(ch) in BIDI_CONTROLS


def name(ch: str) -> str:
    """Human-readable name for a bidi control character."""
    cp = ord(ch)
    if cp in BIDI_CONTROLS:
        return BIDI_CONTROLS[cp]
    try:
        return unicodedata.name(ch)
    except ValueError:
        return f"U+{cp:04X}"


def contains_bidi(text: str) -> bool:
    """True if ``text`` contains any bidi formatting control character."""
    return any(ord(ch) in BIDI_CONTROLS for ch in text)


def find_bidi(text: str) -> list[tuple[int, str]]:
    """Return ``(offset, char)`` for every bidi control character in ``text``."""
    return [(i, ch) for i, ch in enumerate(text) if ord(ch) in BIDI_CONTROLS]


def has_unbalanced_bidi(text: str) -> bool:
    """True if opening bidi scopes are not properly closed on a per-line basis.

    Unbalanced embeddings/overrides/isolates within a single logical line are a
    hallmark of the Trojan-Source attack, where a scope opened inside a comment
    or string spills its reordering effect onto code the author did not intend.
    """
    for line in text.splitlines():
        embed_depth = 0
        isolate_depth = 0
        for ch in line:
            cp = ord(ch)
            if cp in (0x202A, 0x202B, 0x202D, 0x202E):
                embed_depth += 1
            elif cp == 0x202C:  # PDF
                embed_depth -= 1
            elif cp in (0x2066, 0x2067, 0x2068):
                isolate_depth += 1
            elif cp == 0x2069:  # PDI
                isolate_depth -= 1
            if embed_depth < 0 or isolate_depth < 0:
                return True
        if embed_depth != 0 or isolate_depth != 0:
            return True
    return False


def strip_bidi(text: str) -> str:
    """Remove every bidi formatting control character from ``text``."""
    return "".join(ch for ch in text if ord(ch) not in BIDI_CONTROLS)
