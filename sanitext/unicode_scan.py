"""Unicode-security scanner: the defensive core of sanitext.

Detects and (optionally) removes text-based Unicode abuses that let attackers
smuggle invisible or spoofed content past human review:

  * **bidi / Trojan-Source** control characters (CVE-2021-42574) -- see
    :mod:`sanitext.bidi`.
  * **zero-width & invisible** format characters (ZWSP, ZWNJ, ZWJ, BOM, word
    joiner, soft hyphen, Mongolian vowel separator, variation selectors ...).
  * **control characters** -- C0/C1 controls except common whitespace.
  * **homoglyphs / confusables** -- non-ASCII code points that look like
    ASCII/Latin (Unicode UTS #39) -- see :mod:`sanitext.confusables`.

Each detection is reported as a :class:`UFinding` carrying the character offset,
code point, Unicode name, general category, the attack class, and the action
taken (stripped / replaced / normalized). The findings drive a rich before/after
report and CI-gating exit codes.

This layer is standard-library only.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from . import bidi, confusables

# --- category constants -----------------------------------------------------
CAT_BIDI = "bidi"
CAT_ZERO_WIDTH = "zero_width"
CAT_INVISIBLE = "invisible"
CAT_CONTROL = "control"
CAT_HOMOGLYPH = "homoglyph"

# actions
ACT_STRIP = "stripped"
ACT_REPLACE = "replaced"
ACT_NORMALIZE = "normalized"
ACT_FLAG = "flagged"

# Whitespace control characters we consider safe / expected.
_SAFE_WHITESPACE = {0x09, 0x0A, 0x0D}  # tab, LF, CR

# Zero-width and invisible formatting characters. code point -> short label.
ZERO_WIDTH: dict[int, str] = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x200E: "LEFT-TO-RIGHT MARK",  # also bidi; bidi layer takes precedence
    0x200F: "RIGHT-TO-LEFT MARK",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x3164: "HANGUL FILLER",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
}

# Variation selectors VS1..VS16 and the supplementary VS17..VS256.
_VARIATION_SELECTORS = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))
# Tag characters (used in some smuggling / emoji-tag tricks).
_TAG_CHARS = set(range(0xE0000, 0xE0080))


def _codepoint(cp: int) -> str:
    return f"U+{cp:04X}"


def _char_name(ch: str) -> str:
    cp = ord(ch)
    if cp in bidi.BIDI_CONTROLS:
        return bidi.BIDI_CONTROLS[cp]
    if cp in ZERO_WIDTH:
        return ZERO_WIDTH[cp]
    try:
        return unicodedata.name(ch)
    except ValueError:
        return f"<unnamed {_codepoint(cp)}>"


@dataclass(frozen=True)
class UFinding:
    """A single Unicode-security finding at a character offset."""

    offset: int  # character index into the source text
    char: str  # the offending code point (as a 1-char string)
    codepoint: str  # e.g. "U+202E"
    name: str  # Unicode name (or bidi/zero-width label)
    category: str  # one of CAT_*
    unicode_category: str  # Unicode general category, e.g. "Cf", "Cc", "Ll"
    action: str  # ACT_*
    replacement: str  # what the char was replaced with ("" if stripped)
    detail: str = ""  # human-readable note

    @property
    def severity(self) -> str:
        if self.category == CAT_BIDI:
            return "critical"
        if self.category in (CAT_ZERO_WIDTH, CAT_INVISIBLE, CAT_CONTROL):
            return "high"
        if self.category == CAT_HOMOGLYPH:
            return "medium"
        return "low"

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "char": self.char,
            "codepoint": self.codepoint,
            "name": self.name,
            "category": self.category,
            "unicode_category": self.unicode_category,
            "severity": self.severity,
            "action": self.action,
            "replacement": self.replacement,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class UnicodeScanOptions:
    """Toggles for which Unicode-security checks run and whether to strip."""

    bidi: bool = True
    zero_width: bool = True
    invisible: bool = True
    control: bool = True
    homoglyph: bool = True
    # If True, homoglyphs are normalized to their ASCII skeleton; if False they
    # are only flagged (offset + report) and left in place.
    normalize_homoglyphs: bool = True


def _classify_control(cp: int) -> bool:
    """True if ``cp`` is a dangerous control char (C0/C1 minus safe whitespace)."""
    if cp in _SAFE_WHITESPACE:
        return False
    return (0x00 <= cp <= 0x08) or (0x0B <= cp <= 0x1F) or (0x7F <= cp <= 0x9F)


def scan_chars(text: str, options: UnicodeScanOptions | None = None) -> list[UFinding]:
    """Scan ``text`` and return all Unicode-security findings, in offset order.

    Each character is classified at most once, in priority order:
    bidi > zero-width/invisible > control > homoglyph. This keeps a bidi control
    (which is also a format char) from being double-counted.
    """
    opts = options or UnicodeScanOptions()
    findings: list[UFinding] = []

    for i, ch in enumerate(text):
        cp = ord(ch)
        is_bidi_cp = cp in bidi.BIDI_CONTROLS

        # 1. bidi controls (highest priority; Trojan-Source)
        if opts.bidi and is_bidi_cp:
            findings.append(
                UFinding(
                    offset=i,
                    char=ch,
                    codepoint=_codepoint(cp),
                    name=bidi.BIDI_CONTROLS[cp],
                    category=CAT_BIDI,
                    unicode_category=unicodedata.category(ch),
                    action=ACT_STRIP,
                    replacement="",
                    detail="bidirectional control (CVE-2021-42574 Trojan-Source)",
                )
            )
            continue

        # If a code point is a bidi control, it is owned exclusively by the bidi
        # toggle. When bidi scanning is disabled, leave it untouched rather than
        # reclassifying it as zero-width/invisible.
        if is_bidi_cp:
            continue

        # 2. explicit zero-width set
        if opts.zero_width and cp in ZERO_WIDTH:
            findings.append(
                UFinding(
                    offset=i,
                    char=ch,
                    codepoint=_codepoint(cp),
                    name=ZERO_WIDTH[cp],
                    category=CAT_ZERO_WIDTH,
                    unicode_category=unicodedata.category(ch),
                    action=ACT_STRIP,
                    replacement="",
                    detail="zero-width / invisible formatting character",
                )
            )
            continue

        # 3. variation selectors + tag chars (invisible / smuggling)
        if opts.invisible and (cp in _VARIATION_SELECTORS or cp in _TAG_CHARS):
            findings.append(
                UFinding(
                    offset=i,
                    char=ch,
                    codepoint=_codepoint(cp),
                    name=_char_name(ch),
                    category=CAT_INVISIBLE,
                    unicode_category=unicodedata.category(ch),
                    action=ACT_STRIP,
                    replacement="",
                    detail="invisible variation selector / tag character",
                )
            )
            continue

        # 4. control characters (C0/C1 minus safe whitespace)
        if opts.control and _classify_control(cp):
            findings.append(
                UFinding(
                    offset=i,
                    char=ch,
                    codepoint=_codepoint(cp),
                    name=_char_name(ch),
                    category=CAT_CONTROL,
                    unicode_category=unicodedata.category(ch),
                    action=ACT_STRIP,
                    replacement="",
                    detail="C0/C1 control character",
                )
            )
            continue

        # 5. remaining format chars (Cf) not otherwise classified -> invisible
        if opts.invisible and unicodedata.category(ch) == "Cf":
            findings.append(
                UFinding(
                    offset=i,
                    char=ch,
                    codepoint=_codepoint(cp),
                    name=_char_name(ch),
                    category=CAT_INVISIBLE,
                    unicode_category="Cf",
                    action=ACT_STRIP,
                    replacement="",
                    detail="Unicode format character (Cf)",
                )
            )
            continue

        # 6. homoglyph / confusable
        if opts.homoglyph and cp >= 128:
            mapped = confusables.CONFUSABLES.get(ch)
            skel = confusables.skeleton(ch)
            if mapped is not None or (skel != ch and all(ord(c) < 128 for c in skel)):
                repl = mapped if mapped is not None else skel
                findings.append(
                    UFinding(
                        offset=i,
                        char=ch,
                        codepoint=_codepoint(cp),
                        name=_char_name(ch),
                        category=CAT_HOMOGLYPH,
                        unicode_category=unicodedata.category(ch),
                        action=ACT_NORMALIZE if opts.normalize_homoglyphs else ACT_FLAG,
                        replacement=repl,
                        detail=f"confusable with ASCII {repl!r} (UTS #39)",
                    )
                )
                continue

    return findings


def clean_text(text: str, options: UnicodeScanOptions | None = None) -> tuple[str, list[UFinding]]:
    """Return ``(cleaned_text, findings)`` after applying every finding's action.

    Stripped characters are removed; normalized homoglyphs are replaced by their
    ASCII skeleton; flagged homoglyphs are left in place.
    """
    opts = options or UnicodeScanOptions()
    findings = scan_chars(text, opts)
    if not findings:
        return text, findings

    by_offset = {f.offset: f for f in findings}
    out: list[str] = []
    for i, ch in enumerate(text):
        f = by_offset.get(i)
        if f is None:
            out.append(ch)
            continue
        if f.action == ACT_STRIP:
            continue  # drop it
        if f.action in (ACT_REPLACE, ACT_NORMALIZE):
            out.append(f.replacement)
            continue
        # ACT_FLAG -> keep original
        out.append(ch)
    return "".join(out), findings
