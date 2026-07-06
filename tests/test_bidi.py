"""Tests for bidi / Trojan-Source detection (CVE-2021-42574)."""

from sanitext import bidi, scan
from sanitext.unicode_scan import CAT_BIDI

# Every bidi formatting control character and its code point.
ALL_BIDI = {
    0x202A: "LRE",
    0x202B: "RLE",
    0x202C: "PDF",
    0x202D: "LRO",
    0x202E: "RLO",
    0x2066: "LRI",
    0x2067: "RLI",
    0x2068: "FSI",
    0x2069: "PDI",
    0x200E: "LRM",
    0x200F: "RLM",
    0x061C: "ALM",
}


def test_each_bidi_control_detected_and_stripped():
    for cp in ALL_BIDI:
        text = f"a{chr(cp)}b"
        r = scan(text)
        cats = [f.category for f in r.findings]
        assert CAT_BIDI in cats, f"{cp:#06x} not flagged as bidi"
        assert chr(cp) not in r.clean, f"{cp:#06x} not stripped"
        assert r.clean == "ab"
        assert r.dangerous


def test_bidi_finding_metadata():
    r = scan("x‮y")
    f = next(f for f in r.findings if f.category == CAT_BIDI)
    assert f.codepoint == "U+202E"
    assert f.name == "RIGHT-TO-LEFT OVERRIDE"
    assert f.unicode_category == "Cf"
    assert f.offset == 1
    assert "CVE-2021-42574" in f.detail


def test_trojan_source_reordered_comment_sample():
    # Classic Trojan-Source style: an RLO reorders a comment so the rendered
    # order differs from the logical byte order that a compiler sees.
    src = 'access_level = "user‮ ⁦// Check if admin⁩ ⁦"'
    r = scan(src)
    bidi_findings = [f for f in r.findings if f.category == CAT_BIDI]
    assert len(bidi_findings) >= 3  # RLO + two isolates
    assert r.dangerous
    # After cleaning, no bidi controls remain.
    assert not bidi.contains_bidi(r.clean)


def test_helpers():
    assert bidi.is_bidi_control("‮")
    assert not bidi.is_bidi_control("a")
    assert bidi.contains_bidi("a⁦b")
    assert bidi.strip_bidi("a⁦b⁩") == "ab"
    assert bidi.find_bidi("a‮b") == [(1, "‮")]


def test_unbalanced_bidi_detection():
    assert bidi.has_unbalanced_bidi("open ‮ never closed")
    assert not bidi.has_unbalanced_bidi("balanced ‪ text ‬ here")
    assert bidi.has_unbalanced_bidi("⁩ stray pop")


def test_name_fallback():
    assert bidi.name("‮") == "RIGHT-TO-LEFT OVERRIDE"
    assert bidi.name("a") == "LATIN SMALL LETTER A"
