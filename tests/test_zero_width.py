"""Tests for zero-width / invisible / control character detection."""

import pytest

from sanitext import scan
from sanitext.unicode_scan import (
    CAT_CONTROL,
    CAT_INVISIBLE,
    CAT_ZERO_WIDTH,
    ZERO_WIDTH,
)

ZERO_WIDTH_CODEPOINTS = [
    0x200B,  # ZWSP
    0x200C,  # ZWNJ
    0x200D,  # ZWJ
    0x2060,  # WORD JOINER
    0xFEFF,  # BOM / ZWNBSP
    0x00AD,  # SOFT HYPHEN
    0x180E,  # MONGOLIAN VOWEL SEPARATOR
    0x2061,  # FUNCTION APPLICATION
    0x2062,  # INVISIBLE TIMES
    0x2063,  # INVISIBLE SEPARATOR
    0x2064,  # INVISIBLE PLUS
    0x3164,  # HANGUL FILLER
]


@pytest.mark.parametrize("cp", ZERO_WIDTH_CODEPOINTS)
def test_each_zero_width_stripped(cp):
    text = f"a{chr(cp)}b"
    r = scan(text)
    assert r.clean == "ab", f"{cp:#06x} not stripped"
    assert r.dangerous
    assert any(f.category in (CAT_ZERO_WIDTH, CAT_INVISIBLE) for f in r.findings)


def test_zero_width_metadata():
    r = scan("hi​there")
    f = next(f for f in r.findings if f.category == CAT_ZERO_WIDTH)
    assert f.codepoint == "U+200B"
    assert f.name == "ZERO WIDTH SPACE"
    assert f.offset == 2


def test_zero_width_table_nonempty():
    assert 0x200B in ZERO_WIDTH
    assert len(ZERO_WIDTH) >= 12


def test_variation_selector_stripped():
    r = scan("A️B")  # VS16
    assert r.clean == "AB"
    assert any(f.category == CAT_INVISIBLE for f in r.findings)


def test_supplementary_variation_selector():
    r = scan("A\U000e0100B")  # VS17
    assert r.clean == "AB"


def test_tag_character_stripped():
    r = scan("A\U000e0041B")  # TAG LATIN CAPITAL A
    assert r.clean == "AB"
    assert any(f.category == CAT_INVISIBLE for f in r.findings)


@pytest.mark.parametrize("cp", [0x00, 0x01, 0x07, 0x08, 0x0B, 0x0C, 0x1B, 0x7F, 0x85, 0x9F])
def test_control_chars_stripped(cp):
    r = scan(f"a{chr(cp)}b")
    assert r.clean == "ab", f"control {cp:#04x} not stripped"
    assert any(f.category == CAT_CONTROL for f in r.findings)


@pytest.mark.parametrize("ch", ["\t", "\n", "\r"])
def test_safe_whitespace_preserved(ch):
    r = scan(f"a{ch}b")
    assert r.clean == f"a{ch}b"
    assert not r.dangerous


def test_multiple_invisible_chars_all_found():
    text = "﻿header​ body‍ end­"
    r = scan(text)
    assert r.clean == "header body end"
    assert len([f for f in r.findings if f.category in (CAT_ZERO_WIDTH, CAT_INVISIBLE)]) == 4
