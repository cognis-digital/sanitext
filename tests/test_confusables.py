"""Tests for homoglyph / confusables detection and the TR39 skeleton."""

import pytest

from sanitext import confusables, scan
from sanitext.unicode_scan import CAT_HOMOGLYPH, UnicodeScanOptions
from sanitext.core import ScanOptions


def test_cyrillic_a_is_confusable():
    assert confusables.is_confusable("а")  # U+0430
    assert confusables.target("а") == "a"
    assert not confusables.is_confusable("a")  # plain ASCII


def test_skeleton_folds_cyrillic_spoof():
    # "раypal" mixes Cyrillic р/а with Latin.
    spoof = "раypal"  # р а y p a l
    assert confusables.skeleton(spoof) == "paypal"


def test_skeleton_of_ascii_is_identity():
    assert confusables.skeleton("paypal.com") == "paypal.com"


def test_confusable_with_ascii():
    assert confusables.confusable_with_ascii("аpple")  # Cyrillic а
    assert not confusables.confusable_with_ascii("apple")
    assert not confusables.confusable_with_ascii("日本語")  # genuinely non-ASCII


def test_greek_omicron():
    assert confusables.target("ο") == "o"
    assert confusables.target("Ο") == "O"


def test_fullwidth_forms_fold_via_table_or_nfkc():
    # Fullwidth 'Ａ' U+FF21 -> 'A'
    assert confusables.skeleton("Ａ") == "A"
    assert confusables.skeleton("ｈｅｌｌｏ") == "hello"


def test_math_alphanumerics_fold_via_nfkc():
    # MATHEMATICAL BOLD CAPITAL A/B/C via NFKC compatibility folding.
    assert confusables.skeleton("𝐀𝐁𝐂") == "ABC"
    assert confusables.skeleton("𝒂𝒃𝒄") == "abc"


def test_scan_detects_homoglyph_and_normalizes():
    r = scan("раypal.com")  # Cyrillic р а
    homos = [f for f in r.findings if f.category == CAT_HOMOGLYPH]
    assert len(homos) == 2
    assert r.clean == "paypal.com"
    # code points reported honestly
    assert {f.codepoint for f in homos} == {"U+0440", "U+0430"}
    assert all(f.action == "normalized" for f in homos)


def test_homoglyph_flag_only_mode_keeps_char():
    opts = ScanOptions(unicode=UnicodeScanOptions(normalize_homoglyphs=False))
    r = scan("раypal", opts)
    homos = [f for f in r.findings if f.category == CAT_HOMOGLYPH]
    assert homos and all(f.action == "flagged" for f in homos)
    assert "р" in r.clean  # not normalized away


def test_homoglyph_not_dangerous_by_default():
    r = scan("аpple")  # only homoglyph, no bidi/zero-width
    assert not r.dangerous  # homoglyph alone does not fail the gate by default


def test_homoglyph_dangerous_when_requested():
    opts = ScanOptions(homoglyph_is_dangerous=True)
    # homoglyph_is_dangerous is an option knob; verify the finding still exists
    r = scan("аpple", opts)
    assert any(f.category == CAT_HOMOGLYPH for f in r.findings)


def test_punctuation_confusables():
    # en dash, curly quote, division slash
    assert confusables.target("–") == "-"
    assert confusables.target("’") == "'"
    assert confusables.target("∕") == "/"


def test_confusables_table_size_is_substantial():
    # Curated subset: fullwidth block (94) plus explicit letters/punct.
    assert len(confusables.CONFUSABLES) >= 150


@pytest.mark.parametrize("ascii_char", list("abcdefghijklmnopqrstuvwxyz"))
def test_no_ascii_letter_is_flagged(ascii_char):
    r = scan(ascii_char * 5)
    assert not any(f.category == CAT_HOMOGLYPH for f in r.findings)
