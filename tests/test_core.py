"""Tests for the top-level scan/clean API and PII integration."""

from sanitext import clean, scan
from sanitext.core import ScanOptions
from sanitext.unicode_scan import UnicodeScanOptions


def test_clean_removes_zero_width():
    assert clean("hi​there") == "hithere"


def test_scan_result_shape():
    r = scan("plain text")
    assert r.source == "plain text"
    assert r.clean == "plain text"
    assert r.findings == []
    assert not r.dangerous


def test_findings_is_unicode_alias():
    r = scan("x‮y")
    assert r.findings is r.unicode_findings


def test_pii_still_redacted():
    r = scan("email bob@example.com and key sk-ABCDEF0123456789ABCD")
    cats = {f.category for f in r.pii_findings}
    assert "pii" in cats and "secret" in cats
    assert "bob@example.com" not in r.clean
    assert "sk-ABCDEF" not in r.clean


def test_ssn_and_ip_and_phone():
    r = scan("ssn 123-45-6789 ip 10.0.0.1 phone 555-123-4567")
    dets = {f.detector for f in r.pii_findings}
    assert {"ssn", "ipv4", "phone"} <= dets


def test_pii_can_be_disabled():
    opts = ScanOptions(pii=False)
    r = scan("email bob@example.com", opts)
    assert r.pii_findings == []
    assert "bob@example.com" in r.clean


def test_mixed_pii_and_unicode():
    # zero-width space inside an email + a bidi control + a secret
    text = "reach b​ob@example.com ‮ key AKIAIOSFODNN7EXAMPLE"
    r = scan(text)
    assert r.dangerous  # bidi/zero-width present
    ucats = {f.category for f in r.unicode_findings}
    assert "zero_width" in ucats and "bidi" in ucats
    # after zero-width removal the email is contiguous and gets redacted
    assert "example.com" not in r.clean
    assert "[redacted-secret]" in r.clean


def test_counts():
    r = scan("a​b‮c")
    c = r.counts()
    assert c.get("zero_width") == 1
    assert c.get("bidi") == 1


def test_to_dict_roundtrip():
    r = scan("x‮y")
    d = r.to_dict()
    assert d["dangerous"] is True
    assert d["unicode_findings"][0]["codepoint"] == "U+202E"
    assert "clean" in d


def test_toggle_disables_category():
    opts = ScanOptions(unicode=UnicodeScanOptions(bidi=False))
    r = scan("x‮y", opts)
    assert not any(f.category == "bidi" for f in r.findings)
    assert "‮" in r.clean  # left in place because bidi scanning is off


def test_offsets_are_accurate():
    text = "abc‮def"
    r = scan(text)
    f = r.findings[0]
    assert text[f.offset] == "‮"
