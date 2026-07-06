"""Tests for the human-readable before/after scan report."""

from sanitext import scan
from sanitext.report import render_scan


def test_report_clean_text():
    out = render_scan(scan("perfectly normal text"))
    assert "no dangerous characters" in out


def test_report_lists_findings_with_metadata():
    out = render_scan(scan("x‮y"))
    assert "U+202E" in out
    assert "RIGHT-TO-LEFT OVERRIDE" in out
    assert "bidi" in out
    assert "DANGEROUS" in out


def test_report_before_after_section():
    out = render_scan(scan("hi​there"))
    assert "Before/after:" in out
    assert "before:" in out
    assert "after :" in out


def test_report_shows_pii():
    out = render_scan(scan("mail bob@example.com"))
    assert "PII / secret findings" in out
    assert "email" in out


def test_report_invisible_chars_rendered_as_placeholder():
    # The raw invisible char must not appear literally; a placeholder stands in.
    out = render_scan(scan("a\x00b"))
    assert "\x00" not in out
    assert "control" in out


def test_report_counts_line():
    out = render_scan(scan("a‮b​c"))
    assert "bidi=1" in out
    assert "zero_width=1" in out
