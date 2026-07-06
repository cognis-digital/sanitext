"""Cleaning cleaned text must yield no further findings (idempotence)."""

import pytest

from sanitext import clean, scan

SAMPLES = [
    "hi​there",  # zero-width
    "if x != ‮egelivirp‬) {",  # bidi
    "раypal.com",  # homoglyph
    "bad\x07bell\x00null",  # control chars
    "email bob@example.com key sk-ABCDEF0123456789ABCD",  # pii/secret
    "﻿BOM header​ mixed‍ ‮ AKIAIOSFODNN7EXAMPLE",  # everything
    "normal clean text with tabs\tand\nnewlines",  # should be unchanged
]


@pytest.mark.parametrize("text", SAMPLES)
def test_clean_is_idempotent(text):
    once = clean(text)
    twice = clean(once)
    assert once == twice


@pytest.mark.parametrize("text", SAMPLES)
def test_cleaned_text_has_no_dangerous_findings(text):
    cleaned = clean(text)
    assert not scan(cleaned).dangerous


@pytest.mark.parametrize("text", SAMPLES)
def test_cleaned_text_has_no_unicode_findings(text):
    cleaned = clean(text)
    r = scan(cleaned)
    # No bidi/zero-width/control/homoglyph should survive a clean pass.
    assert r.unicode_findings == []
