from sanitext import detectors


def cats(text):
    return {f.category for f in detectors.detect(text)}


def test_detects_email_and_secret():
    found = cats("reach me at bob@example.com key sk-ABCDEF0123456789ABCD")
    assert "pii" in found
    assert "secret" in found


def test_detects_profanity():
    found = detectors.detect("this is shit")
    assert any(f.category == "profanity" and f.matched == "shit" for f in found)


def test_no_overlap():
    fs = detectors.detect("email bob@example.com and AKIAIOSFODNN7EXAMPLE here")
    spans = sorted((f.start, f.end) for f in fs)
    for (s1, e1), (s2, e2) in zip(spans, spans[1:]):
        assert e1 <= s2  # non-overlapping, ordered


def test_clean_text_has_no_findings():
    assert detectors.detect("This is a perfectly normal sentence.") == []


def test_ssn_is_critical():
    fs = detectors.detect("ssn 123-45-6789")
    assert any(f.category == "pii" and f.severity == "critical" for f in fs)
