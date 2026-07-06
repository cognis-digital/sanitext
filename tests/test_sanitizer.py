import json

from sanitext import sanitize
from sanitext.sanitizer import Lexicon


def test_profanity_is_softened():
    r = sanitize("this is shit and I am pissed")
    assert "shit" not in r.clean.lower()
    assert "pissed" not in r.clean.lower()


def test_secret_is_redacted_and_blocks():
    r = sanitize("my key is sk-ABCDEF0123456789ABCD", provider="generic")
    assert "sk-ABCDEF" not in r.clean
    assert "[redacted-secret]" in r.clean
    assert not r.report.acceptable
    assert "secret" in r.report.blocked_by


def test_clean_text_is_acceptable():
    r = sanitize("Thank you for the update, I will review it today.")
    assert r.report.acceptable
    assert r.report.score == 100


def test_capitalization_preserved():
    r = sanitize("Damn it.")
    assert r.clean[0].isupper()


def test_pii_redacted():
    r = sanitize("contact me at jane@corp.com")
    assert "jane@corp.com" not in r.clean
    assert "[redacted-email]" in r.clean


def test_custom_lexicon_merge(tmp_path):
    p = tmp_path / "lex.json"
    p.write_text(json.dumps({"profanity": {"frobnicate": "process"}}), encoding="utf-8")
    lex = Lexicon.default().merged_with(p)
    r = sanitize("do not frobnicate the data", lexicon=lex)
    assert "frobnicate" not in r.clean
    assert "process" in r.clean


def test_report_roundtrips_to_dict():
    r = sanitize("this is shit")
    d = r.to_dict()
    assert "clean" in d and "report" in d
    assert d["report"]["counts"].get("profanity") == 1


def test_aggressive_drops_blocking_sentence():
    text = "Here is a normal sentence. Leaked sk-ABCDEF0123456789ABCD now."
    r = sanitize(text, aggressive=True)
    assert "redacted" not in r.clean  # whole sentence dropped, not just token
    assert "normal sentence" in r.clean
