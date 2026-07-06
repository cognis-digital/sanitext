"""CLI tests: exit codes, stdin, output formats, backward compatibility."""

import json
import subprocess
import sys

from sanitext.cli import main

BIDI = "if x != ‮egelivirp‬) {"


def run(args, stdin=None):
    """Invoke the CLI in-process, capturing exit code."""
    return main(args)


# --- exit codes -------------------------------------------------------------

def test_scan_dangerous_exits_1(capsys):
    code = run(["scan", "-t", BIDI])
    assert code == 1
    out = capsys.readouterr().out
    assert "DANGEROUS" in out


def test_scan_clean_exits_0(capsys):
    code = run(["scan", "-t", "perfectly normal"])
    assert code == 0
    assert "no dangerous" in capsys.readouterr().out


def test_clean_exits_0_and_emits_clean(capsys):
    code = run(["clean", "-t", "hi​there"])
    assert code == 0
    assert capsys.readouterr().out.strip() == "hithere"


def test_clean_output_rescans_clean(capsys):
    run(["clean", "-t", BIDI])
    cleaned = capsys.readouterr().out.strip()
    code = run(["scan", "-t", cleaned])
    assert code == 0


# --- output formats ---------------------------------------------------------

def test_scan_json(capsys):
    run(["scan", "-t", "x‮y", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["dangerous"] is True
    assert data["unicode_findings"][0]["codepoint"] == "U+202E"


def test_scan_sarif(capsys):
    run(["scan", "-t", "x‮y", "--sarif"])
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"


def test_clean_json(capsys):
    run(["clean", "-t", "hi​there", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["clean"] == "hithere"


# --- toggles ----------------------------------------------------------------

def test_no_bidi_toggle(capsys):
    code = run(["scan", "-t", "x‮y", "--no-bidi"])
    assert code == 0  # bidi ignored -> not dangerous


def test_no_pii_leaves_email(capsys):
    run(["clean", "-t", "mail bob@example.com", "--no-pii"])
    assert "bob@example.com" in capsys.readouterr().out


def test_flag_only_homoglyph_keeps_char(capsys):
    run(["clean", "-t", "раypal", "--flag-only-homoglyphs"])
    assert "р" in capsys.readouterr().out


# --- file + stdin -----------------------------------------------------------

def test_scan_file(tmp_path, capsys):
    p = tmp_path / "in.txt"
    p.write_text(BIDI, encoding="utf-8")
    code = run(["scan", str(p)])
    assert code == 1


def test_clean_to_out_file(tmp_path):
    p = tmp_path / "out.txt"
    run(["clean", "-t", "hi​there", "-o", str(p)])
    assert p.read_text(encoding="utf-8").strip() == "hithere"


def test_stdin_scan(tmp_path):
    # Exercise the real process for stdin handling.
    proc = subprocess.run(
        [sys.executable, "-m", "sanitext", "scan", "-"],
        input="x‮y".encode("utf-8"),
        capture_output=True,
    )
    assert proc.returncode == 1


def test_version():
    proc = subprocess.run(
        [sys.executable, "-m", "sanitext", "--version"], capture_output=True, text=True
    )
    assert "sanitext" in proc.stdout


# --- backward compatibility -------------------------------------------------

def test_legacy_bare_normalize(capsys):
    code = run(["-t", "this is shit"])
    assert code == 0
    assert "junk" in capsys.readouterr().out


def test_explicit_normalize_check(capsys):
    code = run(["normalize", "-t", "clean text", "--check"])
    assert code == 0
