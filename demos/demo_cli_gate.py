"""Demo: using `sanitext scan` as a CI gate (nonzero exit on dangerous input).

Simulates the CLI end-to-end in-process: scanning a bidi sample exits 1, and
scanning the cleaned output exits 0 -- the pattern you would wire into a
pre-commit hook or CI step to reject invisible-character smuggling.
"""

import io
import sys
from contextlib import redirect_stdout

from sanitext.cli import main

BIDI = "if x != ‮egelivirp‬) {"


def _run(args) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(args)
    return code, buf.getvalue()


def main_demo() -> int:
    print("== CLI gate ==")
    code, out = _run(["scan", "-t", BIDI])
    print(f"scan dangerous input -> exit {code}")
    assert code == 1

    code_clean, cleaned = _run(["clean", "-t", BIDI])
    cleaned = cleaned.strip()
    print(f"clean produced: {cleaned!r}")

    code_rescan, _ = _run(["scan", "-t", cleaned])
    print(f"rescan cleaned input -> exit {code_rescan}")
    assert code_rescan == 0
    print("\nOK: gate rejects dangerous text, accepts cleaned text.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_demo())
