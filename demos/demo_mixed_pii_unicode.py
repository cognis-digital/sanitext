"""Demo: a document mixing PII/secrets with Unicode abuse.

A single pasted blob carries a zero-width space inside an email, a bidi control,
a fake AWS key, and an SSN. sanitext scrubs the invisible/bidi layer AND the
PII/secret layer in one pass. The secret is a fake AKIA... value -- never a
real credential.
"""

from sanitext import scan
from sanitext.report import render_scan

DOC = (
    "Contact on-call at b​ob@example.com or 555-123-4567.\n"
    "SSN 123-45-6789. Rotate leaked key AKIAFAKEEXAMPLE12345 now.‮"
)


def main() -> int:
    print("== Mixed PII + Unicode document ==")
    result = scan(DOC)
    print(render_scan(result))
    ucats = {f.category for f in result.unicode_findings}
    pcats = {f.category for f in result.pii_findings}
    assert "zero_width" in ucats and "bidi" in ucats
    assert "pii" in pcats and "secret" in pcats
    assert "example.com" not in result.clean
    assert "AKIAFAKE" not in result.clean
    assert "123-45-6789" not in result.clean
    print("\nOK: invisible/bidi stripped and PII/secret redacted in one pass.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
