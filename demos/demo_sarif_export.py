"""Demo: export findings as SARIF 2.1.0 for CI / code-scanning dashboards.

SARIF lets sanitext act like a code scanner: pipe the JSON into GitHub code
scanning or a SARIF viewer and each bidi/invisible/homoglyph finding becomes an
annotation at the exact line and column.
"""

import json

from sanitext import scan
from sanitext.sarif import to_sarif

SOURCE = 'name = "user"\nif level != "admin‮ // ok⁩" {\ncall(раypal)'


def main() -> int:
    print("== SARIF 2.1.0 export ==")
    result = scan(SOURCE)
    sarif = to_sarif(result, artifact_uri="app.py")
    print(json.dumps(sarif, indent=2, ensure_ascii=False))
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert results, "expected SARIF results"
    rule_ids = {r["ruleId"] for r in results}
    assert "sanitext/bidi-control" in rule_ids
    print(f"\nOK: {len(results)} SARIF result(s), rules: {sorted(rule_ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
