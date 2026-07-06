"""Tests for SARIF 2.1.0 export."""

from sanitext import scan
from sanitext.sarif import SARIF_VERSION, to_sarif


def test_sarif_version_and_schema():
    s = to_sarif(scan("x‮y"))
    assert s["version"] == SARIF_VERSION == "2.1.0"
    assert s["$schema"].endswith("sarif-schema-2.1.0.json")


def test_sarif_has_runs_and_tool():
    s = to_sarif(scan("x‮y"))
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "sanitext"
    assert run["results"]


def test_sarif_result_fields():
    s = to_sarif(scan("x‮y"), artifact_uri="demo.txt")
    res = s["runs"][0]["results"][0]
    assert res["ruleId"] == "sanitext/bidi-control"
    assert res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "demo.txt"
    assert loc["region"]["charOffset"] == 1
    assert res["properties"]["codepoint"] == "U+202E"


def test_sarif_line_column_translation():
    s = to_sarif(scan("line1\nabc‮def"))
    region = s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 2
    assert region["startColumn"] == 4  # 1-based column of the bidi char on line 2


def test_sarif_rules_deduplicated():
    s = to_sarif(scan("a‮b​c"))  # bidi + zero-width -> two distinct rules
    rules = s["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    assert "sanitext/bidi-control" in ids
    assert "sanitext/zero-width" in ids


def test_sarif_empty_when_clean():
    s = to_sarif(scan("perfectly normal"))
    assert s["runs"][0]["results"] == []
