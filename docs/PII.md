# PII & secret redaction (optional layer)

The Unicode-security scanner is the headline product; PII/secret redaction is an
**optional layer** that runs on the Unicode-cleaned text so offsets and matches
line up with what a downstream consumer actually receives. Disable it with
`--no-pii` or `ScanOptions(pii=False)`.

## What it detects

| Detector | Pattern (shape) | Action |
|---|---|---|
| `email` | `user@host.tld` | `[redacted-email]` |
| `phone` | North-American style, optional `+1`, separators | `[redacted-phone]` |
| `ssn` | `NNN-NN-NNNN` | `[redacted-ssn]` |
| `ipv4` | dotted quad, octets 0–255 | `[redacted-ip]` |
| `openai_key` | `sk-…` | `[redacted-secret]` |
| `anthropic_key` | `sk-ant-…` | `[redacted-secret]` |
| `aws_access_key` | `AKIA` + 16 alnum | `[redacted-secret]` |
| `github_token` | `ghp_`/`gho_`/… + ≥20 | `[redacted-secret]` |
| `slack_token` | `xox[baprs]-…` | `[redacted-secret]` |
| `generic_bearer` | `Bearer <token>` | `[redacted-secret]` |

Overlapping matches resolve to the highest-severity, then longest, then earliest
span (see `detectors.detect`). `secret` and `pii` findings are surfaced in
`ScanResult.pii_findings` and in JSON/report output.

## Why order matters with Unicode

A zero-width space inside an email (`b​ob@example.com`) would defeat a naive
email regex. sanitext strips the invisible characters **first**, then runs PII
detection on the cleaned text, so the smuggled-apart email is caught and
redacted. See `tests/test_core.py::test_mixed_pii_and_unicode`.

## Honest limitations

- Detection is **regex-based** and pattern-matchable only. It will miss unusual
  formats, obfuscated secrets, and non-US PII conventions.
- The credential shapes match **prefixes/lengths**, not validity — a
  `[redacted-secret]` may be a false positive on a similar-looking string.
- This is **not** a full DLP solution. Treat it as a useful pre-flight scrub,
  not a compliance guarantee.

## Example

```console
$ sanitext clean -t "mail bob@example.com key AKIAFAKEEXAMPLE12345"
mail [redacted-email] key [redacted-secret]
```

(The `AKIAFAKE…` value is a deliberately fake example, never a real credential.)
