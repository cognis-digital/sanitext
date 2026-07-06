# Trojan Source & bidi controls (CVE-2021-42574)

## The attack

Unicode's bidirectional algorithm (UAX #9) uses invisible control characters to
override or isolate the display direction of text so that right-to-left scripts
(Arabic, Hebrew) render correctly alongside left-to-right text. These same
controls, placed inside **source code, comments, strings, commit messages, or
chat**, let an attacker make the *rendered* order of characters differ from the
*logical* (byte) order that a compiler or interpreter actually processes.

This is the **Trojan Source** attack, published by Nicholas Boucher and Ross
Anderson (2021) and assigned **CVE-2021-42574**
(https://trojansource.codes/). The core insight: code review is done on
*rendered* text, but compilation happens on *logical* bytes. If those disagree,
a reviewer can approve code that does something different from what they see.

A canonical example — an early-return smuggled into what looks like a comment:

```text
rendered (what a reviewer sees):   if (isAdmin) { /* begin admins only */
logical  (what compiles):          if (isAdmin) { begin admins only */ }
```

The reordering is produced by invisible RIGHT-TO-LEFT OVERRIDE / isolate
characters — nothing visible on screen hints that anything is wrong.

## The dangerous characters

| Code point | Name | Class |
|---|---|---|
| U+202A | LEFT-TO-RIGHT EMBEDDING (LRE) | embedding |
| U+202B | RIGHT-TO-LEFT EMBEDDING (RLE) | embedding |
| U+202C | POP DIRECTIONAL FORMATTING (PDF) | pop |
| U+202D | LEFT-TO-RIGHT OVERRIDE (LRO) | override |
| U+202E | RIGHT-TO-LEFT OVERRIDE (RLO) | override |
| U+2066 | LEFT-TO-RIGHT ISOLATE (LRI) | isolate |
| U+2067 | RIGHT-TO-LEFT ISOLATE (RLI) | isolate |
| U+2068 | FIRST STRONG ISOLATE (FSI) | isolate |
| U+2069 | POP DIRECTIONAL ISOLATE (PDI) | pop |
| U+200E | LEFT-TO-RIGHT MARK (LRM) | mark |
| U+200F | RIGHT-TO-LEFT MARK (RLM) | mark |
| U+061C | ARABIC LETTER MARK (ALM) | mark |

## How sanitext handles them

sanitext treats **every** bidi formatting character as dangerous by default:

- **Detects** each one with its offset, code point, Unicode name, and general
  category (`Cf`). Severity is `critical`.
- **Strips** all of them in `clean` output.
- **Flags** the input as `dangerous`, so `sanitext scan` exits nonzero — a CI
  gate can reject any diff, commit message, or file containing bidi controls.
- Provides `bidi.has_unbalanced_bidi()` to detect the specific unbalanced
  embedding/override/isolate pattern that is a hallmark of the attack (a scope
  opened inside a comment or string that spills onto following code).

### Why strip rather than "balance"?

Legitimate right-to-left text renders correctly from the base paragraph
direction in the overwhelming majority of cases without embedded overrides.
Embedded bidi controls in code and identifiers have no legitimate use and a
clear abuse case, so the safe default is removal. If you need to preserve them
for genuine RTL prose, disable the check with `--no-bidi` (you then lose the
Trojan-Source protection).

## Try it

```bash
python demos/demo_trojan_source.py
sanitext scan -t "if x != ‮egelivirp‬) {"   # exits 1
```

## References

- CVE-2021-42574
- Boucher, N. & Anderson, R. *Trojan Source: Invisible Vulnerabilities* (2021),
  https://trojansource.codes/
- Unicode UAX #9, *Unicode Bidirectional Algorithm*
- Unicode UTS #39, *Unicode Security Mechanisms*
