# sanitext

Turn raw, uncensored text into **provider-acceptable** text — clean, professional
output you can safely paste into **Claude**, **ChatGPT**, or any public channel.

Point it at the raw output of an uncensored local model (or any unfiltered text)
and it strips profanity, slurs, hateful/harassing tone, personal data, and leaked
secrets, then hands you something a content filter — and a human reader — will
accept.

> **Scope.** sanitext is a *compliance normalizer*, not a filter-evasion tool. It
> makes text genuinely acceptable (removes the disallowed content); it does **not**
> try to sneak prohibited content past a provider's safety systems.

## Why

Local uncensored models are great for drafting, but their output often carries
expletives, hostile phrasing, or accidentally-pasted secrets that get a request
refused — or that you simply don't want to publish. sanitext is the cleanup pass
between "raw draft" and "ready to send."

## Two engines

| Engine | Flag | What it does | Network |
|---|---|---|---|
| **Rules** | `--mode rules` (default) | Deterministic detect → redact/substitute. Profanity softened, slurs/secrets/PII redacted. | none |
| **LLM** | `--mode llm` | A model re-authors the text into fluent, clean prose preserving meaning. | yes |

LLM backends: `local` (Ollama-compatible, e.g. your local fleet — default),
`anthropic` (Claude, `claude-opus-4-8`), `openai` (ChatGPT).

## Install

```bash
pip install -e .                 # core (rules mode, local LLM backend)
pip install -e ".[anthropic]"    # + Claude backend
pip install -e ".[openai]"       # + ChatGPT backend
```

Rules mode and the `local` backend need **no third-party dependencies**.

## Usage

```bash
# Clean a file with offline rules
sanitext examples/sample_in.txt

# Pipe from your uncensored model straight into a clean result
cog4 cc "draft the incident note" | sanitext --provider claude

# Just score it — exit 1 if it wouldn't be acceptable (good for CI / hooks)
sanitext examples/sample_in.txt --check --provider openai

# Fluent rewrite via your local fleet
sanitext examples/sample_in.txt --mode llm --backend local --model omnicoder

# Fluent rewrite via Claude
ANTHROPIC_API_KEY=... sanitext input.txt --mode llm --backend anthropic

# Full machine-readable output
sanitext input.txt --json
```

### Example

Input (`examples/sample_in.txt`):

> Holy shit this damn API is fucking broken again. The idiot who wrote it left my
> key sk-ABCDEF0123456789ABCD right in the logs, and you can reach the on-call
> moron at jane@corp.com or 555-123-4567. Whoever shipped this should just shut up
> and fix it.

`sanitext examples/sample_in.txt --report` →

> Holy junk this darn API is very broken again. The idiot who wrote it left my key
> [redacted-secret] right in the logs, and you can reach the on-call moron at
> [redacted-email] or [redacted-phone]. Whoever shipped this should please hold on
> and fix it.

```
[generic] NOT ACCEPTABLE  score=0/100 (threshold 80)
  blocked by: secret
  findings: hostility=1, pii=2, profanity=3, secret=1
```

The secret is redacted *and* flagged as blocking — so you know to scrub it at the
source, not just in the copy. (Use `--mode llm` for fluent rephrasing instead of
token substitution.)

## Library

```python
from sanitext import sanitize, rewrite, get_policy

result = sanitize(raw_text, provider="claude")
print(result.clean)              # cleaned text
print(result.report.summary())   # score + findings
print(result.report.acceptable)  # bool

# LLM re-authoring
clean = rewrite(raw_text, policy=get_policy("openai"), backend="local", model="omnicoder")
```

## Provider profiles

`generic`, `claude`, `openai` — each defines blocking categories (secrets, slurs),
per-category penalty weights, and a pass threshold. They share the same baseline;
tune weights/threshold per destination in `sanitext/policies.py`.

## Custom lexicons

Built-in lists are intentionally small and ship **no slurs in source**. Supply
your own with `--lexicon lex.json`:

```json
{
  "profanity": { "frobnicate": "process" },
  "slurs": ["term-to-redact"],
  "softeners": { "this is garbage": "this needs work" }
}
```

Entries merge over (and override) the built-ins. `slurs` are always redacted,
never softened.

## Detected categories

`profanity` (softened) · `hostility` (softened) · `slur` (redacted) ·
`pii` — email, phone, SSN, IPv4 (redacted) · `secret` — OpenAI/Anthropic/AWS/
GitHub/Slack keys, bearer tokens (redacted, blocking).

## Test

```bash
pytest
```

## License

MIT
