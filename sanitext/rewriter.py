"""LLM-backed rewriting.

Where the rule-based sanitizer redacts/substitutes tokens, the rewriter asks a
model to *re-author* the text into clean, professional, provider-acceptable
prose while preserving meaning. Use it when token-level scrubbing reads badly
and you want fluent output.

Backends:
    local      -> an Ollama-compatible server (default: http://localhost:11434),
                  e.g. your local fleet. No API key. stdlib HTTP only.
    anthropic  -> Claude via the official `anthropic` SDK (model claude-opus-4-8).
    openai     -> ChatGPT via the official `openai` SDK.

The rewriter never tries to defeat a provider's safety system. Its job is the
opposite: produce text the provider will accept because it is genuinely clean.
"""

from __future__ import annotations

import json
import os
import urllib.request

from .policies import Policy

_SYSTEM_TEMPLATE = (
    "You are a text compliance normalizer. You are given raw, possibly uncensored "
    "text. Rewrite it so it is acceptable to post to {description}.\n"
    "Rules:\n"
    "- Preserve the author's meaning, facts, and intent.\n"
    "- Remove profanity, slurs, hateful or harassing language, and gratuitous "
    "explicit content; rephrase the underlying point in neutral, professional language.\n"
    "- Redact personal data and secrets (emails, phone numbers, SSNs, API keys, "
    "tokens) as [redacted].\n"
    "- Do NOT add disclaimers, apologies, or commentary about the rewrite.\n"
    "- Output ONLY the rewritten text, nothing else."
)


def _system_prompt(policy: Policy) -> str:
    return _SYSTEM_TEMPLATE.format(description=policy.description or policy.name)


def rewrite(text: str, *, policy: Policy, backend: str = "local", model: str | None = None,
            base_url: str | None = None, timeout: float = 120.0) -> str:
    system = _system_prompt(policy)
    if backend == "local":
        return _rewrite_local(text, system, model or "llama3.1", base_url, timeout)
    if backend == "anthropic":
        return _rewrite_anthropic(text, system, model or "claude-opus-4-8")
    if backend == "openai":
        return _rewrite_openai(text, system, model or "gpt-4o-mini")
    raise ValueError(f"unknown backend {backend!r}; choose local | anthropic | openai")


def _rewrite_local(text, system, model, base_url, timeout) -> str:
    url = (base_url or os.environ.get("SANITEXT_OLLAMA_URL") or "http://localhost:11434").rstrip("/")
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": text},
        ],
    }
    req = urllib.request.Request(
        url + "/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return (data.get("message", {}).get("content") or "").strip()


def _rewrite_anthropic(text, system, model) -> str:
    try:
        import anthropic
    except ImportError as e:
        raise RuntimeError("anthropic SDK not installed: pip install anthropic") from e
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
    resp = client.messages.create(
        model=model,
        max_tokens=16000,
        system=system,
        messages=[{"role": "user", "content": text}],
    )
    return "".join(b.text for b in resp.content if b.type == "text").strip()


def _rewrite_openai(text, system, model) -> str:
    try:
        from openai import OpenAI
    except ImportError as e:
        raise RuntimeError("openai SDK not installed: pip install openai") from e
    client = OpenAI()  # reads OPENAI_API_KEY from env
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": text},
        ],
    )
    return (resp.choices[0].message.content or "").strip()
