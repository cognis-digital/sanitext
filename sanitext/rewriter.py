"""Optional LLM-backed rewriting (secondary to the Unicode-security core).

Where the rule-based normalizer redacts/substitutes tokens, the rewriter asks a
model to *re-author* text into clean, neutral prose while preserving meaning.
This is an optional convenience layer -- the headline product is the offline
Unicode-security scanner, which needs no network and no model.

Backends (provider-neutral):
    local   -> a local, Ollama-compatible server (default http://localhost:11434).
               No API key. Standard-library HTTP only.
    openai  -> any OpenAI-compatible Chat Completions endpoint (hosted or local),
               configured via OPENAI_API_KEY and optionally OPENAI_BASE_URL.

The rewriter never tries to defeat a provider's safety system; its job is the
opposite -- produce text that is genuinely clean.
"""

from __future__ import annotations

import json
import os
import urllib.request

from .policies import Policy

_SYSTEM_TEMPLATE = (
    "You are a text normalizer. You are given raw, possibly uncensored text. "
    "Rewrite it so it is neutral and professional for {description}.\n"
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
    """Re-author ``text`` via a local or OpenAI-compatible endpoint.

    ``backend`` is ``"local"`` (Ollama-compatible, default) or ``"openai"`` (any
    OpenAI-compatible Chat Completions endpoint, hosted or self-hosted).
    """
    system = _system_prompt(policy)
    if backend == "local":
        return _rewrite_local(text, system, model or "llama3.1", base_url, timeout)
    if backend == "openai":
        return _rewrite_openai(text, system, model or "gpt-4o-mini", base_url)
    raise ValueError(f"unknown backend {backend!r}; choose local | openai")


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


def _rewrite_openai(text, system, model, base_url=None) -> str:
    """Use any OpenAI-compatible Chat Completions endpoint.

    Reads OPENAI_API_KEY (and optional OPENAI_BASE_URL) from the environment, so
    it works against a hosted provider or a local OpenAI-compatible server.
    """
    try:
        from openai import OpenAI
    except ImportError as e:
        raise RuntimeError("openai SDK not installed: pip install 'sanitext[openai]'") from e
    kwargs = {}
    env_base = base_url or os.environ.get("OPENAI_BASE_URL")
    if env_base:
        kwargs["base_url"] = env_base
    client = OpenAI(**kwargs)  # reads OPENAI_API_KEY from env
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": text},
        ],
    )
    return (resp.choices[0].message.content or "").strip()
