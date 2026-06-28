"""Built-in lexicons used by the rule-based sanitizer.

These lists are intentionally small and conservative. The goal is to clean raw
model output (profanity, casual hostility) into professional, provider-acceptable
prose -- not to maintain an exhaustive dictionary of every offensive word.

For domain- or language-specific terms (including slur lists, which are
deliberately NOT shipped in source here), supply your own lexicon file with
``--lexicon path.json``. The file is a JSON object::

    {
      "profanity": {"badword": "replacement", ...},
      "slurs": ["term1", "term2"],          # redacted, never softened
      "softeners": {"phrase": "replacement", ...}
    }

Custom entries are merged on top of (and override) the built-ins.
"""

from __future__ import annotations

# Common profanity -> neutral replacement. Keys are matched case-insensitively
# as whole words (see detectors._word_pattern). Replacements preserve meaning
# while removing the expletive.
PROFANITY: dict[str, str] = {
    "fuck": "mess up",
    "fucking": "very",
    "fucked": "ruined",
    "shit": "junk",
    "shitty": "poor",
    "bullshit": "nonsense",
    "ass": "backside",
    "asshole": "jerk",
    "bastard": "scoundrel",
    "bitch": "complain",
    "damn": "darn",
    "goddamn": "darn",
    "hell": "heck",
    "crap": "junk",
    "piss": "annoy",
    "pissed": "annoyed",
    "dick": "jerk",
    "douche": "jerk",
    "douchebag": "jerk",
    "screwed": "in trouble",
}

# Hostile / abusive phrasings -> measured equivalents. Helps convert a toxic
# tone into something a content filter (and a human reader) will accept.
SOFTENERS: dict[str, str] = {
    "shut up": "please hold on",
    "kill yourself": "[removed]",
    "kys": "[removed]",
    "i hate you": "I strongly disagree",
    "you're an idiot": "I see this differently",
    "you are an idiot": "I see this differently",
    "you're stupid": "I disagree",
    "you are stupid": "I disagree",
    "stfu": "please hold on",
    "wtf": "what",
    "omfg": "wow",
}

# Slurs are detected and REDACTED (never softened). None are shipped in source;
# load your own via --lexicon. This stays empty by design.
SLURS: list[str] = []
