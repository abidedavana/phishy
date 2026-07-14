"""Adversarial perturbations.

Each perturbation is a semantics-preserving transform: it keeps the email a
phishing attempt (a human would still be fooled) while trying to reduce the
signals a classifier keys on. Running them against the classifier maps out
which signals actually hold the decision — i.e. where the boundary is.

Every transform takes (email: dict, strength: float in 0..1) and returns a new
email dict; the original is never mutated. strength=0 is a near no-op, 1.0 is
the most aggressive version of that technique.

Note: these mirror real evasion tradecraft, but applied only to synthetic
samples for measurement. Nothing here weaponises anything — it exists to show
the classifier's blind spots so they can be defended.
"""

from __future__ import annotations

import copy
import hashlib
import re
from typing import Callable

# Look-alike unicode homoglyphs for common ASCII letters.
_HOMOGLYPHS = {
    "a": "а",  # cyrillic a
    "e": "е",  # cyrillic e
    "o": "о",  # cyrillic o
    "i": "і",  # cyrillic dotless-style i
    "c": "с",  # cyrillic c
    "p": "р",  # cyrillic p
}
_ZWSP = "​"  # zero-width space

# Trigger words we try to hide from keyword-based detection.
_TRIGGERS = [
    "verify", "verified", "suspend", "suspended", "urgent", "password",
    "confirm", "account", "immediately", "expire", "expires", "locked",
    "billing", "credentials", "login", "log in", "sign in",
]

_URGENCY_PHRASES = [
    (r"within 24 hours", "at your convenience"),
    (r"immediately", "when you can"),
    (r"urgent[:!]?", ""),
    (r"will be permanently suspended", "may need attention"),
    (r"will be disabled", "should be reviewed"),
    (r"or your account will be disabled", ""),
    (r"action needed", "for your reference"),
    (r"action required", "for your reference"),
]

_BENIGN_PADDING = (
    " Thank you for being a valued customer. We appreciate your continued "
    "trust and are always here to help with any questions. Have a great day."
)


def _clone(email: dict) -> dict:
    return copy.deepcopy(email)


def homoglyph_swap(email: dict, strength: float = 1.0) -> dict:
    """Replace some ASCII letters in the body with look-alike unicode.

    Hides trigger words from literal substring matching while staying readable
    to a human. Higher strength swaps a larger fraction of eligible letters.
    """
    e = _clone(email)
    body = e.get("body", "") or ""

    def swap_word(w: str) -> str:
        chars = list(w)
        for idx, ch in enumerate(chars):
            low = ch.lower()
            if low in _HOMOGLYPHS and (idx % max(1, round(1 / max(strength, 0.01))) == 0):
                chars[idx] = _HOMOGLYPHS[low]
        return "".join(chars)

    out = []
    for token in re.split(r"(\s+)", body):
        if token.strip().lower().strip(".,:;!?") in _TRIGGERS:
            out.append(swap_word(token))
        else:
            out.append(token)
    e["body"] = "".join(out)
    return e


def zero_width_injection(email: dict, strength: float = 1.0) -> dict:
    """Insert zero-width spaces inside trigger words (e.g. 'ver<zwsp>ify')."""
    e = _clone(email)
    body = e.get("body", "") or ""
    n = max(1, round(strength * 2))  # how many zwsp to sprinkle per word

    def zwsp_word(w: str) -> str:
        if len(w) < 3:
            return w
        pos = len(w) // 2
        return w[:pos] + (_ZWSP * n) + w[pos:]

    out = []
    for token in re.split(r"(\s+)", body):
        core = token.strip(".,:;!?").lower()
        out.append(zwsp_word(token) if core in _TRIGGERS else token)
    e["body"] = "".join(out)
    return e


def soften_urgency(email: dict, strength: float = 1.0) -> dict:
    """Remove or soften urgency / pressure language."""
    e = _clone(email)
    body = e.get("body", "") or ""
    subject = e.get("subject", "") or ""
    cutoff = max(1, round(len(_URGENCY_PHRASES) * strength))
    for pat, repl in _URGENCY_PHRASES[:cutoff]:
        body = re.sub(pat, repl, body, flags=re.I)
        subject = re.sub(pat, repl, subject, flags=re.I)
    e["body"] = re.sub(r"\s{2,}", " ", body).strip()
    e["subject"] = re.sub(r"\s{2,}", " ", subject).strip()
    return e


def benign_padding(email: dict, strength: float = 1.0) -> dict:
    """Dilute suspicious content with legitimate-sounding filler text."""
    e = _clone(email)
    reps = max(1, round(strength * 3))
    e["body"] = (e.get("body", "") or "") + (_BENIGN_PADDING * reps)
    return e


def align_reply_to(email: dict, strength: float = 1.0) -> dict:
    """Make Reply-To / Return-Path match the From domain (hides header spoof).

    strength >= 0.5 also aligns Return-Path; below that only Reply-To.
    """
    e = _clone(email)
    from_addr = e.get("from_addr", "") or ""
    if "@" in from_addr:
        dom = from_addr.split("@")[-1]
        e["reply_to"] = f"support@{dom}"
        if strength >= 0.5:
            e["return_path"] = f"bounce@{dom}"
    return e


# Neutral-looking shortener hosts: no brand look-alike, no suspicious TLD.
_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "rebrand.ly"]

# Matches live and defanged URLs so both get rewritten.
_URL_IN_BODY = re.compile(
    r"(?:h\s*x\s*x\s*ps?|https?)://[^\s<>\"')]+|www\.[^\s<>\"')]+", re.I
)


def url_shortener(email: dict, strength: float = 1.0) -> dict:
    """Hide destination URLs behind a link-shortener (real-world #1 evasion).

    Replaces look-alike / suspicious-TLD / IP-literal links with a neutral
    shortener URL. The email is still phishing — the link still leads somewhere
    hostile — but the structural signals a URL-based classifier keys on are
    gone. strength < 0.5 only rewrites the first URL; >= 0.5 rewrites all.
    """
    e = _clone(email)
    body = e.get("body", "") or ""
    only_first = strength < 0.5
    state = {"done": False}

    def repl(m: re.Match) -> str:
        if only_first and state["done"]:
            return m.group(0)
        state["done"] = True
        code = hashlib.md5(m.group(0).encode("utf-8")).hexdigest()[:7]
        return f"https://{_SHORTENERS[0]}/{code}"

    e["body"] = _URL_IN_BODY.sub(repl, body)
    return e


def strip_display_brand(email: dict, strength: float = 1.0) -> dict:
    """Replace a brand-y display name with a neutral one (hides name spoof)."""
    e = _clone(email)
    e["from_display"] = "Customer Service" if strength >= 0.5 else "Support Team"
    return e


# A generic, real free-webmail sender — simulates a compromised or throwaway
# account, the way real BEC / account-takeover phishing evades sender reputation.
_NEUTRAL_SENDER = ("Account Services", "account.services.notice@gmail.com")


def neutral_sender(email: dict, strength: float = 1.0) -> dict:
    """Send from a benign free-webmail address instead of a look-alike domain.

    Removes the sender-domain signal (brand look-alike, bad TLD) that both
    heuristic and LLM classifiers lean on, while the body stays malicious — a
    compromised-account phish. strength >= 0.5 also aligns Reply-To/Return-Path
    so no header mismatch remains.
    """
    e = _clone(email)
    name, addr = _NEUTRAL_SENDER
    e["from_display"] = name
    e["from_addr"] = addr
    if strength >= 0.5:
        e["reply_to"] = addr
        e["return_path"] = addr
    return e


# name -> transform. Order is roughly weakest-signal-first.
PERTURBATIONS: dict[str, Callable[[dict, float], dict]] = {
    "soften_urgency": soften_urgency,
    "benign_padding": benign_padding,
    "homoglyph_swap": homoglyph_swap,
    "zero_width_injection": zero_width_injection,
    "url_shortener": url_shortener,
    "align_reply_to": align_reply_to,
    "strip_display_brand": strip_display_brand,
    "neutral_sender": neutral_sender,
}


def apply_chain(email: dict, names: list[str], strength: float = 1.0) -> dict:
    """Apply several perturbations in sequence (a combined attack)."""
    e = email
    for n in names:
        e = PERTURBATIONS[n](e, strength)
    return e
