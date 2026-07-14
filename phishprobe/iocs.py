"""IOC extraction.

Pulls indicators of compromise out of an email dict and returns them as a
structured, JSON-serialisable list. Everything here is deterministic and
offline — no network calls, no external lookups — so it is safe to run on
untrusted samples.

Email dict shape (all optional except body):
    {
      "id": str, "subject": str,
      "from_display": str, "from_addr": str,
      "reply_to": str, "return_path": str,
      "body": str,
    }
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict, field
from difflib import SequenceMatcher
from typing import Any


# Brands commonly impersonated in phishing. Used to flag look-alike / typo-squat
# domains. This is intentionally small and illustrative, not exhaustive.
KNOWN_BRANDS = [
    "paypal.com", "apple.com", "microsoft.com", "office365.com", "amazon.com",
    "google.com", "dhl.com", "fedex.com", "netflix.com", "github.com",
    "workday.com", "emiratesnbd.com", "adcb.com",
]

URGENCY_WORDS = [
    "urgent", "immediately", "within 24 hours", "suspend", "suspended",
    "expire", "expires", "verify", "confirm your", "account will be",
    "action needed", "action required", "locked", "disabled", "avoid",
]

SUSPICIOUS_TLDS = {
    "top", "xyz", "help", "info", "ru", "zip", "mov", "click", "link",
    "country", "gq", "tk", "ml", "cf", "work", "support",
}

# http(s) URLs, plus bare www.* hosts. Refanging handles defanged forms first.
_URL_RE = re.compile(r"""(?xi)
    \b(
        (?:https?://|www\.)          # scheme or www
        [a-z0-9\-._~%]+              # host
        (?::\d+)?                    # optional port
        (?:/[^\s<>"')]*)?            # optional path
    )
""")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)


def refang(text: str) -> str:
    """Turn defanged indicators (hxxp, [.], [dot]) back into parseable form."""
    if not text:
        return ""
    t = text
    t = re.sub(r"h\s*x\s*x\s*p", "http", t, flags=re.I)
    t = t.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    t = re.sub(r"\[\s*dot\s*\]", ".", t, flags=re.I)
    t = re.sub(r"\[\s*at\s*\]", "@", t, flags=re.I)
    t = t.replace("[://]", "://").replace("hxxps", "https")
    return t


def defang(indicator: str) -> str:
    """Render an indicator safe to paste into a report (no live links)."""
    return indicator.replace("http", "hxxp").replace(".", "[.]")


def domain_of(host_or_url: str) -> str:
    h = host_or_url.strip().lower()
    h = re.sub(r"^https?://", "", h)
    h = h.split("/")[0].split("@")[-1].split(":")[0]
    return h


def registrable_domain(host: str) -> str:
    """Naive eTLD+1 (last two labels). Good enough for demo-scale detection."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def looks_like_brand(host: str) -> tuple[str, float] | None:
    """Return (brand, similarity) if host resembles a known brand but is not it.

    Typosquats usually hide the brand token inside a longer SLD
    (`paypa1-secure.com`, `dhl-tracking-update.top`), so we compare the brand
    name against both the whole second-level domain and each of its
    hyphen/dot-separated tokens, not just the full domain string.
    """
    reg = registrable_domain(host)
    if reg in KNOWN_BRANDS:
        return None  # exact match -> legitimate, not a look-alike

    sld = reg.rsplit(".", 1)[0] if "." in reg else reg
    tokens = [t for t in re.split(r"[-.]", sld) if t]

    best = None
    for brand in KNOWN_BRANDS:
        brand_name = brand.split(".")[0]
        candidates = [_similarity(sld, brand_name)]
        candidates += [_similarity(t, brand_name) for t in tokens]
        score = max(candidates)
        # Require a strong per-token match, or a decent whole-SLD match.
        if score >= 0.8 and (best is None or score > best[1]):
            best = (brand, round(score, 3))
    return best


@dataclass
class Indicator:
    type: str                 # url | domain | ip | email | header-spoof | keyword
    value: str                # defanged, report-safe
    severity: str             # low | medium | high
    note: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _add(seen: set, out: list, ind: Indicator) -> None:
    key = (ind.type, ind.value)
    if key not in seen:
        seen.add(key)
        out.append(ind)


def extract_iocs(email: dict) -> list[Indicator]:
    """Extract a de-duplicated, severity-scored list of indicators."""
    out: list[Indicator] = []
    seen: set = set()

    body = email.get("body", "") or ""
    text = " ".join(
        str(email.get(k, "") or "")
        for k in ("subject", "from_display", "body")
    )
    refanged = refang(body + " " + text)

    # --- URLs, domains, IPs from the body ---
    for m in _URL_RE.finditer(refanged):
        url = m.group(1).rstrip(".,)")
        host = domain_of(url)
        tags: list[str] = []
        severity = "medium"

        if _IPV4_RE.fullmatch(host):
            severity = "high"
            tags.append("ip-literal-url")
            _add(seen, out, Indicator("ip", host, "high", "URL points at a raw IP address", ["ip-literal-url"]))
        else:
            tld = host.rsplit(".", 1)[-1]
            if tld in SUSPICIOUS_TLDS:
                tags.append("suspicious-tld")
                severity = "high"
            if host.startswith("xn--") or "xn--" in host:
                tags.append("punycode")
                severity = "high"
            if any(ord(c) > 127 for c in host):
                tags.append("non-ascii-homoglyph")
                severity = "high"
            lk = looks_like_brand(host)
            if lk:
                brand, score = lk
                tags.append("brand-lookalike")
                severity = "high"
                _add(seen, out, Indicator(
                    "domain", defang(host), "high",
                    f"Look-alike of {brand} (similarity {score})",
                    ["brand-lookalike", brand],
                ))

        _add(seen, out, Indicator("url", defang(url), severity, "URL found in message body", tags))

    # --- header / sender spoofing signals ---
    from_addr = (email.get("from_addr") or "").lower()
    reply_to = (email.get("reply_to") or "").lower()
    return_path = (email.get("return_path") or "").lower()
    display = (email.get("from_display") or "").strip()

    from_dom = registrable_domain(domain_of(from_addr)) if from_addr else ""

    if reply_to and from_addr:
        rdom = registrable_domain(domain_of(reply_to))
        if rdom and rdom != from_dom:
            _add(seen, out, Indicator(
                "header-spoof", f"reply-to:{defang(reply_to)}", "high",
                f"Reply-To domain ({rdom}) differs from From domain ({from_dom})",
                ["reply-to-mismatch"],
            ))

    if return_path and from_addr:
        pdom = registrable_domain(domain_of(return_path))
        if pdom and pdom != from_dom:
            _add(seen, out, Indicator(
                "header-spoof", f"return-path:{defang(return_path)}", "medium",
                f"Return-Path domain ({pdom}) differs from From domain ({from_dom})",
                ["return-path-mismatch"],
            ))

    # Display name claims a brand the sending domain does not match.
    if display and from_dom:
        for brand in KNOWN_BRANDS:
            brand_name = brand.split(".")[0]
            if brand_name in display.lower() and brand not in from_addr:
                _add(seen, out, Indicator(
                    "header-spoof", f"display:{display} <{defang(from_addr)}>", "high",
                    f"Display name claims '{display}' but sender domain is {from_dom}",
                    ["display-name-spoof", brand],
                ))
                break

    # Sending domain itself is a brand look-alike.
    if from_dom:
        lk = looks_like_brand(from_dom)
        if lk:
            brand, score = lk
            _add(seen, out, Indicator(
                "domain", defang(from_dom), "high",
                f"Sender domain resembles {brand} (similarity {score})",
                ["brand-lookalike", brand],
            ))

    # --- urgency / social-engineering keywords ---
    low = refanged.lower()
    hits = [w for w in URGENCY_WORDS if w in low]
    if hits:
        _add(seen, out, Indicator(
            "keyword", ", ".join(sorted(set(hits))[:6]),
            "low", "Urgency / social-engineering language", ["social-engineering"],
        ))

    # Stable ordering: severity desc, then type, then value.
    rank = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda i: (rank.get(i.severity, 3), i.type, i.value))
    return out


def iocs_to_dicts(indicators: list[Indicator]) -> list[dict]:
    return [i.to_dict() for i in indicators]
