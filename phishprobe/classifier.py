"""Phishing classifiers.

Two backends behind one interface:

* HeuristicClassifier — deterministic, offline, zero-dependency. Always works,
  and gives the prober a stable target so results are reproducible.
* LLMClassifier — calls any OpenAI-compatible /chat/completions endpoint
  (Fireworks AI, OpenAI, Together, a local vLLM, ...). Configured entirely
  through environment variables so no secrets live in the code.

`get_classifier()` picks the backend from PHISHPROBE_BACKEND (or falls back to
heuristic when no LLM credentials are present).
"""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any

from .iocs import (
    refang, domain_of, registrable_domain, looks_like_brand,
    URGENCY_WORDS, SUSPICIOUS_TLDS,
)


@dataclass
class Classification:
    label: str                       # "phishing" | "legit"
    confidence: float                # model confidence in `label`, 0..1
    phishing_score: float            # P(phishing), 0..1
    reasons: list[str] = field(default_factory=list)
    backend: str = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _email_text(email: dict) -> str:
    return " ".join(
        str(email.get(k, "") or "")
        for k in ("subject", "from_display", "from_addr", "reply_to", "body")
    )


class BaseClassifier:
    name = "base"

    def classify(self, email: dict) -> Classification:  # pragma: no cover
        raise NotImplementedError


class HeuristicClassifier(BaseClassifier):
    """Weighted-feature scorer squashed through a logistic function.

    The weights are hand-tuned, not learned — the point of the project is not
    the classifier itself but having a well-understood decision boundary to
    probe. Keeping it interpretable means every flip during probing has a
    traceable cause.
    """

    name = "heuristic"

    # feature_name -> weight (positive pushes toward "phishing")
    WEIGHTS = {
        "urgency": 0.9,
        "credential_ask": 1.1,
        "brand_lookalike_url": 1.6,
        "ip_literal_url": 1.5,
        "suspicious_tld": 1.0,
        "punycode_or_homoglyph": 1.6,
        "reply_to_mismatch": 1.2,
        "return_path_mismatch": 0.6,
        "display_name_spoof": 1.4,
        "many_links": 0.4,
    }
    BIAS = -1.4  # default toward "legit" until signals accumulate

    CRED_WORDS = ["password", "verify your", "confirm your identity",
                  "log in", "sign in", "credentials", "billing information",
                  "otp", "one-time"]

    def features(self, email: dict) -> dict[str, float]:
        body = refang(email.get("body", "") or "")
        text = refang(_email_text(email)).lower()
        f: dict[str, float] = {}

        f["urgency"] = 1.0 if sum(w in text for w in URGENCY_WORDS) >= 2 else 0.0
        f["credential_ask"] = 1.0 if any(w in text for w in self.CRED_WORDS) else 0.0

        urls = re.findall(r"(?:https?://|www\.)[^\s<>\"')]+", body, re.I)
        hosts = [domain_of(u) for u in urls]

        f["ip_literal_url"] = 1.0 if any(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", h) for h in hosts) else 0.0
        f["suspicious_tld"] = 1.0 if any(h.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS for h in hosts) else 0.0
        f["punycode_or_homoglyph"] = 1.0 if any(
            "xn--" in h or any(ord(c) > 127 for c in h) for h in hosts
        ) else 0.0
        f["brand_lookalike_url"] = 1.0 if any(looks_like_brand(h) for h in hosts if h) else 0.0
        f["many_links"] = 1.0 if len(urls) >= 3 else 0.0

        from_addr = (email.get("from_addr") or "").lower()
        from_dom = registrable_domain(domain_of(from_addr)) if from_addr else ""
        reply_to = (email.get("reply_to") or "").lower()
        return_path = (email.get("return_path") or "").lower()

        f["reply_to_mismatch"] = 1.0 if (
            reply_to and from_dom and registrable_domain(domain_of(reply_to)) != from_dom
        ) else 0.0
        f["return_path_mismatch"] = 1.0 if (
            return_path and from_dom and registrable_domain(domain_of(return_path)) != from_dom
        ) else 0.0

        display = (email.get("from_display") or "").lower()
        spoof = False
        if display and from_dom:
            from .iocs import KNOWN_BRANDS
            for brand in KNOWN_BRANDS:
                if brand.split(".")[0] in display and brand not in from_addr:
                    spoof = True
                    break
        f["display_name_spoof"] = 1.0 if spoof else 0.0
        return f

    def classify(self, email: dict) -> Classification:
        f = self.features(email)
        z = self.BIAS + sum(self.WEIGHTS[k] * v for k, v in f.items())
        p = 1.0 / (1.0 + math.exp(-z))  # P(phishing)
        label = "phishing" if p >= 0.5 else "legit"
        confidence = p if label == "phishing" else 1.0 - p
        reasons = [k.replace("_", " ") for k, v in f.items() if v > 0]
        if not reasons:
            reasons = ["no strong phishing signals detected"]
        return Classification(
            label=label,
            confidence=round(confidence, 4),
            phishing_score=round(p, 4),
            reasons=reasons,
            backend=self.name,
        )


class LLMClassifier(BaseClassifier):
    """OpenAI-compatible chat backend (Fireworks AI, OpenAI, Together, ...).

    Env vars:
        PHISHPROBE_API_KEY   (or FIREWORKS_API_KEY / OPENAI_API_KEY)
        PHISHPROBE_BASE_URL  default https://api.fireworks.ai/inference/v1
        PHISHPROBE_MODEL     default accounts/fireworks/models/gpt-oss-120b
    """

    name = "llm"

    SYSTEM = (
        "You are a security classifier. Decide whether an email is a phishing "
        "attempt or legitimate. Respond ONLY with compact JSON: "
        '{"label": "phishing"|"legit", "phishing_score": <0..1 float>, '
        '"reasons": [<short strings>]}. No prose outside the JSON.'
    )

    def __init__(self, api_key: str | None = None, base_url: str | None = None,
                 model: str | None = None, timeout: int = 30):
        self.api_key = (
            api_key or os.getenv("PHISHPROBE_API_KEY")
            or os.getenv("FIREWORKS_API_KEY") or os.getenv("OPENAI_API_KEY")
        )
        self.base_url = (
            base_url or os.getenv("PHISHPROBE_BASE_URL")
            or "https://api.fireworks.ai/inference/v1"
        ).rstrip("/")
        self.model = (
            model or os.getenv("PHISHPROBE_MODEL")
            or "accounts/fireworks/models/gpt-oss-120b"
        )
        self.timeout = timeout
        if not self.api_key:
            raise RuntimeError(
                "No API key. Set PHISHPROBE_API_KEY (or FIREWORKS_API_KEY / "
                "OPENAI_API_KEY), or use the heuristic backend."
            )

    def _user_prompt(self, email: dict) -> str:
        fields = {k: email.get(k, "") for k in
                  ("subject", "from_display", "from_addr", "reply_to", "return_path", "body")}
        return "Classify this email:\n" + json.dumps(fields, ensure_ascii=False, indent=2)

    def classify(self, email: dict) -> Classification:
        import requests  # imported lazily so the offline path needs no deps

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.SYSTEM},
                {"role": "user", "content": self._user_prompt(email)},
            ],
            "temperature": 0,
            "max_tokens": 300,
        }
        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"},
            json=payload, timeout=self.timeout,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        data = self._parse(content)

        score = float(data.get("phishing_score", 0.5))
        score = min(max(score, 0.0), 1.0)
        label = data.get("label") or ("phishing" if score >= 0.5 else "legit")
        confidence = score if label == "phishing" else 1.0 - score
        return Classification(
            label=label,
            confidence=round(confidence, 4),
            phishing_score=round(score, 4),
            reasons=list(data.get("reasons", []))[:6] or ["LLM returned no reasons"],
            backend=f"{self.name}:{self.model.split('/')[-1]}",
        )

    @staticmethod
    def _parse(content: str) -> dict:
        content = content.strip()
        m = re.search(r"\{.*\}", content, re.S)  # tolerate stray text around JSON
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
        # Fallback if the model ignored the format instruction.
        return {"label": "phishing" if "phish" in content.lower() else "legit",
                "phishing_score": 0.5, "reasons": ["unparseable model output"]}


def get_classifier(backend: str | None = None) -> BaseClassifier:
    """Select a backend.

    backend=None -> read PHISHPROBE_BACKEND, else 'heuristic'.
    Falls back to heuristic if 'llm' is requested but no key is configured.
    """
    backend = (backend or os.getenv("PHISHPROBE_BACKEND") or "heuristic").lower()
    if backend in ("llm", "fireworks", "openai"):
        try:
            return LLMClassifier()
        except RuntimeError:
            return HeuristicClassifier()
    return HeuristicClassifier()
