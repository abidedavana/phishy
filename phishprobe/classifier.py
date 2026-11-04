"""A classifier is any function that takes an email and returns a verdict dict."""

import json
import math
import os
import re

from .iocs import extract_iocs

# hand-tuned weights for the tags extract_iocs produces
WEIGHTS = {
    "urgency": 0.9,
    "credential-ask": 1.1,
    "brand-lookalike": 1.6,
    "ip-literal-url": 1.5,
    "suspicious-tld": 1.0,
    "punycode-or-homoglyph": 1.6,
    "reply-to-mismatch": 1.2,
    "return-path-mismatch": 0.6,
    "display-name-spoof": 1.4,
}
BIAS = -1.4


def heuristic(email):
    tags = {tag for indicator in extract_iocs(email) for tag in indicator["tags"]}
    reasons = [tag for tag in WEIGHTS if tag in tags]
    z = BIAS + sum(WEIGHTS[tag] for tag in reasons)
    score = 1 / (1 + math.exp(-z))
    return {
        "label": "phishing" if score >= 0.5 else "legit",
        "phishing_score": round(score, 4),
        "reasons": reasons or ["no strong phishing signals detected"],
    }


SYSTEM_PROMPT = (
    "You are a security classifier. Decide whether an email is a phishing "
    "attempt or legitimate. Respond ONLY with compact JSON: "
    '{"label": "phishing"|"legit", "phishing_score": <0..1 float>, '
    '"reasons": [<short strings>]}. No prose outside the JSON.'
)
DEFAULT_BASE_URL = "https://api.fireworks.ai/inference/v1"
DEFAULT_MODEL = "accounts/fireworks/models/gpt-oss-120b"


def llm(email):
    import requests  # imported here so the heuristic runs without it

    fields = {key: email[key] for key in (
        "subject", "from_display", "from_addr", "reply_to", "return_path", "body")}
    base_url = os.getenv("PHISHPROBE_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    response = requests.post(
        f"{base_url}/chat/completions",
        headers={"Authorization": f"Bearer {os.environ['PHISHPROBE_API_KEY']}"},
        json={
            "model": os.getenv("PHISHPROBE_MODEL", DEFAULT_MODEL),
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": "Classify this email:\n"
                                            + json.dumps(fields, ensure_ascii=False, indent=2)},
            ],
            "temperature": 0,
            "max_tokens": 300,
        },
        timeout=30,
    )
    response.raise_for_status()
    reply = _parse_reply(response.json()["choices"][0]["message"]["content"])

    score = min(max(float(reply.get("phishing_score", 0.5)), 0.0), 1.0)
    return {
        "label": reply.get("label") or ("phishing" if score >= 0.5 else "legit"),
        "phishing_score": round(score, 4),
        "reasons": list(reply.get("reasons", []))[:6] or ["LLM returned no reasons"],
    }


def _parse_reply(content):
    # models sometimes wrap the JSON in extra text
    match = re.search(r"\{.*\}", content, re.S)
    try:
        return json.loads(match.group())
    except (AttributeError, json.JSONDecodeError):
        # one bad reply shouldn't kill a long run
        return {"label": "phishing" if "phish" in content.lower() else "legit",
                "reasons": ["unparseable model output"]}
