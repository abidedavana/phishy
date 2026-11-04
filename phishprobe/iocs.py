"""Pull indicators of compromise out of an email."""

import re
from difflib import SequenceMatcher

# brands to check look-alike domains against
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

CREDENTIAL_WORDS = [
    "password", "verify your", "confirm your identity", "log in", "sign in",
    "credentials", "billing information", "otp", "one-time",
]

SUSPICIOUS_TLDS = {
    "top", "xyz", "help", "info", "ru", "zip", "mov", "click", "link",
    "country", "gq", "tk", "ml", "cf", "work", "support",
}

_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+", re.I)
_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def refang(text):
    text = re.sub(r"h\s*x\s*x\s*p", "http", text, flags=re.I)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    text = re.sub(r"\[\s*dot\s*\]", ".", text, flags=re.I)
    text = re.sub(r"\[\s*at\s*\]", "@", text, flags=re.I)
    return text.replace("[://]", "://")


def defang(indicator):
    return indicator.replace("http", "hxxp").replace(".", "[.]")


def domain_of(host_or_url):
    host = re.sub(r"^https?://", "", host_or_url.strip().lower())
    return host.split("/")[0].split("@")[-1].split(":")[0]


def registrable_domain(host):
    # just the last two labels, so this gets things like .co.uk wrong
    return ".".join(host.split(".")[-2:])


def looks_like_brand(host):
    domain = registrable_domain(host)
    if domain in KNOWN_BRANDS:
        return None

    # typosquats hide the brand in a longer name (paypa1-secure.com), so check each token too
    name = domain.rsplit(".", 1)[0]
    candidates = [name] + [token for token in re.split(r"[-.]", name) if token]

    best = None
    for brand in KNOWN_BRANDS:
        brand_name = brand.split(".")[0]
        score = max(SequenceMatcher(None, c, brand_name).ratio() for c in candidates)
        if score >= 0.8 and (best is None or score > best[1]):
            best = (brand, round(score, 3))
    return best


def extract_iocs(email):
    indicators = {}

    def add(kind, value, severity, note, tags):
        indicators.setdefault((kind, value), {
            "type": kind, "value": value, "severity": severity,
            "note": note, "tags": tags,
        })

    text = refang(" ".join(email[field] for field in (
        "subject", "from_display", "from_addr", "reply_to", "body")))

    for match in _URL_RE.finditer(text):
        url = match.group().rstrip(".,)")
        host = domain_of(url)
        tags = []
        if _IPV4_RE.fullmatch(host):
            tags.append("ip-literal-url")
            add("ip", defang(host), "high", "URL points at a raw IP address", ["ip-literal-url"])
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            tags.append("suspicious-tld")
        if "xn--" in host or not host.isascii():
            tags.append("punycode-or-homoglyph")
        lookalike = looks_like_brand(host)
        if lookalike:
            brand, score = lookalike
            tags.append("brand-lookalike")
            add("domain", defang(host), "high",
                f"Look-alike of {brand} (similarity {score})", ["brand-lookalike", brand])
        add("url", defang(url), "high" if tags else "medium", "URL found in message", tags)

    from_addr = email["from_addr"].lower()
    from_domain = registrable_domain(domain_of(from_addr))

    for field, header, severity in (("reply_to", "Reply-To", "high"),
                                    ("return_path", "Return-Path", "medium")):
        address = email[field].lower()
        domain = registrable_domain(domain_of(address))
        if domain and from_domain and domain != from_domain:
            add("header-spoof", f"{header.lower()}:{defang(address)}", severity,
                f"{header} domain ({domain}) differs from From domain ({from_domain})",
                [f"{header.lower()}-mismatch"])

    display = email["from_display"].strip()
    if from_domain:
        for brand in KNOWN_BRANDS:
            if brand.split(".")[0] in display.lower() and brand not in from_addr:
                add("header-spoof", f"display:{display} <{defang(from_addr)}>", "high",
                    f"Display name claims '{display}' but sender domain is {from_domain}",
                    ["display-name-spoof", brand])
                break

    lookalike = looks_like_brand(from_domain)
    if lookalike:
        brand, score = lookalike
        add("domain", defang(from_domain), "high",
            f"Sender domain resembles {brand} (similarity {score})", ["sender-lookalike", brand])

    lowered = text.lower()
    urgency = sorted(word for word in URGENCY_WORDS if word in lowered)
    if urgency:
        # one urgent word shows up in normal mail, so it takes two to count
        add("keyword", ", ".join(urgency[:6]), "low", "Urgency language",
            ["urgency"] if len(urgency) >= 2 else [])
    credentials = sorted(word for word in CREDENTIAL_WORDS if word in lowered)
    if credentials:
        add("keyword", ", ".join(credentials[:6]), "low", "Asks for credentials",
            ["credential-ask"])

    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(indicators.values(),
                  key=lambda i: (rank[i["severity"]], i["type"], i["value"]))
