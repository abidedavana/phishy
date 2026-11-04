"""Evasion techniques. Each one takes an email and returns a changed copy."""

import hashlib
import re

# Cyrillic look-alikes
_HOMOGLYPHS = str.maketrans({
    "a": "а", "e": "е", "o": "о", "i": "і", "c": "с", "p": "р",
    "A": "а", "E": "е", "O": "о", "I": "і", "C": "с", "P": "р",
})
_ZERO_WIDTH_SPACES = "​" * 2

_TRIGGERS = {
    "verify", "verified", "suspend", "suspended", "urgent", "password",
    "confirm", "account", "immediately", "expire", "expires", "locked",
    "billing", "credentials", "login",
}

_URGENCY_PHRASES = [
    (r"within 24 hours", "at your convenience"),
    (r"immediately", "when you can"),
    (r"urgent[:!]?", ""),
    (r"will be permanently suspended", "may need attention"),
    (r"will be disabled", "should be reviewed"),
    (r"action needed", "for your reference"),
    (r"action required", "for your reference"),
]

_BENIGN_PADDING = (
    " Thank you for being a valued customer. We appreciate your continued "
    "trust and are always here to help with any questions. Have a great day."
)

# also matches defanged URLs
_URL_RE = re.compile(r"(?:h\s*x\s*x\s*ps?|https?)://[^\s<>\"')]+|www\.[^\s<>\"')]+", re.I)


def _rewrite_triggers(body, rewrite):
    def replace(match):
        word = match.group()
        return rewrite(word) if word.strip(".,:;!?").lower() in _TRIGGERS else word
    return re.sub(r"\S+", replace, body)


def soften_urgency(email):
    def soften(text):
        for pattern, replacement in _URGENCY_PHRASES:
            text = re.sub(pattern, replacement, text, flags=re.I)
        return re.sub(r"\s{2,}", " ", text).strip()
    return {**email, "subject": soften(email["subject"]), "body": soften(email["body"])}


def benign_padding(email):
    return {**email, "body": email["body"] + _BENIGN_PADDING * 3}


def homoglyph_swap(email):
    return {**email, "body": _rewrite_triggers(email["body"],
                                               lambda word: word.translate(_HOMOGLYPHS))}


def zero_width_injection(email):
    def split(word):
        middle = len(word) // 2
        return word[:middle] + _ZERO_WIDTH_SPACES + word[middle:]
    return {**email, "body": _rewrite_triggers(email["body"], split)}


def url_shortener(email):
    def shorten(match):
        code = hashlib.md5(match.group().encode("utf-8")).hexdigest()[:7]
        return f"https://bit.ly/{code}"
    return {**email, "body": _URL_RE.sub(shorten, email["body"])}


def align_reply_to(email):
    domain = email["from_addr"].split("@")[-1]
    return {**email, "reply_to": f"support@{domain}", "return_path": f"bounce@{domain}"}


def strip_display_brand(email):
    return {**email, "from_display": "Customer Service"}


def neutral_sender(email):
    address = "account.services.notice@gmail.com"
    return {**email, "from_display": "Account Services", "from_addr": address,
            "reply_to": address, "return_path": address}


PERTURBATIONS = {
    "soften_urgency": soften_urgency,
    "benign_padding": benign_padding,
    "homoglyph_swap": homoglyph_swap,
    "zero_width_injection": zero_width_injection,
    "url_shortener": url_shortener,
    "align_reply_to": align_reply_to,
    "strip_display_brand": strip_display_brand,
    "neutral_sender": neutral_sender,
}
