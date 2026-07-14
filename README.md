# PhishProbe — Adversarial Testing of a Phishing Classifier

A small red-team harness for an email **phishing classifier**. It does three
things:

1. **Classifies** emails as phishing or legitimate (offline heuristic model, or
   a real LLM via an OpenAI-compatible API such as Fireworks AI).
2. **Probes the classifier's decision boundary** with adversarial, meaning-
   preserving perturbations — the evasion tradecraft real phishers use — and
   measures which changes flip the verdict. That's how you surface a model's
   blind spots.
3. **Extracts phishing IOCs** (malicious URLs, look-alike domains, spoofed
   sender metadata, IP-literal links, urgency language) into structured
   JSON / Markdown / CSV reports. All indicators are **defanged** (`hxxp`,
   `[.]`) so the reports are safe to share.

Everything runs on **synthetic, safe sample data** — nothing here weaponises
anything. The perturbations exist to measure a defender's classifier, not to
attack anyone.

> This maps directly to the CV line *"Probed an LLM classifier's decision
> boundary to surface AI-model weaknesses, and extracted phishing IOCs
> (malicious URLs, spoofed metadata) into structured reports."*

---

## Quick start (zero setup, no API key)

```bash
python run_demo.py
```

That runs the whole pipeline on the bundled samples with the offline heuristic
backend and writes reports to `./reports/`. Then explore:

```bash
python -m phishprobe classify              # label emails, score accuracy
python -m phishprobe extract  --out reports   # IOCs -> json/md/csv
python -m phishprobe probe    --out reports   # decision-boundary probe
python -m phishprobe report   --out reports   # extract + probe together
```

Run the tests:

```bash
python -m unittest discover -s tests
```

Only the standard library is needed for the offline path. `requests` is only
required if you switch on the LLM backend.

---

## Using a real LLM (Fireworks AI / OpenAI)

The LLM backend calls any **OpenAI-compatible** `/chat/completions` endpoint.
Copy `.env.example` to `.env`, fill in a key, and export the vars (or set them
in your shell):

```bash
pip install requests
export PHISHPROBE_BACKEND=llm
export PHISHPROBE_API_KEY=fw_xxx
export PHISHPROBE_BASE_URL=https://api.fireworks.ai/inference/v1
export PHISHPROBE_MODEL=accounts/fireworks/models/gpt-oss-120b

python -m phishprobe classify --backend llm
python -m phishprobe probe    --backend llm --out reports
```

List the models your Fireworks key can access (model IDs change over time):

```bash
curl -H "Authorization: Bearer $PHISHPROBE_API_KEY" \
     https://api.fireworks.ai/inference/v1/models
```

Point `PHISHPROBE_BASE_URL` / `PHISHPROBE_MODEL` at OpenAI (`gpt-4o-mini`) or a
local server and it works unchanged. If no key is set, the backend safely falls
back to the heuristic so nothing breaks.

---

## How the decision-boundary probe works

1. Take a seed email the classifier **already flags as phishing** (you can't
   "evade" a detection that never fired).
2. Apply each adversarial perturbation at increasing **strength** (0.25 → 1.0)
   and re-classify. Record whether the verdict flipped phishing → legit and how
   far the phishing score moved.
3. Chain every technique that helped into one **combined attack** and re-test.
4. Aggregate into a per-technique **evasion rate**, **minimum flip strength**
   (how close to the boundary the sample was), and **average score drop**.

### Perturbations (all semantics-preserving)

| Technique | What it does | Signal it targets |
|-----------|--------------|-------------------|
| `soften_urgency` | Removes/softens pressure language | urgency keywords |
| `benign_padding` | Adds legitimate-sounding filler | keyword density |
| `homoglyph_swap` | Unicode look-alike letters in trigger words | keyword matching |
| `zero_width_injection` | Zero-width spaces inside trigger words | keyword matching |
| `url_shortener` | Hides the URL behind a neutral shortener | look-alike domain / bad TLD / IP link |
| `align_reply_to` | Makes Reply-To/Return-Path match From | header mismatch |
| `strip_display_brand` | Neutralises a brand-y display name | display-name spoof |
| `neutral_sender` | Sends from a free-webmail address (compromised-account style) | sender-domain reputation |

### What the demo finds

On the bundled heuristic classifier (100% accuracy on the labelled set):

- **No single technique evades** it — the classifier's defence-in-depth of
  stacked structural + text signals holds against any one perturbation.
- The **combined attack evades 100%** of seeds. The classifier is individually
  robust but **jointly brittle**.
- The **highest-leverage single lever is `url_shortener`** — because the model
  weights URL structure (look-alike domains, suspicious TLDs, IP literals)
  heavily, and hiding the link behind a shortener strips all of that at once.

The takeaway a defender acts on: **don't let any one signal family carry the
decision, and treat link-shortened URLs as first-class risk** (expand them
before scoring).

---

## IOC extraction

`extract_iocs()` returns a structured, severity-ranked list per email:

- **URLs / domains / IPs** — refanged, parsed, then re-defanged for the report.
- **Look-alike domains** — token-level similarity vs a known-brand list
  (`paypa1-secure.com` → PayPal), plus punycode (`xn--`) and unicode homoglyph
  detection.
- **Header / sender spoofing** — Reply-To ≠ From, Return-Path ≠ From, and
  display-name-claims-a-brand-the-domain-isn't.
- **Suspicious TLDs** and **social-engineering language**.

Output: `reports/ioc_report.{json,md,csv}`.

---

## Project layout

```
phishprobe/
  classifier.py     # HeuristicClassifier + LLMClassifier (OpenAI-compatible)
  perturbations.py  # adversarial, semantics-preserving transforms
  prober.py         # decision-boundary probing loop + aggregation
  iocs.py           # IOC extraction, refang/defang, look-alike detection
  report.py         # JSON / Markdown / CSV writers
  cli.py            # `python -m phishprobe ...`
data/samples.jsonl  # synthetic phishing + legit emails (safe)
tests/              # unittest suite (22 tests)
run_demo.py         # one-command end-to-end demo
INTERVIEW.md        # talking points + likely Q&A
```

## Safety & scope

- All sample data is synthetic (`example`-style and clearly fake look-alike
  domains). No real malware, credentials, or live malicious links.
- Report indicators are defanged so they can't be clicked by accident.
- The perturbations measure a classifier you own; they are not a phishing kit.
- The heuristic model is intentionally simple and interpretable — the project's
  value is the **probing methodology and reporting**, not a state-of-the-art
  detector.
