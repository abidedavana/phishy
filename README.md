# PhishProbe

Detects phishing emails and tests how easily that detection can be fooled.

It labels each email as phishing or legit and pulls the URLs, look-alike domains and spoofed headers into a report, with the links defanged. Then it rewrites the emails it caught using tricks real phishers use and checks which ones change the verdict.

The sample emails are made up.

## Usage

```bash
python -m phishprobe
```

This only needs Python. Results go to `reports/report.md`, with the full data in `reports/report.json`.

To check your own emails, put them in a JSONL file with one email per line and pass it with `--email`:

```bash
python -m phishprobe --email my_emails.jsonl
```

Each line looks like this. Missing fields count as empty, and `label` is optional (`phishing` or `legit`, only used to work out accuracy):

```json
{"id": "1", "subject": "Your account", "from_display": "PayPal", "from_addr": "help@paypa1.xyz", "reply_to": "", "return_path": "", "body": "Verify your account here: http://paypa1.xyz/login", "label": "phishing"}
```

To use an LLM instead of the built-in heuristic classifier:

```bash
pip install -r requirements.txt
export PHISHPROBE_API_KEY=your_key
python -m phishprobe --backend llm
```

It uses Fireworks by default. Set `PHISHPROBE_BASE_URL` and `PHISHPROBE_MODEL` to use another OpenAI-compatible API. A run on the sample emails makes 76 API calls.

To run the tests:

```bash
python -m unittest discover -s tests
```

## The tricks

- `soften_urgency` tones down pressure language
- `benign_padding` adds friendly filler text
- `homoglyph_swap` swaps letters in trigger words for Cyrillic look-alikes
- `zero_width_injection` hides zero-width spaces inside trigger words
- `url_shortener` hides links behind a shortener
- `align_reply_to` makes Reply-To and Return-Path match From
- `strip_display_brand` replaces a brand display name with a generic one
- `neutral_sender` sends from a Gmail address

Each one is tried alone, then the ones that lowered the score are stacked together.

## Results

The heuristic gets all 11 sample emails right. No single trick gets a phishing email past it, but stacking them gets all 6 through. `url_shortener` does the most damage because it removes every URL signal in one go.

The heuristic only looks for technical signs like bad domains, mismatched headers and urgent wording, so a plain scam from a normal Gmail address can get through.

## ml/

A separate notebook that trains URL classifiers on a 10,000 URL dataset. See [ml/README.md](ml/README.md).
