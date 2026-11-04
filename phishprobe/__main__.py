import argparse
import json
import os
import sys

from .classifier import heuristic, llm
from .iocs import extract_iocs
from .prober import probe
from .report import write_reports

BACKENDS = {"heuristic": heuristic, "llm": llm}
EMAIL_FIELDS = ("id", "subject", "from_display", "from_addr", "reply_to", "return_path", "body")


def load_emails(path):
    with open(path, encoding="utf-8") as f:
        return [{**dict.fromkeys(EMAIL_FIELDS, ""), **json.loads(line)}
                for line in f if line.strip()]


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows console default

    parser = argparse.ArgumentParser(prog="phishprobe",
                                     description="Test how easily a phishing classifier can be fooled.")
    parser.add_argument("--backend", choices=BACKENDS, default="heuristic")
    parser.add_argument("--email", default="data/samples.jsonl", help="JSONL file of emails")
    parser.add_argument("--out", default="reports", help="output directory")
    args = parser.parse_args()
    if args.backend == "llm" and not os.getenv("PHISHPROBE_API_KEY"):
        parser.error("the llm backend needs PHISHPROBE_API_KEY to be set")

    classify = BACKENDS[args.backend]
    emails = load_emails(args.email)

    print(f"Classifying {len(emails)} emails with the {args.backend} backend")
    records = []
    for email in emails:
        verdict = classify(email)
        records.append({"id": email["id"], "subject": email["subject"], "verdict": verdict,
                        "indicators": extract_iocs(email)})
        print(f"  {email['id']:>4}  {verdict['label']:8} score={verdict['phishing_score']:.2f}  "
              f"{email['subject'][:48]}")

    labelled = [(e, r) for e, r in zip(emails, records) if e.get("label")]
    if labelled:
        correct = sum(e["label"] == r["verdict"]["label"] for e, r in labelled)
        print(f"Accuracy: {correct}/{len(labelled)} ({correct / len(labelled):.0%})")

    indicators = [ind for record in records for ind in record["indicators"]]
    high = sum(ind["severity"] == "high" for ind in indicators)
    print(f"\nExtracted {len(indicators)} indicators ({high} high severity)")

    result = probe(emails, classify)
    print(f"\nProbed {result['seeds_probed']} phishing seeds")
    print(f"Most effective techniques: {', '.join(result['most_effective'])}")
    print(f"Combined-attack evasion rate: {result['combined_attack_evasion_rate']:.0%}")
    print(f"Verdict: {result['verdict']}")

    print()
    for path in write_reports(args.out, args.backend, records, result):
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()
