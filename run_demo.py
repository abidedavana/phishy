#!/usr/bin/env python3
"""One-command end-to-end demo.

    python run_demo.py

Runs the full pipeline on the bundled synthetic samples with the offline
heuristic backend (no API key needed): classify -> extract IOCs -> probe the
decision boundary -> write reports to ./reports. Prints a short summary so you
can talk through the result in ~30 seconds.
"""

from __future__ import annotations

import os
import sys

from phishprobe.classifier import get_classifier
from phishprobe.iocs import extract_iocs
from phishprobe.prober import DecisionBoundaryProber
from phishprobe import report as R
from phishprobe.cli import load_emails

DATA = os.path.join(os.path.dirname(__file__), "data", "samples.jsonl")
OUT = os.path.join(os.path.dirname(__file__), "reports")


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    backend = os.getenv("PHISHPROBE_BACKEND", "heuristic")
    clf = get_classifier(backend)
    emails = load_emails(DATA)

    print("=" * 64)
    print(f"PhishProbe demo  |  backend: {clf.name}  |  {len(emails)} emails")
    print("=" * 64)

    # 1) classify
    correct = labeled = 0
    print("\n[1] Classification")
    for e in emails:
        c = clf.classify(e)
        gold = e.get("label")
        if gold:
            labeled += 1
            correct += gold == c.label
        print(f"    {e['id']:>4}  {c.label:8} score={c.phishing_score:.2f}  "
              f"{e.get('subject','')[:44]}")
    if labeled:
        print(f"    -> accuracy {correct}/{labeled} ({100*correct/labeled:.0f}%)")

    # 2) IOC extraction
    print("\n[2] IOC extraction")
    records = R.build_ioc_records(emails, extract_iocs, clf)
    total = sum(len(r["indicators"]) for r in records)
    high = sum(1 for r in records for i in r["indicators"] if i["severity"] == "high")
    print(f"    -> {total} indicators ({high} high-severity) across {len(records)} emails")
    R.write_ioc_json(records, os.path.join(OUT, "ioc_report.json"))
    R.write_ioc_markdown(records, os.path.join(OUT, "ioc_report.md"))
    R.write_ioc_csv(records, os.path.join(OUT, "ioc_report.csv"))

    # 3) decision-boundary probing
    print("\n[3] Decision-boundary probing")
    result = DecisionBoundaryProber(clf).run(emails)
    s = result.summary
    print(f"    -> probed {s['seeds_probed']} phishing seeds")
    print(f"    -> most effective evasions: {', '.join(s['most_effective'])}")
    print(f"    -> combined-attack evasion rate: "
          f"{int(s['combined_attack_evasion_rate']*100)}%")
    print(f"    -> verdict: {s['verdict']}")
    R.write_probe_json(result, os.path.join(OUT, "probe_report.json"))
    R.write_probe_markdown(result, os.path.join(OUT, "probe_report.md"))

    print("\nReports written to ./reports/:")
    for f in sorted(os.listdir(OUT)):
        print(f"    reports/{f}")
    print("\nDone. Open reports/probe_report.md and reports/ioc_report.md.")


if __name__ == "__main__":
    main()
