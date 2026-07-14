"""Command-line interface.

    python -m phishprobe classify --email data/samples.jsonl
    python -m phishprobe extract  --email data/samples.jsonl --out reports/
    python -m phishprobe probe    --email data/samples.jsonl --out reports/
    python -m phishprobe report   --email data/samples.jsonl --out reports/   # all of the above

Use --backend llm to route classification through an LLM (Fireworks/OpenAI);
otherwise the offline heuristic backend is used.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .classifier import get_classifier
from .iocs import extract_iocs
from .prober import DecisionBoundaryProber
from . import report as R


def load_emails(path: str) -> list[dict]:
    emails: list[dict] = []
    if path.endswith(".jsonl"):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    emails.append(json.loads(line))
    else:  # a single .json file: list or object
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        emails = data if isinstance(data, list) else [data]
    return emails


def cmd_classify(args) -> int:
    clf = get_classifier(args.backend)
    emails = load_emails(args.email)
    print(f"Backend: {clf.name}\n")
    correct = 0
    labeled = 0
    for e in emails:
        c = clf.classify(e)
        gold = e.get("label")
        mark = ""
        if gold:
            labeled += 1
            ok = gold == c.label
            correct += ok
            mark = "[ok]" if ok else "[MISS]"
        print(f"[{e.get('id','?'):>4}] {c.label:8} score={c.phishing_score:.2f} "
              f"conf={c.confidence:.2f} {mark}  {e.get('subject','')[:48]}")
    if labeled:
        print(f"\nAccuracy on labelled set: {correct}/{labeled} "
              f"({100*correct/labeled:.0f}%)")
    return 0


def cmd_extract(args) -> int:
    clf = get_classifier(args.backend)
    emails = load_emails(args.email)
    records = R.build_ioc_records(emails, extract_iocs, clf)
    out = args.out
    j = R.write_ioc_json(records, os.path.join(out, "ioc_report.json"))
    m = R.write_ioc_markdown(records, os.path.join(out, "ioc_report.md"))
    c = R.write_ioc_csv(records, os.path.join(out, "ioc_report.csv"))
    total = sum(len(r["indicators"]) for r in records)
    print(f"Extracted {total} indicators from {len(records)} emails.")
    for p in (j, m, c):
        print(f"  wrote {p}")
    return 0


def cmd_probe(args) -> int:
    clf = get_classifier(args.backend)
    emails = load_emails(args.email)
    prober = DecisionBoundaryProber(clf)
    result = prober.run(emails)
    out = args.out
    j = R.write_probe_json(result, os.path.join(out, "probe_report.json"))
    m = R.write_probe_markdown(result, os.path.join(out, "probe_report.md"))
    s = result.summary
    print(f"Probed {s['seeds_probed']} phishing seeds with backend '{clf.name}'.")
    print(f"Most effective evasions: {', '.join(s['most_effective'])}")
    print(f"Combined-attack evasion rate: "
          f"{int(s['combined_attack_evasion_rate']*100)}%")
    print(f"Verdict: {s['verdict']}")
    for p in (j, m):
        print(f"  wrote {p}")
    return 0


def cmd_report(args) -> int:
    cmd_extract(args)
    print()
    cmd_probe(args)
    return 0


def build_parser() -> argparse.ArgumentParser:
    # Shared options live on a parent parser so they can be given after the
    # subcommand, e.g. `phishprobe classify --backend llm`.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backend", default=None,
                        help="heuristic (default) | llm")
    common.add_argument("--email", default="data/samples.jsonl",
                        help="path to .jsonl or .json email set")
    common.add_argument("--out", default="reports",
                        help="output directory for reports")

    p = argparse.ArgumentParser(prog="phishprobe",
                                description="Adversarial testing of a phishing classifier.")
    sub = p.add_subparsers(dest="command", required=True)

    for name, fn, help_ in [
        ("classify", cmd_classify, "label emails and (if gold labels present) score accuracy"),
        ("extract", cmd_extract, "extract IOCs to json/md/csv"),
        ("probe", cmd_probe, "probe the classifier's decision boundary"),
        ("report", cmd_report, "run extract + probe together"),
    ]:
        sp = sub.add_parser(name, help=help_, parents=[common])
        sp.set_defaults(func=fn)
    return p


def _force_utf8_stdout() -> None:
    # LLM output (and user-supplied emails) may contain non-ASCII; a Windows
    # console defaults to cp1252 and would crash on print. Make stdout UTF-8.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
