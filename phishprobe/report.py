"""Structured report writers.

Turns IOC extraction and probe results into machine-readable JSON and
human-readable Markdown (plus CSV for IOCs). All URLs/domains in reports are
defanged by the extractor, so the output is safe to share.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone

from .iocs import Indicator, iocs_to_dicts
from .prober import ProbeResult


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)


# ----------------------------- IOC reports -----------------------------------

def write_ioc_json(records: list[dict], path: str) -> str:
    _ensure_dir(path)
    doc = {"generated": _now(), "type": "ioc-report", "count": len(records),
           "emails": records}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return path


def write_ioc_csv(records: list[dict], path: str) -> str:
    _ensure_dir(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["email_id", "type", "value", "severity", "note", "tags"])
        for rec in records:
            for ind in rec["indicators"]:
                w.writerow([rec["email_id"], ind["type"], ind["value"],
                            ind["severity"], ind["note"], "|".join(ind["tags"])])
    return path


def write_ioc_markdown(records: list[dict], path: str) -> str:
    _ensure_dir(path)
    lines = [f"# Phishing IOC Report", "", f"_Generated: {_now()}_", "",
             f"Emails analysed: **{len(records)}**", ""]
    sev_emoji = {"high": "🔴", "medium": "🟠", "low": "🟡"}
    for rec in records:
        cls = rec.get("classification", {})
        lines.append(f"## {rec['email_id']} — {rec.get('subject','(no subject)')}")
        if cls:
            lines.append(
                f"- **Verdict:** `{cls['label']}` "
                f"(phishing score {cls['phishing_score']}, confidence {cls['confidence']}, "
                f"via {cls['backend']})"
            )
        if not rec["indicators"]:
            lines.append("- No indicators extracted.")
            lines.append("")
            continue
        lines.append("")
        lines.append("| Sev | Type | Indicator | Note |")
        lines.append("|-----|------|-----------|------|")
        for ind in rec["indicators"]:
            emoji = sev_emoji.get(ind["severity"], "")
            lines.append(
                f"| {emoji} {ind['severity']} | {ind['type']} | `{ind['value']}` | {ind['note']} |"
            )
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def build_ioc_records(emails: list[dict], extractor, classifier=None) -> list[dict]:
    """Run extraction (and optional classification) over emails -> records."""
    records = []
    for e in emails:
        inds = extractor(e)
        rec = {
            "email_id": e.get("id", "?"),
            "subject": e.get("subject", ""),
            "indicators": iocs_to_dicts(inds),
        }
        if classifier is not None:
            rec["classification"] = classifier.classify(e).to_dict()
        records.append(rec)
    return records


# ---------------------------- Probe reports ----------------------------------

def write_probe_json(result: ProbeResult, path: str) -> str:
    _ensure_dir(path)
    doc = {"generated": _now(), "type": "boundary-probe-report"}
    doc.update(result.to_dict())
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return path


def write_probe_markdown(result: ProbeResult, path: str) -> str:
    _ensure_dir(path)
    s = result.summary
    lines = [
        "# Decision-Boundary Probe Report", "",
        f"_Generated: {_now()}_", "",
        f"- **Classifier backend:** `{result.backend}`",
        f"- **Seeds probed (correctly-flagged phishing):** {s.get('seeds_probed', 0)}",
        f"- **Perturbation strengths:** {result.strengths}",
        f"- **Combined-attack evasion rate:** "
        f"{int(s.get('combined_attack_evasion_rate', 0) * 100)}%",
        f"- **Verdict:** {s.get('verdict', '')}",
        "",
        "## Technique effectiveness (higher = weaker classifier here)", "",
        "| Technique | Evasion rate | Avg score drop |",
        "|-----------|--------------|----------------|",
    ]
    per = s.get("per_technique", {})
    for name in s.get("most_effective", []) + [k for k in per if k not in s.get("most_effective", [])]:
        v = per.get(name)
        if not v:
            continue
        lines.append(f"| {name} | {int(v['evasion_rate']*100)}% | {v['avg_score_drop']} |")
    lines += ["", "## Per-seed detail", ""]
    for seed in result.seeds:
        lines.append(f"### {seed.seed_id} (baseline score {seed.baseline_score})")
        for name, v in seed.per_technique.items():
            flag = "✅ evades" if v["evades"] else "—"
            mf = v["min_flip_strength"]
            lines.append(
                f"- `{name}`: {flag}"
                + (f" at strength {mf}" if mf is not None else "")
                + f" (max score drop {v['max_score_drop']})"
            )
        if seed.combined:
            c = seed.combined
            verdict = "✅ EVADED" if c["flipped"] else "held"
            lines.append(
                f"- **combined** ({len(c['techniques'])} techniques): {verdict}, "
                f"score {seed.baseline_score} → {c['phishing_score']} (drop {c['score_drop']})"
            )
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path
