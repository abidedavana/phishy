"""Write report.json and report.md."""

import json
import os


def write_reports(out_dir, backend, records, probe_result):
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "report.json")
    md_path = os.path.join(out_dir, "report.md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"backend": backend, "emails": records, "probe": probe_result},
                  f, indent=2, ensure_ascii=False)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(_markdown(backend, records, probe_result))
    return [json_path, md_path]


def _markdown(backend, records, probe_result):
    table = probe_result["per_technique"]
    lines = [
        "# PhishProbe report", "",
        f"- Backend: `{backend}`",
        f"- Emails analysed: {len(records)}",
        f"- Seeds probed: {probe_result['seeds_probed']}",
        f"- Combined-attack evasion rate: {probe_result['combined_attack_evasion_rate']:.0%}",
        f"- Verdict: {probe_result['verdict']}", "",
        "## Techniques", "",
        "| Technique | Evasion rate | Avg score drop |",
        "|-----------|--------------|----------------|",
    ]
    for name in sorted(table, key=lambda n: table[n]["avg_score_drop"], reverse=True):
        lines.append(f"| {name} | {table[name]['evasion_rate']:.0%} | "
                     f"{table[name]['avg_score_drop']} |")

    lines += ["", "## Combined attack", "",
              "| Seed | Baseline score | Techniques stacked | Result | Score drop |",
              "|------|----------------|--------------------|--------|------------|"]
    for seed in probe_result["seeds"]:
        combined = seed["combined"]
        result = "evaded" if combined["evades"] else "held"
        lines.append(f"| {seed['id']} | {seed['baseline_score']} | "
                     f"{len(combined['techniques'])} | {result} | {combined['score_drop']} |")

    lines += ["", "## Indicators", ""]
    for record in records:
        verdict = record["verdict"]
        lines += [f"### {record['id']}: {record['subject']}", "",
                  f"Verdict: `{verdict['label']}` (score {verdict['phishing_score']})", ""]
        if record["indicators"]:
            lines += ["| Severity | Type | Indicator | Note |",
                      "|----------|------|-----------|------|"]
            for ind in record["indicators"]:
                lines.append(f"| {ind['severity']} | {ind['type']} | `{ind['value']}` | "
                             f"{ind['note']} |")
            lines.append("")
    return "\n".join(lines)
