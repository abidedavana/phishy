"""Try every perturbation on each flagged email, alone and then stacked."""

from .perturbations import PERTURBATIONS


def probe_seed(email, classify):
    baseline = classify(email)
    if baseline["label"] != "phishing":
        return None

    def attack(adversarial):
        verdict = classify(adversarial)
        return {
            "evades": verdict["label"] == "legit",
            "score_drop": round(baseline["phishing_score"] - verdict["phishing_score"], 4),
        }

    techniques = {name: attack(perturb(email)) for name, perturb in PERTURBATIONS.items()}

    helpful = [name for name, result in techniques.items() if result["score_drop"] > 0.01]
    stacked = email
    for name in helpful:
        stacked = PERTURBATIONS[name](stacked)

    return {
        "id": email["id"],
        "baseline_score": baseline["phishing_score"],
        "techniques": techniques,
        "combined": {"techniques": helpful, **attack(stacked)},
    }


def probe(emails, classify):
    seeds = [seed for seed in (probe_seed(e, classify) for e in emails) if seed]
    count = len(seeds) or 1

    table = {}
    for name in PERTURBATIONS:
        results = [seed["techniques"][name] for seed in seeds]
        table[name] = {
            "evasion_rate": round(sum(r["evades"] for r in results) / count, 3),
            "avg_score_drop": round(sum(r["score_drop"] for r in results) / count, 4),
        }

    combined_rate = round(sum(s["combined"]["evades"] for s in seeds) / count, 3)
    if any(row["evasion_rate"] > 0 for row in table.values()):
        verdict = "BRITTLE: at least one single technique evades this classifier on its own."
    elif combined_rate > 0:
        verdict = "JOINTLY BRITTLE: no single technique evades, but stacking them does."
    else:
        verdict = "ROBUST: neither single techniques nor the combined attack evaded it."

    ranked = sorted(table, reverse=True,
                    key=lambda name: (table[name]["evasion_rate"], table[name]["avg_score_drop"]))
    return {
        "seeds_probed": len(seeds),
        "per_technique": table,
        "most_effective": ranked[:3],
        "combined_attack_evasion_rate": combined_rate,
        "verdict": verdict,
        "seeds": seeds,
    }
