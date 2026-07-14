"""Decision-boundary probing.

Given a classifier and a set of seed phishing emails that the classifier
already flags correctly, this sweeps each adversarial perturbation across
increasing strengths and records how the classifier's phishing_score moves.

We report, per technique:
  * evasion@strength     — did the label flip phishing -> legit?
  * min_flip_strength    — the smallest strength that caused a flip (boundary)
  * max_score_drop       — largest drop in phishing_score observed
And a combined attack that chains the individually-effective techniques.

The "decision boundary" is the strength at which a small, meaning-preserving
change tips the label. Techniques that flip it cheaply are the model's
weaknesses.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .classifier import BaseClassifier, Classification
from .perturbations import PERTURBATIONS, apply_chain


@dataclass
class Trial:
    technique: str
    strength: float
    label: str
    phishing_score: float
    flipped: bool                     # phishing -> legit vs the seed baseline

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SeedResult:
    seed_id: str
    baseline_label: str
    baseline_score: float
    trials: list[Trial] = field(default_factory=list)
    # technique -> summary
    per_technique: dict[str, dict] = field(default_factory=dict)
    combined: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class ProbeResult:
    backend: str
    strengths: list[float]
    seeds: list[SeedResult] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "strengths": self.strengths,
            "seeds": [s.to_dict() for s in self.seeds],
            "summary": self.summary,
        }


class DecisionBoundaryProber:
    def __init__(self, classifier: BaseClassifier,
                 strengths: list[float] | None = None):
        self.clf = classifier
        self.strengths = strengths or [0.25, 0.5, 0.75, 1.0]

    def probe_seed(self, email: dict) -> SeedResult | None:
        base = self.clf.classify(email)
        # Only probe samples the classifier actually flags as phishing —
        # you cannot "evade" a detection that never fired.
        if base.label != "phishing":
            return None

        seed = SeedResult(
            seed_id=email.get("id", "?"),
            baseline_label=base.label,
            baseline_score=base.phishing_score,
        )

        for name, fn in PERTURBATIONS.items():
            min_flip: float | None = None
            max_drop = 0.0
            for s in self.strengths:
                adv = fn(email, s)
                c = self.clf.classify(adv)
                flipped = c.label == "legit"
                drop = round(base.phishing_score - c.phishing_score, 4)
                max_drop = max(max_drop, drop)
                if flipped and min_flip is None:
                    min_flip = s
                seed.trials.append(Trial(name, s, c.label, c.phishing_score, flipped))
            seed.per_technique[name] = {
                "evades": min_flip is not None,
                "min_flip_strength": min_flip,
                "max_score_drop": max_drop,
            }

        # Combined attack: chain every technique that helped (dropped the score),
        # at full strength — the realistic "stacked" evasion.
        helpful = [n for n, v in seed.per_technique.items() if v["max_score_drop"] > 0.01]
        if helpful:
            adv = apply_chain(email, helpful, strength=1.0)
            c = self.clf.classify(adv)
            seed.combined = {
                "techniques": helpful,
                "label": c.label,
                "phishing_score": c.phishing_score,
                "flipped": c.label == "legit",
                "score_drop": round(base.phishing_score - c.phishing_score, 4),
            }
        return seed

    def run(self, emails: list[dict]) -> ProbeResult:
        result = ProbeResult(backend=self.clf.name, strengths=self.strengths)
        for e in emails:
            sr = self.probe_seed(e)
            if sr is not None:
                result.seeds.append(sr)
        result.summary = self._summarise(result)
        return result

    @staticmethod
    def _summarise(result: ProbeResult) -> dict:
        n_seeds = len(result.seeds)
        # aggregate per-technique evasion rate across seeds
        techniques: dict[str, dict] = {}
        for seed in result.seeds:
            for name, v in seed.per_technique.items():
                t = techniques.setdefault(name, {"evaded": 0, "drops": []})
                if v["evades"]:
                    t["evaded"] += 1
                t["drops"].append(v["max_score_drop"])

        table = {}
        for name, t in techniques.items():
            drops = t["drops"] or [0.0]
            table[name] = {
                "evasion_rate": round(t["evaded"] / n_seeds, 3) if n_seeds else 0.0,
                "avg_score_drop": round(sum(drops) / len(drops), 4),
            }

        combined_flips = sum(
            1 for s in result.seeds if s.combined and s.combined["flipped"]
        )
        combined_rate = round(combined_flips / n_seeds, 3) if n_seeds else 0.0
        # rank techniques by evasion rate then average score drop
        ranked = sorted(
            table.items(),
            key=lambda kv: (kv[1]["evasion_rate"], kv[1]["avg_score_drop"]),
            reverse=True,
        )

        any_single = any(v["evasion_rate"] > 0 for v in table.values())
        if combined_rate == 0 and not any_single:
            verdict = ("ROBUST — no single technique and no combined attack "
                       "evaded this classifier on any probed seed.")
        elif combined_rate > 0 and not any_single:
            verdict = ("JOINTLY BRITTLE — no single technique evades, but "
                       "stacking them does (individually-weak signals).")
        else:
            verdict = ("BRITTLE — at least one single technique evades this "
                       "classifier on its own.")

        return {
            "seeds_probed": n_seeds,
            "per_technique": table,
            "most_effective": [name for name, _ in ranked[:3]],
            "combined_attack_evasion_rate": combined_rate,
            "verdict": verdict,
        }
