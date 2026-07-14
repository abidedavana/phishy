import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishprobe.classifier import HeuristicClassifier
from phishprobe.perturbations import (
    PERTURBATIONS, homoglyph_swap, align_reply_to, soften_urgency,
)
from phishprobe.prober import DecisionBoundaryProber
from phishprobe.cli import load_emails

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "data", "samples.jsonl")

PHISH = {
    "id": "p", "subject": "Urgent: verify your account",
    "from_display": "PayPal Security", "from_addr": "a@paypa1-secure.com",
    "reply_to": "b@evil.ru", "return_path": "c@paypa1-secure.com",
    "body": "Verify your account immediately or it will be suspended. "
            "Confirm here: http://paypa1-secure.com/login within 24 hours.",
}


class TestPerturbationsPreserveInput(unittest.TestCase):
    def test_original_not_mutated(self):
        original = dict(PHISH)
        homoglyph_swap(PHISH, 1.0)
        self.assertEqual(PHISH, original)  # transforms return copies

    def test_align_reply_to_matches_from_domain(self):
        out = align_reply_to(PHISH, 1.0)
        self.assertTrue(out["reply_to"].endswith("paypa1-secure.com"))
        self.assertTrue(out["return_path"].endswith("paypa1-secure.com"))

    def test_soften_removes_urgency_terms(self):
        out = soften_urgency(PHISH, 1.0)
        self.assertNotIn("immediately", out["body"].lower())

    def test_all_perturbations_return_dicts(self):
        for name, fn in PERTURBATIONS.items():
            out = fn(PHISH, 0.5)
            self.assertIsInstance(out, dict, name)
            self.assertIn("body", out, name)


class TestProber(unittest.TestCase):
    def test_probe_only_runs_on_flagged_phish(self):
        clf = HeuristicClassifier()
        prober = DecisionBoundaryProber(clf)
        # a legit email should not be probed (returns None)
        legit = {"id": "l", "subject": "notes", "from_addr": "s@company.com",
                 "reply_to": "s@company.com", "return_path": "s@company.com",
                 "from_display": "Sarah", "body": "notes are in the drive"}
        self.assertIsNone(prober.probe_seed(legit))

    def test_run_produces_summary(self):
        clf = HeuristicClassifier()
        result = DecisionBoundaryProber(clf).run(load_emails(DATA))
        self.assertIn("per_technique", result.summary)
        self.assertGreater(result.summary["seeds_probed"], 0)
        self.assertEqual(len(result.summary["most_effective"]), 3)

    def test_summary_has_verdict(self):
        clf = HeuristicClassifier()
        result = DecisionBoundaryProber(clf).run(load_emails(DATA))
        v = result.summary["verdict"]
        self.assertTrue(v.startswith(("ROBUST", "JOINTLY BRITTLE", "BRITTLE")))

    def test_at_least_one_technique_moves_the_score(self):
        clf = HeuristicClassifier()
        seed = DecisionBoundaryProber(clf).probe_seed(PHISH)
        self.assertIsNotNone(seed)
        drops = [v["max_score_drop"] for v in seed.per_technique.values()]
        self.assertTrue(any(d > 0 for d in drops))


if __name__ == "__main__":
    unittest.main()
