import unittest

from phishprobe.__main__ import load_emails
from phishprobe.classifier import heuristic
from phishprobe.perturbations import PERTURBATIONS, align_reply_to, soften_urgency
from phishprobe.prober import probe, probe_seed

DATA = "data/samples.jsonl"

PHISH = {
    "id": "p", "subject": "Urgent: verify your account",
    "from_display": "PayPal Security", "from_addr": "a@paypa1-secure.com",
    "reply_to": "b@evil.ru", "return_path": "c@paypa1-secure.com",
    "body": "Verify your account immediately or it will be suspended. "
            "Confirm here: http://paypa1-secure.com/login within 24 hours.",
}


class TestPerturbations(unittest.TestCase):
    def test_original_not_mutated(self):
        original = dict(PHISH)
        for perturb in PERTURBATIONS.values():
            perturb(PHISH)
        self.assertEqual(PHISH, original)

    def test_align_reply_to_matches_from_domain(self):
        out = align_reply_to(PHISH)
        self.assertTrue(out["reply_to"].endswith("paypa1-secure.com"))
        self.assertTrue(out["return_path"].endswith("paypa1-secure.com"))

    def test_soften_removes_urgency_terms(self):
        self.assertNotIn("immediately", soften_urgency(PHISH)["body"].lower())


class TestProber(unittest.TestCase):
    def test_probe_only_runs_on_flagged_phish(self):
        legit = {"id": "l", "subject": "notes", "from_addr": "s@company.com",
                 "reply_to": "s@company.com", "return_path": "s@company.com",
                 "from_display": "Sarah", "body": "notes are in the drive"}
        self.assertIsNone(probe_seed(legit, heuristic))

    def test_at_least_one_technique_moves_the_score(self):
        seed = probe_seed(PHISH, heuristic)
        self.assertTrue(any(r["score_drop"] > 0 for r in seed["techniques"].values()))

    def test_headline_finding_on_the_samples(self):
        result = probe(load_emails(DATA), heuristic)
        self.assertEqual(result["seeds_probed"], 6)
        self.assertTrue(all(r["evasion_rate"] == 0 for r in result["per_technique"].values()))
        self.assertEqual(result["combined_attack_evasion_rate"], 1.0)
        self.assertEqual(result["most_effective"][0], "url_shortener")
        self.assertTrue(result["verdict"].startswith("JOINTLY BRITTLE"))


if __name__ == "__main__":
    unittest.main()
