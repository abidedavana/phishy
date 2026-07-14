import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishprobe.classifier import HeuristicClassifier, get_classifier
from phishprobe.cli import load_emails

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "data", "samples.jsonl")


class TestHeuristic(unittest.TestCase):
    def setUp(self):
        self.clf = HeuristicClassifier()

    def test_flags_obvious_phish(self):
        e = {
            "id": "x", "subject": "Urgent verify",
            "from_display": "PayPal", "from_addr": "a@paypa1-secure.com",
            "reply_to": "b@evil.ru", "return_path": "c@paypa1-secure.com",
            "body": "Verify your account immediately or it will be suspended: "
                    "http://paypa1-secure.com/login within 24 hours",
        }
        c = self.clf.classify(e)
        self.assertEqual(c.label, "phishing")
        self.assertGreater(c.phishing_score, 0.5)

    def test_passes_clean_legit(self):
        e = {
            "id": "y", "subject": "Team notes",
            "from_display": "Sarah", "from_addr": "sarah@company.com",
            "reply_to": "sarah@company.com", "return_path": "sarah@company.com",
            "body": "Thanks for the sync, notes are in the shared drive.",
        }
        c = self.clf.classify(e)
        self.assertEqual(c.label, "legit")

    def test_scores_are_bounded(self):
        for e in load_emails(DATA):
            c = self.clf.classify(e)
            self.assertGreaterEqual(c.phishing_score, 0.0)
            self.assertLessEqual(c.phishing_score, 1.0)
            self.assertIn(c.label, ("phishing", "legit"))

    def test_accuracy_on_labelled_samples(self):
        emails = load_emails(DATA)
        correct = sum(self.clf.classify(e).label == e["label"] for e in emails)
        self.assertGreaterEqual(correct / len(emails), 0.8)  # >=80% on the demo set

    def test_get_classifier_defaults_to_heuristic(self):
        self.assertEqual(get_classifier().name, "heuristic")


if __name__ == "__main__":
    unittest.main()
