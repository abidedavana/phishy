import unittest

from phishprobe.__main__ import load_emails
from phishprobe.classifier import _parse_reply, heuristic

DATA = "data/samples.jsonl"


class TestHeuristic(unittest.TestCase):
    def test_flags_obvious_phish(self):
        e = {
            "id": "x", "subject": "Urgent verify",
            "from_display": "PayPal", "from_addr": "a@paypa1-secure.com",
            "reply_to": "b@evil.ru", "return_path": "c@paypa1-secure.com",
            "body": "Verify your account immediately or it will be suspended: "
                    "http://paypa1-secure.com/login within 24 hours",
        }
        verdict = heuristic(e)
        self.assertEqual(verdict["label"], "phishing")
        self.assertGreater(verdict["phishing_score"], 0.5)

    def test_passes_clean_legit(self):
        e = {
            "id": "y", "subject": "Team notes",
            "from_display": "Sarah", "from_addr": "sarah@company.com",
            "reply_to": "sarah@company.com", "return_path": "sarah@company.com",
            "body": "Thanks for the sync, notes are in the shared drive.",
        }
        self.assertEqual(heuristic(e)["label"], "legit")

    def test_scores_are_bounded(self):
        for e in load_emails(DATA):
            verdict = heuristic(e)
            self.assertGreaterEqual(verdict["phishing_score"], 0.0)
            self.assertLessEqual(verdict["phishing_score"], 1.0)
            self.assertIn(verdict["label"], ("phishing", "legit"))

    def test_accuracy_on_labelled_samples(self):
        emails = load_emails(DATA)
        correct = sum(heuristic(e)["label"] == e["label"] for e in emails)
        self.assertGreaterEqual(correct / len(emails), 0.8)


class TestParseReply(unittest.TestCase):
    def test_tolerates_text_around_json(self):
        reply = _parse_reply('Sure! {"label": "legit", "phishing_score": 0.1} Done.')
        self.assertEqual(reply["label"], "legit")

    def test_unparseable_reply_does_not_crash(self):
        self.assertEqual(_parse_reply("this looks like phishing")["label"], "phishing")
        self.assertEqual(_parse_reply("{not json}")["label"], "legit")


if __name__ == "__main__":
    unittest.main()
