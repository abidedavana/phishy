import unittest

from phishprobe.iocs import defang, extract_iocs, looks_like_brand, refang, registrable_domain


class TestHelpers(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(refang("hxxp://bad[.]com"), "http://bad.com")
        self.assertEqual(refang("hxxps://a[dot]b[.]com"), "https://a.b.com")

    def test_defang_roundtrip_is_safe(self):
        d = defang("http://evil.com")
        self.assertNotIn("http:", d)
        self.assertIn("hxxp", d)

    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("login.secure.paypa1-secure.com"),
                         "paypa1-secure.com")

    def test_lookalike_detects_typosquat(self):
        self.assertIsNotNone(looks_like_brand("paypa1-secure.com"))

    def test_exact_brand_is_not_lookalike(self):
        self.assertIsNone(looks_like_brand("amazon.com"))


class TestExtraction(unittest.TestCase):
    def setUp(self):
        self.phish = {
            "id": "t1", "subject": "Verify now",
            "from_display": "PayPal Security",
            "from_addr": "service@paypa1-secure.com",
            "reply_to": "verify@mailer-support.ru",
            "return_path": "bounce@paypa1-secure.com",
            "body": "Verify your account http://paypa1-secure.com/login urgent within 24 hours",
        }

    def test_extracts_url_and_defangs(self):
        urls = [i for i in extract_iocs(self.phish) if i["type"] == "url"]
        self.assertTrue(urls)
        self.assertNotIn("http:", urls[0]["value"])

    def test_detects_reply_to_mismatch(self):
        self.assertTrue(any("reply-to-mismatch" in i["tags"] for i in extract_iocs(self.phish)))

    def test_detects_display_name_spoof(self):
        self.assertTrue(any("display-name-spoof" in i["tags"] for i in extract_iocs(self.phish)))

    def test_ip_literal_url_flagged_high_and_defanged(self):
        e = dict(self.phish, body="pay here http://185.203.118.44/dhl", reply_to="", return_path="")
        ips = [i for i in extract_iocs(e) if i["type"] == "ip"]
        self.assertEqual(ips[0]["severity"], "high")
        self.assertEqual(ips[0]["value"], "185[.]203[.]118[.]44")

    def test_unicode_host_flagged(self):
        e = dict(self.phish, body="log in at http://pаypal.com/login")
        self.assertTrue(any("punycode-or-homoglyph" in i["tags"] for i in extract_iocs(e)))

    def test_legit_email_has_no_high_severity(self):
        legit = {
            "id": "t2", "subject": "Your order shipped",
            "from_display": "Amazon.com", "from_addr": "ship@amazon.com",
            "reply_to": "ship@amazon.com", "return_path": "bounce@amazon.com",
            "body": "Your order has shipped and arrives Thursday. No action needed.",
        }
        self.assertFalse(any(i["severity"] == "high" for i in extract_iocs(legit)))


if __name__ == "__main__":
    unittest.main()
