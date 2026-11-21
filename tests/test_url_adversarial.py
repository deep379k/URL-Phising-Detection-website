"""Adversarial URL cases that must remain stable across model retraining."""

import unittest

from app import app


class URLAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def scan(self, value):
        return self.client.post("/api/predict/url", json={"url": value})

    def test_malformed_inputs_are_rejected_before_prediction(self):
        malformed = [
            "hvbdkb",
            "a" * 70 + ".com",
            "bad_domain.com",
            "bad..com",
            "-leadinghyphen.com",
            "trailinghyphen-.com",
            "example.c",
            "http://example.com:99999",
        ]
        for value in malformed:
            with self.subTest(value=value):
                response = self.scan(value)
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.get_json()["success"])

    def test_high_confidence_phishing_patterns(self):
        suspicious = [
            "http://192.168.1.10:8080/login",
            "http://https-secure-login.com/account",
            "http://google-security-check.example.com/login",
            "http://secure-login.example.com/account",
            "http://a.b.c.d.example.com/login",
            "http://example.com//redirect/account",
        ]
        for value in suspicious:
            with self.subTest(value=value):
                response = self.scan(value)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()["prediction"], "Potential Phishing")

    def test_stretched_brand_names_are_detected(self):
        stretched = [
            "gooooooogle.in",
            "goooogle.com",
            "paypaall.com",
            "amaaazon.in",
            "netfliiix.com",
        ]
        for value in stretched:
            with self.subTest(value=value):
                response = self.scan(value)
                self.assertEqual(response.status_code, 200)
                body = response.get_json()
                self.assertEqual(body["prediction"], "Potential Phishing")
                self.assertEqual(body["risk_level"], "High")
                self.assertIn("BrandLookalike", [item["feature"] for item in body["indicators"]])

    def test_random_well_formed_domains_are_never_called_legitimate(self):
        random_domains = [
            "https://hvbdkb.com",
            "https://qwertyuiopasdfgh.net",
            "https://random-domain-name-49382.org",
        ]
        for value in random_domains:
            with self.subTest(value=value):
                response = self.scan(value)
                self.assertEqual(response.status_code, 200)
                self.assertNotEqual(response.get_json()["prediction"], "Likely Legitimate")

    def test_long_and_symbol_heavy_urls_do_not_crash(self):
        cases = [
            "https://unknown-example.com/" + "a" * 500,
            "https://unknown-example.com/path?next=%2Faccount&x=1&y=2#section",
            "https://unknown-example.com/verify?token=" + "ab12" * 100,
        ]
        for value in cases:
            with self.subTest(value=value):
                response = self.scan(value)
                self.assertEqual(response.status_code, 200)
                self.assertIn(response.get_json()["prediction"], {"Potential Phishing", "Unverified Domain"})

    def test_recognized_official_domains_remain_legitimate(self):
        for value in ("https://google.com", "https://www.microsoft.com", "https://paypal.com"):
            with self.subTest(value=value):
                response = self.scan(value)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()["prediction"], "Likely Legitimate")

    def test_official_domain_over_http_is_never_called_legitimate(self):
        value = (
            "http://docs.google.com/spreadsheet/viewform?"
            "formkey=dE5rVEdSV2pBdkpSRy11V3o2eDdwbmc6MQ"
        )
        response = self.scan(value)
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["prediction"], "Potential Phishing")
        self.assertEqual(body["risk_level"], "High")
        self.assertEqual(body["analysis_source"], "security-rule")
        self.assertIn("HTTPS", [item["feature"] for item in body["indicators"]])


if __name__ == "__main__":
    unittest.main()
