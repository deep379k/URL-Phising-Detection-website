"""Regression tests for the shared URL features and Flask API."""

import unittest

from app import app
from url_features import InvalidURL, extract_url_features


class URLFeatureTests(unittest.TestCase):
    def test_legitimate_https_url(self):
        features = extract_url_features("https://www.google.com")
        self.assertEqual(features["UsingIP"], 1)
        self.assertEqual(features["HTTPS"], 1)
        self.assertEqual(features["NonStdPort"], 1)

    def test_ip_http_url(self):
        features = extract_url_features("http://192.168.1.1:8080/login")
        self.assertEqual(features["UsingIP"], -1)
        self.assertEqual(features["HTTPS"], -1)
        self.assertEqual(features["NonStdPort"], -1)

    def test_invalid_url(self):
        with self.assertRaises(InvalidURL):
            extract_url_features("not a valid url")


class URLAPITests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["url_model_loaded"])

    def test_safe_example(self):
        response = self.client.post("/api/predict/url", json={"url": "https://www.google.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["prediction"], "Likely Legitimate")

    def test_critical_ip_rule(self):
        response = self.client.post(
            "/api/predict/url", json={"url": "http://192.168.1.1:8080/login"}
        )
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["prediction"], "Potential Phishing")
        self.assertEqual(body["risk_level"], "High")
        self.assertEqual(body["analysis_source"], "security-rule")

    def test_brand_lookalike_is_phishing(self):
        response = self.client.post("/api/predict/url", json={"url": "gooogle.in"})
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["prediction"], "Potential Phishing")
        self.assertEqual(body["risk_level"], "High")
        self.assertEqual(body["analysis_source"], "security-rule")
        self.assertEqual(body["indicators"][0]["feature"], "BrandLookalike")

    def test_https_word_in_insecure_hostname_is_phishing(self):
        response = self.client.post("/api/predict/url", json={"url": "https.abess.cc"})
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["prediction"], "Potential Phishing")
        self.assertEqual(body["risk_level"], "High")
        self.assertEqual(body["analysis_source"], "security-rule")
        self.assertIn("HTTPSDomainURL", [item["feature"] for item in body["indicators"]])

    def test_unknown_clean_domain_is_not_called_legitimate(self):
        response = self.client.post("/api/predict/url", json={"url": "hukufehkusj.com"})
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["prediction"], "Unverified Domain")
        self.assertEqual(body["risk_level"], "Medium")
        self.assertEqual(body["analysis_source"], "verification-policy")
        self.assertIn("UnverifiedDomain", [item["feature"] for item in body["indicators"]])

    def test_official_brand_domain_is_not_lookalike(self):
        response = self.client.post(
            "/api/predict/url", json={"url": "https://www.google.com"}
        )
        body = response.get_json()
        self.assertNotIn("BrandLookalike", [item["feature"] for item in body["indicators"]])

    def test_invalid_url_response(self):
        response = self.client.post("/api/predict/url", json={"url": "not a valid url"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["success"])

    def test_manual_feature_prediction(self):
        names = [
            "UsingIP", "PrefixSuffix-", "SubDomains", "HTTPS", "NonStdPort",
            "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags",
            "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding",
            "StatusBarCust", "DisableRightClick", "AgeofDomain", "DNSRecording",
            "WebsiteTraffic", "PageRank", "GoogleIndex", "StatsReport",
        ]
        response = self.client.post(
            "/api/predict/url/manual",
            json={"features": {name: 1 for name in names}},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["feature_count"], 21)

    def test_manual_feature_validation(self):
        response = self.client.post(
            "/api/predict/url/manual", json={"features": {"UsingIP": 2}}
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["success"])


if __name__ == "__main__":
    unittest.main()

