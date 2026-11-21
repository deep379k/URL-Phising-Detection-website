"""Tests for merging live intelligence with the URL model verdict."""

import unittest
from unittest.mock import patch

from app import app


class URLIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @patch("services.url_prediction.analyze_live_url")
    def test_critical_reputation_result_overrides_model(self, live_mock):
        live_mock.return_value = {
            "malicious": True,
            "caution": True,
            "checks": [{
                "name": "Google Safe Browsing",
                "status": "failed",
                "severity": "critical",
                "detail": "Google reported this URL as unsafe.",
            }],
        }
        response = self.client.post(
            "/api/predict/url",
            json={"url": "https://google.com", "live_checks": True},
        )
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["prediction"], "Potential Phishing")
        self.assertEqual(body["risk_level"], "High")
        self.assertEqual(body["analysis_source"], "hybrid-live-intelligence")

    @patch("services.url_prediction.analyze_live_url")
    def test_unavailable_provider_does_not_become_safe_evidence(self, live_mock):
        live_mock.return_value = {
            "malicious": False,
            "caution": False,
            "checks": [{
                "name": "VirusTotal",
                "status": "unavailable",
                "severity": "info",
                "detail": "No existing report.",
            }],
        }
        response = self.client.post(
            "/api/predict/url",
            json={"url": "https://random-domain-name-49382.org", "live_checks": True},
        )
        body = response.get_json()
        self.assertNotEqual(body["prediction"], "Likely Legitimate")
        self.assertEqual(body["live_intelligence"]["checks"][0]["status"], "unavailable")

    def test_live_checks_are_opt_in_for_non_browser_consumers(self):
        response = self.client.post("/api/predict/url", json={"url": "https://google.com"})
        body = response.get_json()
        self.assertTrue(body["live_intelligence"]["skipped"])


if __name__ == "__main__":
    unittest.main()
