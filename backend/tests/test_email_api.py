"""Regression tests for the lightweight email analysis endpoint."""

import unittest

from app import app
from services.email_analysis import InvalidEmail, normalize_email


class EmailAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_html_is_safely_reduced_to_text(self):
        self.assertEqual(normalize_email("<p>Hello <b>there</b></p>"), "Hello there")

    def test_empty_email(self):
        with self.assertRaises(InvalidEmail):
            normalize_email("  ")

    def test_legitimate_email(self):
        response = self.client.post(
            "/api/predict/email",
            json={"email": "Subject: Meeting update\nHi team, our meeting is at 3 pm tomorrow."},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["prediction"], "Likely Legitimate")

    def test_suspicious_email_with_phishing_url(self):
        response = self.client.post(
            "/api/predict/email",
            json={
                "email": (
                    "From: Support <help@example.com>\n"
                    "Reply-To: agent@unrelated.test\n"
                    "Subject: URGENT account verification\n\n"
                    "Dear customer, verify your account immediately at "
                    "http://192.168.1.1:8080/login"
                )
            },
        )
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["prediction"], "Potential Phishing")
        self.assertEqual(body["risk_level"], "High")
        self.assertTrue(any(item["name"] == "Reply-to domain mismatch" for item in body["indicators"]))

    def test_empty_email_response(self):
        response = self.client.post("/api/predict/email", json={"email": ""})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
