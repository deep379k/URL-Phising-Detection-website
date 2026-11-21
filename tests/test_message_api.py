"""Regression tests for message NLP classification and API validation."""

import unittest

from app import app
from services.message_prediction import InvalidMessage, extract_urls, normalize_message


class MessageServiceTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize_message("  Hello\n  there  "), "Hello there")

    def test_empty_message(self):
        with self.assertRaises(InvalidMessage):
            normalize_message("   ")

    def test_url_extraction(self):
        self.assertEqual(
            extract_urls("Check https://example.com/login and www.test.org now"),
            ["https://example.com/login", "http://www.test.org"],
        )


class MessageAPITests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_legitimate_message(self):
        response = self.client.post(
            "/api/predict/message", json={"message": "Hi, I will reach the office at 5 pm."}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["prediction"], "Likely Legitimate")

    def test_spam_message_with_url_and_themes(self):
        response = self.client.post(
            "/api/predict/message",
            json={
                "message": (
                    "URGENT! You won a free prize. Claim now and verify your account at "
                    "http://192.168.1.1:8080/login"
                )
            },
        )
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["prediction"], "Likely Spam")
        self.assertTrue(body["scam_themes"])
        self.assertEqual(body["url_results"][0]["prediction"], "Potential Phishing")

    def test_empty_message_response(self):
        response = self.client.post("/api/predict/message", json={"message": ""})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["success"])


if __name__ == "__main__":
    unittest.main()
