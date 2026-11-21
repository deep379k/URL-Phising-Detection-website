"""Admin session and analytics access regression tests."""

import unittest

from werkzeug.security import generate_password_hash

from app import app


class AdminAuthenticationTests(unittest.TestCase):
    def setUp(self):
        app.config.update(
            TESTING=True,
            ADMIN_USERNAME="test-admin",
            ADMIN_PASSWORD_HASH=generate_password_hash("correct-password"),
        )
        self.client = app.test_client()

    def test_analytics_requires_authentication(self):
        response = self.client.get("/api/analytics/overview")
        self.assertEqual(response.status_code, 401)

    def test_login_session_and_logout(self):
        login = self.client.post(
            "/api/admin/login",
            json={"username": "test-admin", "password": "correct-password"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertTrue(self.client.get("/api/admin/session").get_json()["authenticated"])
        self.assertEqual(self.client.post("/api/admin/logout").status_code, 200)
        self.assertFalse(self.client.get("/api/admin/session").get_json()["authenticated"])

    def test_invalid_password_is_rejected(self):
        response = self.client.post(
            "/api/admin/login",
            json={"username": "test-admin", "password": "wrong-password"},
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
