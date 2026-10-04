import unittest

from usertrace_cli import classify_response, load_catalog, validate_username


class UserTraceTests(unittest.TestCase):
    def setUp(self):
        self.platform = {
            "name": "Test", "category": "test",
            "url_template": "https://example.com/{username}",
            "detection_method": "status_code", "error_code": 404,
            "not_found_strings": ["user not found"], "found_strings": [],
        }

    def test_username_validation(self):
        for value in ("a", "john_doe", "9.test-user", "a" * 30):
            self.assertTrue(validate_username(value), value)
        for value in ("", ".john", "-john", "a" * 31, "two words", "a/b", ";whoami"):
            self.assertFalse(validate_username(value), value)

    def test_http_and_body_classification(self):
        base = "https://example.com/johndoe"
        self.assertEqual(classify_response(self.platform, 429, base, ""), ("UNCERTAIN", "rate-limited"))
        self.assertEqual(classify_response(self.platform, 403, base, ""), ("UNCERTAIN", "access restricted"))
        self.assertEqual(classify_response(self.platform, 503, base, ""), ("UNCERTAIN", "upstream server error"))
        self.assertEqual(classify_response(self.platform, 200, base, "verify you are human"), ("UNCERTAIN", "anti-bot challenge"))
        self.assertEqual(classify_response(self.platform, 404, base, "" )[0], "NOT FOUND")
        self.assertEqual(classify_response(self.platform, 200, base, "Welcome" )[0], "FOUND")
        self.assertEqual(classify_response(self.platform, 302, "https://example.com/login", "" )[0], "UNCERTAIN")

    def test_error_message_mode_requires_positive_marker(self):
        p = {**self.platform, "detection_method": "error_message", "found_strings": ["profile-view"]}
        self.assertEqual(classify_response(p, 200, "https://example.com/johndoe", "generic page")[0], "UNCERTAIN")
        self.assertEqual(classify_response(p, 200, "https://example.com/johndoe", "PROFILE-VIEW")[0], "FOUND")

    def test_catalog_has_120_plus_valid_entries(self):
        catalog = load_catalog()
        self.assertGreaterEqual(len(catalog), 120)
        self.assertTrue(all(p.get("name") and p.get("category") and "{username}" in p.get("url_template", "") for p in catalog))
        self.assertTrue(any(p.get("high_difficulty") for p in catalog))


if __name__ == "__main__":
    unittest.main()
