import unittest
from detector.url_features import analyze_url

class URLFeatureTests(unittest.TestCase):
    def test_adds_scheme(self):
        parsed, error = analyze_url("example.com")
        self.assertIsNone(error)
        self.assertEqual(parsed["scheme"], "http")
        self.assertEqual(parsed["hostname"], "example.com")

    def test_rejects_unsupported_scheme(self):
        parsed, error = analyze_url("file:///etc/passwd")
        self.assertIsNone(parsed)
        self.assertIn("Only http", error)

    def test_ip_literal(self):
        parsed, error = analyze_url("http://192.0.2.1/login")
        self.assertIsNone(error)
        self.assertTrue(parsed["features"]["ip_literal"])

    def test_empty_url(self):
        parsed, error = analyze_url("")
        self.assertIsNone(parsed)
        self.assertIsNotNone(error)

if __name__ == "__main__":
    unittest.main()
