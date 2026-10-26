import unittest
from detector.url_features import analyze_url
from detector.rule_engine import score_rules
from detector.fusion import combine_signals

class ScoringTests(unittest.TestCase):
    def test_score_bounded(self):
        parsed, error = analyze_url("http://192.0.2.1/login/verify/account?x=" + "a"*120)
        self.assertIsNone(error)
        result = score_rules(parsed)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_reputation_match_forces_high(self):
        parsed, _ = analyze_url("https://example.com")
        rules = score_rules(parsed)
        result = combine_signals(parsed, {"status":"resolved"}, rules,
                                 {"status":"flagged","flagged":True,"message":"match"})
        self.assertEqual(result["risk_band"], "High")
        self.assertGreaterEqual(result["risk_score"], 85)

if __name__ == "__main__":
    unittest.main()
