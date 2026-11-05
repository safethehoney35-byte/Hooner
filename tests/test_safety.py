import unittest
from main import BLOCKED_TERMS, DETECTION_ONLY

class SafetyRulesTest(unittest.TestCase):
    def test_linkvertise_selectors_are_detection_only(self):
        self.assertIn("watchAds", DETECTION_ONLY)
        self.assertIn("skipAdContainer", DETECTION_ONLY)
        self.assertIn("openHereButton", DETECTION_ONLY)

    def test_reward_and_sensitive_labels_are_blocked(self):
        for label in ("Watch Ads", "Skip Ad", "Claim reward", "Payment", "Delete account"):
            self.assertIsNotNone(BLOCKED_TERMS.search(label), label)

    def test_ordinary_label_is_not_blocked(self):
        self.assertIsNone(BLOCKED_TERMS.search("Open settings"))

if __name__ == "__main__":
    unittest.main()
