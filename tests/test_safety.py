import unittest
from main import BLOCKED_TERMS, DETECTION_ONLY

class SafetyRulesTest(unittest.TestCase):
    def test_linkvertise_selectors_are_detection_only(self):
        self.assertIn("watchAds", DETECTION_ONLY)
        self.assertIn("skipAdContainer", DETECTION_ONLY)
        self.assertIn("openHereButton", DETECTION_ONLY)

    def test_financial_and_destructive_labels_are_blocked(self):
        for label in ("Payment", "Pay now", "Purchase", "Checkout", "Delete account", "Withdraw", "Payout", "Transfer"):
            self.assertIsNotNone(BLOCKED_TERMS.search(label), label)

    def test_ad_labels_are_not_blocked(self):
        # Watch Ads / Skip Ad are linkvertise flow actions — intentionally clickable.
        for label in ("Watch Ads", "Skip Ad", "Watch ads to continue", "Skip advertisement"):
            self.assertIsNone(BLOCKED_TERMS.search(label), f"Should not block: {label}")

    def test_ordinary_label_is_not_blocked(self):
        self.assertIsNone(BLOCKED_TERMS.search("Open settings"))

if __name__ == "__main__":
    unittest.main()
