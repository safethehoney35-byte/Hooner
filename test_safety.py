import unittest
from main import BLOCKED_TERMS, DETECTION_ONLY, RESTRICTED_DETECTION_ACTIONS, detection_approval_policy, playwright_error_detail

class SafetyRulesTest(unittest.TestCase):
    def test_linkvertise_selectors_are_visible_but_not_automated(self):
        self.assertEqual(set(DETECTION_ONLY), set(RESTRICTED_DETECTION_ACTIONS))
        for name in DETECTION_ONLY:
            allowed, reason = detection_approval_policy([name], clickable=True)
            self.assertFalse(allowed, name)
            self.assertTrue(reason, name)

    def test_ordinary_eligible_predefined_target_can_be_reviewed(self):
        allowed, reason = detection_approval_policy([], clickable=True)
        self.assertTrue(allowed)
        self.assertIn("Eligible", reason)

    def test_ineligible_predefined_target_has_reason(self):
        allowed, reason = detection_approval_policy([], clickable=False)
        self.assertFalse(allowed)
        self.assertIn("not a visible", reason)

    def test_playwright_error_keeps_actionability_call_log(self):
        error = Exception("Timeout 7000ms exceeded.\nCall log:\n - waiting for locator(\"button\")\n - <div class=overlay> intercepts pointer events")
        detail = playwright_error_detail(error)
        self.assertIn("intercepts pointer events", detail)
        self.assertIn("waiting for locator", detail)

    def test_financial_and_destructive_labels_are_blocked(self):
        for label in ("Payment", "Pay now", "Purchase", "Checkout", "Delete account", "Withdraw", "Payout", "Transfer"):
            self.assertIsNotNone(BLOCKED_TERMS.search(label), label)

    def test_ad_and_reward_labels_are_blocked(self):
        for label in ("Watch Ads", "Skip Ad", "Watch ads to continue", "Skip advertisement", "Claim reward"):
            self.assertIsNotNone(BLOCKED_TERMS.search(label), label)

    def test_ordinary_label_is_not_blocked(self):
        self.assertIsNone(BLOCKED_TERMS.search("Open settings"))

if __name__ == "__main__":
    unittest.main()
