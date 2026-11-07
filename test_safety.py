import unittest

from main import (
    REPLAY_BLOCKED_TERMS,
    normalized_action,
    replay_block_reason,
    adapt_recorder_target,
)


class ReplaySafetyTest(unittest.TestCase):
    def test_ad_reward_financial_and_destructive_terms_are_blocked(self):
        for label in (
            "Watch Ads", "Skip Ad", "Watch ads to continue", "Claim reward",
            "Pay now", "Purchase", "Checkout", "Delete account",
            "Withdraw", "Payout", "Transfer",
        ):
            self.assertIsNotNone(REPLAY_BLOCKED_TERMS.search(label), label)

    def test_ordinary_label_is_not_blocked(self):
        self.assertIsNone(REPLAY_BLOCKED_TERMS.search("Open settings"))

    def test_replay_policy_blocks_ad_and_reward_targets(self):
        for label in ("Watch Ads", "Continue to reward", "Skip Ad"):
            action = normalized_action({
                "type": "click",
                "target": {"tag": "button", "text": label},
                "gapMs": 100,
            })
            self.assertIsNotNone(replay_block_reason(action), label)

    def test_replay_policy_allows_ordinary_target(self):
        action = normalized_action({
            "type": "click",
            "target": {"tag": "button", "text": "Open settings"},
            "gapMs": 100,
        })
        self.assertIsNone(replay_block_reason(action))

    def test_normalization_preserves_target_identity_and_clamps_gap(self):
        action = normalized_action({
            "type": "click",
            "gapMs": 9999999,
            "target": {
                "identity": {"fingerprint": {"tag": "button", "attrs": {"id": "save"}}},
                "cssPath": "button#save",
            },
        })
        self.assertEqual(action["gapMs"], 600000)
        self.assertEqual(action["target"]["tag"], "button")
        self.assertIn("button#save", action["target"]["_nexus_selectors"])

    def test_invalid_action_is_rejected(self):
        with self.assertRaises(ValueError):
            normalized_action({"type": "type", "target": {}})


if __name__ == "__main__":
    unittest.main()
