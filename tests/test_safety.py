import asyncio
import unittest
from unittest.mock import patch

import main


SAMPLE_TARGET = {
    "tag": "button",
    "role": "button",
    "text": "Add Element",
    "attrs": {"dataAttributes": {}},
    "context": {"ancestors": [
        {"tag": "div", "id": "", "text": "Add Element"},
        {"tag": "div", "id": "content", "text": "Add/Remove Elements Add Element"},
    ]},
    "cssPath": "div#content > div > button",
    "selectorCandidates": [],
    "uniqueSelector": None,
    "identity": {"peiId": "NX-PEI-test", "fingerprint": {
        "origin": "https://the-internet.herokuapp.com",
        "tag": "button", "role": "button", "text": "Add Element",
        "attrs": {"dataAttributes": {}},
        "context": {"ancestors": [
            {"tag": "div", "id": "", "text": "Add Element"},
            {"tag": "div", "id": "content", "text": "Add/Remove Elements Add Element"},
        ]},
    }},
}


class ReplayEngineTests(unittest.TestCase):
    def test_css_path_is_used_when_unique_selector_fields_are_empty(self):
        target = main.adapt_recorder_target(SAMPLE_TARGET)
        self.assertEqual(target["_nexus_selectors"], ["div#content > div > button"])
        self.assertEqual(target["tag"], "button")
        self.assertEqual(target["role"], "button")

    def test_nested_pei_identity_matches_native_button_role(self):
        target = main.adapt_recorder_target(SAMPLE_TARGET)
        live = {
            "tag": "button", "role": "button", "id": "", "testId": "",
            "ariaLabel": "", "name": "", "text": "Add Element",
            "attrs": {"class": "", "dataAttributes": {}}, "ancestors": [],
        }
        self.assertTrue(main.fingerprint_matches(live, target))

    def test_identity_rejects_wrong_button_text(self):
        target = main.adapt_recorder_target(SAMPLE_TARGET)
        live = {"tag": "button", "role": "button", "text": "Delete", "attrs": {}, "ancestors": []}
        self.assertFalse(main.fingerprint_matches(live, target))

    def test_recorded_gap_is_not_capped_at_three_seconds(self):
        seen = {}
        async def fake_wait(awaitable, timeout):
            seen["timeout"] = timeout
            awaitable.close()
            raise asyncio.TimeoutError
        main.stop_event.clear()
        with patch.object(main.asyncio, "wait_for", fake_wait):
            result = asyncio.run(main._wait_recorded_gap({"gapMs": 17000}))
        self.assertTrue(result)
        self.assertEqual(seen["timeout"], 17.0)


if __name__ == "__main__":
    unittest.main()
