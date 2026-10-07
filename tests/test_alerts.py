import json
import unittest

import bot


def alert_line(**overrides):
    event = {
        "event_type": "alert",
        "src_ip": "203.0.113.10",
        "alert": {
            "category": "Attempted Administrator Privilege Gain",
            "signature": "ET EXPLOIT Example",
            "priority": 1,
        },
    }
    event.update(overrides)
    return json.dumps(event)


class FormatAlertTests(unittest.TestCase):
    def test_high_priority(self):
        message = bot.format_alert(json.loads(alert_line()))
        self.assertEqual(
            message,
            "\n".join(
                [
                    "HIGH SEVERITY ALERT",
                    "Priority: 1",
                    "Type: Attempted Administrator Privilege Gain",
                    "Signature: ET EXPLOIT Example",
                    "Source IP: 203.0.113.10",
                ]
            ),
        )

    def test_medium_priority(self):
        event = json.loads(alert_line())
        event["alert"]["priority"] = 2
        event["alert"]["category"] = "Potentially Bad Traffic"
        event["alert"]["signature"] = "GPL ATTACK_RESPONSE id check returned root"
        message = bot.format_alert(event)
        self.assertTrue(message.startswith("MEDIUM SEVERITY ALERT\n"))
        self.assertIn("Priority: 2\n", message)
        self.assertIn("GPL ATTACK_RESPONSE id check returned root", message)

    def test_low_priority_and_above(self):
        for priority in (3, 4):
            event = json.loads(alert_line())
            event["alert"]["priority"] = priority
            message = bot.format_alert(event)
            self.assertTrue(message.startswith("LOW PRIORITY NOTICE\n"))
            self.assertIn(f"Priority: {priority}\n", message)

    def test_numeric_priority_string(self):
        event = json.loads(alert_line())
        event["alert"]["priority"] = "1"
        self.assertTrue(bot.format_alert(event).startswith("HIGH SEVERITY ALERT\n"))

    def test_missing_fields_use_defaults(self):
        message = bot.format_alert({"event_type": "alert", "alert": {}})
        self.assertEqual(
            message,
            "\n".join(
                [
                    "LOW PRIORITY NOTICE",
                    "Priority: 3",
                    "Type: Unknown Category",
                    "Signature: Unknown Signature",
                    "Source IP: Unknown IP",
                ]
            ),
        )

    def test_invalid_priority_defaults_to_low(self):
        event = json.loads(alert_line())
        event["alert"]["priority"] = "high"
        message = bot.format_alert(event)
        self.assertTrue(message.startswith("LOW PRIORITY NOTICE\n"))
        self.assertIn("Priority: 3\n", message)

    def test_ignores_non_alerts(self):
        self.assertIsNone(bot.format_alert({"event_type": "dns", "src_ip": "192.0.2.1"}))
        self.assertIsNone(bot.format_alert({"event_type": "stats"}))
        self.assertIsNone(bot.format_alert([]))
        self.assertIsNone(bot.format_alert(None))

    def test_alert_object_not_a_dict(self):
        message = bot.format_alert({"event_type": "alert", "alert": "bad", "src_ip": "192.0.2.5"})
        self.assertIn("Type: Unknown Category", message)
        self.assertIn("Source IP: 192.0.2.5", message)


class ParseEventLineTests(unittest.TestCase):
    def test_parses_alert_line(self):
        message = bot.parse_event_line(alert_line() + "\n")
        self.assertIsNotNone(message)
        self.assertIn("Source IP: 203.0.113.10", message)

    def test_skips_bad_json_and_blank_lines(self):
        self.assertIsNone(bot.parse_event_line(""))
        self.assertIsNone(bot.parse_event_line("   \n"))
        self.assertIsNone(bot.parse_event_line("{not json}\n"))
        self.assertIsNone(bot.parse_event_line("null\n"))

    def test_skips_non_alert_json(self):
        line = json.dumps({"event_type": "flow", "src_ip": "192.0.2.8"})
        self.assertIsNone(bot.parse_event_line(line))


if __name__ == "__main__":
    unittest.main()
