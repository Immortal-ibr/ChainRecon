"""Common structured secret forms are removed from derived display data."""

from __future__ import annotations

from chainrecon.frida_events import parse_event_line
from chainrecon.utils.redaction import redact_report_data, redact_text


def test_bare_and_nested_token_keys_are_redacted_without_losing_counts() -> None:
    value = {"token": "hidden", "nested": {"refresh_token": "also-hidden", "tokens": ["one"]}, "token_count": 3}
    safe = redact_report_data(value)
    assert safe["token"] == "[REDACTED]"
    assert safe["nested"]["refresh_token"] == "[REDACTED]"
    assert safe["nested"]["tokens"] == "[REDACTED]"
    assert safe["token_count"] == 3


def test_quoted_assignments_in_status_events_are_redacted() -> None:
    message = '[STATUS] {"token":"private-value","api_key":"another-value"}'
    safe = parse_event_line(message)["message"]
    assert "private-value" not in safe
    assert "another-value" not in safe
    assert "token" in safe
    assert "[REDACTED]" in safe
    assert "private-value" in parse_event_line(message, reveal_sensitive=True)["message"]
    assert "private-value" not in redact_text(message)


def test_cli_secret_flag_values_are_redacted_in_logs_and_exports() -> None:
    command = 'python check.py --token private-value --api-key "two words" --target 192.0.2.10'
    safe = redact_text(command)
    assert "private-value" not in safe
    assert "two words" not in safe
    assert "--token [REDACTED]" in safe
    assert "--api-key [REDACTED]" in safe
    assert "--target 192.0.2.10" in safe
