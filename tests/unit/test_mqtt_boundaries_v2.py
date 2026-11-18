"""Known MQTT frame outcomes and privacy boundaries for the legacy adapter."""

from __future__ import annotations

import json
from types import SimpleNamespace

from chainrecon.analysis.mqtt_analyzer import MQTTAnalyzer


def _packet(raw: bytes, *, port: int = 1883, decoded=None, tls: bool = False):
    fields = {
        "tcp": SimpleNamespace(srcport=str(port), dstport="51000"),
        "data": SimpleNamespace(data_data=raw.hex()),
        "ip": SimpleNamespace(src="192.0.2.10", dst="192.0.2.20"),
    }
    if decoded is not None:
        fields["mqtt"] = decoded
    if tls:
        fields["tls"] = SimpleNamespace()
    return SimpleNamespace(**fields)


def _connect(*, username: bytes = b"researcher", password: bytes = b"private-value") -> bytes:
    fields = (
        b"\x00\x04MQTT\x04\xc2\x00\x3c"
        + b"\x00\x06client"
        + len(username).to_bytes(2, "big") + username
        + len(password).to_bytes(2, "big") + password
    )
    return b"\x10" + bytes([len(fields)]) + fields


def test_valid_plaintext_connect_proves_field_presence_but_not_broker_policy() -> None:
    result = MQTTAnalyzer().analyze([_packet(_connect())])
    connect = result["findings"]["deep_parsed"][0]
    assert connect["type"] == "CONNECT"
    assert connect["username_present"] is True
    assert connect["password_present"] is True
    assert result["findings"]["authentication"]["authenticated"] is None
    assert result["summary"]["encrypted"] is None
    assert len(result["risk_indicators"]) == 1
    assert "private-value" not in json.dumps(result)
    assert "researcher" not in json.dumps(result)


def test_truncated_or_malformed_connect_does_not_produce_credential_finding() -> None:
    full = _connect()
    invalid_length = b"\x10\xff\xff\xff\xff\x01" + full[2:]
    missing_password = full[:-4]
    for raw in (full[:7], invalid_length, missing_password):
        result = MQTTAnalyzer().analyze([_packet(raw)])
        assert result["findings"]["deep_parsed"] == []
        assert result["risk_indicators"] == []


def test_publish_metadata_does_not_return_payload() -> None:
    secret = b"arbitrary-secret-that-redaction-would-miss"
    topic = b"device/status"
    body = len(topic).to_bytes(2, "big") + topic + secret
    frame = b"\x30" + bytes([len(body)]) + body
    decoded = SimpleNamespace(topic="device/status", msg=secret.hex(), qos="0", msgtype="3")
    result = MQTTAnalyzer().analyze([_packet(frame, decoded=decoded)])
    assert result["findings"]["payloads"][0]["payload_length"] == len(secret)
    assert result["findings"]["deep_parsed"][0]["payload_length"] == len(secret)
    assert "arbitrary-secret" not in json.dumps(result)
    assert "payload_preview" not in json.dumps(result)


def test_port_and_tls_layer_are_observations_not_encryption_proof() -> None:
    result = MQTTAnalyzer().analyze([_packet(b"\x16\x03\x03\x00", port=8883, tls=True)])
    assert result["findings"]["tls"]["tls_on_port_8883_observed"] is True
    assert result["findings"]["tls"]["encrypted"] is None
    assert result["findings"]["deep_parsed"] == []
    assert result["risk_indicators"] == []
