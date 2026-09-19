from __future__ import annotations

import pytest

from ids_parser.models import CaptureContext, NormalizedIDSEvent


def test_capture_context_requires_supported_mode() -> None:
    with pytest.raises(ValueError, match="Capture mode"):
        CaptureContext(mode="socket", source="eth0")  # type: ignore[arg-type]


def test_normalized_event_has_stable_default_layers() -> None:
    event = NormalizedIDSEvent(
        packet_id=1,
        timestamp="2026-09-19T00:00:00.000000Z",
        capture={"mode": "pcap", "source": "sample.pcap"},
        packet_length=42,
    ).to_dict()

    assert event["network"] is None
    assert event["transport"] is None
    assert event["application"] == {"protocol": "UNKNOWN", "fields": {}}
    assert event["payload"] == {"length": 0, "encoding": None, "data": None}
    assert event["status"] == "captured"
    assert event["errors"] == []

