from __future__ import annotations

from ids_parser.flow import FlowTracker, FlowTrackerConfig


def _event(
    *,
    packet_id: int,
    timestamp: str,
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
) -> dict:
    return {
        "packet_id": packet_id,
        "timestamp": timestamp,
        "packet_length": 40,
        "network": {
            "protocol": "IPv4",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
        },
        "transport": {
            "protocol": "TCP",
            "source_port": source_port,
            "destination_port": destination_port,
            "payload_length": 0,
            "flags": {"syn": True, "ack": False},
        },
        "payload": {"length": 0, "encoding": None, "data": None},
        "processing_action": "process",
    }


def test_t11_idle_flow_is_exported_and_removed_on_timeout() -> None:
    tracker = FlowTracker(FlowTrackerConfig(idle_timeout_seconds=10))
    first = tracker.process(
        _event(
            packet_id=1,
            timestamp="2024-01-01T00:00:00Z",
            source_ip="10.0.0.1",
            source_port=50000,
            destination_ip="10.0.0.2",
            destination_port=80,
        )
    )

    assert first["expired_flows"] == []
    assert tracker.active_count == 1

    second = tracker.process(
        _event(
            packet_id=2,
            timestamp="2024-01-01T00:00:11Z",
            source_ip="10.0.0.3",
            source_port=50001,
            destination_ip="10.0.0.4",
            destination_port=443,
        )
    )

    assert len(second["expired_flows"]) == 1
    assert second["expired_flows"][0]["flow_id"] == first["flow"]["flow_id"]
    assert second["expired_flows"][0]["expired"] is True
    assert tracker.active_count == 1
