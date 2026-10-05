from __future__ import annotations

from copy import deepcopy

from ids_parser.preprocessor import EventPreprocessor


def test_t06_preprocessor_fills_missing_optional_http_fields() -> None:
    event = {
        "packet_id": 1,
        "timestamp": "2024-01-02T03:04:05Z",
        "capture": {"mode": "pcap", "source": "missing-fields.pcap"},
        "packet_length": 54,
        "network": {
            "protocol": "IPv4",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
        },
        "transport": {
            "protocol": "TCP",
            "source_port": 50000,
            "destination_port": 80,
            "payload_length": 0,
            "flags": {"ack": True},
        },
        "application": {
            "protocol": "HTTP",
            "fields": {
                "message_type": "request",
                "method": "GET",
                "target": "/",
                "headers": {"Host": ["Example.COM."]},
            },
        },
        "payload": {"length": 0, "encoding": None, "data": None},
        "status": "partial",
        "errors": [],
    }
    original = deepcopy(event)

    normalized = EventPreprocessor().process(event)
    fields = normalized["application"]["fields"]

    assert event == original
    assert fields["content_length"] is None
    assert fields["content_type"] is None
    assert fields["body"] == {"length": 0, "encoding": None, "data": None}
    assert fields["headers_complete"] is None
    assert fields["body_complete"] is None
    assert fields["message_length"] is None
    assert fields["remaining_bytes"] is None
    assert fields["host"] == "example.com"
    assert normalized["preprocess_status"] == "partial"
    assert normalized["processing_action"] == "process"
    assert "content_length" in normalized["reason"]


def test_t06_preprocessor_uses_empty_lists_for_missing_dns_records() -> None:
    event = {
        "packet_id": 2,
        "timestamp": "2024-01-02T03:04:06Z",
        "capture": {"mode": "pcap", "source": "missing-dns.pcap"},
        "packet_length": 70,
        "network": {
            "protocol": "IPv4",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.53",
        },
        "transport": {
            "protocol": "UDP",
            "source_port": 53000,
            "destination_port": 53,
            "payload_length": 28,
        },
        "application": {
            "protocol": "DNS",
            "fields": {"message_type": "query", "transaction_id": 1},
        },
        "payload": {"length": 28, "encoding": "hex", "data": "00" * 28},
        "status": "parsed",
        "errors": [],
    }

    normalized = EventPreprocessor().process(event)
    fields = normalized["application"]["fields"]

    assert fields["questions"] == []
    assert fields["answers"] == []
    assert fields["authorities"] == []
    assert fields["additionals"] == []
    assert fields["counts"] == {
        "questions": 0,
        "answers": 0,
        "authorities": 0,
        "additionals": 0,
    }
    assert normalized["preprocess_status"] == "valid"
