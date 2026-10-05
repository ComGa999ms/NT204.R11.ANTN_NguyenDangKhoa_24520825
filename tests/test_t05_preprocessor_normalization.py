from __future__ import annotations

from ids_parser.preprocessor import EventPreprocessor


def test_t05_preprocessor_normalizes_case_format_and_safe_uri() -> None:
    event = {
        "packet_id": "1",
        "timestamp": "2024-01-02T03:04:05+07:00",
        "capture": {"mode": "PCAP", "source": " sample.pcap "},
        "packet_length": "128",
        "network": {
            "protocol": "ipv4",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
        },
        "transport": {
            "protocol": "tcp",
            "source_port": "49152",
            "destination_port": "80",
            "payload_length": "20",
            "flags": {"SYN": "0", "ACK": "true"},
        },
        "application": {
            "protocol": "http",
            "fields": {
                "message_type": "REQUEST",
                "method": "get",
                "target": "/A/%7euser/%2fkeep?Q=%41%2f%252e",
                "http_version": "http/1.1",
                "headers": {
                    "Host": "Example.COM.",
                    "Content-Type": "Text/HTML; Charset=UTF-8",
                    "Content-Length": "0",
                },
                "content_type": "Text/HTML; Charset=UTF-8",
                "content_length": "0",
                "body": {"length": 0, "encoding": None, "data": None},
                "headers_complete": "true",
                "body_complete": "true",
                "message_length": 20,
                "remaining_bytes": 0,
            },
        },
        "payload": {"length": 20, "encoding": "utf-8", "data": "GET / HTTP/1.1"},
        "status": "PARSED",
        "errors": [],
    }

    normalized = EventPreprocessor().process(event)
    fields = normalized["application"]["fields"]

    assert normalized["timestamp"] == "2024-01-01T20:04:05.000000Z"
    assert normalized["capture"] == {"mode": "pcap", "source": "sample.pcap"}
    assert normalized["network"]["protocol"] == "IPv4"
    assert normalized["transport"]["protocol"] == "TCP"
    assert normalized["transport"]["source_port"] == 49152
    assert normalized["transport"]["flags"] == {"syn": False, "ack": True}
    assert normalized["application"]["protocol"] == "HTTP"
    assert fields["method"] == "GET"
    assert fields["message_type"] == "request"
    assert fields["http_version"] == "HTTP/1.1"
    assert fields["headers"] == {
        "host": ["Example.COM."],
        "content-type": ["Text/HTML; Charset=UTF-8"],
        "content-length": ["0"],
    }
    assert fields["host"] == "example.com"
    assert fields["content_type"] == "text/html; charset=utf-8"
    assert fields["normalized_target"] == "/A/~user/%2Fkeep?Q=A%2F%252e"
    assert fields["normalized_path"] == "/A/~user/%2Fkeep"
    assert normalized["preprocess_status"] == "valid"
    assert normalized["processing_action"] == "process"
    assert normalized["reason"] is None
