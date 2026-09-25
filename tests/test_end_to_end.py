from __future__ import annotations

import json
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

from ids_parser import cli


EVENT_KEYS = {
    "packet_id",
    "timestamp",
    "capture",
    "packet_length",
    "network",
    "transport",
    "application",
    "payload",
    "status",
    "errors",
}


def build_protocol_packets() -> list[Packet]:
    dns_query = bytes(
        DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    dns_response = bytes(
        DNS(
            id=0x1234,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(
                rrname="example.com",
                type="A",
                ttl=60,
                rdata="203.0.113.7",
            ),
        )
    )

    return [
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=41001, dport=18080, seq=100, flags="PA")
        / Raw(b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        IP(src="198.51.100.20", dst="192.0.2.10")
        / TCP(sport=18080, dport=41001, seq=500, flags="PA")
        / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
        IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=41002, dport=5300)
        / Raw(dns_query),
        IP(src="198.51.100.53", dst="192.0.2.10")
        / UDP(sport=5300, dport=41002)
        / Raw(dns_response),
        IP(src="192.0.2.10", dst="198.51.100.25")
        / TCP(sport=41003, dport=2525, seq=1000, flags="PA")
        / Raw(b"EHLO client.example\r\n"),
        IP(src="198.51.100.25", dst="192.0.2.10")
        / TCP(sport=2525, dport=41003, seq=2000, flags="PA")
        / Raw(b"250 mail.example Hello\r\n"),
        IP(src="192.0.2.10", dst="198.51.100.30")
        / UDP(sport=41004, dport=41005)
        / Raw(b"\xff\x00\x80\x01"),
    ]


def test_pcap_cli_parses_all_supported_application_protocols(
    tmp_path: Path,
) -> None:
    pcap_path = tmp_path / "protocols.pcap"
    output_path = tmp_path / "protocols.jsonl"
    wrpcap(str(pcap_path), build_protocol_packets())

    result = cli.main(
        ["--pcap", str(pcap_path), "--output", str(output_path)]
    )

    assert result == 0
    events = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(events) == 7
    assert [event["packet_id"] for event in events] == list(range(1, 8))
    assert [event["application"]["protocol"] for event in events] == [
        "HTTP",
        "HTTP",
        "DNS",
        "DNS",
        "SMTP",
        "SMTP",
        "UNKNOWN",
    ]

    assert events[0]["application"]["fields"]["method"] == "GET"
    assert events[1]["application"]["fields"]["status_code"] == 200
    assert events[2]["application"]["fields"]["questions"][0]["name"] == (
        "example.com"
    )
    assert events[3]["application"]["fields"]["answers"][0]["data"] == (
        "203.0.113.7"
    )
    assert events[4]["application"]["fields"]["commands"][0]["command"] == (
        "EHLO"
    )
    assert events[5]["application"]["fields"]["responses"][0]["status_code"] == (
        250
    )
    assert events[6]["payload"] == {
        "length": 4,
        "encoding": "hex",
        "data": "ff008001",
    }

    assert all(set(event) == EVENT_KEYS for event in events)
    assert all(event["capture"]["mode"] == "pcap" for event in events)
    assert all(event["status"] == "parsed" for event in events)
    assert all(event["errors"] == [] for event in events)
