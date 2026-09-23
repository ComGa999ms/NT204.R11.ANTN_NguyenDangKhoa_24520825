from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from ids_parser.detector import detect_application
from ids_parser.models import CaptureContext
from ids_parser.parsers.dns import parse_dns
from ids_parser.parsers.payload import normalize_payload
from ids_parser.pipeline import PacketPipeline


def dns_query_bytes() -> bytes:
    return bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))


def test_parse_dns_query_domain_and_type() -> None:
    fields = parse_dns(dns_query_bytes(), "UDP")

    assert fields["message_type"] == "query"
    assert fields["transaction_id"] == 0x1234
    assert fields["flags"]["recursion_desired"] is True
    assert fields["questions"] == [
        {
            "name": "example.com",
            "type": 1,
            "type_name": "A",
            "class": 1,
            "class_name": "IN",
        }
    ]


def test_detect_dns_query_on_non_standard_udp_port() -> None:
    transport = {
        "protocol": "UDP",
        "source_port": 40000,
        "destination_port": 5300,
    }

    assert detect_application(
        transport, normalize_payload(dns_query_bytes())
    ) == "DNS"


def test_pipeline_parses_udp_dns_query() -> None:
    packet = (
        IP(src="192.0.2.1", dst="198.51.100.53")
        / UDP(sport=40000, dport=53)
        / Raw(dns_query_bytes())
    )
    event = PacketPipeline().process_packet(
        packet, CaptureContext(mode="pcap", source="dns.pcap")
    )

    assert event["application"]["protocol"] == "DNS"
    assert event["application"]["fields"]["questions"][0]["name"] == "example.com"
    assert event["status"] == "parsed"


def test_pipeline_reassembles_dns_over_tcp() -> None:
    message = dns_query_bytes()
    framed = len(message).to_bytes(2, "big") + message
    split = 7
    pipeline = PacketPipeline()
    context = CaptureContext(mode="pcap", source="dns-tcp.pcap")

    first = pipeline.process_packet(
        IP(src="192.0.2.1", dst="198.51.100.53")
        / TCP(sport=40000, dport=53, seq=100, flags="PA")
        / Raw(framed[:split]),
        context,
    )
    second = pipeline.process_packet(
        IP(src="192.0.2.1", dst="198.51.100.53")
        / TCP(sport=40000, dport=53, seq=100 + split, flags="PA")
        / Raw(framed[split:]),
        context,
    )

    assert first["application"]["protocol"] == "UNKNOWN"
    assert second["application"]["protocol"] == "DNS"
    assert second["application"]["fields"]["tcp_framed"] is True
