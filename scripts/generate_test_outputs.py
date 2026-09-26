"""Generate reproducible PCAP inputs and JSONL outputs for required test cases."""

from __future__ import annotations

import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIRECTORY = PROJECT_ROOT / "src"
if str(SRC_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SRC_DIRECTORY))

from ids_parser.capture import read_pcap  # noqa: E402
from ids_parser.pipeline import PacketPipeline  # noqa: E402
from ids_parser.writer import JSONLinesWriter  # noqa: E402


TEST_DIRECTORY = PROJECT_ROOT / "TEST"
BASE_TIMESTAMP = 1_700_000_000
EXPECTED_APPLICATIONS = {
    "tcp-handshake": ["UNKNOWN", "UNKNOWN", "UNKNOWN"],
    "tcp-data": ["UNKNOWN"],
    "udp": ["UNKNOWN"],
    "http-get": ["HTTP"],
    "http-post": ["HTTP"],
    "http-response": ["HTTP"],
    "dns-query": ["DNS"],
    "dns-response": ["DNS"],
    "smtp-command": ["SMTP"],
    "smtp-response": ["SMTP"],
    "unknown-protocol": ["UNKNOWN"],
    "malformed-packet": ["HTTP"],
}


def _dns_query() -> bytes:
    return bytes(
        DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )


def _dns_response() -> bytes:
    return bytes(
        DNS(
            id=0x1234,
            qr=1,
            aa=1,
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


def build_cases() -> dict[str, list[Packet]]:
    client = "192.0.2.10"
    server = "198.51.100.20"

    return {
        "tcp-handshake": [
            IP(src=client, dst=server)
            / TCP(sport=40000, dport=8080, seq=100, flags="S"),
            IP(src=server, dst=client)
            / TCP(sport=8080, dport=40000, seq=200, ack=101, flags="SA"),
            IP(src=client, dst=server)
            / TCP(sport=40000, dport=8080, seq=101, ack=201, flags="A"),
        ],
        "tcp-data": [
            IP(src=client, dst=server)
            / TCP(sport=40001, dport=9001, seq=100, flags="PA")
            / Raw(b"hello from tcp"),
        ],
        "udp": [
            IP(src=client, dst=server)
            / UDP(sport=40002, dport=9002)
            / Raw(b"hello from udp"),
        ],
        "http-get": [
            IP(src=client, dst=server)
            / TCP(sport=40003, dport=18080, seq=100, flags="PA")
            / Raw(b"GET /index HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ],
        "http-post": [
            IP(src=client, dst=server)
            / TCP(sport=40004, dport=18080, seq=100, flags="PA")
            / Raw(
                b"POST /login HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"Content-Length: 7\r\n\r\n"
                b"a=1&b=2"
            ),
        ],
        "http-response": [
            IP(src=server, dst=client)
            / TCP(sport=18080, dport=40005, seq=100, flags="PA")
            / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
        ],
        "dns-query": [
            IP(src=client, dst="198.51.100.53")
            / UDP(sport=40006, dport=5300)
            / Raw(_dns_query()),
        ],
        "dns-response": [
            IP(src="198.51.100.53", dst=client)
            / UDP(sport=5300, dport=40006)
            / Raw(_dns_response()),
        ],
        "smtp-command": [
            IP(src=client, dst="198.51.100.25")
            / TCP(sport=40007, dport=2525, seq=100, flags="PA")
            / Raw(b"EHLO client.example\r\n"),
        ],
        "smtp-response": [
            IP(src="198.51.100.25", dst=client)
            / TCP(sport=2525, dport=40007, seq=100, flags="PA")
            / Raw(b"250 mail.example Hello\r\n"),
        ],
        "unknown-protocol": [
            IP(src=client, dst=server)
            / TCP(sport=40008, dport=31337, seq=100, flags="PA")
            / Raw(b"\xff\x00\x80\x01"),
        ],
        "malformed-packet": [
            IP(src=client, dst=server)
            / TCP(sport=40009, dport=18080, seq=100, flags="PA")
            / Raw(b"GET / HTTP/1.1\r\nMalformedHeader\r\n\r\n"),
        ],
    }


def _set_timestamps(cases: dict[str, list[Packet]]) -> None:
    offset = 0
    for packets in cases.values():
        for packet in packets:
            packet.time = BASE_TIMESTAMP + offset
            offset += 1


def generate() -> None:
    cases = build_cases()
    _set_timestamps(cases)
    TEST_DIRECTORY.mkdir(parents=True, exist_ok=True)

    for name, packets in cases.items():
        pcap_path = TEST_DIRECTORY / f"{name}.pcap"
        output_path = TEST_DIRECTORY / f"{name}.jsonl"
        wrpcap(str(pcap_path), packets)

        events: list[dict] = []
        with JSONLinesWriter(output_path) as writer:
            def record_event(event: dict) -> None:
                events.append(event)
                writer.write(event)

            pipeline = PacketPipeline(sink=record_event)
            processed = read_pcap(pcap_path, pipeline)

        if processed != len(packets) or len(events) != len(packets):
            raise RuntimeError(f"{name}: packet count mismatch")
        applications = [event["application"]["protocol"] for event in events]
        if applications != EXPECTED_APPLICATIONS[name]:
            raise RuntimeError(
                f"{name}: expected {EXPECTED_APPLICATIONS[name]}, got {applications}"
            )
        expected_status = "partial" if name == "malformed-packet" else "parsed"
        if any(event["status"] != expected_status for event in events):
            raise RuntimeError(f"{name}: unexpected event status")
        print(
            f"{name}: {processed} packet(s), "
            f"status={','.join(event['status'] for event in events)}, "
            f"application={','.join(applications)}"
        )


if __name__ == "__main__":
    generate()
