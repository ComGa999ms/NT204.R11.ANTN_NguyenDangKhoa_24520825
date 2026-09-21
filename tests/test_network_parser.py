from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether

from ids_parser.parsers.network import parse_ipv4


def build_parsed_ipv4_packet() -> IP:
    original = IP(
        src="192.0.2.10",
        dst="198.51.100.20",
        ttl=48,
        id=1234,
        flags="DF",
        frag=0,
        tos=(46 << 2) | 3,
    ) / TCP(sport=40000, dport=443)
    return IP(bytes(original))


def test_parse_ipv4_extracts_normalized_header_fields() -> None:
    packet = build_parsed_ipv4_packet()

    result = parse_ipv4(packet)

    assert result is not None
    assert result["protocol"] == "IPv4"
    assert result["version"] == 4
    assert result["source_ip"] == "192.0.2.10"
    assert result["destination_ip"] == "198.51.100.20"
    assert result["header_length"] == 20
    assert result["total_length"] == len(bytes(packet))
    assert result["identification"] == 1234
    assert result["dscp"] == 46
    assert result["ecn"] == 3
    assert result["flags"] == {
        "reserved": False,
        "dont_fragment": True,
        "more_fragments": False,
    }
    assert result["fragment_offset"] == 0
    assert result["ttl"] == 48
    assert result["transport_protocol_number"] == 6
    assert isinstance(result["checksum"], int)


def test_parse_ipv4_returns_none_for_non_ipv4_packet() -> None:
    packet = Ether() / ARP()

    assert parse_ipv4(packet) is None

