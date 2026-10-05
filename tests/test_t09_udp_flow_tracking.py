from __future__ import annotations

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def test_t09_udp_packets_are_grouped_into_one_bidirectional_flow() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="pcap", source="udp-flow.pcap")
    query = (
        IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=53000, dport=53)
        / Raw(b"query")
    )
    response = (
        IP(src="198.51.100.53", dst="192.0.2.10")
        / UDP(sport=53, dport=53000)
        / Raw(b"answer")
    )
    query.time = 1_700_000_000
    response.time = 1_700_000_001

    first = pipeline.process_packet(query, context)
    second = pipeline.process_packet(response, context)

    assert first["flow"]["flow_id"] == second["flow"]["flow_id"]
    assert second["flow"]["protocol"] == "UDP"
    assert second["flow"]["tcp_state"] is None
    assert second["flow"]["packet_count"] == 2
    assert second["flow"]["a_to_b"]["packets"] == 1
    assert second["flow"]["b_to_a"]["packets"] == 1
