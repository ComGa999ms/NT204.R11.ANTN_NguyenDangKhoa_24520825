from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def test_t10_flow_tracks_directional_packet_and_byte_counts() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="pcap", source="flow-stats.pcap")
    request = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=8080, seq=1, flags="PA")
        / Raw(b"hello")
    )
    response = (
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=8080, dport=50000, seq=1, ack=6, flags="PA")
        / Raw(b"world!!")
    )
    request.time = 1_700_000_000
    response.time = 1_700_000_002

    first = pipeline.process_packet(request, context)
    second = pipeline.process_packet(response, context)

    assert second["flow"]["packet_count"] == 2
    assert second["flow"]["byte_count"] == len(bytes(request)) + len(bytes(response))
    assert first["flow"]["a_to_b"]["bytes"] == len(bytes(request))
    assert second["flow"]["a_to_b"]["bytes"] == len(bytes(request))
    assert second["flow"]["b_to_a"]["bytes"] == len(bytes(response))
    assert second["flow"]["duration_seconds"] == 2.0
