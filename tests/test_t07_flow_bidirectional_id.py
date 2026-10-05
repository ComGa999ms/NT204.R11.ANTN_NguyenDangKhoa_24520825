from __future__ import annotations

from scapy.layers.inet import IP, TCP

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def test_t07_tcp_flow_id_is_stable_in_both_directions() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="pcap", source="flow-id.pcap")
    client_syn = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=50000,
        dport=80,
        seq=100,
        flags="S",
    )
    server_syn_ack = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
        sport=80,
        dport=50000,
        seq=900,
        ack=101,
        flags="SA",
    )
    client_syn.time = 1_700_000_000
    server_syn_ack.time = 1_700_000_001

    first = pipeline.process_packet(client_syn, context)
    second = pipeline.process_packet(server_syn_ack, context)

    assert first["flow"]["flow_id"] == second["flow"]["flow_id"]
    assert first["flow"]["direction"] == "a_to_b"
    assert second["flow"]["direction"] == "b_to_a"
    assert second["flow"]["packet_count"] == 2
    assert second["flow"]["endpoint_a"] == {"ip": "10.0.0.1", "port": 50000}
    assert second["flow"]["endpoint_b"] == {"ip": "10.0.0.2", "port": 80}
