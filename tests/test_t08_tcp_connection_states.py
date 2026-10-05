from __future__ import annotations

from scapy.layers.inet import IP, TCP

from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline


def test_t08_tcp_handshake_reaches_established_state() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="pcap", source="tcp-state.pcap")
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=80, seq=100, flags="S"),
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=50000, seq=900, ack=101, flags="SA"),
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=80, seq=101, ack=901, flags="A"),
    ]
    for offset, packet in enumerate(packets):
        packet.time = 1_700_000_000 + offset

    events = [pipeline.process_packet(packet, context) for packet in packets]

    assert [event["flow"]["tcp_state"] for event in events] == [
        "SYN_SENT",
        "SYN_RECEIVED",
        "ESTABLISHED",
    ]
    assert events[-1]["flow"]["tcp_flags_seen"]["syn"] is True
    assert events[-1]["flow"]["tcp_flags_seen"]["ack"] is True


def test_t08_tcp_fin_and_rst_are_tracked() -> None:
    pipeline = PacketPipeline()
    context = CaptureContext(mode="pcap", source="tcp-close.pcap")
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=80, seq=100, flags="S"),
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=50000, seq=900, ack=101, flags="SA"),
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=80, seq=101, ack=901, flags="A"),
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=80, seq=101, ack=901, flags="FA"),
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=50000, seq=901, ack=102, flags="FA"),
    ]
    for offset, packet in enumerate(packets):
        packet.time = 1_700_000_010 + offset

    events = [pipeline.process_packet(packet, context) for packet in packets]

    assert events[3]["flow"]["tcp_state"] == "FIN_WAIT"
    assert events[4]["flow"]["tcp_state"] == "CLOSED"

    reset_packet = IP(src="10.0.0.3", dst="10.0.0.4") / TCP(
        sport=50001,
        dport=443,
        seq=1,
        flags="R",
    )
    reset_packet.time = 1_700_000_020

    reset_event = pipeline.process_packet(reset_packet, context)

    assert reset_event["flow"]["tcp_state"] == "RESET"
    assert reset_event["flow"]["tcp_flags_seen"]["rst"] is True
