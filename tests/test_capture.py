from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap

from ids_parser import capture
from ids_parser.capture import CaptureError, capture_live, read_pcap, resolve_interface


class RecordingPipeline:
    def __init__(self) -> None:
        self.calls: list[tuple[object, object]] = []

    def process_packet(self, packet: object, context: object) -> dict:
        self.calls.append((packet, context))
        return {}


class FakeInterface:
    name = "Wi-Fi"
    description = "Wireless adapter"
    network_name = r"\Device\NPF_TEST"

    def __str__(self) -> str:
        return self.network_name


class FakeInterfaceTable:
    def __init__(self, interfaces: list[object]) -> None:
        self._interfaces = interfaces

    def values(self) -> list[object]:
        return self._interfaces


def test_resolve_interface_accepts_friendly_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = FakeInterface()
    monkeypatch.setattr(
        capture.conf, "ifaces", FakeInterfaceTable([expected])
    )

    assert resolve_interface("wi-fi") is expected


def test_read_pcap_streams_packets_through_shared_pipeline(tmp_path: Path) -> None:
    pcap_path = tmp_path / "two-packets.pcap"
    wrpcap(
        str(pcap_path),
        [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80),
            IP(src="10.0.0.2", dst="10.0.0.1") / UDP(dport=53),
        ],
    )
    pipeline = RecordingPipeline()

    processed = read_pcap(pcap_path, pipeline)  # type: ignore[arg-type]

    assert processed == 2
    assert len(pipeline.calls) == 2
    contexts = [context for _, context in pipeline.calls]
    assert all(context.mode == "pcap" for context in contexts)
    assert all(context.source == str(pcap_path.resolve()) for context in contexts)


def test_read_pcap_honors_packet_limit(tmp_path: Path) -> None:
    pcap_path = tmp_path / "limited.pcap"
    wrpcap(str(pcap_path), [IP(), IP(), IP()])
    pipeline = RecordingPipeline()

    processed = read_pcap(pcap_path, pipeline, count=2)  # type: ignore[arg-type]

    assert processed == 2
    assert len(pipeline.calls) == 2


def test_read_pcap_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CaptureError, match="does not exist"):
        read_pcap(tmp_path / "missing.pcap", RecordingPipeline())  # type: ignore[arg-type]


def test_live_capture_uses_the_same_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    packets = [IP() / TCP(), IP() / UDP()]
    sniff_arguments: dict = {}

    def fake_sniff(**kwargs: object) -> None:
        sniff_arguments.update(kwargs)
        callback = kwargs["prn"]
        for packet in packets:
            callback(packet)  # type: ignore[operator]

    monkeypatch.setattr(capture, "sniff", fake_sniff)
    monkeypatch.setattr(
        capture, "resolve_interface", lambda name: f"resolved:{name}"
    )
    pipeline = RecordingPipeline()

    processed = capture_live(
        "Ethernet",
        pipeline,  # type: ignore[arg-type]
        count=2,
        capture_filter="tcp or udp",
    )

    assert processed == 2
    assert len(pipeline.calls) == 2
    contexts = [context for _, context in pipeline.calls]
    assert all(context.mode == "live" for context in contexts)
    assert all(context.source == "Ethernet" for context in contexts)
    assert sniff_arguments["iface"] == "resolved:Ethernet"
    assert sniff_arguments["store"] is False
    assert sniff_arguments["count"] == 2
    assert sniff_arguments["filter"] == "tcp or udp"
