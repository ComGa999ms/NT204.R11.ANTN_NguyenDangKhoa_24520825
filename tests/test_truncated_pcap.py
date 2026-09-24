from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from ids_parser import capture
from ids_parser.capture import CaptureError, read_pcap


class RecordingPipeline:
    def __init__(self) -> None:
        self.packets: list[object] = []

    def process_packet(self, packet: object, context: object) -> dict:
        self.packets.append(packet)
        return {}


class ReaderWithTruncatedTail:
    def __enter__(self) -> ReaderWithTruncatedTail:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def __iter__(self):
        yield IP() / TCP()
        raise EOFError("truncated packet record")


def test_truncated_pcap_tail_keeps_already_processed_packets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pcap_path = tmp_path / "truncated.pcap"
    pcap_path.write_bytes(b"placeholder")
    monkeypatch.setattr(capture, "PcapReader", lambda path: ReaderWithTruncatedTail())
    pipeline = RecordingPipeline()

    processed = read_pcap(pcap_path, pipeline)  # type: ignore[arg-type]

    assert processed == 1
    assert len(pipeline.packets) == 1


def test_real_truncated_pcap_does_not_discard_valid_prefix(tmp_path: Path) -> None:
    pcap_path = tmp_path / "real-truncated.pcap"
    first = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=80)
    second = IP(src="192.0.2.2", dst="192.0.2.1") / TCP(sport=80)
    wrpcap(str(pcap_path), [first, second])

    first_record_end = 24 + 16 + len(bytes(first))
    second_record_partial_end = first_record_end + 16 + 5
    pcap_path.write_bytes(pcap_path.read_bytes()[:second_record_partial_end])
    pipeline = RecordingPipeline()

    processed = read_pcap(pcap_path, pipeline)  # type: ignore[arg-type]

    assert processed >= 1
    assert len(pipeline.packets) == processed


def test_invalid_pcap_header_still_reports_capture_error(tmp_path: Path) -> None:
    pcap_path = tmp_path / "invalid.pcap"
    pcap_path.write_bytes(b"not a pcap file")

    with pytest.raises(CaptureError, match="Could not read PCAP"):
        read_pcap(pcap_path, RecordingPipeline())  # type: ignore[arg-type]
