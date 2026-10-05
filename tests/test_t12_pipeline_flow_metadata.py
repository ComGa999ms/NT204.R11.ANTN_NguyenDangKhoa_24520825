from __future__ import annotations

import json
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from ids_parser import cli


def test_t12_cli_writes_flow_metadata_and_expired_flows(tmp_path: Path) -> None:
    pcap_path = tmp_path / "flow-cli.pcap"
    output_path = tmp_path / "flow-cli.jsonl"
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=80, seq=100, flags="S"),
        IP(src="10.0.0.3", dst="10.0.0.4")
        / TCP(sport=50001, dport=443, seq=200, flags="S"),
    ]
    packets[0].time = 1_700_000_000
    packets[1].time = 1_700_000_010
    wrpcap(str(pcap_path), packets)

    result = cli.main(
        [
            "--pcap",
            str(pcap_path),
            "--output",
            str(output_path),
            "--flow-timeout",
            "5",
        ]
    )

    assert result == 0
    events = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]
    assert events[0]["flow"]["flow_id"]
    assert events[0]["expired_flows"] == []
    assert len(events[1]["expired_flows"]) == 1
    assert events[1]["expired_flows"][0]["flow_id"] == events[0]["flow"]["flow_id"]
