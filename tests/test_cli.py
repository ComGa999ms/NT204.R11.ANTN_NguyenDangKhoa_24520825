from __future__ import annotations

import json
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from ids_parser import cli


def test_list_interfaces_does_not_create_output(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "list_interfaces", lambda: ["Ethernet", "Wi-Fi"])

    result = cli.main(["--list-interfaces"])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out.splitlines() == ["1. Ethernet", "2. Wi-Fi"]
    assert not (tmp_path / "events.jsonl").exists()


def test_pcap_cli_writes_one_json_object_per_packet(tmp_path: Path) -> None:
    pcap_path = tmp_path / "input.pcap"
    output_path = tmp_path / "events.jsonl"
    wrpcap(
        str(pcap_path),
        [
            IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=80),
            IP(src="192.0.2.2", dst="192.0.2.1") / TCP(sport=80),
        ],
    )

    result = cli.main(
        ["--pcap", str(pcap_path), "--output", str(output_path)]
    )

    assert result == 0
    lines = output_path.read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]
    assert [event["packet_id"] for event in events] == [1, 2]
    assert all(event["capture"]["mode"] == "pcap" for event in events)
    assert all(event["network"]["protocol"] == "IPv4" for event in events)
    assert all(event["transport"]["protocol"] == "TCP" for event in events)
    assert all(event["status"] == "parsed" for event in events)
