from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

from ids_parser import cli
from ids_parser.core_engine import RuleEvaluationEngine, RuleMatchingEngine, RuleRepository
from ids_parser.models import CaptureContext
from ids_parser.pipeline import PacketPipeline
from ids_parser.rules import RuleParser


def rule(options: str, header: str = "alert tcp 10.0.0.0/24 any -> 192.0.2.20 80"):
    parsed = RuleParser().parse(f'{header} (msg:"test"; sid:100001; rev:1; {options})')
    assert parsed.rule is not None, parsed.issues
    return parsed.rule


def event(payload: bytes = b"GET /admin HTTP/1.1\r\n\r\n", *, reverse: bool = False):
    source, destination = ("192.0.2.20", "10.0.0.5") if reverse else ("10.0.0.5", "192.0.2.20")
    sport, dport = (80, 50000) if reverse else (50000, 80)
    return {
        "packet_id": 1, "timestamp": "2026-10-27T00:00:00Z", "processing_action": "process",
        "network": {"source_ip": source, "destination_ip": destination},
        "transport": {"protocol": "TCP", "source_port": sport, "destination_port": dport,
                      "payload_length": len(payload), "flags": {"ack": True, "psh": True}},
        "payload": {"length": len(payload), "encoding": "utf-8", "data": payload.decode("utf-8")},
        "application": {"protocol": "HTTP", "fields": {"target": "/admin"}},
        "flow": {"flow_id": "F123", "tcp_state": "ESTABLISHED",
                 "client_endpoint": {"ip": "10.0.0.5", "port": 50000}},
    }


def test_indexer_filters_protocol_port_ip_and_direction():
    forward = rule("", "alert tcp 10.0.0.0/24 any -> 192.0.2.20 80")
    reverse = rule("", "alert tcp 10.0.0.0/24 any <> 192.0.2.20 80")
    udp = rule("", "alert udp any any -> any 53")
    ranged = rule("", "alert tcp any any -> any 70:90")
    repository = RuleRepository([forward, reverse, udp, ranged])
    assert repository.candidates(event()) == [forward, reverse, ranged]
    assert repository.candidates(event(reverse=True)) == [reverse]
    wrong_ip = event()
    wrong_ip["network"]["source_ip"] = "203.0.113.1"
    assert repository.candidates(wrong_ip) == [ranged]
    udp_event = event()
    udp_event["transport"]["protocol"] = "UDP"
    udp_event["transport"]["destination_port"] = 53
    assert repository.candidates(udp_event) == [udp]


@pytest.mark.parametrize(
    ("options", "payload", "expected"),
    [
        ('content:"ADMIN";', b"GET /admin HTTP/1.1\r\n\r\n", False),
        ('content:"ADMIN"; nocase;', b"GET /admin HTTP/1.1\r\n\r\n", True),
        ('content:"admin"; offset:5; depth:6;', b"GET /admin HTTP/1.1\r\n\r\n", True),
        ('content:"admin"; offset:0; depth:6;', b"GET /admin HTTP/1.1\r\n\r\n", False),
        ('content:"GET"; content:"admin"; distance:2; within:10;', b"GET /admin HTTP/1.1\r\n\r\n", True),
        ('content:"GET"; content:"admin"; distance:3; within:10;', b"GET /admin HTTP/1.1\r\n\r\n", False),
        ('content:"GET"; content:"admin"; distance:2; within:5;', b"GET /admin HTTP/1.1\r\n\r\n", False),
        ('flags:AP; dsize:>10;', b"GET /admin HTTP/1.1\r\n\r\n", True),
        ('flags:S;', b"GET /admin HTTP/1.1\r\n\r\n", False),
        ('dsize:<10;', b"GET /admin HTTP/1.1\r\n\r\n", False),
    ],
)
def test_content_flags_and_dsize(options, payload, expected):
    assert RuleMatchingEngine().match(rule(options), event(payload)).matched is expected


def test_flow_direction_and_tcp_state():
    matcher = RuleMatchingEngine()
    to_server = rule("flow:to_server,established;")
    to_client = rule("flow:to_client,established;", "alert tcp 192.0.2.20 80 -> 10.0.0.0/24 any")
    assert matcher.match(to_server, event()).matched
    assert matcher.match(to_client, event(reverse=True)).matched
    assert not matcher.match(to_server, event(reverse=True)).matched
    incomplete = event()
    incomplete["flow"]["tcp_state"] = "SYN_SENT"
    assert not matcher.match(to_server, incomplete).matched
    assert matcher.match(rule("flow:not_established;"), incomplete).matched
    no_flow = event()
    no_flow["flow"] = None
    assert not matcher.match(to_server, no_flow).matched


def test_application_fallback_when_payload_is_unavailable():
    current = event()
    current["payload"] = {"length": 0, "encoding": None, "data": None}
    assert RuleMatchingEngine().match(rule('content:"admin";'), current).matched


def test_relative_content_search_backtracks_to_later_first_occurrence():
    current = event(b"GET xxxx GET /admin HTTP/1.1\r\n\r\n")
    matched = RuleMatchingEngine().match(
        rule('content:"GET"; content:"admin"; distance:2; within:10;'), current
    )
    assert matched.matched
    assert matched.information["contents"][0]["offset"] == 9


def test_evaluation_emits_every_match_and_counts_candidates():
    first = rule('content:"admin";')
    second = rule('content:"GET";')
    second.sid = 100002
    evaluator = RuleEvaluationEngine(RuleRepository([first, second]))
    detections = evaluator.evaluate(event())
    assert [item["sid"] for item in detections] == [100001, 100002]
    assert detections[0]["match"]["contents"][0]["offset"] == 5
    assert detections[0]["flow_id"] == "F123"
    assert detections[0]["source_ip"] == "10.0.0.5"
    assert (evaluator.events_evaluated, evaluator.candidates_evaluated, evaluator.match_count) == (1, 2, 2)
    skipped = event()
    skipped["processing_action"] = "skip"
    assert evaluator.evaluate(skipped) == []
    assert evaluator.events_evaluated == 1


def test_cli_pcap_writes_packet_and_detection_jsonl(tmp_path: Path):
    pcap = tmp_path / "request.pcap"
    rules = tmp_path / "demo.rules"
    output = tmp_path / "events.jsonl"
    alerts = tmp_path / "alerts.jsonl"
    packet = IP(src="10.0.0.5", dst="192.0.2.20") / TCP(sport=50000, dport=80, flags="PA") / Raw(
        b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    wrpcap(str(pcap), [packet])
    rules.write_text(
        'alert tcp any any -> any 80 (msg:"Admin path"; sid:100001; rev:1; content:"admin";)\n'
        'alert tcp any any -> any 80 (msg:"GET method"; sid:100002; rev:1; content:"GET";)\n'
        'alert tcp any any -> any 80 (msg:"Unsupported"; sid:100003; rev:1; pcre:"/x/";)\n',
        encoding="utf-8",
    )
    assert cli.main(["--pcap", str(pcap), "--rules", str(rules), "--output", str(output),
                     "--alerts-output", str(alerts)]) == 0
    packet_event = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    detections = [json.loads(line) for line in alerts.read_text(encoding="utf-8").splitlines()]
    assert [item["sid"] for item in detections] == [100001, 100002]
    assert packet_event["detections"] == detections


def test_parser_rejects_unsafe_flags_and_invalid_dsize():
    assert RuleParser().parse('alert tcp any any -> any any (msg:"x"; sid:1; rev:1; flags:Z;)').status == "unsupported"
    assert RuleParser().parse('alert tcp any any -> any any (msg:"x"; sid:1; rev:1; dsize:10<>5;)').status == "invalid"


def test_pipeline_uses_real_tcp_handshake_for_established_flow():
    current_rule = rule('flow:to_server,established; content:"admin";')
    evaluator = RuleEvaluationEngine(RuleRepository([current_rule]))
    pipeline = PacketPipeline(rule_engine=evaluator)
    context = CaptureContext(mode="pcap", source="handshake.pcap")
    packets = [
        IP(src="10.0.0.5", dst="192.0.2.20") / TCP(sport=50000, dport=80, seq=100, flags="S"),
        IP(src="192.0.2.20", dst="10.0.0.5") / TCP(sport=80, dport=50000, seq=200, ack=101, flags="SA"),
        IP(src="10.0.0.5", dst="192.0.2.20") / TCP(sport=50000, dport=80, seq=101, ack=201, flags="A"),
        IP(src="10.0.0.5", dst="192.0.2.20") / TCP(sport=50000, dport=80, seq=101, ack=201, flags="PA")
        / Raw(b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index
    events = [pipeline.process_packet(packet, context) for packet in packets]
    assert [len(item["detections"]) for item in events] == [0, 0, 0, 1]
    assert events[-1]["flow"]["tcp_state"] == "ESTABLISHED"


def test_cli_can_disable_one_sid(tmp_path: Path):
    pcap = tmp_path / "request.pcap"
    rules = tmp_path / "demo.rules"
    output = tmp_path / "events.jsonl"
    alerts = tmp_path / "alerts.jsonl"
    wrpcap(str(pcap), [IP(src="10.0.0.5", dst="192.0.2.20") /
                      TCP(sport=50000, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\n\r\n")])
    rules.write_text(
        'alert tcp any any -> any 80 (msg:"One"; sid:1; rev:1; content:"GET";)\n'
        'alert tcp any any -> any 80 (msg:"Two"; sid:2; rev:1; content:"GET";)\n',
        encoding="utf-8",
    )
    assert cli.main(["--pcap", str(pcap), "--rules", str(rules), "--disable-sid", "1",
                     "--output", str(output), "--alerts-output", str(alerts)]) == 0
    assert [json.loads(line)["sid"] for line in alerts.read_text(encoding="utf-8").splitlines()] == [2]
