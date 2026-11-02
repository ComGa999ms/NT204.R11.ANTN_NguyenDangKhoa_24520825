"""Rule indexing, matching, evaluation, and detection event generation."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Mapping

from .parsers.payload import payload_to_bytes
from .rules import ContentSpec, InternalRule


class RuleRepository:
    """Index rules by transport protocol and destination port."""

    def __init__(self, rules: list[InternalRule]) -> None:
        self._exact: dict[tuple[str, int], list[InternalRule]] = defaultdict(list)
        self._other: dict[str, list[InternalRule]] = defaultdict(list)
        for rule in rules:
            if rule.dst_port.start is not None and rule.dst_port.start == rule.dst_port.end:
                self._exact[rule.protocol, rule.dst_port.start].append(rule)
                if rule.direction == "<>":
                    self._other[rule.protocol].append(rule)
            else:
                self._other[rule.protocol].append(rule)

    def candidates(self, event: Mapping[str, Any]) -> list[InternalRule]:
        network, transport = event.get("network"), event.get("transport")
        if not isinstance(network, Mapping) or not isinstance(transport, Mapping):
            return []
        protocol = str(transport.get("protocol", "")).lower()
        if protocol not in {"tcp", "udp"}:
            return []
        destination_port = transport.get("destination_port")
        if not isinstance(destination_port, int):
            return []
        pool = self._exact.get((protocol, destination_port), []) + self._other.get(protocol, [])
        result: list[InternalRule] = []
        seen: set[int] = set()
        for rule in pool:
            if id(rule) not in seen and _header_matches(rule, network, transport) is not None:
                result.append(rule)
                seen.add(id(rule))
        return result


def _header_matches(
    rule: InternalRule, network: Mapping[str, Any], transport: Mapping[str, Any]
) -> str | None:
    if str(transport.get("protocol", "")).lower() != rule.protocol:
        return None
    src_ip, dst_ip = network.get("source_ip"), network.get("destination_ip")
    src_port, dst_port = transport.get("source_port"), transport.get("destination_port")
    if not isinstance(src_ip, str) or not isinstance(dst_ip, str):
        return None
    if not isinstance(src_port, int) or not isinstance(dst_port, int):
        return None
    if (
        rule.src_ip.matches(src_ip)
        and rule.dst_ip.matches(dst_ip)
        and rule.src_port.matches(src_port)
        and rule.dst_port.matches(dst_port)
    ):
        return "forward"
    if rule.direction == "<>" and (
        rule.src_ip.matches(dst_ip)
        and rule.dst_ip.matches(src_ip)
        and rule.src_port.matches(dst_port)
        and rule.dst_port.matches(src_port)
    ):
        return "reverse"
    return None


@dataclass(frozen=True, slots=True)
class MatchResult:
    matched: bool
    information: dict[str, Any] | None = None


class RuleMatchingEngine:
    """Check one validated rule against one normalized event and flow context."""

    def match(
        self, rule: InternalRule, event: Mapping[str, Any], *, stream_data: bytes | None = None
    ) -> MatchResult:
        network, transport = event.get("network"), event.get("transport")
        if not isinstance(network, Mapping) or not isinstance(transport, Mapping):
            return MatchResult(False)
        orientation = _header_matches(rule, network, transport)
        if orientation is None:
            return MatchResult(False)
        flow = event.get("flow")
        if rule.flow:
            if not isinstance(flow, Mapping):
                return MatchResult(False)
            state = flow.get("tcp_state")
            client = flow.get("client_endpoint")
            if ("to_server" in rule.flow or "to_client" in rule.flow) and not isinstance(client, Mapping):
                return MatchResult(False)
            packet_from_client = (
                isinstance(client, Mapping)
                and client.get("ip") == network.get("source_ip")
                and client.get("port") == transport.get("source_port")
            )
            for condition in rule.flow:
                if condition == "to_server" and not packet_from_client:
                    return MatchResult(False)
                if condition == "to_client" and packet_from_client:
                    return MatchResult(False)
                if condition == "established" and state != "ESTABLISHED":
                    return MatchResult(False)
                if condition == "not_established" and state == "ESTABLISHED":
                    return MatchResult(False)
        if rule.flags is not None:
            flags = transport.get("flags")
            if not isinstance(flags, Mapping):
                return MatchResult(False)
            names = {"S": "syn", "A": "ack", "F": "fin", "R": "rst", "P": "psh", "U": "urg"}
            required = {names[letter] for letter in rule.flags.upper()}
            actual = {name for name in names.values() if flags.get(name)}
            if required != actual:
                return MatchResult(False)
        if rule.dsize is not None:
            size = transport.get("payload_length")
            if not isinstance(size, int) or not _dsize_matches(rule.dsize, size):
                return MatchResult(False)

        if not rule.content:
            return MatchResult(True, {"field": "header"})
        for field, data in _content_buffers(event, stream_data):
            spans = _find_contents(rule.content, data)
            if spans is not None:
                return MatchResult(
                    True,
                    {"field": field, "contents": [
                        {"pattern_hex": spec.pattern.hex(), "offset": start, "length": end - start}
                        for spec, (start, end) in zip(rule.content, spans)
                    ]},
                )
        return MatchResult(False)


def _dsize_matches(expression: str, size: int) -> bool:
    if "<>" in expression:
        low, high = (int(part) for part in expression.split("<>", 1))
        return low < size < high
    match = re.fullmatch(r"(<=|>=|<|>|=)?(\d+)", expression)
    if match is None:
        return False
    operator, number = match.group(1) or "=", int(match.group(2))
    return {"<": size < number, "<=": size <= number, ">": size > number,
            ">=": size >= number, "=": size == number}[operator]


def _content_buffers(event: Mapping[str, Any], stream_data: bytes | None) -> list[tuple[str, bytes]]:
    buffers: list[tuple[str, bytes]] = []
    if stream_data is not None:
        return [("tcp_stream", stream_data)]
    payload = event.get("payload")
    if isinstance(payload, Mapping):
        try:
            data = payload_to_bytes(payload)
            if data:
                buffers.append(("payload", data))
        except (TypeError, ValueError):
            pass
    if buffers:
        return buffers
    application = event.get("application")
    fields = application.get("fields") if isinstance(application, Mapping) else None
    if isinstance(fields, Mapping):
        for key in ("target", "decoded_target", "normalized_target", "decoded_body"):
            value = fields.get(key)
            if isinstance(value, str):
                buffers.append((f"application.{key}", value.encode("utf-8")))
            elif isinstance(value, Mapping):
                data = value.get("data")
                if isinstance(data, str):
                    buffers.append((f"application.{key}", data.encode("utf-8")))
        for key in ("body",):
            value = fields.get(key)
            if isinstance(value, Mapping):
                try:
                    buffers.append((f"application.{key}", payload_to_bytes(value)))
                except (TypeError, ValueError):
                    pass
    return buffers


def _find_contents(specs: list[ContentSpec], data: bytes) -> list[tuple[int, int]] | None:
    def search(index: int, previous_end: int, spans: list[tuple[int, int]]) -> list[tuple[int, int]] | None:
        if index == len(specs):
            return spans
        spec = specs[index]
        relative = spec.distance is not None or spec.within is not None
        start = previous_end + (spec.distance or 0) if relative else (spec.offset or 0)
        end = len(data)
        if spec.depth is not None:
            end = min(end, (spec.offset or 0) + spec.depth)
        if spec.within is not None:
            end = min(end, previous_end + spec.within)
        haystack = data.lower() if spec.nocase else data
        needle = spec.pattern.lower() if spec.nocase else spec.pattern
        position = haystack.find(needle, start, end)
        while position >= 0:
            next_end = position + len(needle)
            found = search(index + 1, next_end, spans + [(position, next_end)])
            if found is not None:
                return found
            position = haystack.find(needle, position + 1, end)
        return None

    return search(0, 0, [])


def detection_event(rule: InternalRule, event: Mapping[str, Any], match: MatchResult) -> dict[str, Any]:
    network, transport = event["network"], event["transport"]
    application, flow = event.get("application"), event.get("flow")
    return {
        "timestamp": event.get("timestamp"), "packet_id": event.get("packet_id"),
        "sid": rule.sid, "rev": rule.rev, "msg": rule.msg,
        "priority": rule.priority, "classtype": rule.classtype,
        "source_ip": network["source_ip"], "source_port": transport["source_port"],
        "destination_ip": network["destination_ip"], "destination_port": transport["destination_port"],
        "protocol": transport["protocol"],
        "application_protocol": application.get("protocol") if isinstance(application, Mapping) else None,
        "flow_id": flow.get("flow_id") if isinstance(flow, Mapping) else None,
        "match": match.information,
    }


class RuleEvaluationEngine:
    """Evaluate all candidates and track basic performance counters."""

    def __init__(self, repository: RuleRepository, matcher: RuleMatchingEngine | None = None) -> None:
        self.repository = repository
        self.matcher = matcher or RuleMatchingEngine()
        self.events_evaluated = 0
        self.candidates_evaluated = 0
        self.match_count = 0

    def evaluate(self, event: Mapping[str, Any], *, stream_data: bytes | None = None) -> list[dict[str, Any]]:
        if event.get("processing_action") == "skip":
            return []
        self.events_evaluated += 1
        candidates = self.repository.candidates(event)
        self.candidates_evaluated += len(candidates)
        detections = []
        for rule in candidates:
            match = self.matcher.match(rule, event, stream_data=stream_data)
            if match.matched:
                detections.append(detection_event(rule, event, match))
        self.match_count += len(detections)
        return detections
