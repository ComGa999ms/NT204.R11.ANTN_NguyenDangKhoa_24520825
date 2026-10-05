"""Bidirectional flow and TCP connection tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha1
from ipaddress import ip_address
from typing import Any, Mapping


Endpoint = tuple[str, int]


@dataclass(frozen=True, slots=True)
class FlowTrackerConfig:
    """Runtime limits for flow tracking."""

    idle_timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        if self.idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be greater than zero")


@dataclass(slots=True)
class _DirectionalStats:
    packets: int = 0
    bytes: int = 0


@dataclass(slots=True)
class _TCPProgress:
    syn_from_a: bool = False
    syn_from_b: bool = False
    established: bool = False
    fin_from_a: bool = False
    fin_from_b: bool = False
    reset: bool = False
    flags_seen: dict[str, bool] = field(
        default_factory=lambda: {
            "syn": False,
            "ack": False,
            "fin": False,
            "rst": False,
            "psh": False,
            "urg": False,
        }
    )


@dataclass(slots=True)
class _FlowState:
    flow_id: str
    protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    started_at: str
    started_epoch: float
    last_seen_at: str
    last_seen_epoch: float
    packets: int = 0
    bytes: int = 0
    a_to_b: _DirectionalStats = field(default_factory=_DirectionalStats)
    b_to_a: _DirectionalStats = field(default_factory=_DirectionalStats)
    tcp: _TCPProgress | None = None
    expired: bool = False


class FlowTracker:
    """Aggregate packets into stable bidirectional flow records."""

    def __init__(self, config: FlowTrackerConfig | None = None) -> None:
        self._config = config or FlowTrackerConfig()
        self._flows: dict[str, _FlowState] = {}

    @property
    def active_count(self) -> int:
        return len(self._flows)

    def process(self, event: Mapping[str, Any] | Any) -> dict[str, Any]:
        if not isinstance(event, Mapping):
            return {"flow": None, "expired_flows": []}

        timestamp = _parse_timestamp(event.get("timestamp"))
        expired = self.expire_idle(timestamp)
        if event.get("processing_action") == "skip":
            return {"flow": None, "expired_flows": expired}

        endpoints = _event_endpoints(event)
        if endpoints is None:
            return {"flow": None, "expired_flows": expired}

        protocol, source, destination = endpoints
        endpoint_a, endpoint_b = _canonical_endpoints(source, destination)
        flow_id = _flow_id(protocol, endpoint_a, endpoint_b)
        now_text = _format_timestamp(timestamp)
        flow = self._flows.get(flow_id)
        is_new = flow is None
        if flow is None:
            flow = _FlowState(
                flow_id=flow_id,
                protocol=protocol,
                endpoint_a=endpoint_a,
                endpoint_b=endpoint_b,
                started_at=now_text,
                started_epoch=timestamp,
                last_seen_at=now_text,
                last_seen_epoch=timestamp,
                tcp=_TCPProgress() if protocol == "TCP" else None,
            )
            self._flows[flow_id] = flow

        direction = "a_to_b" if source == flow.endpoint_a else "b_to_a"
        packet_bytes = _packet_bytes(event)
        flow.packets += 1
        flow.bytes += packet_bytes
        flow.last_seen_at = now_text
        flow.last_seen_epoch = timestamp
        stats = flow.a_to_b if direction == "a_to_b" else flow.b_to_a
        stats.packets += 1
        stats.bytes += packet_bytes

        if protocol == "TCP" and flow.tcp is not None:
            _update_tcp_state(flow.tcp, direction, event)

        return {
            "flow": _snapshot(flow, direction=direction, is_new=is_new),
            "expired_flows": expired,
        }

    def expire_idle(self, reference_time: float | str | None = None) -> list[dict[str, Any]]:
        reference_epoch = _parse_timestamp(reference_time)
        expired: list[dict[str, Any]] = []
        for flow_id, flow in list(self._flows.items()):
            if reference_epoch - flow.last_seen_epoch < self._config.idle_timeout_seconds:
                continue
            flow.expired = True
            expired.append(_snapshot(flow, direction=None, is_new=False))
            del self._flows[flow_id]
        return expired

    def export_active(self) -> list[dict[str, Any]]:
        return [
            _snapshot(flow, direction=None, is_new=False)
            for flow in self._flows.values()
        ]


def _parse_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str) and value.strip():
        text = value.strip()
        parse_text = f"{text[:-1]}+00:00" if text.endswith("Z") else text
        try:
            parsed = datetime.fromisoformat(parse_text)
        except ValueError:
            return datetime.now(timezone.utc).timestamp()
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).timestamp()
    return datetime.now(timezone.utc).timestamp()


def _format_timestamp(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _event_endpoints(event: Mapping[str, Any]) -> tuple[str, Endpoint, Endpoint] | None:
    network = event.get("network")
    transport = event.get("transport")
    if not isinstance(network, Mapping) or not isinstance(transport, Mapping):
        return None

    protocol = transport.get("protocol")
    source_ip = network.get("source_ip")
    destination_ip = network.get("destination_ip")
    source_port = transport.get("source_port")
    destination_port = transport.get("destination_port")
    if protocol not in {"TCP", "UDP"}:
        return None
    if not isinstance(source_ip, str) or not isinstance(destination_ip, str):
        return None
    if not isinstance(source_port, int) or not isinstance(destination_port, int):
        return None
    return protocol, (source_ip, source_port), (destination_ip, destination_port)


def _endpoint_sort_key(endpoint: Endpoint) -> tuple[int, int, int]:
    address, port = endpoint
    try:
        parsed = ip_address(address)
        return parsed.version, int(parsed), port
    except ValueError:
        fallback = int.from_bytes(address.encode("utf-8"), "big", signed=False)
        return 99, fallback, port


def _canonical_endpoints(source: Endpoint, destination: Endpoint) -> tuple[Endpoint, Endpoint]:
    if _endpoint_sort_key(source) <= _endpoint_sort_key(destination):
        return source, destination
    return destination, source


def _flow_id(protocol: str, endpoint_a: Endpoint, endpoint_b: Endpoint) -> str:
    material = (
        f"{protocol}|{endpoint_a[0]}:{endpoint_a[1]}|"
        f"{endpoint_b[0]}:{endpoint_b[1]}"
    )
    return sha1(material.encode("utf-8")).hexdigest()[:16]


def _packet_bytes(event: Mapping[str, Any]) -> int:
    packet_length = event.get("packet_length")
    if isinstance(packet_length, int) and not isinstance(packet_length, bool):
        return max(0, packet_length)
    payload = event.get("payload")
    if isinstance(payload, Mapping):
        payload_length = payload.get("length")
        if isinstance(payload_length, int) and not isinstance(payload_length, bool):
            return max(0, payload_length)
    return 0


def _update_tcp_state(tcp: _TCPProgress, direction: str, event: Mapping[str, Any]) -> None:
    transport = event.get("transport")
    flags = transport.get("flags") if isinstance(transport, Mapping) else None
    if not isinstance(flags, Mapping):
        return

    syn = bool(flags.get("syn"))
    ack = bool(flags.get("ack"))
    fin = bool(flags.get("fin"))
    rst = bool(flags.get("rst"))
    for name in tcp.flags_seen:
        tcp.flags_seen[name] = tcp.flags_seen[name] or bool(flags.get(name))

    if rst:
        tcp.reset = True
        return
    if syn and direction == "a_to_b":
        tcp.syn_from_a = True
    if syn and direction == "b_to_a":
        tcp.syn_from_b = True
    if ack and not syn and tcp.syn_from_a and tcp.syn_from_b:
        tcp.established = True
    if _packet_payload_length(event) > 0 and tcp.syn_from_a and tcp.syn_from_b:
        tcp.established = True
    if fin and direction == "a_to_b":
        tcp.fin_from_a = True
    if fin and direction == "b_to_a":
        tcp.fin_from_b = True


def _packet_payload_length(event: Mapping[str, Any]) -> int:
    transport = event.get("transport")
    if isinstance(transport, Mapping):
        payload_length = transport.get("payload_length")
        if isinstance(payload_length, int) and not isinstance(payload_length, bool):
            return payload_length
    return 0


def _tcp_state(tcp: _TCPProgress | None) -> str | None:
    if tcp is None:
        return None
    if tcp.reset:
        return "RESET"
    if tcp.fin_from_a and tcp.fin_from_b:
        return "CLOSED"
    if tcp.fin_from_a or tcp.fin_from_b:
        return "FIN_WAIT"
    if tcp.established:
        return "ESTABLISHED"
    if tcp.syn_from_a and tcp.syn_from_b:
        return "SYN_RECEIVED"
    if tcp.syn_from_a or tcp.syn_from_b:
        return "SYN_SENT"
    return "NEW"


def _endpoint_dict(endpoint: Endpoint) -> dict[str, Any]:
    return {"ip": endpoint[0], "port": endpoint[1]}


def _stats_dict(stats: _DirectionalStats) -> dict[str, int]:
    return {"packets": stats.packets, "bytes": stats.bytes}


def _snapshot(
    flow: _FlowState, *, direction: str | None, is_new: bool
) -> dict[str, Any]:
    return {
        "flow_id": flow.flow_id,
        "protocol": flow.protocol,
        "endpoint_a": _endpoint_dict(flow.endpoint_a),
        "endpoint_b": _endpoint_dict(flow.endpoint_b),
        "direction": direction,
        "is_new": is_new,
        "expired": flow.expired,
        "started_at": flow.started_at,
        "last_seen_at": flow.last_seen_at,
        "duration_seconds": round(
            max(0.0, flow.last_seen_epoch - flow.started_epoch), 6
        ),
        "packet_count": flow.packets,
        "byte_count": flow.bytes,
        "a_to_b": _stats_dict(flow.a_to_b),
        "b_to_a": _stats_dict(flow.b_to_a),
        "tcp_state": _tcp_state(flow.tcp),
        "tcp_flags_seen": None if flow.tcp is None else dict(flow.tcp.flags_seen),
    }
