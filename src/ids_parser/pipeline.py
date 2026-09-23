"""Common packet processing pipeline used by live traffic and PCAP files."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from .detector import detect_application
from .models import CaptureContext, NormalizedIDSEvent
from .parsers.http import parse_http
from .parsers.network import parse_ipv4
from .parsers.payload import payload_to_bytes
from .parsers.transport import empty_payload, parse_transport


EventSink = Callable[[dict[str, Any]], None]


class PacketPipeline:
    """Convert raw packets to normalized events and send them to a sink.

    Capture sources intentionally know nothing about individual protocol
    parsers. IPv4, TCP, UDP, and HTTP parsing all happens behind
    ``process_packet``.
    """

    def __init__(self, sink: EventSink | None = None) -> None:
        self._sink = sink
        self._packet_id = 0
        self._id_lock = Lock()

    def _next_packet_id(self) -> int:
        with self._id_lock:
            self._packet_id += 1
            return self._packet_id

    @staticmethod
    def _packet_timestamp(packet: Any) -> tuple[str, list[str]]:
        errors: list[str] = []
        try:
            unix_timestamp = float(packet.time)
            timestamp = datetime.fromtimestamp(
                unix_timestamp, tz=timezone.utc
            ).isoformat(timespec="microseconds")
        except (AttributeError, OSError, OverflowError, TypeError, ValueError):
            timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            errors.append("Packet timestamp was unavailable; capture time was used")
        return timestamp.replace("+00:00", "Z"), errors

    @staticmethod
    def _packet_length(packet: Any) -> tuple[int, list[str]]:
        try:
            return len(bytes(packet)), []
        except (TypeError, ValueError):
            return 0, ["Packet length could not be determined"]

    def process_packet(
        self, packet: Any, context: CaptureContext
    ) -> dict[str, Any]:
        """Normalize one packet and forward it to the configured sink."""

        timestamp, timestamp_errors = self._packet_timestamp(packet)
        packet_length, length_errors = self._packet_length(packet)
        errors = timestamp_errors + length_errors

        network: dict[str, Any] | None = None
        transport: dict[str, Any] | None = None
        payload = empty_payload()
        application: dict[str, Any] = {"protocol": "UNKNOWN", "fields": {}}

        try:
            network = parse_ipv4(packet)
            if network is not None:
                transport, payload = parse_transport(packet)
                protocol = detect_application(transport, payload)
                if protocol == "HTTP":
                    application["protocol"] = "HTTP"
                    try:
                        application["fields"] = parse_http(payload_to_bytes(payload))
                    except (UnicodeDecodeError, ValueError) as error:
                        errors.append(f"HTTP parsing failed: {error}")
        except Exception as error:
            errors.append(f"Protocol parsing failed: {type(error).__name__}: {error}")

        status = "parsed" if network is not None and transport is not None else "partial"
        if application["protocol"] == "HTTP":
            fields = application["fields"]
            if not fields or not fields["headers_complete"] or not fields["body_complete"]:
                status = "partial"
        if errors and status == "parsed":
            status = "partial"
        if errors and network is None and packet_length == 0:
            status = "error"

        event = NormalizedIDSEvent(
            packet_id=self._next_packet_id(),
            timestamp=timestamp,
            capture={"mode": context.mode, "source": context.source},
            packet_length=packet_length,
            network=network,
            transport=transport,
            application=application,
            payload=payload,
            status=status,
            errors=errors,
        ).to_dict()

        if self._sink is not None:
            self._sink(event)
        return event
