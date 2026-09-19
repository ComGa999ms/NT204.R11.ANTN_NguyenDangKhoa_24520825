"""Common packet processing pipeline used by live traffic and PCAP files."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from .models import CaptureContext, NormalizedIDSEvent


EventSink = Callable[[dict[str, Any]], None]


class PacketPipeline:
    """Convert raw packets to normalized events and send them to a sink.

    Protocol parsing will be added behind ``process_packet``. Capture sources
    intentionally know nothing about individual protocol parsers.
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

        event = NormalizedIDSEvent(
            packet_id=self._next_packet_id(),
            timestamp=timestamp,
            capture={"mode": context.mode, "source": context.source},
            packet_length=packet_length,
            status="partial" if errors else "captured",
            errors=errors,
        ).to_dict()

        if self._sink is not None:
            self._sink(event)
        return event

