"""Common packet processing pipeline used by live traffic and PCAP files."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from .detector import detect_application
from .models import CaptureContext, NormalizedIDSEvent
from .parsers.dns import parse_dns
from .parsers.http import parse_http
from .parsers.network import parse_ipv4
from .parsers.payload import normalize_payload, payload_to_bytes
from .parsers.smtp import parse_smtp
from .parsers.transport import empty_payload, parse_transport
from .reassembly import FlowKey, TCPStreamReassembler


EventSink = Callable[[dict[str, Any]], None]


class PacketPipeline:
    """Convert raw packets to normalized events and send them to a sink.

    Capture sources intentionally know nothing about individual protocol
    parsers. IPv4, TCP, UDP, HTTP, DNS, and SMTP parsing all happens behind
    ``process_packet``.
    """

    def __init__(
        self,
        sink: EventSink | None = None,
        *,
        tcp_reassembler: TCPStreamReassembler | None = None,
    ) -> None:
        self._sink = sink
        self._packet_id = 0
        self._id_lock = Lock()
        self._tcp_streams = tcp_reassembler or TCPStreamReassembler()

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
        except Exception:
            # Raw capture adapters can expose malformed metadata through
            # library-specific exceptions. Metadata failure must not stop the
            # packet stream.
            timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            errors.append("Packet timestamp was unavailable; capture time was used")
        return timestamp.replace("+00:00", "Z"), errors

    @staticmethod
    def _packet_length(packet: Any) -> tuple[int, list[str]]:
        try:
            return len(bytes(packet)), []
        except Exception:
            return 0, ["Packet length could not be determined"]

    @staticmethod
    def _capture_time(packet: Any) -> float:
        try:
            return float(packet.time)
        except Exception:
            return datetime.now(timezone.utc).timestamp()

    @staticmethod
    def _flow_key(
        network: dict[str, Any], transport: dict[str, Any]
    ) -> FlowKey:
        return (
            str(network["source_ip"]),
            int(transport["source_port"]),
            str(network["destination_ip"]),
            int(transport["destination_port"]),
        )

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
        application_raw = b""
        reassembly_flow: FlowKey | None = None

        try:
            network = parse_ipv4(packet)
            if network is not None:
                transport, payload = parse_transport(packet)
                application_raw = payload_to_bytes(payload)
                if transport is not None and transport["protocol"] == "TCP":
                    flags = transport["flags"]
                    if application_raw or any(
                        flags[name] for name in ("syn", "fin", "rst")
                    ):
                        reassembly_flow = self._flow_key(network, transport)
                        result = self._tcp_streams.add_segment(
                            reassembly_flow,
                            transport["sequence_number"],
                            application_raw,
                            timestamp=self._capture_time(packet),
                            syn=flags["syn"],
                            ack=flags["ack"],
                            fin=flags["fin"],
                            rst=flags["rst"],
                        )
                        transport["reassembly"] = result.metadata()
                        application_raw = result.data
                        if result.overflowed:
                            errors.append("TCP reassembly buffer limit was exceeded")

                application_payload = normalize_payload(application_raw)
                protocol = detect_application(transport, application_payload)
                if protocol == "HTTP":
                    application["protocol"] = "HTTP"
                    try:
                        application["fields"] = parse_http(application_raw)
                    except (UnicodeDecodeError, ValueError) as error:
                        errors.append(f"HTTP parsing failed: {error}")
                elif protocol == "DNS" and transport is not None:
                    application["protocol"] = "DNS"
                    try:
                        application["fields"] = parse_dns(
                            application_raw, transport["protocol"]
                        )
                    except (AttributeError, IndexError, TypeError, ValueError) as error:
                        errors.append(f"DNS parsing failed: {error}")
                elif protocol == "SMTP":
                    application["protocol"] = "SMTP"
                    try:
                        application["fields"] = parse_smtp(application_raw)
                    except (UnicodeDecodeError, ValueError) as error:
                        errors.append(f"SMTP parsing failed: {error}")
        except Exception as error:
            errors.append(f"Protocol parsing failed: {type(error).__name__}: {error}")

        status = "parsed" if network is not None and transport is not None else "partial"
        if application["protocol"] == "HTTP":
            fields = application["fields"]
            if not fields or not fields["headers_complete"] or not fields["body_complete"]:
                status = "partial"
            elif reassembly_flow is not None:
                self._tcp_streams.consume(reassembly_flow, fields["message_length"])
        elif application["protocol"] == "DNS":
            fields = application["fields"]
            if not fields:
                status = "partial"
            elif reassembly_flow is not None:
                self._tcp_streams.consume(reassembly_flow, fields["message_length"])
        elif application["protocol"] == "SMTP":
            fields = application["fields"]
            if not fields or not fields["stream_complete"]:
                status = "partial"
            if fields and reassembly_flow is not None:
                self._tcp_streams.consume(reassembly_flow, fields["message_length"])
        if transport is not None and "reassembly" in transport:
            metadata = transport["reassembly"]
            if metadata["has_gap"] or metadata["overflowed"]:
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
