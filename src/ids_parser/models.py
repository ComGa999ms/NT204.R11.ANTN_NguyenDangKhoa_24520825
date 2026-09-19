"""Normalized data models shared by every capture source and parser."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


CaptureMode = Literal["live", "pcap"]
EventStatus = Literal["captured", "parsed", "partial", "error"]


@dataclass(frozen=True, slots=True)
class CaptureContext:
    """Describes where a packet entered the common parsing pipeline."""

    mode: CaptureMode
    source: str

    def __post_init__(self) -> None:
        if self.mode not in {"live", "pcap"}:
            raise ValueError("Capture mode must be 'live' or 'pcap'")
        if not self.source.strip():
            raise ValueError("Capture source must not be empty")


@dataclass(slots=True)
class NormalizedIDSEvent:
    """JSON-compatible event consumed by later IDS modules.

    Network, transport, and application parsers will populate the layer
    dictionaries in later tasks. Keeping the keys present from the beginning
    gives downstream code one stable schema.
    """

    packet_id: int
    timestamp: str
    capture: dict[str, str]
    packet_length: int
    network: dict[str, Any] | None = None
    transport: dict[str, Any] | None = None
    application: dict[str, Any] = field(
        default_factory=lambda: {"protocol": "UNKNOWN", "fields": {}}
    )
    payload: dict[str, Any] = field(
        default_factory=lambda: {
            "length": 0,
            "encoding": None,
            "data": None,
        }
    )
    status: EventStatus = "captured"
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.packet_id < 1:
            raise ValueError("packet_id must be greater than zero")
        if self.packet_length < 0:
            raise ValueError("packet_length must not be negative")
        if self.status not in {"captured", "parsed", "partial", "error"}:
            raise ValueError(f"Unsupported event status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        """Return a deep, JSON-compatible dictionary representation."""

        return asdict(self)

