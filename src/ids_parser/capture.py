"""Packet input adapters for live interfaces and PCAP files."""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

from scapy.all import PcapReader, conf, sniff
from scapy.error import Scapy_Exception

from .models import CaptureContext
from .pipeline import PacketPipeline


class CaptureError(RuntimeError):
    """A user-facing failure while opening or reading a capture source."""


def list_interfaces() -> list[str]:
    """Return user-facing interface names in stable, duplicate-free order."""

    try:
        names = (
            str(getattr(interface, "name", None) or interface)
            for interface in conf.ifaces.values()
        )
        return list(dict.fromkeys(names))
    except (OSError, Scapy_Exception) as error:
        raise CaptureError(f"Could not list network interfaces: {error}") from error


def resolve_interface(interface_name: str) -> Any:
    """Resolve a friendly name or capture identifier to a Scapy interface."""

    requested = interface_name.strip().casefold()
    try:
        for interface in conf.ifaces.values():
            identifiers = {
                str(interface),
                str(getattr(interface, "name", "")),
                str(getattr(interface, "description", "")),
                str(getattr(interface, "network_name", "")),
            }
            if any(identifier.casefold() == requested for identifier in identifiers):
                return interface
    except (OSError, Scapy_Exception) as error:
        raise CaptureError(f"Could not inspect network interfaces: {error}") from error
    raise CaptureError(
        f"Network interface '{interface_name}' was not found. "
        "Use --list-interfaces to see available names."
    )


def read_pcap(
    pcap_path: str | Path,
    pipeline: PacketPipeline,
    *,
    count: int | None = None,
) -> int:
    """Stream packets from a PCAP into the shared packet pipeline."""

    path = Path(pcap_path).expanduser()
    if not path.exists():
        raise CaptureError(f"PCAP file does not exist: {path}")
    if not path.is_file():
        raise CaptureError(f"PCAP path is not a file: {path}")

    context = CaptureContext(mode="pcap", source=str(path.resolve()))
    processed = 0
    try:
        with PcapReader(str(path)) as reader:
            try:
                for packet in reader:
                    pipeline.process_packet(packet, context)
                    processed += 1
                    if count is not None and processed >= count:
                        break
            except (EOFError, Scapy_Exception) as error:
                # A damaged final record must not discard packets that were
                # already read successfully. If nothing could be recovered,
                # keep reporting the file as unreadable to the caller.
                if processed == 0:
                    raise CaptureError(
                        f"Could not read PCAP file '{path}': {error}"
                    ) from error
                warnings.warn(
                    f"PCAP file '{path}' ended with an unreadable record after "
                    f"{processed} packet(s): {error}",
                    RuntimeWarning,
                    stacklevel=2,
                )
    except CaptureError:
        raise
    except (EOFError, OSError, Scapy_Exception) as error:
        raise CaptureError(f"Could not read PCAP file '{path}': {error}") from error
    return processed


def capture_live(
    interface: str,
    pipeline: PacketPipeline,
    *,
    count: int | None = None,
    capture_filter: str | None = None,
) -> int:
    """Capture live packets and send each one through the shared pipeline."""

    if not interface.strip():
        raise CaptureError("Network interface must not be empty")

    resolved_interface = resolve_interface(interface)
    context = CaptureContext(mode="live", source=interface)
    processed = 0

    def handle_packet(packet: Any) -> None:
        nonlocal processed
        pipeline.process_packet(packet, context)
        processed += 1

    try:
        sniff(
            iface=resolved_interface,
            prn=handle_packet,
            store=False,
            count=0 if count is None else count,
            filter=capture_filter,
        )
    except (OSError, Scapy_Exception) as error:
        raise CaptureError(
            f"Could not capture packets on interface '{interface}': {error}"
        ) from error
    return processed
