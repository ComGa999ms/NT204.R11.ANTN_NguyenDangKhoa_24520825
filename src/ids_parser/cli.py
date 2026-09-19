"""Command-line interface for packet capture and PCAP import."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .capture import CaptureError, capture_live, list_interfaces, read_pcap
from .pipeline import PacketPipeline
from .writer import JSONLinesWriter


def positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture packets or import a PCAP into the IDS pipeline."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--interface", help="network interface for live capture")
    source.add_argument("--pcap", type=Path, help="PCAP file to import")
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="list available network interfaces and exit",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("events.jsonl"),
        help="JSON Lines output path (default: events.jsonl)",
    )
    parser.add_argument(
        "--count",
        type=positive_integer,
        help="stop after this many packets (live capture is unlimited by default)",
    )
    parser.add_argument(
        "--filter",
        dest="capture_filter",
        help="optional BPF filter for live capture, for example 'tcp port 80'",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_interfaces:
        if args.interface is not None or args.pcap is not None:
            parser.error("--list-interfaces cannot be combined with a capture source")
        try:
            interfaces = list_interfaces()
        except CaptureError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        if not interfaces:
            print("No network interfaces were found.")
        else:
            for index, interface in enumerate(interfaces, start=1):
                print(f"{index}. {interface}")
        return 0

    if args.interface is None and args.pcap is None:
        parser.error("one of --interface or --pcap is required")
    if args.pcap is not None and args.capture_filter is not None:
        parser.error("--filter is only supported with --interface")

    try:
        with JSONLinesWriter(args.output) as writer:
            pipeline = PacketPipeline(sink=writer.write)
            if args.pcap is not None:
                processed = read_pcap(args.pcap, pipeline, count=args.count)
            else:
                processed = capture_live(
                    args.interface,
                    pipeline,
                    count=args.count,
                    capture_filter=args.capture_filter,
                )
    except CaptureError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCapture stopped by user.", file=sys.stderr)
        return 130

    print(f"Processed {processed} packet(s). Output: {args.output}")
    return 0


def entrypoint() -> None:
    raise SystemExit(main())

