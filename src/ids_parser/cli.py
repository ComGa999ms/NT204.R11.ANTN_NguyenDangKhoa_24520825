"""CLI nhận lệnh bắt gói tin hoặc đọc file PCAP."""

from __future__ import annotations

import argparse
import sys
from contextlib import ExitStack
from collections.abc import Sequence
from pathlib import Path

from .capture import CaptureError, capture_live, list_interfaces, read_pcap
from .core_engine import RuleEvaluationEngine, RuleRepository
from .flow import FlowTrackerConfig
from .pipeline import PacketPipeline
from .preprocessor import PreprocessConfig
from .rules import RuleLoader
from .writer import JSONLinesWriter


def positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if parsed <= 0:
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
    parser.add_argument(
        "--invalid-policy",
        choices=("mark", "skip"),
        default="mark",
        help="mark or skip structurally invalid events (default: mark)",
    )
    parser.add_argument(
        "--unsupported-policy",
        choices=("mark", "skip"),
        default="mark",
        help="mark or skip unsupported protocol events (default: mark)",
    )
    parser.add_argument(
        "--max-packet-length",
        type=positive_integer,
        default=16 * 1024 * 1024,
        help="maximum accepted packet_length before preprocessing marks invalid",
    )
    parser.add_argument(
        "--flow-timeout",
        type=positive_float,
        default=60.0,
        help="idle seconds before a flow is exported and removed (default: 60)",
    )
    parser.add_argument("--rules", type=Path, action="append", help="Snort .rules file; may be repeated")
    parser.add_argument("--alerts-output", type=Path, help="Detection JSONL path (default: alerts.jsonl)")
    parser.add_argument("--disable-sid", type=positive_integer, action="append", default=[], help="Disable a rule SID")
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
    if args.alerts_output is not None and not args.rules:
        parser.error("--alerts-output requires --rules")

    try:
        preprocess_config = PreprocessConfig(
            invalid_policy=args.invalid_policy,
            unsupported_policy=args.unsupported_policy,
            max_packet_length=args.max_packet_length,
        )
        flow_config = FlowTrackerConfig(idle_timeout_seconds=args.flow_timeout)
        loaded = RuleLoader().load(args.rules or [], disabled_sids=args.disable_sid)
        for warning in loaded.warnings:
            print(f"rule {warning.status}: {warning.source}:{warning.line_number}: {warning.message}", file=sys.stderr)
        if args.rules and not loaded.rules:
            print("warning: no valid enabled rules loaded", file=sys.stderr)
        alerts_path = args.alerts_output or Path("alerts.jsonl")
        if args.rules and args.output.resolve() == alerts_path.resolve():
            parser.error("--output and --alerts-output must differ")
        if args.rules:
            rule_paths = {path.resolve() for path in args.rules}
            if args.output.resolve() in rule_paths or alerts_path.resolve() in rule_paths:
                parser.error("output paths must differ from input .rules files")
        with ExitStack() as stack:
            writer = stack.enter_context(JSONLinesWriter(args.output))
            alert_writer = stack.enter_context(JSONLinesWriter(alerts_path)) if args.rules else None
            pipeline = PacketPipeline(
                sink=writer.write,
                preprocess_config=preprocess_config,
                flow_config=flow_config,
                rule_engine=RuleEvaluationEngine(RuleRepository(loaded.rules)) if args.rules else None,
                detection_sink=alert_writer.write if alert_writer is not None else None,
            )
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

