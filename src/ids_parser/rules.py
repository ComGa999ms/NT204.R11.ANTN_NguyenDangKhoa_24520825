"""Snort rule loading, parsing, and validation for the IDS core engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_network
from pathlib import Path
from typing import Iterable, Literal, Mapping


RuleStatus = Literal["valid", "invalid", "unsupported"]
Direction = Literal["->", "<>"]

SUPPORTED_PROTOCOLS = frozenset({"tcp", "udp"})
SUPPORTED_ACTIONS = frozenset({"alert"})
SUPPORTED_OPTIONS = frozenset(
    {
        "msg",
        "sid",
        "rev",
        "content",
        "nocase",
        "offset",
        "depth",
        "distance",
        "within",
        "flow",
        "flags",
        "dsize",
        "classtype",
        "priority",
    }
)
SUPPORTED_FLOW_VALUES = frozenset(
    {"to_server", "to_client", "established", "not_established"}
)
DSIZE_PATTERN = re.compile(r"(?:[<>]=?|=)?\d+(?:<>\d+)?$")
INTEGER_PATTERN = re.compile(r"\d+$")


@dataclass(frozen=True, slots=True)
class IPPattern:
    """An ``any`` or IPv4/CIDR address pattern from a rule header."""

    raw: str
    network: IPv4Network | None

    def matches(self, value: str | IPv4Address) -> bool:
        if self.network is None:
            return True
        try:
            return IPv4Address(value) in self.network
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class PortSpec:
    """An ``any``, single-port, or inclusive port-range pattern."""

    raw: str
    start: int | None
    end: int | None

    @property
    def is_any(self) -> bool:
        return self.start is None and self.end is None

    def matches(self, port: int) -> bool:
        if self.is_any:
            return True
        if not 0 <= port <= 65535:
            return False
        if self.start is not None and port < self.start:
            return False
        if self.end is not None and port > self.end:
            return False
        return True


@dataclass(slots=True)
class ContentSpec:
    """A content option and modifiers that apply to that content."""

    pattern: bytes
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None


@dataclass(slots=True)
class InternalRule:
    """Validated rule object used by later repository and matcher modules."""

    source: str
    line_number: int
    raw: str
    action: str
    protocol: str
    src_ip: IPPattern
    src_port: PortSpec
    direction: Direction
    dst_ip: IPPattern
    dst_port: PortSpec
    msg: str
    sid: int
    rev: int
    content: list[ContentSpec] = field(default_factory=list)
    flow: tuple[str, ...] = ()
    flags: str | None = None
    dsize: str | None = None
    classtype: str | None = None
    priority: int | None = None


@dataclass(frozen=True, slots=True)
class RuleIssue:
    """A non-fatal rule loading or validation problem."""

    status: RuleStatus
    message: str
    source: str
    line_number: int
    raw: str


@dataclass(frozen=True, slots=True)
class RuleParseResult:
    """Result of parsing one rule line."""

    status: RuleStatus
    rule: InternalRule | None
    issues: tuple[RuleIssue, ...] = ()


@dataclass(slots=True)
class RuleLoadResult:
    """Rules accepted by the loader and warnings for rejected input."""

    rules: list[InternalRule] = field(default_factory=list)
    warnings: list[RuleIssue] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    disabled_sids: list[int] = field(default_factory=list)


class _UnsupportedValue(ValueError):
    pass


class RuleParser:
    """Parse and validate the supported subset of Snort rule syntax."""

    def parse(
        self,
        text: str,
        *,
        source: str = "<string>",
        line_number: int = 1,
    ) -> RuleParseResult:
        raw = text.strip()
        issues: list[RuleIssue] = []
        if not raw:
            return RuleParseResult("invalid", None, (_issue("Empty rule", source, line_number, raw),))
        if raw.startswith("#"):
            return RuleParseResult("invalid", None, (_issue("Comment is not a rule", source, line_number, raw),))

        header_text, options_text = self._split_rule(raw, source, line_number, issues)
        if header_text is None or options_text is None:
            return RuleParseResult(_status(issues), None, tuple(issues))

        header = header_text.split()
        if len(header) != 7:
            issues.append(
                _issue(
                    "Rule header must contain 7 fields",
                    source,
                    line_number,
                    raw,
                )
            )
            return RuleParseResult("invalid", None, tuple(issues))

        action, protocol, src_ip_text, src_port_text, direction, dst_ip_text, dst_port_text = header
        action = action.casefold()
        protocol = protocol.casefold()
        if action not in SUPPORTED_ACTIONS:
            issues.append(
                _issue(
                    f"Unsupported rule action: {action}",
                    source,
                    line_number,
                    raw,
                    status="unsupported",
                )
            )
        if protocol not in SUPPORTED_PROTOCOLS:
            issues.append(
                _issue(
                    f"Unsupported protocol: {protocol}",
                    source,
                    line_number,
                    raw,
                    status="unsupported",
                )
            )
        if direction not in {"->", "<>"}:
            issues.append(
                _issue(
                    f"Unsupported direction: {direction}",
                    source,
                    line_number,
                    raw,
                )
            )

        src_ip = _parse_ip(src_ip_text, source, line_number, raw, issues)
        dst_ip = _parse_ip(dst_ip_text, source, line_number, raw, issues)
        src_port = _parse_port(src_port_text, source, line_number, raw, issues)
        dst_port = _parse_port(dst_port_text, source, line_number, raw, issues)

        parsed_options = self._parse_options(
            options_text,
            source=source,
            line_number=line_number,
            raw=raw,
            protocol=protocol,
            issues=issues,
        )
        if parsed_options is None:
            return RuleParseResult(_status(issues), None, tuple(issues))

        msg = parsed_options["msg"]
        sid = parsed_options["sid"]
        rev = parsed_options["rev"]
        if msg is None:
            issues.append(_issue("Missing required option: msg", source, line_number, raw))
        if sid is None:
            issues.append(_issue("Missing required option: sid", source, line_number, raw))
        if rev is None:
            issues.append(_issue("Missing required option: rev", source, line_number, raw))

        if src_ip is None or dst_ip is None or src_port is None or dst_port is None or issues:
            return RuleParseResult(_status(issues), None, tuple(issues))

        assert msg is not None and sid is not None and rev is not None
        assert direction in {"->", "<>"}
        rule = InternalRule(
            source=source,
            line_number=line_number,
            raw=raw,
            action=action,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            direction=direction,
            dst_ip=dst_ip,
            dst_port=dst_port,
            msg=msg,
            sid=sid,
            rev=rev,
            content=parsed_options["content"],
            flow=tuple(parsed_options["flow"]),
            flags=parsed_options["flags"],
            dsize=parsed_options["dsize"],
            classtype=parsed_options["classtype"],
            priority=parsed_options["priority"],
        )
        return RuleParseResult("valid", rule)

    @staticmethod
    def _split_rule(
        raw: str,
        source: str,
        line_number: int,
        issues: list[RuleIssue],
    ) -> tuple[str | None, str | None]:
        opening = raw.find("(")
        if opening < 0 or not raw.endswith(")"):
            issues.append(_issue("Rule must contain a parenthesized option block", source, line_number, raw))
            return None, None
        header = raw[:opening].strip()
        options = raw[opening + 1 : -1].strip()
        if not header:
            issues.append(_issue("Rule header is empty", source, line_number, raw))
        if not options:
            issues.append(_issue("Rule option block is empty", source, line_number, raw))
        return header, options

    def _parse_options(
        self,
        text: str,
        *,
        source: str,
        line_number: int,
        raw: str,
        protocol: str,
        issues: list[RuleIssue],
    ) -> dict[str, object] | None:
        try:
            tokens = _split_options(text)
        except ValueError as error:
            issues.append(_issue(str(error), source, line_number, raw))
            return None

        values: dict[str, object] = {
            "msg": None,
            "sid": None,
            "rev": None,
            "content": [],
            "flow": [],
            "flags": None,
            "dsize": None,
            "classtype": None,
            "priority": None,
        }
        seen: set[str] = set()
        current_content: ContentSpec | None = None

        for token in tokens:
            name, separator, raw_value = token.partition(":")
            name = name.strip().casefold()
            value = raw_value.strip()
            if not name:
                issues.append(_issue("Empty rule option", source, line_number, raw))
                continue
            if name not in SUPPORTED_OPTIONS:
                issues.append(
                    _issue(
                        f"Unsupported rule option: {name}",
                        source,
                        line_number,
                        raw,
                        status="unsupported",
                    )
                )
                continue

            if name == "nocase":
                if separator or current_content is None:
                    issues.append(_issue("nocase must follow content", source, line_number, raw))
                else:
                    current_content.nocase = True
                continue

            if not separator or not value:
                issues.append(_issue(f"Option {name} requires a value", source, line_number, raw))
                continue

            if name in {"offset", "depth", "distance", "within"}:
                if current_content is None:
                    issues.append(_issue(f"{name} must follow content", source, line_number, raw))
                    continue
                parsed = _parse_nonnegative_int(value, name, source, line_number, raw, issues)
                if parsed is not None:
                    setattr(current_content, name, parsed)
                continue

            if name == "content":
                if name in seen and not isinstance(values["content"], list):
                    issues.append(_issue("Invalid content option state", source, line_number, raw))
                    continue
                try:
                    pattern = _parse_content(value)
                except ValueError as error:
                    issues.append(_issue(str(error), source, line_number, raw))
                    continue
                current_content = ContentSpec(pattern=pattern)
                values["content"].append(current_content)  # type: ignore[union-attr]
                seen.add(name)
                continue

            if name in seen:
                issues.append(_issue(f"Duplicate option: {name}", source, line_number, raw))
                continue

            if name == "msg":
                try:
                    values[name] = _parse_string(value, name)
                except ValueError as error:
                    issues.append(_issue(str(error), source, line_number, raw))
                    continue
            elif name == "classtype":
                if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                    issues.append(_issue("classtype must be a non-empty token", source, line_number, raw))
                    continue
                values[name] = value
            elif name in {"sid", "rev", "priority"}:
                parsed = _parse_positive_int(value, name, source, line_number, raw, issues)
                if parsed is None:
                    continue
                values[name] = parsed
            elif name == "flow":
                flow_values = tuple(item.strip().casefold() for item in value.split(",") if item.strip())
                if not flow_values:
                    issues.append(_issue("flow must contain at least one value", source, line_number, raw))
                    continue
                unsupported = [item for item in flow_values if item not in SUPPORTED_FLOW_VALUES]
                if unsupported:
                    issues.append(
                        _issue(
                            f"Unsupported flow value(s): {', '.join(unsupported)}",
                            source,
                            line_number,
                            raw,
                            status="unsupported",
                        )
                    )
                    continue
                values[name] = list(flow_values)
            elif name == "flags":
                if protocol != "tcp":
                    issues.append(_issue("flags is only valid for TCP rules", source, line_number, raw))
                    continue
                values[name] = value
            elif name == "dsize":
                if not DSIZE_PATTERN.fullmatch(value):
                    issues.append(_issue(f"Invalid dsize expression: {value}", source, line_number, raw))
                    continue
                values[name] = value
            seen.add(name)

        return values


class RuleLoader:
    """Load rules from files while keeping individual failures non-fatal."""

    def __init__(self, parser: RuleParser | None = None) -> None:
        self.parser = parser or RuleParser()

    def load(
        self,
        paths: Iterable[str | Path],
        *,
        enabled_files: Mapping[str, bool] | None = None,
        disabled_sids: Iterable[int] = (),
    ) -> RuleLoadResult:
        disabled_sid_set = frozenset(int(sid) for sid in disabled_sids)
        result = RuleLoadResult(disabled_sids=sorted(disabled_sid_set))

        for input_path in paths:
            path = Path(input_path).expanduser()
            if enabled_files is not None and not _file_enabled(path, enabled_files):
                result.skipped_files.append(str(path))
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                result.warnings.append(
                    _issue(
                        f"Could not read rule file: {error}",
                        str(path),
                        0,
                        "",
                    )
                )
                continue

            for line_number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parsed = self.parser.parse(
                    stripped,
                    source=str(path),
                    line_number=line_number,
                )
                if parsed.rule is not None and parsed.status == "valid":
                    if parsed.rule.sid in disabled_sid_set:
                        continue
                    result.rules.append(parsed.rule)
                else:
                    result.warnings.extend(parsed.issues)
        return result


def _file_enabled(path: Path, enabled_files: Mapping[str, bool]) -> bool:
    candidates = {str(path), str(path.resolve()), path.name}
    for configured_path, enabled in enabled_files.items():
        if str(configured_path) in candidates:
            return bool(enabled)
    return True


def _parse_ip(
    value: str,
    source: str,
    line_number: int,
    raw: str,
    issues: list[RuleIssue],
) -> IPPattern | None:
    if value.casefold() == "any":
        return IPPattern(raw=value, network=None)
    try:
        network = ip_network(value, strict=False)
    except ValueError:
        issues.append(_issue(f"Invalid IP or CIDR: {value}", source, line_number, raw))
        return None
    if not isinstance(network, IPv4Network):
        issues.append(
            _issue(
                f"IPv6 is outside the supported scope: {value}",
                source,
                line_number,
                raw,
                status="unsupported",
            )
        )
        return None
    return IPPattern(raw=value, network=network)


def _parse_port(
    value: str,
    source: str,
    line_number: int,
    raw: str,
    issues: list[RuleIssue],
) -> PortSpec | None:
    if value.casefold() == "any":
        return PortSpec(raw=value, start=None, end=None)
    if ":" in value:
        start_text, end_text = value.split(":", 1)
    elif "-" in value:
        start_text, end_text = value.split("-", 1)
    else:
        start_text = end_text = value
    try:
        start = None if not start_text else int(start_text)
        end = None if not end_text else int(end_text)
    except ValueError:
        start = end = None
    if start is None and end is None:
        issues.append(_issue(f"Invalid port: {value}", source, line_number, raw))
        return None
    if start is not None and not 0 <= start <= 65535:
        issues.append(_issue(f"Port is outside range 0-65535: {value}", source, line_number, raw))
        return None
    if end is not None and not 0 <= end <= 65535:
        issues.append(_issue(f"Port is outside range 0-65535: {value}", source, line_number, raw))
        return None
    if start is not None and end is not None and start > end:
        issues.append(_issue(f"Port range is reversed: {value}", source, line_number, raw))
        return None
    return PortSpec(raw=value, start=start, end=end)


def _parse_nonnegative_int(
    value: str,
    name: str,
    source: str,
    line_number: int,
    raw: str,
    issues: list[RuleIssue],
) -> int | None:
    if not INTEGER_PATTERN.fullmatch(value):
        issues.append(_issue(f"{name} must be a non-negative integer", source, line_number, raw))
        return None
    return int(value)


def _parse_positive_int(
    value: str,
    name: str,
    source: str,
    line_number: int,
    raw: str,
    issues: list[RuleIssue],
) -> int | None:
    parsed = _parse_nonnegative_int(value, name, source, line_number, raw, issues)
    if parsed == 0:
        issues.append(_issue(f"{name} must be greater than zero", source, line_number, raw))
        return None
    return parsed


def _parse_string(value: str, name: str) -> str:
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise ValueError(f"{name} must be double-quoted")
    return _decode_escaped(value[1:-1])


def _decode_escaped(value: str) -> str:
    output: list[str] = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"'}
    while index < len(value):
        char = value[index]
        if char != "\\":
            output.append(char)
            index += 1
            continue
        if index + 1 >= len(value):
            raise ValueError("Unterminated escape sequence")
        escaped = value[index + 1]
        if escaped == "x":
            hex_value = value[index + 2 : index + 4]
            if len(hex_value) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", hex_value):
                raise ValueError("Invalid hexadecimal escape sequence")
            output.append(chr(int(hex_value, 16)))
            index += 4
            continue
        output.append(escapes.get(escaped, escaped))
        index += 2
    return "".join(output)


def _parse_content(value: str) -> bytes:
    text = _parse_string(value, "content")
    output = bytearray()
    index = 0
    while index < len(text):
        if text[index] != "|":
            next_hex = text.find("|", index)
            literal = text[index:] if next_hex < 0 else text[index:next_hex]
            output.extend(literal.encode("utf-8"))
            if next_hex < 0:
                break
            index = next_hex
            continue
        closing = text.find("|", index + 1)
        if closing < 0:
            raise ValueError("Unterminated hexadecimal content block")
        hex_values = text[index + 1 : closing].split()
        if not hex_values or any(
            len(item) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", item)
            for item in hex_values
        ):
            raise ValueError("Invalid hexadecimal content block")
        output.extend(bytes.fromhex("".join(hex_values)))
        index = closing + 1
    if not output:
        raise ValueError("content must not be empty")
    return bytes(output)


def _split_options(text: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in text:
        if quote is not None:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
            current.append(char)
        elif char == ";":
            token = "".join(current).strip()
            if token:
                tokens.append(token)
            current = []
        else:
            current.append(char)
    if quote is not None:
        raise ValueError("Unterminated quoted option value")
    token = "".join(current).strip()
    if token:
        tokens.append(token)
    return tokens


def _issue(
    message: str,
    source: str,
    line_number: int,
    raw: str,
    *,
    status: RuleStatus = "invalid",
) -> RuleIssue:
    return RuleIssue(
        status=status,
        message=message,
        source=source,
        line_number=line_number,
        raw=raw,
    )


def _status(issues: Iterable[RuleIssue]) -> RuleStatus:
    collected = tuple(issues)
    if any(issue.status == "invalid" for issue in collected):
        return "invalid"
    if any(issue.status == "unsupported" for issue in collected):
        return "unsupported"
    return "valid"


__all__ = [
    "ContentSpec",
    "IPPattern",
    "InternalRule",
    "PortSpec",
    "RuleIssue",
    "RuleLoadResult",
    "RuleLoader",
    "RuleParseResult",
    "RuleParser",
]
