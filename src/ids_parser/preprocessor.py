"""Preprocessing and validation for normalized IDS events."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit, urlunsplit


PreprocessPolicy = Literal["mark", "skip"]


SUPPORTED_APPLICATION_PROTOCOLS = {"HTTP", "DNS", "SMTP"}
SUPPORTED_TRANSPORT_PROTOCOLS = {"TCP", "UDP"}
SUPPORTED_NETWORK_PROTOCOLS = {"IPv4", "IPv6"}
EVENT_STATUSES = {"captured", "parsed", "partial", "error"}
PAYLOAD_ENCODINGS = {None, "utf-8", "hex"}
UNRESERVED_URI = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


@dataclass(frozen=True, slots=True)
class PreprocessConfig:
    """Controls how malformed or unsupported events are handled."""

    invalid_policy: PreprocessPolicy = "mark"
    unsupported_policy: PreprocessPolicy = "mark"
    max_packet_length: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.invalid_policy not in {"mark", "skip"}:
            raise ValueError("invalid_policy must be 'mark' or 'skip'")
        if self.unsupported_policy not in {"mark", "skip"}:
            raise ValueError("unsupported_policy must be 'mark' or 'skip'")
        if self.max_packet_length < 1:
            raise ValueError("max_packet_length must be greater than zero")


@dataclass(slots=True)
class _Issues:
    invalid: list[str] = field(default_factory=list)
    partial: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    def reason(self) -> str | None:
        messages = self.invalid + self.unsupported + self.partial
        return "; ".join(messages) if messages else None


class EventPreprocessor:
    """Validate and normalize one decoded IDS event at a time."""

    def __init__(self, config: PreprocessConfig | None = None) -> None:
        self._config = config or PreprocessConfig()

    def process(self, event: Mapping[str, Any] | Any) -> dict[str, Any]:
        issues = _Issues()
        if isinstance(event, Mapping):
            normalized = deepcopy(dict(event))
        else:
            normalized = {}
            issues.invalid.append("Event must be a JSON object")

        normalized["packet_id"] = _coerce_positive_int(
            normalized.get("packet_id"), "packet_id", issues.invalid
        )
        normalized["timestamp"] = _normalize_timestamp(
            normalized.get("timestamp"), issues
        )
        normalized["capture"] = _normalize_capture(normalized.get("capture"), issues)
        normalized["packet_length"] = _coerce_packet_length(
            normalized.get("packet_length"), self._config.max_packet_length, issues
        )
        normalized["network"] = _normalize_network(normalized.get("network"), issues)
        normalized["transport"] = _normalize_transport(
            normalized.get("transport"), issues
        )
        normalized["payload"] = _normalize_payload(normalized.get("payload"), issues)
        normalized["application"] = _normalize_application(
            normalized.get("application"), normalized["payload"], issues
        )
        normalized["status"] = _normalize_status(normalized.get("status"), issues)
        normalized["errors"] = _normalize_errors(normalized.get("errors"), issues)

        if issues.invalid:
            preprocess_status = "invalid"
            action = "skip" if self._config.invalid_policy == "skip" else "mark"
        elif issues.unsupported:
            preprocess_status = "partial"
            action = (
                "skip" if self._config.unsupported_policy == "skip" else "mark"
            )
        elif issues.partial or normalized["status"] in {"partial", "error"}:
            preprocess_status = "partial"
            action = "process"
        else:
            preprocess_status = "valid"
            action = "process"

        normalized["preprocess_status"] = preprocess_status
        normalized["processing_action"] = action
        normalized["reason"] = issues.reason()
        return normalized


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _coerce_positive_int(
    value: Any, field_name: str, invalid: list[str]
) -> int | None:
    if _is_int(value):
        parsed = value
    elif isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
    else:
        invalid.append(f"{field_name} is missing or not an integer")
        return None
    if parsed < 1:
        invalid.append(f"{field_name} must be greater than zero")
        return None
    return parsed


def _coerce_nonnegative_int(
    value: Any, field_name: str, issues: _Issues, *, required: bool = False
) -> int | None:
    if value is None:
        target = issues.invalid if required else issues.partial
        target.append(f"{field_name} is missing")
        return None
    if _is_int(value):
        parsed = value
    elif isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
    else:
        issues.invalid.append(f"{field_name} is not an integer")
        return None
    if parsed < 0:
        issues.invalid.append(f"{field_name} must not be negative")
        return None
    return parsed


def _coerce_packet_length(
    value: Any, max_packet_length: int, issues: _Issues
) -> int | None:
    packet_length = _coerce_nonnegative_int(
        value, "packet_length", issues, required=True
    )
    if packet_length is not None and packet_length > max_packet_length:
        issues.invalid.append(
            f"packet_length exceeds configured limit ({max_packet_length})"
        )
    return packet_length


def _coerce_port(value: Any, field_name: str, issues: _Issues) -> int | None:
    port = _coerce_nonnegative_int(value, field_name, issues, required=True)
    if port is not None and port > 65535:
        issues.invalid.append(f"{field_name} must be between 0 and 65535")
        return None
    return port


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().casefold()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    if _is_int(value) and value in {0, 1}:
        return bool(value)
    return None


def _normalize_timestamp(value: Any, issues: _Issues) -> str | None:
    if not isinstance(value, str) or not value.strip():
        issues.invalid.append("timestamp is missing or not a string")
        return None

    text = value.strip()
    parse_text = f"{text[:-1]}+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(parse_text)
    except ValueError:
        issues.invalid.append("timestamp is not valid ISO 8601")
        return text

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
        issues.partial.append("timestamp had no timezone; UTC was assumed")
    return parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _normalize_capture(value: Any, issues: _Issues) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        issues.partial.append("capture metadata is missing")
        return {"mode": None, "source": None}

    capture = deepcopy(dict(value))
    mode = capture.get("mode")
    if isinstance(mode, str):
        mode = mode.strip().casefold()
    if mode not in {"live", "pcap"}:
        issues.partial.append("capture.mode is missing or unsupported")
        mode = None
    source = capture.get("source")
    if not isinstance(source, str) or not source.strip():
        issues.partial.append("capture.source is missing")
        source = None
    else:
        source = source.strip()
    capture["mode"] = mode
    capture["source"] = source
    return capture


def _canonical_protocol(value: Any, aliases: Mapping[str, str]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    folded = value.strip().replace("-", "").replace("_", "").casefold()
    return aliases.get(folded, value.strip().upper())


def _normalize_ip(value: Any, field_name: str, issues: _Issues) -> str | None:
    if not isinstance(value, str) or not value.strip():
        issues.invalid.append(f"{field_name} is missing or not a string")
        return None
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        issues.invalid.append(f"{field_name} is not a valid IP address")
        return value.strip()


def _normalize_domain(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value).strip().rstrip(".").casefold() or None
    text = value.strip().rstrip(".")
    return text.casefold() or None


def _normalize_host(value: Any) -> str | None:
    text = _first_value(value)
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None

    if text.startswith("[") and "]" in text:
        host, rest = text[1:].split("]", 1)
        port = rest if rest.startswith(":") else ""
        try:
            return f"[{ip_address(host)}]{port}"
        except ValueError:
            return f"[{host.casefold().rstrip('.')}]{port}"

    host = text
    port = ""
    if text.count(":") == 1:
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            port = f":{maybe_port}"
    try:
        normalized_host = str(ip_address(host))
    except ValueError:
        normalized_host = host.rstrip(".").casefold()
    return f"{normalized_host}{port}" if normalized_host else None


def _first_value(value: Any) -> str | None:
    if isinstance(value, list):
        for item in value:
            if item is not None:
                return str(item)
        return None
    if value is None:
        return None
    return str(value)


def _normalize_network(value: Any, issues: _Issues) -> dict[str, Any] | None:
    if value is None:
        issues.partial.append("network layer is missing")
        return None
    if not isinstance(value, Mapping):
        issues.invalid.append("network must be an object")
        return None

    network = deepcopy(dict(value))
    protocol = _canonical_protocol(network.get("protocol"), {"ipv4": "IPv4", "ip": "IPv4", "ipv6": "IPv6"})
    if protocol is None:
        issues.invalid.append("network.protocol is missing")
    elif protocol not in SUPPORTED_NETWORK_PROTOCOLS:
        issues.unsupported.append(f"unsupported network protocol: {protocol}")
    network["protocol"] = protocol
    network["source_ip"] = _normalize_ip(
        network.get("source_ip"), "network.source_ip", issues
    )
    network["destination_ip"] = _normalize_ip(
        network.get("destination_ip"), "network.destination_ip", issues
    )
    return network


def _normalize_transport(value: Any, issues: _Issues) -> dict[str, Any] | None:
    if value is None:
        issues.partial.append("transport layer is missing")
        return None
    if not isinstance(value, Mapping):
        issues.invalid.append("transport must be an object")
        return None

    transport = deepcopy(dict(value))
    protocol = _canonical_protocol(
        transport.get("protocol"), {"tcp": "TCP", "udp": "UDP"}
    )
    if protocol is None:
        issues.invalid.append("transport.protocol is missing")
    elif protocol not in SUPPORTED_TRANSPORT_PROTOCOLS:
        issues.unsupported.append(f"unsupported transport protocol: {protocol}")
    transport["protocol"] = protocol

    if protocol in SUPPORTED_TRANSPORT_PROTOCOLS:
        transport["source_port"] = _coerce_port(
            transport.get("source_port"), "transport.source_port", issues
        )
        transport["destination_port"] = _coerce_port(
            transport.get("destination_port"), "transport.destination_port", issues
        )
        if "payload_length" in transport:
            transport["payload_length"] = _coerce_nonnegative_int(
                transport.get("payload_length"), "transport.payload_length", issues
            )
        else:
            transport["payload_length"] = None
            issues.partial.append("transport.payload_length is missing")

    if protocol == "TCP":
        flags = transport.get("flags")
        if isinstance(flags, Mapping):
            normalized_flags: dict[str, bool] = {}
            for name, value in flags.items():
                parsed = _coerce_bool(value)
                if parsed is None:
                    issues.partial.append(f"transport.flags.{name} is not boolean")
                    continue
                normalized_flags[str(name).casefold()] = parsed
            transport["flags"] = normalized_flags
        else:
            transport["flags"] = {}
            issues.partial.append("transport.flags is missing")
        if not isinstance(transport.get("options"), list):
            transport["options"] = []
    return transport


def _normalize_payload(value: Any, issues: _Issues) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        issues.partial.append("payload is missing")
        return {"length": 0, "encoding": None, "data": None}

    payload = deepcopy(dict(value))
    length = _coerce_nonnegative_int(payload.get("length"), "payload.length", issues)
    encoding = payload.get("encoding")
    if encoding not in PAYLOAD_ENCODINGS:
        issues.invalid.append("payload.encoding is unsupported")
        encoding = None
    data = payload.get("data")
    if data is not None and not isinstance(data, str):
        issues.invalid.append("payload.data must be a string or null")
        data = str(data)
    if encoding == "hex" and isinstance(data, str):
        try:
            bytes.fromhex(data)
        except ValueError:
            issues.invalid.append("payload.data is not valid hex")
    if length is not None and data is None and length > 0:
        issues.partial.append("payload.data is missing while payload.length is nonzero")
    payload["length"] = length
    payload["encoding"] = encoding
    payload["data"] = data
    return payload


def _payload_has_data(payload: Mapping[str, Any]) -> bool:
    length = payload.get("length")
    return _is_int(length) and length > 0


def _normalize_headers(value: Any, issues: _Issues, label: str) -> dict[str, list[str]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        issues.partial.append(f"{label} must be an object")
        return {}
    headers: dict[str, list[str]] = {}
    for raw_name, raw_values in value.items():
        name = str(raw_name).strip().casefold()
        if not name:
            issues.partial.append(f"{label} contains an empty header name")
            continue
        if isinstance(raw_values, list):
            values = [str(item).strip() for item in raw_values if item is not None]
        elif raw_values is None:
            values = []
        else:
            values = [str(raw_values).strip()]
        headers.setdefault(name, []).extend(values)
    return headers


def _normalize_content_type(value: Any) -> str | None:
    text = _first_value(value)
    if text is None:
        return None
    pieces = [piece.strip().casefold() for piece in text.split(";")]
    return "; ".join(piece for piece in pieces if piece) or None


def _normalize_percent_encoded(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%" and index + 2 < len(value):
            candidate = value[index + 1 : index + 3]
            try:
                decoded = chr(int(candidate, 16))
            except ValueError:
                output.append(char)
                index += 1
                continue
            if decoded in UNRESERVED_URI:
                output.append(decoded)
            else:
                output.append(f"%{candidate.upper()}")
            index += 3
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _normalize_uri_target(value: str) -> tuple[str, str | None]:
    try:
        split = urlsplit(value)
    except ValueError:
        normalized = _normalize_percent_encoded(value)
        return normalized, None
    path = _normalize_percent_encoded(split.path)
    query = _normalize_percent_encoded(split.query)
    fragment = _normalize_percent_encoded(split.fragment)
    target = urlunsplit((split.scheme, split.netloc, path, query, fragment))
    return target, path or None


def _first_header(headers: Mapping[str, list[str]], name: str) -> str | None:
    values = headers.get(name)
    return values[0] if values else None


def _normalize_http_fields(fields: dict[str, Any], issues: _Issues) -> dict[str, Any]:
    headers = _normalize_headers(fields.get("headers"), issues, "HTTP headers")
    fields["headers"] = headers

    content_type = fields.get("content_type") or _first_header(headers, "content-type")
    fields["content_type"] = _normalize_content_type(content_type)
    if "content_length" not in fields:
        fields["content_length"] = _coerce_nonnegative_int(
            _first_header(headers, "content-length"),
            "application.fields.content_length",
            issues,
        )
    elif fields["content_length"] is not None:
        fields["content_length"] = _coerce_nonnegative_int(
            fields.get("content_length"),
            "application.fields.content_length",
            issues,
        )

    if fields.get("host") is None:
        fields["host"] = _normalize_host(_first_header(headers, "host"))
    else:
        fields["host"] = _normalize_host(fields.get("host"))

    target = fields.get("target")
    if isinstance(target, str):
        normalized_target, normalized_path = _normalize_uri_target(target.strip())
        fields["target"] = target.strip()
        fields["normalized_target"] = normalized_target
        fields["normalized_path"] = normalized_path
    elif fields.get("message_type") == "request":
        fields["normalized_target"] = None
        fields["normalized_path"] = None
        issues.partial.append("HTTP request target is missing")
    if isinstance(fields.get("method"), str):
        fields["method"] = fields["method"].strip().upper()
    if isinstance(fields.get("message_type"), str):
        fields["message_type"] = fields["message_type"].strip().casefold()
    if isinstance(fields.get("http_version"), str):
        fields["http_version"] = fields["http_version"].strip().upper()

    fields["body"] = _normalize_payload(fields.get("body"), issues)
    for name in ("headers_complete", "body_complete"):
        if name in fields:
            fields[name] = _coerce_bool(fields[name])
            if fields[name] is None:
                issues.partial.append(f"application.fields.{name} is not boolean")
        else:
            fields[name] = None
            issues.partial.append(f"application.fields.{name} is missing")
    for name in ("message_length", "remaining_bytes"):
        if name in fields:
            fields[name] = _coerce_nonnegative_int(
                fields[name], f"application.fields.{name}", issues
            )
        else:
            fields[name] = None
    return fields


def _normalize_dns_name_items(
    items: Any, issues: _Issues, label: str
) -> list[dict[str, Any]]:
    if items is None:
        return []
    if not isinstance(items, list):
        issues.partial.append(f"{label} must be a list")
        return []
    normalized: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            issues.partial.append(f"{label} contains a non-object record")
            continue
        record = deepcopy(dict(item))
        if "name" in record:
            record["name"] = _normalize_domain(record.get("name"))
        data = record.get("data")
        if isinstance(data, str):
            try:
                record["data"] = str(ip_address(data))
            except ValueError:
                if "." in data:
                    record["data"] = _normalize_domain(data)
        normalized.append(record)
    return normalized


def _normalize_dns_fields(fields: dict[str, Any], issues: _Issues) -> dict[str, Any]:
    fields["questions"] = _normalize_dns_name_items(
        fields.get("questions"), issues, "DNS questions"
    )
    fields["answers"] = _normalize_dns_name_items(
        fields.get("answers"), issues, "DNS answers"
    )
    fields["authorities"] = _normalize_dns_name_items(
        fields.get("authorities"), issues, "DNS authorities"
    )
    fields["additionals"] = _normalize_dns_name_items(
        fields.get("additionals"), issues, "DNS additionals"
    )
    if "counts" not in fields or not isinstance(fields.get("counts"), Mapping):
        fields["counts"] = {
            "questions": len(fields["questions"]),
            "answers": len(fields["answers"]),
            "authorities": len(fields["authorities"]),
            "additionals": len(fields["additionals"]),
        }
    return fields


def _normalize_smtp_fields(fields: dict[str, Any], issues: _Issues) -> dict[str, Any]:
    fields["headers"] = _normalize_headers(
        fields.get("headers"), issues, "SMTP MIME headers"
    )
    fields["content_type"] = _normalize_content_type(fields.get("content_type"))
    fields["content_transfer_encoding"] = _normalize_content_type(
        fields.get("content_transfer_encoding")
    )
    for list_name in ("commands", "responses"):
        value = fields.get(list_name)
        if value is None:
            fields[list_name] = []
        elif not isinstance(value, list):
            fields[list_name] = []
            issues.partial.append(f"SMTP {list_name} must be a list")
    for command in fields["commands"]:
        if not isinstance(command, dict):
            continue
        if "command" in command and isinstance(command["command"], str):
            command["command"] = command["command"].strip().upper()
        if "domain" in command:
            command["domain"] = _normalize_domain(command.get("domain"))
    if "body" in fields:
        fields["body"] = _normalize_payload(fields.get("body"), issues)
    return fields


def _normalize_application(
    value: Any, payload: Mapping[str, Any], issues: _Issues
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        issues.invalid.append("application must be an object")
        return {"protocol": "UNKNOWN", "fields": {}}

    application = deepcopy(dict(value))
    protocol = _canonical_protocol(
        application.get("protocol"),
        {"http": "HTTP", "dns": "DNS", "smtp": "SMTP", "unknown": "UNKNOWN"},
    )
    if protocol is None:
        protocol = "UNKNOWN"
        issues.partial.append("application.protocol is missing")
    application["protocol"] = protocol

    fields = application.get("fields")
    if not isinstance(fields, Mapping):
        fields = {}
        if protocol in SUPPORTED_APPLICATION_PROTOCOLS:
            issues.partial.append("application.fields is missing")
    fields = deepcopy(dict(fields))

    if protocol == "HTTP":
        fields = _normalize_http_fields(fields, issues)
    elif protocol == "DNS":
        fields = _normalize_dns_fields(fields, issues)
    elif protocol == "SMTP":
        fields = _normalize_smtp_fields(fields, issues)
    elif protocol != "UNKNOWN" or _payload_has_data(payload):
        issues.unsupported.append(f"unsupported application protocol: {protocol}")
    application["fields"] = fields
    return application


def _normalize_status(value: Any, issues: _Issues) -> str | None:
    if not isinstance(value, str):
        issues.invalid.append("status is missing or not a string")
        return None
    normalized = value.strip().casefold()
    if normalized not in EVENT_STATUSES:
        issues.invalid.append(f"unsupported event status: {value}")
        return value
    return normalized


def _normalize_errors(value: Any, issues: _Issues) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        issues.partial.append("errors must be a list")
        return [str(value)]
    return [str(item) for item in value]
