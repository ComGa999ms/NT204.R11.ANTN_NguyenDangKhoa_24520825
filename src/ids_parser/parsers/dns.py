"""DNS query and response parser for UDP and TCP payloads."""

from __future__ import annotations

import struct
from typing import Any

from scapy.layers.dns import DNS, dnsclasses, dnsqtypes


OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}
RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def _domain(value: Any) -> str:
    if isinstance(value, bytes):
        raw = value.rstrip(b".")
        try:
            return raw.decode("idna")
        except UnicodeError:
            return raw.decode("ascii", errors="replace")
    return str(value).rstrip(".")


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    try:
        return list(value)
    except TypeError:
        return [value]


def _unwrap(raw: bytes, transport_protocol: str) -> tuple[bytes, int, bool]:
    if transport_protocol == "TCP":
        if len(raw) < 2:
            raise ValueError("Incomplete DNS-over-TCP length prefix")
        declared = int.from_bytes(raw[:2], "big")
        if declared < 12:
            raise ValueError("Invalid DNS-over-TCP message length")
        if len(raw) - 2 < declared:
            raise ValueError("Incomplete DNS-over-TCP message")
        return raw[2 : 2 + declared], declared + 2, True
    if len(raw) < 12:
        raise ValueError("DNS message is shorter than its header")
    return raw, len(raw), False


def parse_dns(raw: bytes, transport_protocol: str) -> dict[str, Any]:
    """Parse one complete DNS message from UDP or a TCP length frame."""

    message, consumed_bytes, tcp_framed = _unwrap(raw, transport_protocol)
    dns = DNS(message)
    declared_counts = {
        "questions": int(dns.qdcount or 0),
        "answers": int(dns.ancount or 0),
        "authorities": int(dns.nscount or 0),
        "additionals": int(dns.arcount or 0),
    }
    if not any(declared_counts.values()):
        raise ValueError("DNS message contains no records")

    questions = [
        {
            "name": _domain(question.qname),
            "type": int(question.qtype),
            "type_name": str(dnsqtypes.get(int(question.qtype), question.qtype)),
            "class": int(question.qclass),
            "class_name": str(dnsclasses.get(int(question.qclass), question.qclass)),
        }
        for question in _items(dns.qd)
    ]

    def records(section: Any) -> list[dict[str, Any]]:
        parsed: list[dict[str, Any]] = []
        for record in _items(section):
            record_type = int(record.type)
            record_class = int(record.rclass)
            parsed.append(
                {
                    "name": _domain(record.rrname),
                    "type": record_type,
                    "type_name": str(dnsqtypes.get(record_type, record_type)),
                    "class": record_class,
                    "class_name": str(dnsclasses.get(record_class, record_class)),
                    "ttl": int(record.ttl),
                    "data": _json_safe(record.rdata),
                }
            )
        return parsed

    opcode = int(dns.opcode)
    rcode = int(dns.rcode)
    return {
        "message_type": "response" if int(dns.qr) else "query",
        "transaction_id": int(dns.id),
        "opcode": opcode,
        "opcode_name": OPCODES.get(opcode, "UNKNOWN"),
        "rcode": rcode,
        "rcode_name": RCODES.get(rcode, "UNKNOWN"),
        "flags": {
            "authoritative_answer": bool(dns.aa),
            "truncated": bool(dns.tc),
            "recursion_desired": bool(dns.rd),
            "recursion_available": bool(dns.ra),
            "authenticated_data": bool(dns.ad),
            "checking_disabled": bool(dns.cd),
        },
        "counts": declared_counts,
        "questions": questions,
        "answers": records(dns.an),
        "authorities": records(dns.ns),
        "additionals": records(dns.ar),
        "tcp_framed": tcp_framed,
        "message_length": consumed_bytes,
        "remaining_bytes": max(0, len(raw) - consumed_bytes),
    }


def is_dns_message(raw: bytes, transport_protocol: str) -> bool:
    candidate = raw
    if transport_protocol == "TCP":
        if len(raw) < 14:
            return False
        declared = int.from_bytes(raw[:2], "big")
        if declared < 12 or declared > len(raw) - 2:
            return False
        candidate = raw[2 : 2 + declared]
    if len(candidate) < 12:
        return False
    try:
        _, flags, questions, answers, authorities, additionals = struct.unpack(
            "!HHHHHH", candidate[:12]
        )
    except struct.error:
        return False
    opcode = (flags >> 11) & 0x0F
    is_response = bool(flags & 0x8000)
    total_records = questions + answers + authorities + additionals
    if opcode not in OPCODES or flags & 0x0040:
        return False
    if total_records < 1 or total_records > 100 or questions > 20:
        return False
    if not is_response and questions < 1:
        return False
    if len(candidate) < 12 + questions * 5:
        return False
    try:
        fields = parse_dns(raw, transport_protocol)
    except Exception:
        return False
    if fields["message_type"] == "query":
        return bool(fields["questions"])
    return bool(fields["questions"] or fields["answers"])
