"""Safe normalization helpers for transport payload bytes."""

from __future__ import annotations

from typing import Any, Mapping


def empty_payload() -> dict[str, Any]:
    return {"length": 0, "encoding": None, "data": None}


def normalize_payload(payload: bytes) -> dict[str, Any]:
    """Represent payload bytes without losing undecodable binary data."""

    if not payload:
        return empty_payload()
    try:
        data = payload.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        data = payload.hex()
        encoding = "hex"
    return {"length": len(payload), "encoding": encoding, "data": data}


def payload_to_bytes(payload: Mapping[str, Any]) -> bytes:
    """Recover the exact bytes represented by a normalized payload."""

    data = payload.get("data")
    if data is None:
        return b""
    encoding = payload.get("encoding")
    if encoding == "utf-8":
        return str(data).encode("utf-8")
    if encoding == "hex":
        return bytes.fromhex(str(data))
    raise ValueError(f"Unsupported payload encoding: {encoding}")
