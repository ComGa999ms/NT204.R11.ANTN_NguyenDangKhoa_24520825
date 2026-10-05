"""Giải mã dữ liệu application sau bước parser."""

from __future__ import annotations

import base64
import binascii
import quopri
import re
from copy import deepcopy
from html import unescape
from typing import Any, Mapping
from urllib.parse import parse_qs, unquote, unquote_plus, urlsplit

from .parsers.payload import payload_to_bytes


FORM_URLENCODED = "application/x-www-form-urlencoded"
HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}
SUPPORTED_CHARSETS = {"ascii": "ascii", "us-ascii": "ascii", "utf-8": "utf-8"}
CHARSET_PARAMETER = re.compile(r"(?:^|;)\s*charset\s*=\s*[\"']?([^;\"']+)", re.I)


def _media_type(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.split(";", 1)[0].strip().lower()


def _payload_text(payload: Any) -> str | None:
    """Lấy text UTF-8 từ payload nếu dữ liệu hợp lệ."""

    if not isinstance(payload, Mapping):
        return None
    try:
        raw = payload_to_bytes(payload)
        return raw.decode("utf-8")
    except (TypeError, UnicodeDecodeError, ValueError):
        return None


def _charset(content_type: Any, *, default: str = "utf-8") -> str:
    if not isinstance(content_type, str):
        return default
    match = CHARSET_PARAMETER.search(content_type)
    return match.group(1).strip().lower() if match else default


def _decode_character_data(
    raw: bytes, charset: str
) -> tuple[dict[str, Any], str | None]:
    normalized_charset = SUPPORTED_CHARSETS.get(charset.lower())
    if normalized_charset is None:
        return (
            {"length": len(raw), "encoding": "hex", "data": raw.hex()},
            f"Unsupported character encoding: {charset}",
        )
    try:
        text = raw.decode(normalized_charset, errors="strict")
    except UnicodeDecodeError:
        return (
            {"length": len(raw), "encoding": "hex", "data": raw.hex()},
            f"Invalid {normalized_charset} byte sequence",
        )
    return {
        "length": len(raw),
        "encoding": normalized_charset,
        "data": text,
    }, None


def decode_http_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Giải mã URI, form và HTML nhưng vẫn giữ dữ liệu gốc."""

    decoded = deepcopy(dict(fields))
    operations: list[str] = []
    errors: list[str] = []

    target = fields.get("target")
    if isinstance(target, str):
        decoded["raw_target"] = target
        decoded_target = unquote(target, encoding="utf-8", errors="replace")
        decoded["decoded_target"] = decoded_target
        if decoded_target != target:
            operations.append("http_url_percent")

        query = urlsplit(target).query
        if query:
            decoded["decoded_query_parameters"] = parse_qs(
                query,
                keep_blank_values=True,
                encoding="utf-8",
                errors="replace",
            )
            operations.append("http_query_form")

    content_type = _media_type(fields.get("content_type"))
    body_text = _payload_text(fields.get("body"))
    if content_type == FORM_URLENCODED:
        if body_text is None:
            errors.append("HTTP form body is not valid UTF-8 text")
        else:
            decoded["decoded_body"] = unquote_plus(
                body_text, encoding="utf-8", errors="replace"
            )
            decoded["decoded_form_fields"] = parse_qs(
                body_text,
                keep_blank_values=True,
                encoding="utf-8",
                errors="replace",
            )
            operations.append("http_form_urlencoded")
    elif content_type in HTML_CONTENT_TYPES:
        if body_text is None:
            errors.append("HTTP HTML body is not valid UTF-8 text")
        else:
            decoded_body = unescape(body_text)
            decoded["decoded_body"] = decoded_body
            if decoded_body != body_text:
                operations.append("html_entity")
    elif content_type.startswith("text/"):
        body = fields.get("body")
        if isinstance(body, Mapping):
            try:
                raw_body = payload_to_bytes(body)
                decoded_body, error = _decode_character_data(
                    raw_body, _charset(fields.get("content_type"))
                )
                decoded["decoded_body"] = decoded_body
                if error:
                    errors.append(error)
                else:
                    operations.append(f"character_{decoded_body['encoding']}")
            except (TypeError, ValueError) as error:
                errors.append(f"HTTP text body decoding failed: {error}")

    decoded["decode_status"] = (
        "partial" if errors else "decoded" if operations else "not_required"
    )
    decoded["decode_operations"] = operations
    decoded["decode_errors"] = errors
    return decoded


def decode_smtp_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Giải mã MIME transfer encoding và charset của SMTP."""

    decoded = deepcopy(dict(fields))
    operations: list[str] = []
    errors: list[str] = []
    transfer_encoding = str(fields.get("content_transfer_encoding") or "").lower()
    body = fields.get("body")

    if not transfer_encoding or not isinstance(body, Mapping):
        return decoded

    try:
        raw_body = payload_to_bytes(body)
        if transfer_encoding == "base64":
            compact_body = b"".join(raw_body.split())
            transfer_decoded = base64.b64decode(compact_body, validate=True)
            operations.append("smtp_base64")
        elif transfer_encoding in {"quoted-printable", "quopri"}:
            transfer_decoded = quopri.decodestring(raw_body)
            operations.append("smtp_quoted_printable")
        else:
            transfer_decoded = raw_body
            errors.append(
                f"Unsupported MIME transfer encoding: {transfer_encoding}"
            )

        decoded_body, character_error = _decode_character_data(
            transfer_decoded, _charset(fields.get("content_type"), default="ascii")
        )
        decoded["decoded_body"] = decoded_body
        if character_error:
            errors.append(character_error)
        else:
            operations.append(f"character_{decoded_body['encoding']}")
    except (binascii.Error, TypeError, ValueError) as error:
        errors.append(f"MIME body decoding failed: {error}")

    decoded["decode_status"] = "partial" if errors else "decoded"
    decoded["decode_operations"] = operations
    decoded["decode_errors"] = errors
    return decoded


def decode_application(application: Mapping[str, Any]) -> dict[str, Any]:
    """Giải mã field được hỗ trợ nhưng không xóa giá trị gốc."""

    decoded = deepcopy(dict(application))
    protocol = str(application.get("protocol", "")).upper()
    fields = application.get("fields")
    if protocol == "HTTP" and isinstance(fields, Mapping) and fields:
        decoded["fields"] = decode_http_fields(fields)
    elif protocol == "SMTP" and isinstance(fields, Mapping) and fields:
        decoded["fields"] = decode_smtp_fields(fields)
    return decoded
