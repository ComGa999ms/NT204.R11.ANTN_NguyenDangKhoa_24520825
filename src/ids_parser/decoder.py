"""Application-layer decoding performed after protocol parsing."""

from __future__ import annotations

from copy import deepcopy
from html import unescape
from typing import Any, Mapping
from urllib.parse import parse_qs, unquote, unquote_plus, urlsplit

from .parsers.payload import payload_to_bytes


FORM_URLENCODED = "application/x-www-form-urlencoded"
HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}


def _media_type(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.split(";", 1)[0].strip().lower()


def _payload_text(payload: Any) -> str | None:
    """Return UTF-8 text from a normalized payload when it is valid text."""

    if not isinstance(payload, Mapping):
        return None
    try:
        raw = payload_to_bytes(payload)
        return raw.decode("utf-8")
    except (TypeError, UnicodeDecodeError, ValueError):
        return None


def decode_http_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Decode HTTP URI, form data, and HTML text without replacing raw data."""

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

    decoded["decode_status"] = (
        "partial" if errors else "decoded" if operations else "not_required"
    )
    decoded["decode_operations"] = operations
    decoded["decode_errors"] = errors
    return decoded


def decode_application(application: Mapping[str, Any]) -> dict[str, Any]:
    """Decode supported application fields while preserving their raw values."""

    decoded = deepcopy(dict(application))
    if str(application.get("protocol", "")).upper() != "HTTP":
        return decoded

    fields = application.get("fields")
    if isinstance(fields, Mapping) and fields:
        decoded["fields"] = decode_http_fields(fields)
    return decoded
