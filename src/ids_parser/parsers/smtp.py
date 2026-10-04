"""Plaintext SMTP command and response parser."""

from __future__ import annotations

import re
from typing import Any

from .payload import normalize_payload


COMMANDS = frozenset(
    {
        "HELO",
        "EHLO",
        "MAIL",
        "RCPT",
        "DATA",
        "RSET",
        "VRFY",
        "EXPN",
        "HELP",
        "NOOP",
        "QUIT",
        "AUTH",
        "STARTTLS",
    }
)
RESPONSE_LINE = re.compile(r"^([2-5][0-9]{2})([- ])(.*)$")
PATH_ARGUMENT = re.compile(r"^(FROM|TO)\s*:\s*(.*)$", re.IGNORECASE)


def _split_header_body(raw: bytes) -> tuple[bytes, bytes, int] | None:
    if b"\r\n\r\n" in raw:
        header, body = raw.split(b"\r\n\r\n", 1)
        return header, body, len(header) + 4
    if b"\n\n" in raw:
        header, body = raw.split(b"\n\n", 1)
        return header, body, len(header) + 2
    return None


def _parse_mime_headers(raw: bytes) -> tuple[dict[str, list[str]], bytes, int] | None:
    split = _split_header_body(raw)
    if split is None:
        return None
    header_block, body, body_offset = split
    try:
        lines = header_block.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError:
        return None

    headers: dict[str, list[str]] = {}
    current_name: str | None = None
    for line in lines:
        if line[:1] in {" ", "\t"} and current_name is not None:
            headers[current_name][-1] += " " + line.strip()
            continue
        name, separator, value = line.partition(":")
        if not separator or not name.strip():
            return None
        current_name = name.strip().lower()
        headers.setdefault(current_name, []).append(value.strip())

    # A transfer-encoding header is the required signal for this assignment's
    # MIME decoder and prevents arbitrary text from being labeled as SMTP.
    if "content-transfer-encoding" not in headers:
        return None
    return headers, body, body_offset


def _first_header(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name)
    return values[0] if values else None


def _parse_mime_message(raw: bytes) -> dict[str, Any] | None:
    parsed = _parse_mime_headers(raw)
    if parsed is None:
        return None
    headers, body, body_offset = parsed

    terminator = b"\r\n.\r\n"
    has_terminator = body.endswith(terminator)
    message_body = body[: -len(terminator)] if has_terminator else body
    stream_complete = has_terminator or raw.endswith((b"\r\n", b"\n"))
    return {
        "message_type": "mime",
        "commands": [],
        "responses": [],
        "headers": headers,
        "content_type": _first_header(headers, "content-type"),
        "content_transfer_encoding": _first_header(
            headers, "content-transfer-encoding"
        ),
        "body": normalize_payload(message_body),
        "line_count": len(raw.splitlines()),
        "stream_complete": stream_complete,
        "message_length": body_offset + len(body),
        "remaining_bytes": 0,
    }


def _complete_lines(raw: bytes) -> tuple[list[str], int, bool]:
    last_newline = raw.rfind(b"\n")
    if last_newline < 0:
        return [], 0, False
    consumed = last_newline + 1
    text = raw[:consumed].decode("utf-8", errors="strict")
    lines = [line.rstrip("\r") for line in text.splitlines()]
    return [line for line in lines if line], consumed, consumed == len(raw)


def parse_smtp(raw: bytes) -> dict[str, Any]:
    """Parse one or more complete SMTP command/response lines."""

    mime_message = _parse_mime_message(raw)
    if mime_message is not None:
        return mime_message

    lines, consumed_bytes, stream_complete = _complete_lines(raw)
    if not lines:
        raise ValueError("SMTP line is incomplete")

    commands: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    for line in lines:
        response = RESPONSE_LINE.fullmatch(line)
        if response:
            responses.append(
                {
                    "status_code": int(response.group(1)),
                    "continuation": response.group(2) == "-",
                    "message": response.group(3),
                }
            )
            continue

        command, _, argument = line.partition(" ")
        command = command.upper()
        if command not in COMMANDS:
            raise ValueError(f"Unsupported SMTP line: {line}")
        item: dict[str, Any] = {
            "command": command,
            "argument": argument.strip() or None,
        }
        if command in {"HELO", "EHLO"}:
            item["domain"] = argument.strip() or None
        elif command in {"MAIL", "RCPT"}:
            path = PATH_ARGUMENT.fullmatch(argument.strip())
            if path is None:
                raise ValueError(f"Malformed SMTP {command} command")
            expected = "FROM" if command == "MAIL" else "TO"
            if path.group(1).upper() != expected:
                raise ValueError(f"Malformed SMTP {command} command")
            item["path"] = path.group(2).strip()
        commands.append(item)

    if commands and responses:
        message_type = "mixed"
    elif commands:
        message_type = "command"
    else:
        message_type = "response"
    return {
        "message_type": message_type,
        "commands": commands,
        "responses": responses,
        "line_count": len(lines),
        "stream_complete": stream_complete,
        "message_length": consumed_bytes,
        "remaining_bytes": max(0, len(raw) - consumed_bytes),
    }


def is_smtp_message(raw: bytes) -> bool:
    try:
        fields = parse_smtp(raw)
    except (UnicodeDecodeError, ValueError):
        return False
    return fields["message_type"] == "mime" or bool(
        fields["commands"] or fields["responses"]
    )

