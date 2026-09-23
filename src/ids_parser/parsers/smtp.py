"""Plaintext SMTP command and response parser."""

from __future__ import annotations

import re
from typing import Any


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
    return bool(fields["commands"] or fields["responses"])

