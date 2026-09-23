from __future__ import annotations

from ids_parser.parsers.http import parse_http


def test_parse_http_response_status_headers_and_binary_body() -> None:
    raw = (
        b"HTTP/1.1 404 Not Found\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Set-Cookie: a=1\r\n"
        b"Set-Cookie: b=2\r\n"
        b"Content-Length: 2\r\n"
        b"\r\n"
        b"\xff\x80"
    )

    fields = parse_http(raw)

    assert fields["message_type"] == "response"
    assert fields["status_code"] == 404
    assert fields["reason"] == "Not Found"
    assert fields["headers"]["set-cookie"] == ["a=1", "b=2"]
    assert fields["body"] == {"length": 2, "encoding": "hex", "data": "ff80"}

