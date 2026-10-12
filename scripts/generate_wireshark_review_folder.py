"""Tạo folder con cho từng PCAP test trong thư mục TEST.

Ví dụ:

TEST/udp/
  udp.pcap
  udp.jsonl
  README.md

TEST/t05-preprocessor-normalization/
  t05-preprocessor-normalization.jsonl
  README.md
"""

from __future__ import annotations

from pathlib import Path
from shutil import copy2


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_DIR = PROJECT_ROOT / "TEST"


CASES = {
    "tcp-handshake": {
        "title": "TCP handshake",
        "goal": "Kiểm tra parser đọc được IPv4/TCP và nhận đúng 3 bước SYN, SYN-ACK, ACK.",
        "expect": "Output có network IPv4, transport TCP, flags SYN/ACK đúng và có flow TCP.",
    },
    "tcp-data": {
        "title": "TCP data",
        "goal": "Kiểm tra parser đọc được TCP packet có payload.",
        "expect": "Output có transport TCP và payload `hello from tcp`.",
    },
    "udp": {
        "title": "UDP payload",
        "goal": "Kiểm tra parser đọc được UDP packet có payload.",
        "expect": "Output có transport UDP và payload `hello from udp`.",
    },
    "http-get": {
        "title": "HTTP GET",
        "goal": "Kiểm tra nhận diện HTTP request GET dù chạy trên port không chuẩn.",
        "expect": "Output có application HTTP, method GET, target `/index` và header Host.",
    },
    "http-post": {
        "title": "HTTP POST",
        "goal": "Kiểm tra parse HTTP POST có header và body.",
        "expect": "Output có method POST, Content-Length và body `a=1&b=2`.",
    },
    "http-response": {
        "title": "HTTP response",
        "goal": "Kiểm tra parse HTTP response.",
        "expect": "Output có status code 200, reason OK và body `OK`.",
    },
    "dns-query": {
        "title": "DNS query",
        "goal": "Kiểm tra parse DNS query.",
        "expect": "Output có protocol DNS và question name `example.com` type A.",
    },
    "dns-response": {
        "title": "DNS response",
        "goal": "Kiểm tra parse DNS response.",
        "expect": "Output có answer record trỏ về `203.0.113.7`.",
    },
    "smtp-command": {
        "title": "SMTP command",
        "goal": "Kiểm tra parse SMTP command.",
        "expect": "Output có command EHLO và domain `client.example`.",
    },
    "smtp-response": {
        "title": "SMTP response",
        "goal": "Kiểm tra parse SMTP response.",
        "expect": "Output có response code 250 và message SMTP.",
    },
    "unknown-protocol": {
        "title": "Unknown protocol",
        "goal": "Kiểm tra chương trình không lỗi khi gặp payload không thuộc HTTP/DNS/SMTP.",
        "expect": "Output có application protocol UNKNOWN.",
    },
    "malformed-packet": {
        "title": "Malformed HTTP packet",
        "goal": "Kiểm tra packet HTTP lỗi vẫn được ghi nhận thay vì làm chương trình crash.",
        "expect": "Output có status partial và danh sách errors.",
    },
    "t01-http-url-decode": {
        "title": "T01 HTTP URL decode",
        "goal": "Kiểm tra decode URL/query/form bị percent-encoding.",
        "expect": "Output có decoded_target và decoded_form_fields.",
    },
    "t02-html-entity-decode": {
        "title": "T02 HTML entity decode",
        "goal": "Kiểm tra decode HTML entity trong HTTP response.",
        "expect": "Output có decoded_body sau khi giải mã HTML entity.",
    },
    "t03-smtp-mime-decode": {
        "title": "T03 SMTP MIME decode",
        "goal": "Kiểm tra decode SMTP MIME base64 và quoted-printable.",
        "expect": "Output giải mã được nội dung MIME như `Hello IDS` và `Xin chào IDS`.",
    },
    "t04-invalid-character-decode": {
        "title": "T04 invalid character decode",
        "goal": "Kiểm tra xử lý payload text có byte UTF-8 lỗi.",
        "expect": "Packet lỗi được đánh dấu partial, packet hợp lệ sau đó vẫn xử lý tiếp.",
    },
    "t07-flow-bidirectional-id": {
        "title": "T07 bidirectional flow id",
        "goal": "Kiểm tra hai chiều client/server được gom vào cùng một flow.",
        "expect": "Hai packet có cùng flow_id và direction lần lượt là a_to_b, b_to_a.",
    },
    "t08-tcp-connection-states": {
        "title": "T08 TCP connection states",
        "goal": "Kiểm tra trạng thái TCP qua handshake và đóng kết nối.",
        "expect": "Flow đi qua các state SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSED.",
    },
    "t09-udp-flow-tracking": {
        "title": "T09 UDP flow tracking",
        "goal": "Kiểm tra gom UDP request/response thành cùng một flow.",
        "expect": "Hai packet UDP có cùng flow_id, tcp_state là null.",
    },
    "t10-flow-statistics": {
        "title": "T10 flow statistics",
        "goal": "Kiểm tra thống kê số packet và byte của flow.",
        "expect": "Output có packet_count, byte_count và thống kê theo hai chiều.",
    },
    "t11-flow-timeout-export": {
        "title": "T11 flow timeout export",
        "goal": "Kiểm tra flow cũ được export khi quá timeout.",
        "expect": "Khi chạy với --flow-timeout 10, output có expired_flows.",
    },
    "t12-pipeline-flow-metadata": {
        "title": "T12 pipeline flow metadata",
        "goal": "Kiểm tra pipeline gắn metadata flow vào event.",
        "expect": "Output mỗi packet có trường flow và expired_flows.",
    },
    "t13-flow-error-handling": {
        "title": "T13 flow error handling",
        "goal": "Kiểm tra flow tracker bỏ qua event lỗi nhưng vẫn xử lý event hợp lệ sau đó.",
        "expect": "Packet lỗi không tạo flow, packet UDP hợp lệ sau đó vẫn có flow.",
    },
}


EVENT_CASES = {
    "t05-preprocessor-normalization": {
        "title": "T05 preprocessor normalization",
        "goal": "Kiểm tra Preprocessor chuẩn hóa event đầu vào.",
        "expect": "Output có timestamp, capture mode, protocol, IP/domain/header được chuẩn hóa.",
    },
    "t06-preprocessor-missing-fields": {
        "title": "T06 preprocessor missing fields",
        "goal": "Kiểm tra Preprocessor xử lý event thiếu field bắt buộc.",
        "expect": "Output đánh dấu event lỗi là partial/invalid và ghi rõ lý do trong errors/reason.",
    },
    "t14-preprocessor-error-policy": {
        "title": "T14 preprocessor error policy",
        "goal": "Kiểm tra chính sách mark/skip khi gặp event lỗi hoặc protocol chưa hỗ trợ.",
        "expect": "Output thể hiện đúng processing_action theo policy mark hoặc skip.",
    },
}


def _readme_for_case(name: str, data: dict[str, str]) -> str:
    flow_timeout = (
        " --flow-timeout 10"
        if name in {"t11-flow-timeout-export", "t12-pipeline-flow-metadata"}
        else ""
    )
    return f"""# {data["title"]}

## File trong folder

- `{name}.pcap`: file packet để mở bằng Wireshark.
- `{name}.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

{data["goal"]}

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/{name}/{name}.pcap{flow_timeout} --output TEST/{name}/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/{name}/{name}.pcap` bằng Wireshark để xem packet gốc.
2. Mở `{name}.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

{data["expect"]}

## Ghi chú

File `{name}.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
"""


def _readme_for_event_case(name: str, data: dict[str, str]) -> str:
    return f"""# {data["title"]}

## File trong folder

- `{name}.jsonl`: output mẫu của test Preprocessor.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

{data["goal"]}

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python scripts/generate_preprocessor_test_outputs.py
```

Lệnh trên sinh lại các output của nhóm Preprocessor.

## Cách kiểm tra nhanh

1. Mở `{name}.jsonl` để xem output mẫu.
2. Đối chiếu các trường trong output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

{data["expect"]}

## Ghi chú

Case này test trực tiếp event JSON của Preprocessor nên không có file PCAP.
"""


def main() -> int:
    for name, data in CASES.items():
        case_dir = TEST_DIR / name
        source_pcap = TEST_DIR / f"{name}.pcap"
        source_jsonl = TEST_DIR / f"{name}.jsonl"
        destination_pcap = case_dir / f"{name}.pcap"
        destination_jsonl = case_dir / f"{name}.jsonl"
        if not source_pcap.exists() and destination_pcap.exists():
            source_pcap = destination_pcap
        if not source_jsonl.exists() and destination_jsonl.exists():
            source_jsonl = destination_jsonl
        if not source_pcap.exists():
            raise FileNotFoundError(f"Missing PCAP: {source_pcap}")
        if not source_jsonl.exists():
            raise FileNotFoundError(f"Missing JSONL: {source_jsonl}")

        case_dir.mkdir(parents=True, exist_ok=True)
        if source_pcap.resolve() != destination_pcap.resolve():
            copy2(source_pcap, destination_pcap)
        if source_jsonl.resolve() != destination_jsonl.resolve():
            copy2(source_jsonl, destination_jsonl)
        (case_dir / "README.md").write_text(
            _readme_for_case(name, data),
            encoding="utf-8",
            newline="\n",
        )

    for name, data in EVENT_CASES.items():
        case_dir = TEST_DIR / name
        source_jsonl = TEST_DIR / f"{name}.jsonl"
        destination_jsonl = case_dir / f"{name}.jsonl"
        if not source_jsonl.exists() and destination_jsonl.exists():
            source_jsonl = destination_jsonl
        if not source_jsonl.exists():
            raise FileNotFoundError(f"Missing JSONL: {source_jsonl}")

        case_dir.mkdir(parents=True, exist_ok=True)
        if source_jsonl.resolve() != destination_jsonl.resolve():
            copy2(source_jsonl, destination_jsonl)
        (case_dir / "README.md").write_text(
            _readme_for_event_case(name, data),
            encoding="utf-8",
            newline="\n",
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
