# NT204.R11.ANTN_NguyenDangKhoa_24520825

## Thông tin

- Họ và tên: Nguyễn Đăng Khoa
- MSSV: 24520825
- Lớp: NT204.R11.ANTN
- Bài tập 1: Packet Capture & Parser cho hệ thống IDS

## Giới thiệu

Module Python thu thập packet từ network interface hoặc file PCAP, đưa cả hai nguồn qua cùng một pipeline và ghi kết quả chuẩn hóa dưới dạng JSON Lines.

Chức năng hiện tại:

- Live capture và PCAP import bằng Scapy.
- Parse IPv4, TCP và UDP.
- Nhận diện HTTP/1.x bằng payload (kể cả port không tiêu chuẩn) và port gợi ý.
- TCP stream reassembly có giới hạn bộ nhớ, xử lý out-of-order và retransmission.
- Parse HTTP request/response, DNS query/response và SMTP command/response.
- Chuẩn hóa TCP flags, header và payload.
- Lưu payload dạng UTF-8 hoặc hex nếu không decode được.
- Không để các module phía sau phụ thuộc trực tiếp vào Scapy packet.

```text
Live/PCAP -> IPv4 -> TCP/UDP -> Reassembly -> HTTP/DNS/SMTP -> JSONL
```

## Cài đặt

Yêu cầu Python 3.10 trở lên. Live capture trên Windows cần Npcap và có thể cần chạy PowerShell bằng quyền Administrator.

```powershell
git clone https://github.com/ComGa999ms/NT204.R11.ANTN_NguyenDangKhoa_24520825.git
cd NT204.R11.ANTN_NguyenDangKhoa_24520825
python -m pip install -r requirements.txt
```

## Sử dụng

Xem các network interface:

```powershell
python main.py --list-interfaces
```

Đọc tối đa 10 packet từ PCAP:

```powershell
python main.py --pcap challenge.pcap --count 10 --output TEST/pcap-capture.jsonl
```

Bắt 10 packet từ Wi-Fi:

```powershell
python main.py --interface "Wi-Fi" --count 10 --output TEST/wifi-capture.jsonl
```

Live capture với BPF filter:

```powershell
python main.py --interface "Wi-Fi" --filter "tcp or udp" --count 20 --output TEST/filtered-capture.jsonl
```

Xem toàn bộ tùy chọn:

```powershell
python main.py --help
```

## Output

Mỗi dòng trong file output là một JSON object độc lập:

```json
{
  "packet_id": 1,
  "timestamp": "2026-05-17T07:08:02.853581Z",
  "capture": {"mode": "pcap", "source": "challenge.pcap"},
  "packet_length": 56,
  "network": {
    "protocol": "IPv4",
    "source_ip": "127.0.0.1",
    "destination_ip": "127.0.0.1",
    "ttl": 128
  },
  "transport": {
    "protocol": "TCP",
    "source_port": 62763,
    "destination_port": 13371,
    "flags": {"syn": true, "ack": false},
    "payload_length": 0
  },
  "application": {"protocol": "UNKNOWN", "fields": {}},
  "payload": {"length": 0, "encoding": null, "data": null},
  "status": "parsed",
  "errors": []
}
```

Object thực tế chứa thêm các trường chi tiết của IPv4, TCP hoặc UDP. `application.protocol` có thể là `HTTP`, `DNS`, `SMTP` hoặc `UNKNOWN`. Message chưa đủ dữ liệu được giữ trong TCP reassembly buffer và đánh dấu `partial`.

## Kiểm thử

```powershell
python -m pytest
```

Chạy chi tiết:

```powershell
python -m pytest -v
```

Các test hiện bao phủ capture, IPv4, TCP/UDP, stream reassembly, HTTP, DNS, SMTP và pipeline integration.

## Cấu trúc chính

```text
main.py                         CLI entry point
src/ids_parser/capture.py       Live capture và PCAP reader
src/ids_parser/pipeline.py      Pipeline xử lý chung
src/ids_parser/reassembly.py    TCP stream reassembly
src/ids_parser/models.py        Normalized IDS event
src/ids_parser/detector.py       Nhận diện application protocol
src/ids_parser/parsers/         IPv4, TCP, UDP, HTTP, DNS và SMTP parsers
src/ids_parser/writer.py        JSON Lines writer
tests/                          Automated tests
TEST/                           Kết quả test case
```

## Khai báo sử dụng AI

Cái này sẽ updated sau khi hoàn thành bài tập
