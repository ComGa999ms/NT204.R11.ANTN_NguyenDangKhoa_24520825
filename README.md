# NT204.R11.ANTN_NguyenDangKhoa_24520825

## Thông tin 

- Họ và tên: Nguyễn Đăng Khoa
- MSSV: 24520825
- Lớp: NT204.R11.ANTN
- Môn học: Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập
- Bài tập 1: Packet Capture & Parser cho hệ thống IDS

## Giới thiệu

Đây là module thu thập và xử lý packet đầu vào cho một hệ thống Intrusion Detection System (IDS) đơn giản bằng Python. Chương trình hỗ trợ hai nguồn dữ liệu:

- Bắt packet trực tiếp từ một network interface.
- Đọc packet từ file PCAP.

Cả hai nguồn đều đưa packet vào cùng một processing pipeline. Packet sau đó được chuyển thành cấu trúc dữ liệu chuẩn hóa và ghi ra file JSON Lines để các module IDS ở những bài tập sau có thể sử dụng mà không cần truy cập trực tiếp Scapy packet.



## Kiến trúc xử lý

```text
Live Capture ─┐
              ├── PacketPipeline.process_packet()
PCAP Reader ──┘              │
                             v
                   Normalized IDS Event
                             │
                             v
                       JSON Lines file
```

Live capture và PCAP import không sử dụng hai parser riêng. Điểm vào chung của mọi packet là `PacketPipeline.process_packet()`.

## Cấu trúc thư mục

```text
.
├── main.py
├── pyproject.toml
├── requirements.txt
├── src/
│   └── ids_parser/
│       ├── __init__.py
│       ├── capture.py
│       ├── cli.py
│       ├── models.py
│       ├── pipeline.py
│       └── writer.py
├── tests/
│   ├── fixtures/
│   ├── test_capture.py
│   ├── test_cli.py
│   ├── test_models.py
│   └── test_pipeline.py
└── TEST/
```

Vai trò của các module:

- `capture.py`: đọc PCAP, bắt live traffic và quản lý network interface.
- `pipeline.py`: điểm xử lý chung của mọi packet.
- `models.py`: định nghĩa cấu trúc normalized IDS event.
- `writer.py`: ghi mỗi event thành một dòng JSON.
- `cli.py`: xử lý tham số dòng lệnh.
- `main.py`: entry point khi chạy chương trình.


## Cài đặt

Clone repository:

```powershell
git clone https://github.com/ComGa999ms/NT204.R11.ANTN_NguyenDangKhoa_24520825.git
cd NT204.R11.ANTN_NguyenDangKhoa_24520825
```

Cài dependency:

```powershell
python -m pip install -r requirements.txt
```

## Hướng dẫn sử dụng

### Xem trợ giúp

```powershell
python main.py --help
```

### Liệt kê network interface

```powershell
python main.py --list-interfaces
```

Ví dụ kết quả trên Windows:

```text
1. Npcap Loopback Adapter
2. VMware Network Adapter VMnet8
3. Wi-Fi
```

### Đọc packet từ PCAP

```powershell
python main.py --pcap challenge.pcap --output TEST/pcap-capture.jsonl
```

Giới hạn ở 10 packet:

```powershell
python main.py --pcap challenge.pcap --count 10 --output TEST/pcap-capture.jsonl
```

### Bắt packet trực tiếp từ Wi-Fi

```powershell
python main.py --interface "Wi-Fi" --count 10 --output TEST/wifi-capture.jsonl
```

Trong lúc chương trình chờ packet, có thể mở một trang web để tạo network traffic.

### Sử dụng BPF filter

Ví dụ chỉ bắt TCP hoặc UDP:

```powershell
python main.py --interface "Wi-Fi" --filter "tcp or udp" --count 20 --output TEST/filtered-capture.jsonl
```

Tùy chọn `--filter` chỉ áp dụng cho live capture.

## Định dạng output

Output sử dụng JSON Lines: mỗi dòng là một packet/event độc lập và là một JSON object hợp lệ.

Ví dụ event ở giai đoạn capture:

```json
{
  "packet_id": 1,
  "timestamp": "2026-05-17T07:08:02.853581Z",
  "capture": {
    "mode": "pcap",
    "source": "C:\\path\\to\\challenge.pcap"
  },
  "packet_length": 56,
  "network": null,
  "transport": null,
  "application": {
    "protocol": "UNKNOWN",
    "fields": {}
  },
  "payload": {
    "length": 0,
    "encoding": null,
    "data": null
  },
  "status": "captured",
  "errors": []
}
```

Ý nghĩa một số trường:

- `packet_id`: số thứ tự packet trong lần chạy hiện tại.
- `timestamp`: thời điểm packet được thu nhận, biểu diễn theo UTC.
- `capture.mode`: `pcap` hoặc `live`.
- `capture.source`: đường dẫn PCAP hoặc tên network interface.
- `packet_length`: tổng độ dài packet theo byte.
- `status`: trạng thái xử lý packet.
- `errors`: danh sách lỗi không nghiêm trọng gặp trong quá trình xử lý.

Các dấu `\\` trong đường dẫn Windows là JSON escaping hợp lệ. Khi JSON được parse, đường dẫn sẽ trở lại dạng có một dấu `\`.

## Chạy kiểm thử

Chạy toàn bộ test:

```powershell
python -m pytest
```

Chạy test ở chế độ chi tiết:

```powershell
python -m pytest -v
```

Chạy từng nhóm test:

```powershell
python -m pytest tests/test_models.py -v
python -m pytest tests/test_pipeline.py -v
python -m pytest tests/test_capture.py -v
python -m pytest tests/test_cli.py -v
```




## Khai báo sử dụng AI

Cái này sẽ updated sau khi hoàn thành bài tập
