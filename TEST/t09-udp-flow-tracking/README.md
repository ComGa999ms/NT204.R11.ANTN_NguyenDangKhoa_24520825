# T09 UDP flow tracking

## File trong folder

- `t09-udp-flow-tracking.pcap`: file packet để mở bằng Wireshark.
- `t09-udp-flow-tracking.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra gom UDP request/response thành cùng một flow.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t09-udp-flow-tracking/t09-udp-flow-tracking.pcap --output TEST/t09-udp-flow-tracking/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t09-udp-flow-tracking/t09-udp-flow-tracking.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t09-udp-flow-tracking.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Hai packet UDP có cùng flow_id, tcp_state là null.

## Ghi chú

File `t09-udp-flow-tracking.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
