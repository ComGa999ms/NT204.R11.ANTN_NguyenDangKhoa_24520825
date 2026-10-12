# T10 flow statistics

## File trong folder

- `t10-flow-statistics.pcap`: file packet để mở bằng Wireshark.
- `t10-flow-statistics.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra thống kê số packet và byte của flow.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t10-flow-statistics/t10-flow-statistics.pcap --output TEST/t10-flow-statistics/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t10-flow-statistics/t10-flow-statistics.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t10-flow-statistics.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có packet_count, byte_count và thống kê theo hai chiều.

## Ghi chú

File `t10-flow-statistics.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
