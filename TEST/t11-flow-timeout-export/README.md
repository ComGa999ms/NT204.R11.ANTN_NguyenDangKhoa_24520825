# T11 flow timeout export

## File trong folder

- `t11-flow-timeout-export.pcap`: file packet để mở bằng Wireshark.
- `t11-flow-timeout-export.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra flow cũ được export khi quá timeout.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t11-flow-timeout-export/t11-flow-timeout-export.pcap --flow-timeout 10 --output TEST/t11-flow-timeout-export/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t11-flow-timeout-export/t11-flow-timeout-export.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t11-flow-timeout-export.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Khi chạy với --flow-timeout 10, output có expired_flows.

## Ghi chú

File `t11-flow-timeout-export.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
