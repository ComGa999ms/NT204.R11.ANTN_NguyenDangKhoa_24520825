# Unknown protocol

## File trong folder

- `unknown-protocol.pcap`: file packet để mở bằng Wireshark.
- `unknown-protocol.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra chương trình không lỗi khi gặp payload không thuộc HTTP/DNS/SMTP.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/unknown-protocol/unknown-protocol.pcap --output TEST/unknown-protocol/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/unknown-protocol/unknown-protocol.pcap` bằng Wireshark để xem packet gốc.
2. Mở `unknown-protocol.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có application protocol UNKNOWN.

## Ghi chú

File `unknown-protocol.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
