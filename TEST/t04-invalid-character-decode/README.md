# T04 invalid character decode

## File trong folder

- `t04-invalid-character-decode.pcap`: file packet để mở bằng Wireshark.
- `t04-invalid-character-decode.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra xử lý payload text có byte UTF-8 lỗi.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t04-invalid-character-decode/t04-invalid-character-decode.pcap --output TEST/t04-invalid-character-decode/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t04-invalid-character-decode/t04-invalid-character-decode.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t04-invalid-character-decode.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Packet lỗi được đánh dấu partial, packet hợp lệ sau đó vẫn xử lý tiếp.

## Ghi chú

File `t04-invalid-character-decode.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
