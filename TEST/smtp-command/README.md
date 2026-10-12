# SMTP command

## File trong folder

- `smtp-command.pcap`: file packet để mở bằng Wireshark.
- `smtp-command.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra parse SMTP command.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/smtp-command/smtp-command.pcap --output TEST/smtp-command/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/smtp-command/smtp-command.pcap` bằng Wireshark để xem packet gốc.
2. Mở `smtp-command.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có command EHLO và domain `client.example`.

## Ghi chú

File `smtp-command.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
