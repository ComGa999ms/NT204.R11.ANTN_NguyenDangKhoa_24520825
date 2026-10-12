# SMTP response

## File trong folder

- `smtp-response.pcap`: file packet để mở bằng Wireshark.
- `smtp-response.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra parse SMTP response.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/smtp-response/smtp-response.pcap --output TEST/smtp-response/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/smtp-response/smtp-response.pcap` bằng Wireshark để xem packet gốc.
2. Mở `smtp-response.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có response code 250 và message SMTP.

## Ghi chú

File `smtp-response.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
