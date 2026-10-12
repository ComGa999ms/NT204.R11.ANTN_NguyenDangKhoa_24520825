# T03 SMTP MIME decode

## File trong folder

- `t03-smtp-mime-decode.pcap`: file packet để mở bằng Wireshark.
- `t03-smtp-mime-decode.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra decode SMTP MIME base64 và quoted-printable.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t03-smtp-mime-decode/t03-smtp-mime-decode.pcap --output TEST/t03-smtp-mime-decode/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t03-smtp-mime-decode/t03-smtp-mime-decode.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t03-smtp-mime-decode.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output giải mã được nội dung MIME như `Hello IDS` và `Xin chào IDS`.

## Ghi chú

File `t03-smtp-mime-decode.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
