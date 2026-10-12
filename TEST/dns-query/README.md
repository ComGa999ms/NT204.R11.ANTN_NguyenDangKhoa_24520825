# DNS query

## File trong folder

- `dns-query.pcap`: file packet để mở bằng Wireshark.
- `dns-query.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra parse DNS query.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/dns-query/dns-query.pcap --output TEST/dns-query/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/dns-query/dns-query.pcap` bằng Wireshark để xem packet gốc.
2. Mở `dns-query.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có protocol DNS và question name `example.com` type A.

## Ghi chú

File `dns-query.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
