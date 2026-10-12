# DNS response

## File trong folder

- `dns-response.pcap`: file packet để mở bằng Wireshark.
- `dns-response.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra parse DNS response.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/dns-response/dns-response.pcap --output TEST/dns-response/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/dns-response/dns-response.pcap` bằng Wireshark để xem packet gốc.
2. Mở `dns-response.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có answer record trỏ về `203.0.113.7`.

## Ghi chú

File `dns-response.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
