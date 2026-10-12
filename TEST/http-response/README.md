# HTTP response

## File trong folder

- `http-response.pcap`: file packet để mở bằng Wireshark.
- `http-response.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra parse HTTP response.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/http-response/http-response.pcap --output TEST/http-response/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/http-response/http-response.pcap` bằng Wireshark để xem packet gốc.
2. Mở `http-response.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có status code 200, reason OK và body `OK`.

## Ghi chú

File `http-response.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
