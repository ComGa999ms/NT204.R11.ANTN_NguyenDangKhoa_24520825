# HTTP POST

## File trong folder

- `http-post.pcap`: file packet để mở bằng Wireshark.
- `http-post.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra parse HTTP POST có header và body.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/http-post/http-post.pcap --output TEST/http-post/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/http-post/http-post.pcap` bằng Wireshark để xem packet gốc.
2. Mở `http-post.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có method POST, Content-Length và body `a=1&b=2`.

## Ghi chú

File `http-post.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
