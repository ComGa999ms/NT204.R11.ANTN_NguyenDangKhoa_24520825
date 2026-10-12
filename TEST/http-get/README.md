# HTTP GET

## File trong folder

- `http-get.pcap`: file packet để mở bằng Wireshark.
- `http-get.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra nhận diện HTTP request GET dù chạy trên port không chuẩn.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/http-get/http-get.pcap --output TEST/http-get/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/http-get/http-get.pcap` bằng Wireshark để xem packet gốc.
2. Mở `http-get.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có application HTTP, method GET, target `/index` và header Host.

## Ghi chú

File `http-get.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
