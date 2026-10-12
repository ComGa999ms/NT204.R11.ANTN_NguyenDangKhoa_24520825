# T01 HTTP URL decode

## File trong folder

- `t01-http-url-decode.pcap`: file packet để mở bằng Wireshark.
- `t01-http-url-decode.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra decode URL/query/form bị percent-encoding.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t01-http-url-decode/t01-http-url-decode.pcap --output TEST/t01-http-url-decode/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t01-http-url-decode/t01-http-url-decode.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t01-http-url-decode.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có decoded_target và decoded_form_fields.

## Ghi chú

File `t01-http-url-decode.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
