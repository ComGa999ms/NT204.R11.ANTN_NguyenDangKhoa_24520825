# T02 HTML entity decode

## File trong folder

- `t02-html-entity-decode.pcap`: file packet để mở bằng Wireshark.
- `t02-html-entity-decode.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra decode HTML entity trong HTTP response.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t02-html-entity-decode/t02-html-entity-decode.pcap --output TEST/t02-html-entity-decode/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t02-html-entity-decode/t02-html-entity-decode.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t02-html-entity-decode.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có decoded_body sau khi giải mã HTML entity.

## Ghi chú

File `t02-html-entity-decode.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
