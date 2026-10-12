# T13 flow error handling

## File trong folder

- `t13-flow-error-handling.pcap`: file packet để mở bằng Wireshark.
- `t13-flow-error-handling.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra flow tracker bỏ qua event lỗi nhưng vẫn xử lý event hợp lệ sau đó.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t13-flow-error-handling/t13-flow-error-handling.pcap --output TEST/t13-flow-error-handling/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t13-flow-error-handling/t13-flow-error-handling.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t13-flow-error-handling.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Packet lỗi không tạo flow, packet UDP hợp lệ sau đó vẫn có flow.

## Ghi chú

File `t13-flow-error-handling.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
