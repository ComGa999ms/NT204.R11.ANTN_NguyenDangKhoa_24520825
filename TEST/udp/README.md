# UDP payload

## File trong folder

- `udp.pcap`: file packet để mở bằng Wireshark.
- `udp.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra parser đọc được UDP packet có payload.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/udp/udp.pcap --output TEST/udp/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/udp/udp.pcap` bằng Wireshark để xem packet gốc.
2. Mở `udp.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có transport UDP và payload `hello from udp`.

## Ghi chú

File `udp.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
