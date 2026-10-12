# Malformed HTTP packet

## File trong folder

- `malformed-packet.pcap`: file packet để mở bằng Wireshark.
- `malformed-packet.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra packet HTTP lỗi vẫn được ghi nhận thay vì làm chương trình crash.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/malformed-packet/malformed-packet.pcap --output TEST/malformed-packet/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/malformed-packet/malformed-packet.pcap` bằng Wireshark để xem packet gốc.
2. Mở `malformed-packet.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có status partial và danh sách errors.

## Ghi chú

File `malformed-packet.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
