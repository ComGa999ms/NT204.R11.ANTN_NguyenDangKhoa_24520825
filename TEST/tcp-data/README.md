# TCP data

## File trong folder

- `tcp-data.pcap`: file packet để mở bằng Wireshark.
- `tcp-data.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra parser đọc được TCP packet có payload.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/tcp-data/tcp-data.pcap --output TEST/tcp-data/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/tcp-data/tcp-data.pcap` bằng Wireshark để xem packet gốc.
2. Mở `tcp-data.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có transport TCP và payload `hello from tcp`.

## Ghi chú

File `tcp-data.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
