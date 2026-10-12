# TCP handshake

## File trong folder

- `tcp-handshake.pcap`: file packet để mở bằng Wireshark.
- `tcp-handshake.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra parser đọc được IPv4/TCP và nhận đúng 3 bước SYN, SYN-ACK, ACK.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/tcp-handshake/tcp-handshake.pcap --output TEST/tcp-handshake/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/tcp-handshake/tcp-handshake.pcap` bằng Wireshark để xem packet gốc.
2. Mở `tcp-handshake.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có network IPv4, transport TCP, flags SYN/ACK đúng và có flow TCP.

## Ghi chú

File `tcp-handshake.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
