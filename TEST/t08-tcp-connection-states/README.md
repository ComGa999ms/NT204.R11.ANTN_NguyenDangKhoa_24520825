# T08 TCP connection states

## File trong folder

- `t08-tcp-connection-states.pcap`: file packet để mở bằng Wireshark.
- `t08-tcp-connection-states.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra trạng thái TCP qua handshake và đóng kết nối.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t08-tcp-connection-states/t08-tcp-connection-states.pcap --output TEST/t08-tcp-connection-states/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t08-tcp-connection-states/t08-tcp-connection-states.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t08-tcp-connection-states.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Flow đi qua các state SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSED.

## Ghi chú

File `t08-tcp-connection-states.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
