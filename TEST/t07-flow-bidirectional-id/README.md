# T07 bidirectional flow id

## File trong folder

- `t07-flow-bidirectional-id.pcap`: file packet để mở bằng Wireshark.
- `t07-flow-bidirectional-id.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra hai chiều client/server được gom vào cùng một flow.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t07-flow-bidirectional-id/t07-flow-bidirectional-id.pcap --output TEST/t07-flow-bidirectional-id/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t07-flow-bidirectional-id/t07-flow-bidirectional-id.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t07-flow-bidirectional-id.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Hai packet có cùng flow_id và direction lần lượt là a_to_b, b_to_a.

## Ghi chú

File `t07-flow-bidirectional-id.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
