# T12 pipeline flow metadata

## File trong folder

- `t12-pipeline-flow-metadata.pcap`: file packet để mở bằng Wireshark.
- `t12-pipeline-flow-metadata.jsonl`: output mẫu đã chạy sẵn từ chương trình.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra pipeline gắn metadata flow vào event.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/t12-pipeline-flow-metadata/t12-pipeline-flow-metadata.pcap --flow-timeout 10 --output TEST/t12-pipeline-flow-metadata/output.jsonl
```

## Cách kiểm tra nhanh

1. Mở `TEST/t12-pipeline-flow-metadata/t12-pipeline-flow-metadata.pcap` bằng Wireshark để xem packet gốc.
2. Mở `t12-pipeline-flow-metadata.jsonl` để xem output mẫu đã chạy sẵn.
3. Nếu muốn chạy lại, dùng lệnh ở trên để sinh thêm `output.jsonl`.
4. Đối chiếu output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output mỗi packet có trường flow và expired_flows.

## Ghi chú

File `t12-pipeline-flow-metadata.jsonl` trong folder này là kết quả mẫu tương ứng với PCAP.
