# T06 preprocessor missing fields

## File trong folder

- `t06-preprocessor-missing-fields.jsonl`: output mẫu của test Preprocessor.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra Preprocessor xử lý event thiếu field bắt buộc.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python scripts/generate_preprocessor_test_outputs.py
```

Lệnh trên sinh lại các output của nhóm Preprocessor.

## Cách kiểm tra nhanh

1. Mở `t06-preprocessor-missing-fields.jsonl` để xem output mẫu.
2. Đối chiếu các trường trong output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output đánh dấu event lỗi là partial/invalid và ghi rõ lý do trong errors/reason.

## Ghi chú

Case này test trực tiếp event JSON của Preprocessor nên không có file PCAP.
