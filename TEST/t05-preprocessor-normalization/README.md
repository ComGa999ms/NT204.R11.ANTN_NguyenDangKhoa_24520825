# T05 preprocessor normalization

## File trong folder

- `t05-preprocessor-normalization.jsonl`: output mẫu của test Preprocessor.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra Preprocessor chuẩn hóa event đầu vào.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python scripts/generate_preprocessor_test_outputs.py
```

Lệnh trên sinh lại các output của nhóm Preprocessor.

## Cách kiểm tra nhanh

1. Mở `t05-preprocessor-normalization.jsonl` để xem output mẫu.
2. Đối chiếu các trường trong output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output có timestamp, capture mode, protocol, IP/domain/header được chuẩn hóa.

## Ghi chú

Case này test trực tiếp event JSON của Preprocessor nên không có file PCAP.
