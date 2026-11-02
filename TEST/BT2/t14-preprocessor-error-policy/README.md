# T14 preprocessor error policy

## File trong folder

- `t14-preprocessor-error-policy.jsonl`: output mẫu của test Preprocessor.
- `README.md`: mô tả cách chạy và kết quả mong đợi của test này.

## Mục đích

Kiểm tra chính sách mark/skip khi gặp event lỗi hoặc protocol chưa hỗ trợ.

## Cách chạy

Chạy từ thư mục gốc của project:

```powershell
python scripts/generate_preprocessor_test_outputs.py
```

Lệnh trên sinh lại các output của nhóm Preprocessor.

## Cách kiểm tra nhanh

1. Mở `t14-preprocessor-error-policy.jsonl` để xem output mẫu.
2. Đối chiếu các trường trong output với kết quả mong đợi bên dưới.

## Kết quả mong đợi

Output thể hiện đúng processing_action theo policy mark hoặc skip.

## Ghi chú

Case này test trực tiếp event JSON của Preprocessor nên không có file PCAP.
