# BT3: Báo cáo kết quả demo Core Engine IDS

## File trong thư mục

- `demo.pcap`: gói TCP/HTTP gốc để mở bằng Wireshark và chạy lại demo.
- `demo.rules`: hai rule Snort cùng khớp gói tin trong PCAP.
- `packets.jsonl`: Packet Event do chương trình tạo khi đọc `demo.pcap`.
- `detections.jsonl`: các Detection Event do Core Engine tạo.
- `README.md`: cách chạy, kết quả quan sát và bằng chứng kiểm thử.

PCAP chứa lưu lượng mạng đầu vào. Cảnh báo IDS được lưu trong `detections.jsonl`, không nằm trong định dạng PCAP.

## Mục đích

Xác nhận pipeline đọc được PCAP, áp dụng rule BT3 và tạo **hai cảnh báo từ cùng một gói HTTP GET**.

## Cách chạy lại

Chạy từ thư mục gốc của project:

```powershell
python main.py --pcap TEST/BT3/demo.pcap --rules TEST/BT3/demo.rules --output TEST/BT3/packets.jsonl --alerts-output TEST/BT3/detections.jsonl
```

Chương trình báo `Processed 1 packet(s)`. Mở `TEST/BT3/demo.pcap` bằng Wireshark, lọc `tcp.port == 18080` và kiểm tra nội dung TCP:

```text
192.0.2.10:40003 -> 198.51.100.20:18080
GET /index HTTP/1.1
Host: example.com
```

## Kết quả xác nhận

| Bằng chứng | Kết quả |
|---|---|
| `demo.pcap` | 1 gói IPv4/TCP chứa request `GET /index` |
| `packets.jsonl` | 1 Packet Event, `application.protocol = HTTP`, `processing_action = process`, `detections` có 2 phần tử |
| `detections.jsonl` | 2 dòng Detection Event, cùng `packet_id = 1` và cùng `flow_id` |
| SID `300001` | Rule `content:"GET"` khớp đầu TCP stream, offset 0 |
| SID `300002` | Rule `content:"/index"` khớp TCP stream, offset 4 |

Đối chiếu các dòng JSONL với gói tin trong Wireshark: địa chỉ IP, port đích, phương thức GET và đường dẫn `/index` trùng nhau. Đây là kết quả demo của đường chạy PCAP -> Core Engine -> Detection Event.

`--rules` có thể lặp lại để nạp nhiều file rule; `--disable-sid 300001` loại rule này khỏi lần chạy. Rule sai cú pháp hoặc keyword chưa hỗ trợ được báo trên stderr, còn các rule hợp lệ vẫn chạy. Với `flow:to_server`/`to_client`, chương trình dùng gói SYN đầu tiên để xác định client khi có; nếu không có SYN thì suy ra từ port cao hơn.

## Các ca kiểm thử BT3

Chạy `python -m pytest tests/test_bt3_core_engine.py -q`. PCAP ở trên minh họa ca hai rule cùng khớp một gói; các yêu cầu khác được kiểm bằng test tự động:

| # | Yêu cầu | Test kiểm chứng |
|---|---|---|
| 1 | Rule hợp lệ, comment, dòng trống | `test_loader_skips_comments_blank_lines_and_keeps_loading_after_bad_rule` |
| 2 | Rule sai cú pháp, tiếp tục nạp | Test loader trên; `test_parser_rejects_invalid_port_and_missing_required_options` |
| 3 | Keyword chưa hỗ trợ | `test_parser_supports_hex_content_and_reports_unsupported_option` |
| 4 | Header IP/CIDR, port/range | `test_parser_builds_internal_rule_from_tcp_header_and_options` |
| 5 | Hướng `->` và `<>` | `test_indexer_filters_protocol_port_ip_and_direction` |
| 6 | Index TCP/UDP/any | `test_indexer_filters_protocol_port_ip_and_direction` |
| 7 | Lọc header trước khi so content | `test_indexer_filters_protocol_port_ip_and_direction` |
| 8 | `to_server`, `established` | `test_pipeline_uses_real_tcp_handshake_for_established_flow` |
| 9 | `content`, `nocase` | `test_content_flags_and_dsize` |
| 10 | `offset`, `depth` | `test_content_flags_and_dsize` |
| 11 | `distance`, `within` | `test_content_flags_and_dsize`; `test_relative_content_search_backtracks_to_later_first_occurrence` |
| 12 | TCP `flags`, `dsize` | `test_content_flags_and_dsize` |
| 13 | Hai rule khớp một event | `test_evaluation_emits_every_match_and_counts_candidates`; PCAP demo |
| 14 | Trường của Detection Event | `test_evaluation_emits_every_match_and_counts_candidates`; `detections.jsonl` |
