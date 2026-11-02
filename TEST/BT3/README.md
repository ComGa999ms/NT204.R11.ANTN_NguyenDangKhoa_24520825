# BT3 Core Engine demo

Run from the repository root:

```powershell
python main.py --pcap TEST/http-get/http-get.pcap --rules TEST/BT3/demo.rules --output TEST/BT3/packets.jsonl --alerts-output TEST/BT3/detections.jsonl
```

The packet output contains `detections`; the detection output has two lines, one for each matching SID (300001 and 300002). The loader reports invalid and unsupported rules to stderr and continues processing. `--rules` can be repeated for multiple files, and `--disable-sid 300001` excludes one rule. `flow:to_server`/`to_client` use the first SYN packet to identify the client when available; without a SYN, the higher port is assumed to be the client port.

Run the automated BT3 cases with `python -m pytest tests/test_bt3_core_engine.py -q`.

## Required test cases

| # | Requirement | Automated evidence |
|---|---|---|
| 1 | Valid rules, comments, blank lines | `test_loader_skips_comments_blank_lines_and_keeps_loading_after_bad_rule` |
| 2 | Invalid syntax, continue loading | Same loader test; `test_parser_rejects_invalid_port_and_missing_required_options` |
| 3 | Unsupported keyword | `test_parser_supports_hex_content_and_reports_unsupported_option` |
| 4 | Header IP/CIDR, port/range | `test_parser_builds_internal_rule_from_tcp_header_and_options` |
| 5 | `->` and `<>` | `test_indexer_filters_protocol_port_ip_and_direction` |
| 6 | TCP/UDP/any index | `test_indexer_filters_protocol_port_ip_and_direction` |
| 7 | Header rejection before content | `test_indexer_filters_protocol_port_ip_and_direction` |
| 8 | `to_server`, `established` | `test_pipeline_uses_real_tcp_handshake_for_established_flow` |
| 9 | `content`, `nocase` | `test_content_flags_and_dsize` |
| 10 | `offset`, `depth` | `test_content_flags_and_dsize` |
| 11 | `distance`, `within` | `test_content_flags_and_dsize`; `test_relative_content_search_backtracks_to_later_first_occurrence` |
| 12 | TCP `flags`, `dsize` | `test_content_flags_and_dsize` |
| 13 | Two rules on one event | `test_evaluation_emits_every_match_and_counts_candidates`; demo outputs |
| 14 | Detection Event fields | `test_evaluation_emits_every_match_and_counts_candidates`; `detections.jsonl` |

Full suite result: `117 passed`. The included PCAP demo result has one packet event in `packets.jsonl` and two Detection Events in `detections.jsonl`.
