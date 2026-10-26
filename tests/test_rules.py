from __future__ import annotations

from pathlib import Path

from ids_parser.rules import RuleLoader, RuleParser


VALID_TCP_RULE = (
    'alert tcp 10.0.0.0/24 any -> 192.168.1.20 8000:8080 '
    '(msg:"Directory traversal"; sid:100001; rev:1; '
    'content:"../"; nocase; offset:0; depth:64; classtype:web-application-attack; priority:1;)'
)


def test_parser_builds_internal_rule_from_tcp_header_and_options() -> None:
    result = RuleParser().parse(VALID_TCP_RULE, source="web.rules", line_number=4)

    assert result.status == "valid"
    assert result.rule is not None
    assert result.rule.source == "web.rules"
    assert result.rule.line_number == 4
    assert result.rule.protocol == "tcp"
    assert result.rule.direction == "->"
    assert result.rule.src_ip.matches("10.0.0.42")
    assert not result.rule.src_ip.matches("10.0.1.42")
    assert result.rule.dst_port.start == 8000
    assert result.rule.dst_port.end == 8080
    assert result.rule.msg == "Directory traversal"
    assert result.rule.sid == 100001
    assert result.rule.rev == 1
    assert result.rule.content[0].pattern == b"../"
    assert result.rule.content[0].nocase is True
    assert result.rule.content[0].offset == 0
    assert result.rule.content[0].depth == 64


def test_parser_supports_udp_any_ports_and_bidirectional_direction() -> None:
    rule = 'alert udp any any <> 8.8.8.8 53 (msg:"DNS query"; sid:100002; rev:2;)'

    result = RuleParser().parse(rule)

    assert result.status == "valid"
    assert result.rule is not None
    assert result.rule.protocol == "udp"
    assert result.rule.direction == "<>"
    assert result.rule.src_port.is_any
    assert result.rule.dst_port.matches(53)
    assert result.rule.dst_ip.matches("8.8.8.8")


def test_parser_supports_hex_content_and_reports_unsupported_option() -> None:
    rule = 'alert tcp any any -> any 80 (msg:"Traversal"; sid:100003; rev:1; content:"|2e 2e 2f|"; pcre:"/x/";)'

    result = RuleParser().parse(rule, source="rules.rules", line_number=9)

    assert result.status == "unsupported"
    assert result.rule is None
    assert any("pcre" in issue.message for issue in result.issues)


def test_loader_skips_comments_blank_lines_and_keeps_loading_after_bad_rule(
    tmp_path: Path,
) -> None:
    rule_file = tmp_path / "sample.rules"
    rule_file.write_text(
        "\n"
        "# comment\n"
        f"{VALID_TCP_RULE}\n"
        'alert tcp any any -> any 80 (msg:"Missing sid"; rev:1;)\n'
        'alert icmp any any -> any any (msg:"Unsupported"; sid:100004; rev:1;)\n',
        encoding="utf-8",
    )

    loaded = RuleLoader().load([rule_file])

    assert [rule.sid for rule in loaded.rules] == [100001]
    assert len(loaded.warnings) == 2
    assert {issue.status for issue in loaded.warnings} == {"invalid", "unsupported"}
    assert all(issue.source == str(rule_file) for issue in loaded.warnings)


def test_loader_can_disable_a_file_or_specific_sid(tmp_path: Path) -> None:
    first = tmp_path / "first.rules"
    second = tmp_path / "second.rules"
    first.write_text(VALID_TCP_RULE + "\n", encoding="utf-8")
    second.write_text(
        'alert udp any any -> any 53 (msg:"DNS"; sid:100005; rev:1;)\n',
        encoding="utf-8",
    )

    loaded = RuleLoader().load(
        [first, second],
        enabled_files={first.name: False},
        disabled_sids={100005},
    )

    assert loaded.rules == []
    assert loaded.skipped_files == [str(first)]
    assert loaded.disabled_sids == [100005]


def test_parser_rejects_invalid_port_and_missing_required_options() -> None:
    rule = 'alert tcp any 70000 -> any 80 (msg:"Bad"; sid:0;)'

    result = RuleParser().parse(rule)

    assert result.status == "invalid"
    assert result.rule is None
    messages = " ".join(issue.message for issue in result.issues)
    assert "Port is outside range" in messages
    assert "sid must be greater than zero" in messages
    assert "Missing required option: rev" in messages
