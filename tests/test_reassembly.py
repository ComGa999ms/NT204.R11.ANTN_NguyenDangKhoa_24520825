from __future__ import annotations

from ids_parser.reassembly import TCPStreamReassembler


FLOW = ("192.0.2.1", 50000, "198.51.100.2", 80)


def test_reassembles_out_of_order_segments_and_ignores_retransmission() -> None:
    reassembler = TCPStreamReassembler()

    second = reassembler.add_segment(FLOW, 106, b"world", timestamp=1.0)
    first = reassembler.add_segment(FLOW, 100, b"hello ", timestamp=2.0)
    duplicate = reassembler.add_segment(FLOW, 106, b"world", timestamp=3.0)

    assert second.data == b"world"
    assert first.data == b"hello world"
    assert first.out_of_order is True
    assert duplicate.data == b"hello world"
    assert duplicate.retransmission is True


def test_reassembles_gap_when_missing_segment_arrives() -> None:
    reassembler = TCPStreamReassembler()

    first = reassembler.add_segment(FLOW, 100, b"abc", timestamp=1.0)
    third = reassembler.add_segment(FLOW, 106, b"ghi", timestamp=2.0)
    complete = reassembler.add_segment(FLOW, 103, b"def", timestamp=3.0)

    assert first.data == b"abc"
    assert third.data == b"abc"
    assert third.has_gap is True
    assert complete.data == b"abcdefghi"
    assert complete.has_gap is False


def test_overlapping_segment_keeps_first_seen_bytes() -> None:
    reassembler = TCPStreamReassembler()

    reassembler.add_segment(FLOW, 100, b"abcdef", timestamp=1.0)
    result = reassembler.add_segment(FLOW, 103, b"XYZghi", timestamp=2.0)

    assert result.data == b"abcdefghi"
    assert result.retransmission is True


def test_consume_prevents_old_payload_from_being_emitted_again() -> None:
    reassembler = TCPStreamReassembler()
    result = reassembler.add_segment(FLOW, 100, b"message", timestamp=1.0)
    reassembler.consume(FLOW, len(result.data))

    retransmission = reassembler.add_segment(
        FLOW, 100, b"message", timestamp=2.0
    )
    next_message = reassembler.add_segment(FLOW, 107, b"next", timestamp=3.0)

    assert retransmission.data == b""
    assert retransmission.retransmission is True
    assert next_message.data == b"next"


def test_new_syn_resets_existing_directional_stream() -> None:
    reassembler = TCPStreamReassembler()
    reassembler.add_segment(FLOW, 100, b"old", timestamp=1.0)

    result = reassembler.add_segment(
        FLOW, 500, b"new", timestamp=2.0, syn=True, ack=False
    )

    assert result.data == b"new"


def test_syn_sequence_anchors_out_of_order_stream_start() -> None:
    reassembler = TCPStreamReassembler()
    reassembler.add_segment(
        FLOW, 99, b"", timestamp=1.0, syn=True, ack=False
    )

    later = reassembler.add_segment(FLOW, 106, b"world", timestamp=2.0)
    complete = reassembler.add_segment(FLOW, 100, b"hello ", timestamp=3.0)

    assert later.data == b""
    assert later.has_gap is True
    assert complete.data == b"hello world"


def test_stream_buffer_is_bounded() -> None:
    reassembler = TCPStreamReassembler(max_stream_bytes=4)

    result = reassembler.add_segment(FLOW, 100, b"123456", timestamp=1.0)

    assert result.overflowed is True
    assert result.stored_bytes == 4
    assert result.data == b"1234"
