"""Bounded, sequence-aware TCP stream reassembly for application parsers."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Any


FlowKey = tuple[str, int, str, int]


@dataclass(slots=True)
class ReassemblyResult:
    flow_key: FlowKey
    data: bytes
    buffered_bytes: int
    stored_bytes: int
    segment_count: int
    retransmission: bool
    out_of_order: bool
    has_gap: bool
    overflowed: bool

    def metadata(self) -> dict[str, Any]:
        source_ip, source_port, destination_ip, destination_port = self.flow_key
        return {
            "flow": (
                f"{source_ip}:{source_port}->{destination_ip}:{destination_port}"
            ),
            "buffered_bytes": self.buffered_bytes,
            "stored_bytes": self.stored_bytes,
            "segment_count": self.segment_count,
            "retransmission": self.retransmission,
            "out_of_order": self.out_of_order,
            "has_gap": self.has_gap,
            "overflowed": self.overflowed,
        }


@dataclass(slots=True)
class _StreamState:
    segments: list[tuple[int, bytes]] = field(default_factory=list)
    consumed_until: int | None = None
    last_seen: float = 0.0


class TCPStreamReassembler:
    """Reassemble one direction of each IPv4 TCP flow.

    First-seen bytes win when retransmitted data overlaps. State is bounded by
    flow count, byte count, and inactivity timeout to keep live capture safe.
    """

    def __init__(
        self,
        *,
        max_flows: int = 1024,
        max_stream_bytes: int = 1_048_576,
        timeout_seconds: float = 120.0,
    ) -> None:
        if max_flows < 1 or max_stream_bytes < 1 or timeout_seconds <= 0:
            raise ValueError("TCP reassembly limits must be positive")
        self.max_flows = max_flows
        self.max_stream_bytes = max_stream_bytes
        self.timeout_seconds = timeout_seconds
        self._streams: dict[FlowKey, _StreamState] = {}
        self._lock = Lock()

    def _expire(self, now: float) -> None:
        expired = [
            key
            for key, state in self._streams.items()
            if now >= state.last_seen
            and now - state.last_seen > self.timeout_seconds
        ]
        for key in expired:
            del self._streams[key]

    def _ensure_capacity(self) -> None:
        if len(self._streams) < self.max_flows:
            return
        oldest = min(self._streams, key=lambda key: self._streams[key].last_seen)
        del self._streams[oldest]

    @staticmethod
    def _insert_first_seen(
        state: _StreamState, sequence: int, data: bytes
    ) -> tuple[bool, bool]:
        """Insert only byte ranges not already stored.

        Returns ``(retransmission, inserted_any_bytes)``.
        """

        pieces = [(sequence, data)]
        retransmission = False
        for existing_start, existing_data in state.segments:
            existing_end = existing_start + len(existing_data)
            next_pieces: list[tuple[int, bytes]] = []
            for piece_start, piece_data in pieces:
                piece_end = piece_start + len(piece_data)
                overlap_start = max(piece_start, existing_start)
                overlap_end = min(piece_end, existing_end)
                if overlap_start >= overlap_end:
                    next_pieces.append((piece_start, piece_data))
                    continue
                retransmission = True
                if piece_start < overlap_start:
                    next_pieces.append(
                        (piece_start, piece_data[: overlap_start - piece_start])
                    )
                if overlap_end < piece_end:
                    next_pieces.append(
                        (overlap_end, piece_data[overlap_end - piece_start :])
                    )
            pieces = next_pieces
            if not pieces:
                break
        state.segments.extend(pieces)
        state.segments.sort(key=lambda item: item[0])
        return retransmission, bool(pieces)

    @staticmethod
    def _assemble(state: _StreamState) -> tuple[bytes, bool]:
        if not state.segments:
            return b"", False
        cursor = (
            state.consumed_until
            if state.consumed_until is not None
            else state.segments[0][0]
        )
        chunks: list[bytes] = []
        has_gap = False
        for start, data in state.segments:
            if start > cursor:
                has_gap = True
                break
            end = start + len(data)
            if end <= cursor:
                continue
            offset = max(0, cursor - start)
            chunks.append(data[offset:])
            cursor = end
        return b"".join(chunks), has_gap

    def add_segment(
        self,
        flow_key: FlowKey,
        sequence: int,
        data: bytes,
        *,
        timestamp: float,
        syn: bool = False,
        ack: bool = False,
        fin: bool = False,
        rst: bool = False,
    ) -> ReassemblyResult:
        """Add one TCP payload segment and return contiguous stream bytes."""

        sequence = int(sequence) + (1 if syn else 0)
        with self._lock:
            self._expire(timestamp)
            if syn and not ack:
                self._streams.pop(flow_key, None)
            if flow_key not in self._streams:
                self._ensure_capacity()
                self._streams[flow_key] = _StreamState(last_seen=timestamp)
            state = self._streams[flow_key]
            state.last_seen = timestamp
            if syn and not ack:
                state.consumed_until = sequence

            original_sequence = sequence
            original_data = data
            retransmission = False
            if state.consumed_until is not None and data:
                consumed = state.consumed_until
                end = sequence + len(data)
                if end <= consumed:
                    retransmission = True
                    data = b""
                elif sequence < consumed:
                    retransmission = True
                    data = data[consumed - sequence :]
                    sequence = consumed

            existing_base = (
                state.segments[0][0]
                if state.segments
                else state.consumed_until
            )
            contiguous_before, _ = self._assemble(state)
            contiguous_end = (
                (state.segments[0][0] + len(contiguous_before))
                if state.segments
                else state.consumed_until
            )
            out_of_order = bool(
                data
                and existing_base is not None
                and (
                    sequence < existing_base
                    or (contiguous_end is not None and sequence > contiguous_end)
                )
            )

            if data:
                overlap, _ = self._insert_first_seen(state, sequence, data)
                retransmission = retransmission or overlap

            stored_bytes = sum(len(segment) for _, segment in state.segments)
            overflowed = stored_bytes > self.max_stream_bytes
            if overflowed:
                # Drop old state and retain only the current segment as a safe
                # new observation point. It may remain UNKNOWN until a new
                # application message begins.
                state.segments.clear()
                state.consumed_until = None
                if original_data:
                    self._insert_first_seen(
                        state,
                        original_sequence,
                        original_data[: self.max_stream_bytes],
                    )
                stored_bytes = sum(len(segment) for _, segment in state.segments)

            assembled, has_gap = self._assemble(state)
            result = ReassemblyResult(
                flow_key=flow_key,
                data=assembled,
                buffered_bytes=len(assembled),
                stored_bytes=stored_bytes,
                segment_count=len(state.segments),
                retransmission=retransmission,
                out_of_order=out_of_order,
                has_gap=has_gap,
                overflowed=overflowed,
            )
            if fin or rst:
                self._streams.pop(flow_key, None)
            return result

    def consume(self, flow_key: FlowKey, byte_count: int) -> None:
        """Discard an application message already emitted by the pipeline."""

        if byte_count <= 0:
            return
        with self._lock:
            state = self._streams.get(flow_key)
            if state is None or not state.segments:
                return
            base = state.segments[0][0]
            new_base = base + byte_count
            remaining: list[tuple[int, bytes]] = []
            for start, data in state.segments:
                end = start + len(data)
                if end <= new_base:
                    continue
                if start < new_base:
                    remaining.append((new_base, data[new_base - start :]))
                else:
                    remaining.append((start, data))
            state.segments = remaining
            state.consumed_until = new_base

    def clear(self) -> None:
        with self._lock:
            self._streams.clear()
