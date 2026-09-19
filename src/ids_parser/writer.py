"""JSON Lines output for normalized IDS events."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO


class JSONLinesWriter:
    """Write exactly one JSON object per line using UTF-8 encoding."""

    def __init__(self, output_path: str | Path, *, flush: bool = True) -> None:
        self.output_path = Path(output_path)
        self.flush = flush
        self._stream: TextIO | None = None

    def __enter__(self) -> "JSONLinesWriter":
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.output_path.open("w", encoding="utf-8", newline="\n")
        return self

    def write(self, event: Mapping[str, Any]) -> None:
        if self._stream is None:
            raise RuntimeError("JSONLinesWriter must be opened as a context manager")
        json.dump(event, self._stream, ensure_ascii=False, separators=(",", ":"))
        self._stream.write("\n")
        if self.flush:
            self._stream.flush()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

