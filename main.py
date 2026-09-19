"""Project entry point.

This small bootstrap keeps ``python main.py`` working without requiring the
package to be installed first.
"""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIRECTORY = PROJECT_ROOT / "src"
if str(SRC_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SRC_DIRECTORY))

from ids_parser.cli import entrypoint  # noqa: E402


if __name__ == "__main__":
    entrypoint()

