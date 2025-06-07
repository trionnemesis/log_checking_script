from __future__ import annotations
"""Utility helpers for state management, file handling and caching."""

import bz2
import gzip
import io
import json
import logging
from pathlib import Path
from collections import OrderedDict
from typing import Any, Dict, List

from .. import config

logger = logging.getLogger(__name__)

# ----- File state management -----
FileState = Dict[str, Dict[str, Any]]

STATE: FileState = {}


def load_state() -> FileState:
    """Load persisted file offsets from disk."""

    if config.LOG_STATE_FILE.exists():
        try:
            state = json.loads(config.LOG_STATE_FILE.read_text(encoding="utf-8"))
            logger.info(f"Loaded file state from {config.LOG_STATE_FILE}")
            return state
        except Exception as e:
            logger.error(f"Failed to read state file: {e}")
    return {}


def save_state(state: FileState):
    """Persist file offsets so the next run knows where to continue."""

    try:
        config.LOG_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
        logger.info(f"Saved state to {config.LOG_STATE_FILE}")
    except Exception as e:
        logger.error(f"Failed to save state file: {e}")


STATE = load_state()


# ----- Helpers -----
class LRUCache(OrderedDict):
    """Simple least-recently-used cache for memoizing results."""

    def __init__(self, capacity: int) -> None:
        super().__init__()
        self.capacity = capacity

    def get(self, key: Any) -> Any:
        """Retrieve ``key`` or ``None`` if not cached."""
        if key in self:
            self.move_to_end(key)
            return self[key]
        return None

    def put(self, key: Any, value: Any) -> None:
        """Store ``key`` with ``value``, evicting the oldest entry when full."""
        if key in self:
            self.move_to_end(key)
        self[key] = value
        if len(self) > self.capacity:
            self.popitem(last=False)


CACHE = LRUCache(config.CACHE_SIZE)


def open_log(path: Path) -> io.BufferedReader:
    """Open plain or compressed log file for reading as bytes."""

    if path.suffix == ".gz":
        return gzip.open(path, "rb")  # type: ignore
    if path.suffix == ".bz2":
        return bz2.open(path, "rb")  # type: ignore
    return path.open("rb")


def tail_since(path: Path) -> List[str]:
    """Read and return new lines since last offset for ``path``."""

    try:
        inode = path.stat().st_ino
    except FileNotFoundError:
        logger.warning(f"Log file {path} disappeared")
        return []

    file_key = str(path.resolve())
    stored = STATE.get(file_key, {"inode": inode, "offset": 0})

    if stored["inode"] != inode:
        logger.info(f"{path} rotated. Restart reading")
        stored = {"inode": inode, "offset": 0}

    new_lines: List[str] = []
    try:
        with open_log(path) as f:
            f.seek(stored["offset"])
            for line_bytes in f:
                try:
                    new_lines.append(line_bytes.decode("utf-8").rstrip())
                except UnicodeDecodeError:
                    decoded = line_bytes.decode("utf-8", "replace").rstrip()
                    new_lines.append(decoded)
            stored["offset"] = f.tell()
    except Exception as e:
        logger.error(f"Failed reading {path}: {e}")
        return []

    # Persist new offset so subsequent runs only process appended data
    STATE[file_key] = stored
    return new_lines
