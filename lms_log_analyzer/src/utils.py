from __future__ import annotations
"""工具函式，提供狀態管理、檔案處理與快取功能"""

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

# ----- 檔案狀態管理 -----
# 以檔名（完整路徑）為鍵，紀錄 inode 與已讀取的位移量
FileState = Dict[str, Dict[str, Any]]

STATE: FileState = {}


def load_state() -> FileState:
    """從磁碟讀取先前儲存的檔案位移資訊"""

    if config.LOG_STATE_FILE.exists():
        try:
            state = json.loads(config.LOG_STATE_FILE.read_text(encoding="utf-8"))
            logger.info(f"Loaded file state from {config.LOG_STATE_FILE}")
            return state
        except Exception as e:
            logger.error(f"Failed to read state file: {e}")
    return {}


def save_state(state: FileState):
    """將檔案位移資訊寫入磁碟，供下次執行接續使用"""

    try:
        config.LOG_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
        logger.info(f"Saved state to {config.LOG_STATE_FILE}")
    except Exception as e:
        logger.error(f"Failed to save state file: {e}")


STATE = load_state()


# ----- Helpers -----
class LRUCache(OrderedDict):
    """簡易 LRU 快取，用來記憶化函式輸出"""

    def __init__(self, capacity: int) -> None:
        super().__init__()
        self.capacity = capacity

    def get(self, key: Any) -> Any:
        """取得快取值，若不存在則回傳 ``None``"""
        if key in self:
            self.move_to_end(key)
            return self[key]
        return None

    def put(self, key: Any, value: Any) -> None:
        """放入快取，若超過容量則淘汰最舊的項目"""
        if key in self:
            self.move_to_end(key)
        self[key] = value
        if len(self) > self.capacity:
            self.popitem(last=False)


CACHE = LRUCache(config.CACHE_SIZE)


def open_log(path: Path) -> io.BufferedReader:
    """開啟一般或壓縮的日誌檔並回傳檔案物件"""

    if path.suffix == ".gz":
        return gzip.open(path, "rb")  # type: ignore
    if path.suffix == ".bz2":
        return bz2.open(path, "rb")  # type: ignore
    return path.open("rb")


def tail_since(path: Path) -> List[str]:
    """讀取自上次記錄後新增的日誌行"""

    try:
        inode = path.stat().st_ino
    except FileNotFoundError:
        # 檔案可能在期間被刪除或輪替
        logger.warning(f"Log file {path} disappeared")
        return []

    file_key = str(path.resolve())
    stored = STATE.get(file_key, {"inode": inode, "offset": 0})

    if stored["inode"] != inode:
        # inode 改變代表日誌被輪替，從頭開始讀取
        logger.info(f"{path} rotated. Restart reading")
        stored = {"inode": inode, "offset": 0}

    new_lines: List[str] = []
    try:
        with open_log(path) as f:
            f.seek(stored["offset"])
            for line_bytes in f:
                try:
                    # 直接解碼為 UTF-8
                    new_lines.append(line_bytes.decode("utf-8").rstrip())
                except UnicodeDecodeError:
                    # 若遇到非法字元則以替換模式解碼
                    decoded = line_bytes.decode("utf-8", "replace").rstrip()
                    new_lines.append(decoded)
            stored["offset"] = f.tell()
    except Exception as e:
        logger.error(f"Failed reading {path}: {e}")
        return []

    # 更新偏移量，後續執行只讀取新增資料
    STATE[file_key] = stored
    return new_lines
