from __future__ import annotations
"""程式入口點

此腳本負責整合各模組：搜尋待分析的日誌檔、
呼叫處理流程並輸出結果，同時設定日誌系統讓
資訊能寫入檔案與終端機。"""

import logging
import json
from pathlib import Path
from typing import List

from . import config
from .src.log_processor import process_logs
from .src.utils import logger, save_state, STATE
from .src.vector_db import VECTOR_DB

# 先行設定 logging，讓所有模組共用同一組 handler。
# 預設輸出至終端機，若有權限則同時寫入檔案。
log_handlers: List[logging.Handler] = [logging.StreamHandler()]
try:
    file_handler = logging.FileHandler(config.LMS_OPERATIONAL_LOG_FILE, encoding="utf-8")
    log_handlers.append(file_handler)
except PermissionError:
    print(f"[CRITICAL] Cannot write to {config.LMS_OPERATIONAL_LOG_FILE}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    handlers=log_handlers,
)


def main():
    """尋找日誌檔並啟動處理流程"""
    log_paths: List[Path] = []
    if config.LMS_TARGET_LOG_DIR.exists() and config.LMS_TARGET_LOG_DIR.is_dir():
        # 收集目錄下所有支援的日誌檔，包含壓縮格式 (.gz、.bz2)。
        for p in config.LMS_TARGET_LOG_DIR.iterdir():
            if p.is_file() and p.suffix.lower() in [".log", ".gz", ".bz2"]:
                log_paths.append(p)
    if not log_paths:
        logger.info(f"No log files found in {config.LMS_TARGET_LOG_DIR}")
        return

    # 將實際處理交由 log_processor 模組
    results = process_logs(log_paths)
    if results:
        # 有分析結果時將其輸出為 JSON 檔
        try:
            with open(config.LMS_ANALYSIS_OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
        except PermissionError:
            logger.error(f"Cannot write analysis output to {config.LMS_ANALYSIS_OUTPUT_FILE}")

    # 每次執行完畢都要儲存狀態與向量索引
    save_state(STATE)
    VECTOR_DB.save()


if __name__ == "__main__":
    # 直接執行檔案時啟動主函式
    main()
