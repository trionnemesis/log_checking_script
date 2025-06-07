from __future__ import annotations
import logging
import json
from pathlib import Path
from typing import List

from . import config
from .src.log_processor import process_logs
from .src.utils import logger, save_state, STATE
from .src.vector_db import VECTOR_DB

# Configure logging
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
    log_paths: List[Path] = []
    if config.LMS_TARGET_LOG_DIR.exists() and config.LMS_TARGET_LOG_DIR.is_dir():
        for p in config.LMS_TARGET_LOG_DIR.iterdir():
            if p.is_file() and p.suffix.lower() in [".log", ".gz", ".bz2"]:
                log_paths.append(p)
    if not log_paths:
        logger.info(f"No log files found in {config.LMS_TARGET_LOG_DIR}")
        return

    results = process_logs(log_paths)
    if results:
        try:
            with open(config.LMS_ANALYSIS_OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
        except PermissionError:
            logger.error(f"Cannot write analysis output to {config.LMS_ANALYSIS_OUTPUT_FILE}")

    save_state(STATE)
    VECTOR_DB.save()


if __name__ == "__main__":
    main()
