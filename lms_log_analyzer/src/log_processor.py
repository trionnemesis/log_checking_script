from __future__ import annotations
"""日誌讀取與分析核心邏輯"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .. import config
from . import log_parser
from .llm_handler import llm_analyse, COST_TRACKER
from .vector_db import VECTOR_DB, embed
from .utils import tail_since, save_state, STATE
from .wazuh_api import filter_logs

# 模組層級記錄器，供其他函式使用
logger = logging.getLogger(__name__)


def process_logs(log_paths: List[Path]) -> List[Dict[str, Any]]:
    """讀取指定的日誌檔並回傳可疑行的分析結果"""

    # 依序讀取所有待處理的檔案，只保留新增的部分
    all_new_lines: List[str] = []
    for p in log_paths:
        if not p.exists() or not p.is_file():
            continue
        # ``tail_since`` 只會取出自上次處理後的新行
        all_new_lines.extend(tail_since(p))

    if not all_new_lines:
        save_state(STATE)
        VECTOR_DB.save()
        return []

    # 先透過 Wazuh API 篩選可疑行，減少送往 LLM 的量
    alerts = filter_logs(all_new_lines)
    if not alerts:
        save_state(STATE)
        VECTOR_DB.save()
        return []

    # 以啟發式方式為每個告警打分，僅挑選分數最高的部分送往 LLM
    scored = [(log_parser.fast_score(a["line"]), a) for a in alerts]
    scored.sort(key=lambda x: x[0], reverse=True)
    num_to_sample = max(1, int(len(scored) * config.SAMPLE_TOP_PERCENT / 100))
    top_scored = [sl for sl in scored if sl[0] > 0.0][:num_to_sample]
    if not top_scored:
        save_state(STATE)
        VECTOR_DB.save()
        return []

    top_lines = [item["line"] for _, item in top_scored]
    top_alerts = [item["alert"] for _, item in top_scored]
    embeddings: List[List[float]] = []
    if VECTOR_DB.index is not None:
        # 將處理過的日誌轉成向量並存入資料庫，方便日後相似度查詢
        embeddings = [embed(line) for line in top_lines]
        VECTOR_DB.add(embeddings)

    # 送交 LLM 做進一步分析
    analysis_results = llm_analyse(top_alerts)

    # 將結果整理成列表，方便後續儲存或處理
    exported: List[Dict[str, Any]] = []
    for (fast_s, item), analysis in zip(top_scored, analysis_results):
        original_line = item["line"]
        entry: Dict[str, Any] = {
            "log": original_line,
            "fast_score": fast_s,
            "analysis": analysis,
        }
        exported.append(entry)

    # 儲存狀態並輸出 token 使用統計
    save_state(STATE)
    VECTOR_DB.save()
    logger.info(f"LLM stats: {COST_TRACKER.get_total_stats()}")
    return exported
