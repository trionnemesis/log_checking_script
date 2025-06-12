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


def analyse_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """分析多行日誌並回傳結果"""

    if not lines:
        return []

    alerts = filter_logs(lines)
    if not alerts:
        save_state(STATE)
        VECTOR_DB.save()
        return []

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
    embeddings = [embed(line) for line in top_lines]

    contexts = []
    if VECTOR_DB.index is not None:
        for emb in embeddings:
            ids, _ = VECTOR_DB.search(emb, k=3)
            contexts.append(VECTOR_DB.get_cases(ids))
    else:
        contexts = [[] for _ in embeddings]

    analysis_inputs = [
        {"alert": alert, "examples": ctx} for alert, ctx in zip(top_alerts, contexts)
    ]

    analysis_results = llm_analyse(analysis_inputs)

    if VECTOR_DB.index is not None:
        cases_to_add = []
        for line, analysis in zip(top_lines, analysis_results):
            cases_to_add.append({"log": line, "analysis": analysis})
        VECTOR_DB.add(embeddings, cases_to_add)

    exported: List[Dict[str, Any]] = []
    for (fast_s, item), analysis in zip(top_scored, analysis_results):
        entry: Dict[str, Any] = {
            "log": item["line"],
            "fast_score": fast_s,
            "analysis": analysis,
        }
        exported.append(entry)

    save_state(STATE)
    VECTOR_DB.save()
    logger.info(f"LLM stats: {COST_TRACKER.get_total_stats()}")
    return exported


def process_logs(log_paths: List[Path]) -> List[Dict[str, Any]]:
    """讀取指定的日誌檔並回傳可疑行的分析結果"""

    # 依序讀取所有待處理的檔案，只保留新增的部分
    all_new_lines: List[str] = []
    for p in log_paths:
        if not p.exists() or not p.is_file():
            continue
        # ``tail_since`` 只會取出自上次處理後的新行
        all_new_lines.extend(tail_since(p))

    return analyse_lines(all_new_lines)
