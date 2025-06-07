from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .. import config
from . import log_parser
from .llm_handler import llm_analyse, COST_TRACKER
from .vector_db import VECTOR_DB, embed
from .utils import tail_since, save_state, STATE

logger = logging.getLogger(__name__)


def process_logs(log_paths: List[Path]) -> List[Dict[str, Any]]:
    all_new_lines: List[str] = []
    for p in log_paths:
        if not p.exists() or not p.is_file():
            continue
        all_new_lines.extend(tail_since(p))

    if not all_new_lines:
        save_state(STATE)
        VECTOR_DB.save()
        return []

    scored = [(log_parser.fast_score(l), l) for l in all_new_lines]
    scored.sort(key=lambda x: x[0], reverse=True)
    num_to_sample = max(1, int(len(scored) * config.SAMPLE_TOP_PERCENT / 100))
    top_scored = [sl for sl in scored if sl[0] > 0.0][:num_to_sample]
    if not top_scored:
        save_state(STATE)
        VECTOR_DB.save()
        return []

    top_lines = [line for _, line in top_scored]
    embeddings: List[List[float]] = []
    if VECTOR_DB.index is not None:
        embeddings = [embed(line) for line in top_lines]
        VECTOR_DB.add(embeddings)

    analysis_results = llm_analyse(top_lines)

    exported: List[Dict[str, Any]] = []
    for (fast_s, original_line), analysis in zip(top_scored, analysis_results):
        entry: Dict[str, Any] = {
            "log": original_line,
            "fast_score": fast_s,
            "analysis": analysis,
        }
        exported.append(entry)

    save_state(STATE)
    VECTOR_DB.save()
    logger.info(f"LLM stats: {COST_TRACKER.get_total_stats()}")
    return exported
