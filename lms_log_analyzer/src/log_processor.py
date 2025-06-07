from __future__ import annotations
"""Core logic for reading, scoring and analysing log files."""

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

logger = logging.getLogger(__name__)


def process_logs(log_paths: List[Path]) -> List[Dict[str, Any]]:
    """Read given log files and return analysis results for suspicious lines."""

    all_new_lines: List[str] = []
    for p in log_paths:
        if not p.exists() or not p.is_file():
            continue
        # ``tail_since`` only returns new lines since the last run
        all_new_lines.extend(tail_since(p))

    if not all_new_lines:
        save_state(STATE)
        VECTOR_DB.save()
        return []

    # Use Wazuh API to pre-filter lines, reducing LLM usage
    alerts = filter_logs(all_new_lines)
    if not alerts:
        save_state(STATE)
        VECTOR_DB.save()
        return []

    # Score each alert heuristically so we only send the most interesting ones
    # to the LLM.
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
        # Keep track of processed log lines in the vector store to allow future
        # similarity searches.
        embeddings = [embed(line) for line in top_lines]
        VECTOR_DB.add(embeddings)

    analysis_results = llm_analyse(top_alerts)

    # Bundle results together for persistence or further processing
    exported: List[Dict[str, Any]] = []
    for (fast_s, item), analysis in zip(top_scored, analysis_results):
        original_line = item["line"]
        entry: Dict[str, Any] = {
            "log": original_line,
            "fast_score": fast_s,
            "analysis": analysis,
        }
        exported.append(entry)

    # Persist updated state and print token usage for visibility
    save_state(STATE)
    VECTOR_DB.save()
    logger.info(f"LLM stats: {COST_TRACKER.get_total_stats()}")
    return exported
