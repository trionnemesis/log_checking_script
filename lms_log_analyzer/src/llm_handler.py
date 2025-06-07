from __future__ import annotations
import json
import logging
from typing import Any, Dict, List, Optional

from .. import config
from .utils import CACHE

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_core.prompts import PromptTemplate
    from langchain_core.runnables import Runnable
except ImportError:  # pragma: no cover - optional
    ChatGoogleGenerativeAI = None
    PromptTemplate = None
    Runnable = None

logger = logging.getLogger(__name__)

LLM_CHAIN: Optional[Runnable] = None

if config.GEMINI_API_KEY and ChatGoogleGenerativeAI and PromptTemplate:
    try:
        llm = ChatGoogleGenerativeAI(
            model=config.LLM_MODEL_NAME,
            google_api_key=config.GEMINI_API_KEY,
            temperature=0.3,
            convert_system_message_to_human=True,
        )
        PROMPT_TEMPLATE_STR = """
System: 你是一位資安分析助手。請仔細評估以下 Web 伺服器日誌條目，判斷其是否顯示任何潛在的攻擊行為或異常活動。

請根據你的分析，提供一個 JSON 格式的回應，包含以下欄位：
- "is_attack": boolean
- "attack_type": string
- "reason": string
- "severity": string

Log Entry:
{log_entry}

JSON Output:
"""
        PROMPT = PromptTemplate(input_variables=["log_entry"], template=PROMPT_TEMPLATE_STR)
        LLM_CHAIN = PROMPT | llm  # type: ignore
        logger.info(f"LLM ({config.LLM_MODEL_NAME}) initialized")
    except Exception as e:  # pragma: no cover - optional
        logger.error(f"Failed initializing LLM: {e}")
        LLM_CHAIN = None
else:
    if not config.GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set; LLM disabled")
    LLM_CHAIN = None


class LLMCostTracker:
    def __init__(self):
        self.in_tokens_hourly = 0
        self.out_tokens_hourly = 0
        self.cost_hourly = 0.0
        self.total_in_tokens = 0
        self.total_out_tokens = 0
        self.total_cost = 0.0

    def add_usage(self, in_tok: int, out_tok: int):
        self.in_tokens_hourly += in_tok
        self.out_tokens_hourly += out_tok
        current_cost = (in_tok / 1000 * config.PRICE_IN_PER_1K_TOKENS) + (
            out_tok / 1000 * config.PRICE_OUT_PER_1K_TOKENS
        )
        self.cost_hourly += current_cost
        self.total_in_tokens += in_tok
        self.total_out_tokens += out_tok
        self.total_cost += current_cost

    def get_hourly_cost(self) -> float:
        return self.cost_hourly

    def get_total_stats(self) -> dict:
        return {
            "total_input_tokens": self.total_in_tokens,
            "total_output_tokens": self.total_out_tokens,
            "total_cost_usd": self.total_cost,
        }


COST_TRACKER = LLMCostTracker()


def llm_analyse(lines: List[str]) -> List[Optional[dict]]:
    if not LLM_CHAIN:
        logger.warning("LLM disabled")
        return [None] * len(lines)

    results: List[Optional[dict]] = [None] * len(lines)
    indices_to_query: List[int] = []
    batch_inputs: List[Dict[str, str]] = []

    for idx, line in enumerate(lines):
        cached = CACHE.get(line)
        if cached is not None:
            results[idx] = cached
        else:
            indices_to_query.append(idx)
            batch_inputs.append({"log_entry": line})

    if not batch_inputs:
        return results

    if COST_TRACKER.get_hourly_cost() >= config.MAX_HOURLY_COST_USD:
        logger.warning("LLM cost limit reached; skipping analysis")
        for i in indices_to_query:
            results[i] = {
                "is_attack": False,
                "attack_type": "N/A",
                "reason": "Budget limit reached",
                "severity": "None",
            }
        return results

    try:
        responses = LLM_CHAIN.batch(batch_inputs, config={"max_concurrency": 5})  # type: ignore
        total_in = 0
        total_out = 0
        for i, resp in enumerate(responses):
            orig_idx = indices_to_query[i]
            text = resp.content if hasattr(resp, "content") else resp
            try:
                parsed = json.loads(text)
                results[orig_idx] = parsed
                CACHE.put(lines[orig_idx], parsed)
                total_in += len(PROMPT.format(log_entry=lines[orig_idx]).split())  # type: ignore
                total_out += len(text.split())
            except json.JSONDecodeError as e:
                logger.error(f"Failed parsing LLM response: {e}")
                results[orig_idx] = {
                    "is_attack": True,
                    "attack_type": "LLM Parse Error",
                    "reason": str(e),
                    "severity": "Medium",
                }
        COST_TRACKER.add_usage(total_in, total_out)
    except Exception as e:  # pragma: no cover - optional
        logger.error(f"LLM batch call failed: {e}")
        for i in indices_to_query:
            results[i] = {
                "is_attack": True,
                "attack_type": "LLM API Error",
                "reason": str(e),
                "severity": "High",
            }
    return results
