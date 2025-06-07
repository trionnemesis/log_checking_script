from __future__ import annotations
import json
import logging
from typing import Any, Dict, List, Optional

"""LLM interaction utilities used by the log processing pipeline.

This module wraps the Gemini model via LangChain, handles caching of responses
and keeps track of estimated costs.  ``llm_analyse`` is the primary entry point
invoked by :mod:`log_processor`.
"""

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
System: 你是一位資安分析助手。你將收到來自 Wazuh 的告警 JSON，請利用其中提供的事件上下文評估是否存在潛在攻擊或異常活動。

請回傳以下欄位組成的 JSON：
- "is_attack": boolean
- "attack_type": string
- "reason": string
- "severity": string

Wazuh Alert JSON:
{alert_json}

JSON Output:
"""
        PROMPT = PromptTemplate(input_variables=["alert_json"], template=PROMPT_TEMPLATE_STR)
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
    """Track token usage and approximate cost for the LLM calls."""

    def __init__(self) -> None:
        # Counters are kept per hour and in total so operators can enforce
        # spending limits while also monitoring long term usage.
        self.in_tokens_hourly = 0
        self.out_tokens_hourly = 0
        self.cost_hourly = 0.0
        self.total_in_tokens = 0
        self.total_out_tokens = 0
        self.total_cost = 0.0

    def add_usage(self, in_tok: int, out_tok: int):
        """Record a batch of token usage."""

        self.in_tokens_hourly += in_tok
        self.out_tokens_hourly += out_tok
        current_cost = (
            in_tok / 1000 * config.PRICE_IN_PER_1K_TOKENS
            + out_tok / 1000 * config.PRICE_OUT_PER_1K_TOKENS
        )
        self.cost_hourly += current_cost
        self.total_in_tokens += in_tok
        self.total_out_tokens += out_tok
        self.total_cost += current_cost

    def get_hourly_cost(self) -> float:
        """Return the accumulated cost in the current hour."""
        return self.cost_hourly

    def get_total_stats(self) -> dict:
        """Return a dictionary summarizing total usage across runs."""
        return {
            "total_input_tokens": self.total_in_tokens,
            "total_output_tokens": self.total_out_tokens,
            "total_cost_usd": self.total_cost,
        }


COST_TRACKER = LLMCostTracker()


def llm_analyse(alerts: List[Dict[str, Any]]) -> List[Optional[dict]]:
    """Analyse alerts with the LLM and return parsed JSON results.

    Cached results will be reused to save cost.  When the LLM is disabled or the
    hourly budget has been exceeded, placeholder results are produced instead of
    making API calls.
    """

    if not LLM_CHAIN:
        logger.warning("LLM disabled")
        return [None] * len(alerts)

    results: List[Optional[dict]] = [None] * len(alerts)
    indices_to_query: List[int] = []
    batch_inputs: List[Dict[str, str]] = []

    for idx, alert in enumerate(alerts):
        alert_json = json.dumps(alert, ensure_ascii=False, sort_keys=True)
        cached = CACHE.get(alert_json)
        if cached is not None:
            results[idx] = cached
        else:
            indices_to_query.append(idx)
            batch_inputs.append({"alert_json": alert_json})

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
            alert_json = json.dumps(alerts[orig_idx], ensure_ascii=False, sort_keys=True)
            try:
                parsed = json.loads(text)
                results[orig_idx] = parsed
                CACHE.put(alert_json, parsed)
                total_in += len(PROMPT.format(alert_json=alert_json).split())  # type: ignore
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
