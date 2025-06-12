from __future__ import annotations
import json
import logging
from typing import Any, Dict, List, Optional

"""LLM 互動工具

此模組封裝 Gemini 模型與 LangChain 的整合，負責快取回應、
追蹤 Token 使用成本，並提供 ``llm_analyse`` 供 :mod:`log_processor`
 呼叫。"""

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

# 模組記錄器，提供除錯與成本追蹤資訊
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
System: 你是一位資安分析助手。你將收到來自 Wazuh 的告警 JSON，以及若干歷史案例供參考。請綜合評估是否存在潛在攻擊或異常活動。

歷史案例 (JSON)：
{examples_json}

Wazuh Alert JSON:
{alert_json}

請回傳以下欄位組成的 JSON：
- "is_attack": boolean
- "attack_type": string
- "reason": string
- "severity": string

JSON Output:
"""
        PROMPT = PromptTemplate(input_variables=["alert_json", "examples_json"], template=PROMPT_TEMPLATE_STR)
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
    """追蹤 LLM Token 使用量與費用的輔助類別"""

    def __init__(self) -> None:
        # 以小時計算與累積總量，便於限制費用並觀察長期趨勢
        self.in_tokens_hourly = 0
        self.out_tokens_hourly = 0
        self.cost_hourly = 0.0
        self.total_in_tokens = 0
        self.total_out_tokens = 0
        self.total_cost = 0.0

    def add_usage(self, in_tok: int, out_tok: int):
        """記錄一次呼叫的 Token 數量"""

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
        """取得本小時累積費用"""
        return self.cost_hourly

    def get_total_stats(self) -> dict:
        """回傳跨執行期間的總體使用統計"""
        return {
            "total_input_tokens": self.total_in_tokens,
            "total_output_tokens": self.total_out_tokens,
            "total_cost_usd": self.total_cost,
        }


COST_TRACKER = LLMCostTracker()


def llm_analyse(alerts: List[Dict[str, Any]]) -> List[Optional[dict]]:
    """使用 LLM 分析告警並回傳 JSON 結果

    若同一筆資料先前已分析過，將從快取取得結果以節省費用；
    當 LLM 停用或超過本小時預算時，會回傳預設結果而不呼叫 API。
    """

    if not LLM_CHAIN:
        logger.warning("LLM disabled")
        return [None] * len(alerts)

    # 預先建立結果陣列與要查詢的索引
    results: List[Optional[dict]] = [None] * len(alerts)
    indices_to_query: List[int] = []
    batch_inputs: List[Dict[str, str]] = []

    for idx, item in enumerate(alerts):
        alert = item.get("alert", item)
        examples = item.get("examples", [])
        alert_json = json.dumps(alert, ensure_ascii=False, sort_keys=True)
        examples_json = json.dumps(examples, ensure_ascii=False, sort_keys=True)
        cache_key = alert_json + "|" + examples_json
        cached = CACHE.get(cache_key)
        if cached is not None:
            # 若已在快取中，直接使用
            results[idx] = cached
        else:
            indices_to_query.append(idx)
            batch_inputs.append({"alert_json": alert_json, "examples_json": examples_json})

    if not batch_inputs:
        # 全部都有快取，不需再呼叫 LLM
        return results

    if COST_TRACKER.get_hourly_cost() >= config.MAX_HOURLY_COST_USD:
        # 目前累積費用已達上限，不再呼叫 LLM
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
        # 一次批次送出請求，並限制最大並行數
        responses = LLM_CHAIN.batch(batch_inputs, config={"max_concurrency": 5})  # type: ignore
        total_in = 0
        total_out = 0
        for i, resp in enumerate(responses):
            orig_idx = indices_to_query[i]
            text = resp.content if hasattr(resp, "content") else resp
            item = alerts[orig_idx]
            alert = item.get("alert", item)
            examples = item.get("examples", [])
            alert_json = json.dumps(alert, ensure_ascii=False, sort_keys=True)
            examples_json = json.dumps(examples, ensure_ascii=False, sort_keys=True)
            cache_key = alert_json + "|" + examples_json
            try:
                parsed = json.loads(text)
                # 成功解析則寫入結果並更新快取
                results[orig_idx] = parsed
                CACHE.put(cache_key, parsed)
                total_in += len(PROMPT.format(alert_json=alert_json, examples_json=examples_json).split())  # type: ignore
                total_out += len(text.split())
            except json.JSONDecodeError as e:
                logger.error(f"Failed parsing LLM response: {e}")
                results[orig_idx] = {
                    "is_attack": True,
                    "attack_type": "LLM Parse Error",
                    "reason": str(e),
                    "severity": "Medium",
                }
        # 紀錄本次批次的 Token 使用量
        COST_TRACKER.add_usage(total_in, total_out)
    except Exception as e:  # pragma: no cover - optional
        # API 呼叫失敗，回傳錯誤資訊
        logger.error(f"LLM batch call failed: {e}")
        for i in indices_to_query:
            results[i] = {
                "is_attack": True,
                "attack_type": "LLM API Error",
                "reason": str(e),
                "severity": "High",
            }
    return results
