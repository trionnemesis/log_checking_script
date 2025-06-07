from __future__ import annotations
"""整合 Wazuh API，用於在送往 LLM 前過濾日誌"""

import logging
from typing import Dict, List, Optional

import requests

from .. import config

logger = logging.getLogger(__name__)

# 快取的驗證 token
_TOKEN: Optional[str] = None


def _authenticate() -> Optional[str]:
    """向 Wazuh API 取得認證 token"""

    url = f"{config.WAZUH_API_URL}/security/user/authenticate"
    try:
        # 使用基本認證向 Wazuh 取得 token
        resp = requests.get(
            url,
            auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD),
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", {}).get("token")
    except Exception as e:  # pragma: no cover - optional
        logger.error(f"Wazuh auth failed: {e}")
        return None


def _ensure_token() -> Optional[str]:
    """檢查並取得 (或重新取得) token"""

    global _TOKEN
    if _TOKEN is None:
        # 尚無 token 時進行認證
        _TOKEN = _authenticate()
    return _TOKEN


def get_alert(line: str) -> Optional[Dict[str, any]]:
    """若該行觸發 Wazuh 告警則回傳其 JSON"""
    if not config.WAZUH_ENABLED:
        return {"original_log": line}
    token = _ensure_token()
    if not token:
        return None
    url = f"{config.WAZUH_API_URL}/experimental/logtest"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.post(url, headers=headers, json={"event": line}, timeout=5)
        if resp.status_code == 401:
            # token 失效時重新認證一次
            _TOKEN = _authenticate()
            if _TOKEN:
                headers["Authorization"] = f"Bearer {_TOKEN}"
                resp = requests.post(url, headers=headers, json={"event": line}, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        alerts = data.get("data", {}).get("alerts", [])
        if alerts:
            alert = alerts[0]
            alert["original_log"] = line
            return alert
        return None
    except Exception as e:  # pragma: no cover - optional
        logger.error(f"Wazuh API error: {e}")
        return None


def filter_logs(lines: List[str]) -> List[Dict[str, any]]:
    """回傳觸發告警的日誌行及其告警內容"""

    if not config.WAZUH_ENABLED:
        return [{"line": ln, "alert": {"original_log": ln}} for ln in lines]
    # 逐行檢查並蒐集產生告警的項目
    suspicious: List[Dict[str, any]] = []
    for ln in lines:
        alert = get_alert(ln)
        if alert:
            suspicious.append({"line": ln, "alert": alert})
    return suspicious
