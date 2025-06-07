from __future__ import annotations

import logging
from typing import Dict, List, Optional

import requests

from .. import config

logger = logging.getLogger(__name__)

_TOKEN: Optional[str] = None


def _authenticate() -> Optional[str]:
    url = f"{config.WAZUH_API_URL}/security/user/authenticate"
    try:
        resp = requests.get(url, auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD), timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", {}).get("token")
    except Exception as e:  # pragma: no cover - optional
        logger.error(f"Wazuh auth failed: {e}")
        return None


def _ensure_token() -> Optional[str]:
    global _TOKEN
    if _TOKEN is None:
        _TOKEN = _authenticate()
    return _TOKEN


def get_alert(line: str) -> Optional[Dict[str, any]]:
    """Return Wazuh alert JSON if the line triggers one."""
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
    if not config.WAZUH_ENABLED:
        return [{"line": ln, "alert": {"original_log": ln}} for ln in lines]
    suspicious: List[Dict[str, any]] = []
    for ln in lines:
        alert = get_alert(ln)
        if alert:
            suspicious.append({"line": ln, "alert": alert})
    return suspicious
