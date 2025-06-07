from __future__ import annotations

import logging
from typing import List, Optional

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


def is_suspicious(line: str) -> bool:
    """Query Wazuh logtest API to check if the log line is suspicious."""
    if not config.WAZUH_ENABLED:
        return False
    token = _ensure_token()
    if not token:
        return False
    url = f"{config.WAZUH_API_URL}/experimental/logtest"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.post(url, headers=headers, json={"event": line}, timeout=5)
        if resp.status_code == 401:
            # Token may be expired, retry once
            _TOKEN = _authenticate()
            if _TOKEN:
                headers["Authorization"] = f"Bearer {_TOKEN}"
                resp = requests.post(url, headers=headers, json={"event": line}, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        alerts = data.get("data", {}).get("alerts", [])
        return bool(alerts)
    except Exception as e:  # pragma: no cover - optional
        logger.error(f"Wazuh API error: {e}")
        return False


def filter_logs(lines: List[str]) -> List[str]:
    if not config.WAZUH_ENABLED:
        return lines
    suspicious: List[str] = []
    for ln in lines:
        if is_suspicious(ln):
            suspicious.append(ln)
    return suspicious
