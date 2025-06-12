from __future__ import annotations
"""日誌解析與啟發式評分輔助函式"""

from typing import List

# 常見的可疑關鍵字，命中越多得分越高
SUSPICIOUS_KEYWORDS = [
    "/etc/passwd",
    "<script>",
    " OR ",
    "%20OR%20",
    "SELECT ",
    "UNION ",
    "INSERT ",
    "CONCAT("
]


def parse_status(line: str) -> int:
    """從 Apache/Nginx 等格式的日誌行擷取 HTTP 狀態碼"""

    try:
        parts = line.split("\"")
        if len(parts) > 2:
            status_part = parts[2].strip().split()[0]
            return int(status_part)
    except Exception:
        pass
    return 0


def response_time(line: str) -> float:
    """讀取行內的回應時間數值，若無則回傳 0"""

    if "resp_time:" in line:
        try:
            val_str = line.split("resp_time:")[1].split()[0].split("\"")[0]
            return float(val_str)
        except (ValueError, IndexError):
            pass
    return 0.0


def fast_score(line: str) -> float:
    """以啟發式方式替日誌行計算 0 到 1 的分數"""

    score = 0.0
    status = parse_status(line)
    if not 200 <= status < 400 and status != 0:
        # 非正常狀態碼視為可疑
        score += 0.4
    if response_time(line) > 1.0:
        # 回應時間過長亦可能代表異常
        score += 0.2
    lp = line.lower()
    keyword_hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k.lower() in lp)
    if keyword_hits > 0:
        # 命中關鍵字愈多加分愈多，上限 0.4
        score += min(0.4, keyword_hits * 0.1)
    common_scanner_uas = ["nmap", "sqlmap", "nikto", "curl/", "python-requests"]
    if any(ua.lower() in lp for ua in common_scanner_uas):
        # 出現常見掃描器 User-Agent
        score += 0.2
    return min(score, 1.0)
