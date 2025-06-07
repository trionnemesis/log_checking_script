from __future__ import annotations
from typing import List

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
    try:
        parts = line.split("\"")
        if len(parts) > 2:
            status_part = parts[2].strip().split()[0]
            return int(status_part)
    except Exception:
        pass
    return 0


def response_time(line: str) -> float:
    if "resp_time:" in line:
        try:
            val_str = line.split("resp_time:")[1].split()[0].split("\"")[0]
            return float(val_str)
        except (ValueError, IndexError):
            pass
    return 0.0


def fast_score(line: str) -> float:
    score = 0.0
    status = parse_status(line)
    if not 200 <= status < 400 and status != 0:
        score += 0.4
    if response_time(line) > 1.0:
        score += 0.2
    lp = line.lower()
    keyword_hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k.lower() in lp)
    if keyword_hits > 0:
        score += min(0.4, keyword_hits * 0.1)
    common_scanner_uas = ["nmap", "sqlmap", "nikto", "curl/", "python-requests"]
    if any(ua.lower() in lp for ua in common_scanner_uas):
        score += 0.2
    return min(score, 1.0)
