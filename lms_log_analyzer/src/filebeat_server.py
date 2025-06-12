from __future__ import annotations
"""Filebeat HTTP 收集服務

此模組提供簡易的 HTTP 伺服器，
用於接收 Filebeat 送來的日誌 JSON 並即時分析。
"""

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List

from .. import config
from .log_processor import analyse_lines
from .utils import save_state, STATE
from .vector_db import VECTOR_DB

logger = logging.getLogger(__name__)


class FilebeatHandler(BaseHTTPRequestHandler):
    """處理來自 Filebeat 的 POST 請求"""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        lines: List[str] = []
        if isinstance(data, dict):
            msg = data.get("message")
            if msg:
                lines.append(str(msg))
        elif isinstance(data, list):
            for entry in data:
                msg = entry.get("message")
                if msg:
                    lines.append(str(msg))

        results = analyse_lines(lines)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(results, ensure_ascii=False).encode("utf-8"))


def run_server() -> None:
    """啟動 HTTP 伺服器"""

    addr = (config.FILEBEAT_HOST, config.FILEBEAT_PORT)
    httpd = HTTPServer(addr, FilebeatHandler)
    logger.info(f"Filebeat server listening on {addr[0]}:{addr[1]}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        save_state(STATE)
        VECTOR_DB.save()


if __name__ == "__main__":
    run_server()
