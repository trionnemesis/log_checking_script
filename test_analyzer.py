import importlib
import os
import sys
from pathlib import Path

import pytest


def load_analyzer(tmp_path: Path):
    os.environ['LMS_HOME'] = str(tmp_path)
    if 'lms_log_analyzer_v2' in sys.modules:
        return importlib.reload(sys.modules['lms_log_analyzer_v2'])
    return importlib.import_module('lms_log_analyzer_v2')


def test_parse_status_valid(tmp_path):
    analyzer = load_analyzer(tmp_path)
    line = '127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET /index.html HTTP/1.1" 200 123'
    assert analyzer.parse_status(line) == 200


def test_parse_status_invalid(tmp_path):
    analyzer = load_analyzer(tmp_path)
    assert analyzer.parse_status('bad line') == 0


def test_response_time(tmp_path):
    analyzer = load_analyzer(tmp_path)
    line = 'resp_time:0.42'
    assert analyzer.response_time(line) == 0.42


def test_fast_score_positive(tmp_path):
    analyzer = load_analyzer(tmp_path)
    line = '127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 0 "-" "curl/" resp_time:0.2'
    assert analyzer.fast_score(line) > 0.0


def test_process_logs_basic(tmp_path):
    analyzer = load_analyzer(tmp_path)
    log_file = tmp_path / 'sample.log'
    log_file.write_text('127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "curl/" resp_time:0.2\n')
    results = analyzer.process_logs([log_file])
    assert isinstance(results, list)
    assert results and 'fast_score' in results[0]
