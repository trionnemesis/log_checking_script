import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from lms_log_analyzer.src import log_processor

class DummyDB:
    def __init__(self):
        self.index = object()
        self.added = []
        self.cases = []

    def add(self, vecs, cases):
        self.added.extend(vecs)
        self.cases.extend(cases)

    def search(self, vec, k=3):
        return [], []

    def get_cases(self, ids):
        return []

    def save(self):
        pass

class IntegrationTest(TestCase):
    def test_process_logs_pipeline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.log"
            lines = [
                "1.1.1.1 - - [01/Jan/2023:00:00:00 +0000] \"GET /etc/passwd HTTP/1.1\" 404 0 \"-\" \"nmap\" resp_time:2",
                "normal log"
            ]
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            with patch.object(log_processor, 'filter_logs', return_value=[{'line': lines[0], 'alert': {'original_log': lines[0]}}]), \
                 patch.object(log_processor, 'llm_analyse', return_value=[{'is_attack': True}]) as mock_analyse, \
                 patch.object(log_processor, 'embed', return_value=[0.0, 0.0, 0.0]), \
                 patch.object(log_processor, 'VECTOR_DB', DummyDB()), \
                 patch('lms_log_analyzer.src.log_processor.save_state'), \
                 patch('lms_log_analyzer.src.log_processor.STATE', {}):
                results = log_processor.process_logs([log_path])
                mock_analyse.assert_called_once()
                arg = mock_analyse.call_args.args[0][0]
                self.assertIn('alert', arg)
                self.assertIn('examples', arg)

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]['analysis']['is_attack'])
