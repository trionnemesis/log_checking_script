import unittest
from lms_log_analyzer.src import log_parser
from lms_log_analyzer.src.utils import LRUCache

class TestLogParser(unittest.TestCase):
    def test_parse_status(self):
        line = '127.0.0.1 - - [01/Jan/2023:00:00:00 +0000] "GET / HTTP/1.1" 404 123'
        self.assertEqual(log_parser.parse_status(line), 404)
        self.assertEqual(log_parser.parse_status('no status'), 0)

    def test_response_time(self):
        self.assertAlmostEqual(log_parser.response_time('resp_time:1.23'), 1.23)
        self.assertEqual(log_parser.response_time('foo'), 0.0)

    def test_fast_score(self):
        line = '1.1.1.1 - - [01/Jan/2023:00:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 0 "-" "nmap" resp_time:2'
        score = log_parser.fast_score(line)
        self.assertAlmostEqual(score, 0.9, places=2)

class TestLRUCache(unittest.TestCase):
    def test_eviction(self):
        cache = LRUCache(2)
        cache.put('a', 1)
        cache.put('b', 2)
        cache.put('c', 3)
        self.assertIsNone(cache.get('a'))
        self.assertEqual(cache.get('b'), 2)
        self.assertEqual(cache.get('c'), 3)

if __name__ == '__main__':
    unittest.main()
