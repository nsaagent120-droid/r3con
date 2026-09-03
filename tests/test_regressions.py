import unittest
from modules.yara.yara_engine import YARAEngine
from modules.research.research import CVEMatcher
from modules.callgraph.call_graph import CallGraphAnalyzer

class RegressionTests(unittest.TestCase):
    def test_yara_backend_is_explicit(self):
        engine = YARAEngine()
        self.assertIn(engine.capabilities()["backend"], {"yara-python", "builtin-pattern-fallback"})
        self.assertTrue(engine.scan_bytes(b"admin:admin"))

    def test_cve_match_is_heuristic(self):
        result = CVEMatcher().extract_patterns("gets(buf);")
        self.assertEqual(result[0]["evidence_type"], "heuristic-pattern")
        self.assertIn("not proof", result[0]["disclaimer"])

    def test_callgraph_single_api(self):
        code = 'void sink(char *p){ strcpy(dst,p); }\nvoid source(){ char *x=getenv("X"); sink(x); }'
        result = CallGraphAnalyzer().analyze(code, "fixture.c")
        self.assertIn("sink", result["call_graph"].get("source", []))
        self.assertIn("dangerous_paths", result)

if __name__ == "__main__":
    unittest.main()
