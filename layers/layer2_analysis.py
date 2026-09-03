"""
r3con - Couche 2 : Analysis Core
Moteur d'analyse principal — 100% offline, sans aucune IA.
L'outil est déjà complet et puissant avec cette seule couche.
"""

import sys
from pathlib import Path
from typing import List, Dict

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.audit.static_analyzer     import StaticAnalyzer
from modules.advanced.heap_analyzer    import HeapAnalyzer
from modules.advanced.crypto_checker   import CryptoChecker
from modules.advanced.kernel_patterns  import KernelPatternScanner
from modules.research.research         import CVEMatcher
from modules.apk.apk_analyzer          import APKAnalyzer
from modules.firmware.firmware_analyzer import FirmwareAnalyzer
from modules.analysis.taint_analysis   import TaintAnalyzer, ExploitChainBuilder
from modules.analysis.hypothesis_engine import AdvancedHypothesisEngine


class AnalysisCore:
    """
    Couche 2 — L'outil est COMPLET et PUISSANT ici.
    Tout fonctionne sans IA, sans connexion, sans rien.
    """

    def __init__(self):
        self.static_analyzer    = StaticAnalyzer()
        self.heap_analyzer      = HeapAnalyzer()
        self.crypto_checker     = CryptoChecker()
        self.kernel_scanner     = KernelPatternScanner()
        self.cve_matcher        = CVEMatcher()
        self.hypothesis_engine  = AdvancedHypothesisEngine()
        self.taint_analyzer     = TaintAnalyzer()
        self.chain_builder      = ExploitChainBuilder()

    # ── Source code analysis ──────────────────────────────────

    def analyze_source(self, code: str, lang: str = "auto",
                        filename: str = "unknown") -> Dict:
        """Analyse complète d'un fichier source — 100% offline."""
        findings = []

        # Static patterns
        findings += self.static_analyzer.analyze(code, focus="all")

        # Heap patterns
        findings += self.heap_analyzer.analyze(code)

        # Crypto patterns
        findings += self.crypto_checker.analyze(code)

        # Kernel patterns (if C/C++)
        if lang in ("c", "cpp", "auto"):
            findings += self.kernel_scanner.analyze(code)

        # Add file reference
        for f in findings:
            if not f.get("file"):
                f["file"] = filename

        # Taint analysis
        taint_flows = self.taint_analyzer.analyze(code, filename=filename)

        # Exploit chains
        chains = self.chain_builder.build_chains(taint_flows)

        # Hypothesis engine
        hypotheses = self.hypothesis_engine.analyze_code(code)

        # CVE matching
        cve_matches = self.cve_matcher.extract_patterns(code)

        return {
            "findings":      sorted(findings,
                                    key=lambda x: self._sev_order(x["severity"])),
            "taint_flows":   taint_flows,
            "exploit_chains": chains,
            "hypotheses":    hypotheses,
            "cve_matches":   cve_matches,
            "stats":         self._compute_stats(findings, chains, taint_flows),
        }

    # ── APK analysis ─────────────────────────────────────────

    def analyze_apk(self, apk_path: str) -> Dict:
        """Analyse complète APK — 100% offline."""
        analyzer = APKAnalyzer(apk_path)
        if not analyzer.load():
            return {"error": analyzer.last_error or "Could not load APK"}

        findings  = []
        findings += analyzer.analyze_manifest()
        findings += analyzer.analyze_smali()
        findings += analyzer.analyze_strings()
        components = analyzer.get_components()

        return {
            "findings":   sorted(findings,
                                 key=lambda x: self._sev_order(x["severity"])),
            "components": components,
            "summary":    analyzer.get_file_summary(),
            "stats":      self._compute_stats(findings),
        }

    # ── Firmware analysis ────────────────────────────────────

    def analyze_firmware(self, fw_path: str) -> Dict:
        """Analyse complète firmware — 100% offline."""
        fw = FirmwareAnalyzer(fw_path)
        fw.load()

        identification = fw.identify()
        strings        = fw.extract_strings()
        entropy        = fw.high_entropy_regions()
        findings       = fw.scan_vulns()
        paths          = fw.find_interesting_paths()

        return {
            "identification": identification,
            "findings":       sorted(findings,
                                     key=lambda x: self._sev_order(x["severity"])),
            "strings":        strings,
            "entropy_regions": entropy,
            "interesting_paths": paths,
            "stats":          self._compute_stats(findings),
        }

    # ── Helpers ───────────────────────────────────────────────

    def _sev_order(self, sev: str) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MED": 2,
                "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(sev, 5)

    def _compute_stats(self, findings: List, chains: List = None,
                       flows: List = None) -> Dict:
        counts = {}
        for f in findings:
            s = f.get("severity", "INFO")
            counts[s] = counts.get(s, 0) + 1
        return {
            "total":          len(findings),
            "by_severity":    counts,
            "exploit_chains": len(chains or []),
            "taint_flows":    len(flows or []),
            "risk_score":     self._risk_score(counts),
        }

    def _risk_score(self, counts: Dict) -> int:
        """Score de risque global 0-100."""
        score = (counts.get("CRITICAL", 0) * 40 +
                 counts.get("HIGH",     0) * 20 +
                 counts.get("MED",      0) * 10 +
                 counts.get("MEDIUM",   0) * 10 +
                 counts.get("LOW",      0) *  5)
        return min(score, 100)
