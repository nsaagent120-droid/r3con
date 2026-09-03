"""
r3con - Orchestrateur Principal
Assemble les couches disponibles automatiquement.
L'utilisateur configure ce qu'il veut, r3con s'adapte.

Couche 1 (Foundation)    — TOUJOURS présente
Couche 2 (Analysis Core) — TOUJOURS présente
Couche 3 (Intelligence)  — SI R3CON_EXPERT_MODE=true
Couche 4 (AI)            — SI API cloud ou IA locale disponible
"""

import sys
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime
import uuid

sys.path.insert(0, str(Path(__file__).parent))

from layers.layer1_foundation   import Foundation
from layers.layer2_analysis     import AnalysisCore
from layers.layer3_intelligence import IntelligenceLayer
from layers.layer4_ai           import AIEnhancement
from modules.db.database        import AnalysisDB
from core.report_gen            import ReportGenerator


class R3con:
    """
    Orchestrateur r3con.
    Assemble automatiquement les couches disponibles.
    """

    def __init__(self, verbose: bool = True):
        self.verbose      = verbose
        self.foundation   = Foundation()
        self.analysis     = AnalysisCore()
        self.db           = AnalysisDB()
        self.report_gen   = ReportGenerator()

        # Détecter les couches disponibles
        self.layers       = self.foundation.detect_layers()
        self.tools        = self.foundation.available_tools()

        # Initialiser couches optionnelles
        self.intelligence = IntelligenceLayer() if self.layers[3]["available"] else None
        self.ai           = AIEnhancement()
        if self.ai.available:
            self.layers[4]["available"] = True
            self.layers[4]["reason"]    = f"{self.ai.provider} / {self.ai.model}"
        else:
            self.layers[4]["available"] = False

        if self.verbose:
            self._print_startup()

    def _print_startup(self):
        """Afficher le statut des couches au démarrage."""
        print("\n  r3con v4.3.0 — Layer Status")
        print(f"  {'─'*40}")
        for num, info in self.layers.items():
            icon   = "✓" if info["available"] else "○"
            color  = "\033[32m" if info["available"] else "\033[33m"
            reset  = "\033[0m"
            print(f"  {color}{icon}{reset}  Layer {num}: {info['name']:<20} {info['reason']}")
        print(f"  {'─'*40}\n")

    # ── Source code analysis ──────────────────────────────────

    def analyze_source(self, code: str, lang: str = "auto",
                        filename: str = "unknown",
                        save_to_db: bool = True) -> Dict:
        """
        Analyse complète d'un source code.
        Utilise les couches disponibles automatiquement.
        """
        analysis_id = self._new_id()

        if save_to_db:
            self.db.add_analysis(analysis_id, filename, "source_code",
                                  {"lang": lang, "layers": self._active_layers()})

        # Couche 2 — Toujours
        result = self.analysis.analyze_source(code, lang, filename)

        # Couche 3 — Si activée
        if self.intelligence:
            result = self.intelligence.enrich(result)

        # Couche 4 — Si disponible
        if self.ai.available:
            result = self.ai.enhance(result)

        # Sauvegarder en DB
        if save_to_db:
            for f in result.get("findings", []):
                self.db.add_finding(analysis_id, f)
            for chain in result.get("exploit_chains", []):
                self.db.add_exploit_chain(analysis_id, chain)
            for flow in result.get("taint_flows", []):
                self.db.add_taint_flow(analysis_id, flow)
            self.db.update_analysis(analysis_id, {
                "status":          "completed",
                "total_findings":  len(result.get("findings", [])),
                "critical_count":  sum(1 for f in result.get("findings",[])
                                       if f.get("severity") == "CRITICAL"),
                "high_count":      sum(1 for f in result.get("findings",[])
                                       if f.get("severity") == "HIGH"),
                "exploit_chains":  len(result.get("exploit_chains", [])),
                "completed_at":    datetime.now().isoformat(),
            })

        result["analysis_id"] = analysis_id
        return result

    def analyze_apk(self, apk_path: str, save_to_db: bool = True) -> Dict:
        """Analyse complète d'un APK Android."""
        analysis_id = self._new_id()

        if save_to_db:
            self.db.add_analysis(analysis_id, apk_path, "apk",
                                  {"layers": self._active_layers()})

        result = self.analysis.analyze_apk(apk_path)

        if self.intelligence:
            result = self.intelligence.enrich(result)

        if self.ai.available:
            result = self.ai.enhance(result)

        if save_to_db:
            for f in result.get("findings", []):
                self.db.add_finding(analysis_id, f)
            self.db.update_analysis(analysis_id, {
                "status":         "completed",
                "total_findings": len(result.get("findings", [])),
                "completed_at":   datetime.now().isoformat(),
            })

        result["analysis_id"] = analysis_id
        return result

    def analyze_firmware(self, fw_path: str, save_to_db: bool = True) -> Dict:
        """Analyse complète d'un firmware."""
        analysis_id = self._new_id()

        if save_to_db:
            self.db.add_analysis(analysis_id, fw_path, "firmware",
                                  {"layers": self._active_layers()})

        result = self.analysis.analyze_firmware(fw_path)

        if self.intelligence:
            result = self.intelligence.enrich(result)

        if self.ai.available:
            result = self.ai.enhance(result)

        if save_to_db:
            for f in result.get("findings", []):
                self.db.add_finding(analysis_id, f)
            self.db.update_analysis(analysis_id, {
                "status":         "completed",
                "total_findings": len(result.get("findings", [])),
                "completed_at":   datetime.now().isoformat(),
            })

        result["analysis_id"] = analysis_id
        return result

    def generate_report(self, analysis_id: str,
                         fmt: str = "md") -> Optional[str]:
        """Générer un rapport à partir d'une analyse."""
        findings = self.db.get_findings(analysis_id)
        chains   = self.db.get_exploit_chains(analysis_id)
        analysis = self.db.get_analysis(analysis_id)

        if not analysis:
            return None

        return self.report_gen.generate({
            "type":           analysis["analysis_type"],
            "target":         analysis["target"],
            "findings":       findings,
            "exploit_chains": chains,
            "layers_used":    self._active_layers(),
        })

    # ── Analyse dynamique ─────────────────────────────────────

    def analyze_binary_dynamic(self, binary_path: str,
                                input_data: str = None,
                                find_offset: bool = False,
                                analyze_heap: bool = False,
                                save_to_db: bool = True) -> Dict:
        """
        Analyse dynamique d'un binaire avec GDB + pwndbg.
        Combine analyse statique + dynamique pour un résultat complet.

        Args:
            binary_path:  Chemin du binaire à analyser
            input_data:   Données d'entrée pour tester un crash
            find_offset:  Chercher l'offset BOF automatiquement
            analyze_heap: Analyser l'état de la heap
            save_to_db:   Sauvegarder en DB

        Returns:
            Dict avec tous les résultats statiques + dynamiques
        """
        from modules.dynamic.gdb_analyzer import DynamicAnalyzer
        from modules.disasm.binary_parser   import BinaryParser
        from modules.disasm.capstone_engine import DisasmEngine
        from modules.binary.rop_gadgets     import ROPGadgetFinder
        from modules.yara.yara_engine       import YARAEngine

        analysis_id = self._new_id()
        findings    = []
        dynamic_results = {}

        # ── Analyse statique binaire ───────────────────────────
        bp       = BinaryParser(binary_path)
        info     = bp.parse()
        strings  = bp.get_suspicious_strings()
        imports  = bp.get_imports()
        sec_score = bp.get_security_score()

        # Findings depuis les strings suspectes
        for s in strings:
            findings.append({
                "severity":    s.get("severity", "MEDIUM"),
                "type":        f"Suspicious String ({s.get('category','')})",
                "description": f"Found: {s.get('value','')[:80]}",
                "file":        binary_path,
                "line":        None,
                "recommendation": "Remove hardcoded sensitive strings from binary.",
            })

        # Findings depuis les imports dangereux
        for imp in imports:
            if imp.get("danger_level"):
                findings.append({
                    "severity":    imp["danger_level"],
                    "type":        f"Dangerous Import ({imp['name']})",
                    "description": imp.get("danger_reason", ""),
                    "file":        binary_path,
                    "line":        None,
                    "recommendation": f"Review usage of {imp['name']}().",
                })

        # ── Désassemblage et gadgets ──────────────────────────
        de      = DisasmEngine(binary_path)
        stats   = de.get_statistics()
        vuln_b  = de.scan_for_vulnerabilities()
        findings.extend(vuln_b)

        rop     = ROPGadgetFinder()
        rop_res = rop.find_gadgets(binary_path)
        findings.extend(rop_res.get("findings", []))

        # ── YARA scan ─────────────────────────────────────────
        ye        = YARAEngine()
        yara_res  = ye.scan_file(binary_path)
        for yr in yara_res:
            findings.append({
                "severity":    yr.get("severity", "MEDIUM"),
                "type":        f"YARA: {yr.get('rule','')}",
                "description": yr.get("description", ""),
                "file":        binary_path,
                "line":        None,
                "recommendation": "Investigate YARA pattern match.",
            })

        # ── Analyse dynamique GDB ─────────────────────────────
        da     = DynamicAnalyzer(binary_path)
        d_stat = da.status()

        if d_stat["gdb_available"]:
            # Tester un crash si input fourni
            if input_data:
                crash_res = da.analyze_crash(input_data)
                dynamic_results["crash_analysis"] = crash_res
                if crash_res.get("crashed"):
                    sev = "CRITICAL" if crash_res.get("controlled_ip") else "HIGH"
                    findings.append({
                        "severity":    sev,
                        "type":        "Dynamic: Crash Detected",
                        "description": crash_res.get("exploitability", "Crash confirmed"),
                        "file":        binary_path,
                        "line":        None,
                        "recommendation": "Analyze crash cause. Check with ASAN: -fsanitize=address",
                    })

            # Trouver l'offset BOF
            if find_offset:
                offset_res = da.find_bof_offset()
                dynamic_results["bof_offset"] = offset_res
                if offset_res.get("offset", -1) != -1:
                    findings.append({
                        "severity":    "CRITICAL",
                        "type":        "Dynamic: BOF Offset Found",
                        "description": f"Buffer overflow offset: {offset_res['offset']} bytes",
                        "file":        binary_path,
                        "line":        None,
                        "recommendation": f"Patch at offset {offset_res['offset']}. Enable stack canaries.",
                    })

            # Analyser la heap
            if analyze_heap:
                heap_res = da.analyze_heap()
                dynamic_results["heap_analysis"] = heap_res

        else:
            dynamic_results["gdb_status"] = {
                "available": False,
                "message":   "GDB not installed — dynamic analysis skipped",
                "install":   "sudo apt install gdb && git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh",
            }

        # ── Expert System (Couche 3) ───────────────────────────
        if self.intelligence and findings:
            enriched = self.intelligence.enrich({"findings": findings})
            findings = enriched.get("findings", findings)

        # ── Sauvegarder en DB ─────────────────────────────────
        if save_to_db:
            self.db.add_analysis(analysis_id, binary_path, "dynamic_binary")
            for f in findings:
                self.db.add_finding(analysis_id, f)
            self.db.update_analysis(analysis_id, {
                "status":         "completed",
                "total_findings": len(findings),
                "critical_count": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
                "high_count":     sum(1 for f in findings if f.get("severity") == "HIGH"),
            })

        return {
            "analysis_id":   analysis_id,
            "binary":        binary_path,
            "binary_info":   info,
            "security_score": sec_score,
            "findings":      findings,
            "dynamic":       dynamic_results,
            "rop_analysis":  rop_res,
            "gdb_available": d_stat["gdb_available"],
            "framework":     d_stat["framework"],
            "stats": {
                "total_findings": len(findings),
                "critical":       sum(1 for f in findings if f.get("severity") == "CRITICAL"),
                "high":           sum(1 for f in findings if f.get("severity") == "HIGH"),
                "binary_size":    stats.get("file_size_human", "?"),
                "gadgets_found":  rop_res.get("total_gadgets", 0),
            }
        }

    def dynamic_crash_analysis(self, binary_path: str,
                                input_data: str) -> Dict:
        """Analyser rapidement un crash."""
        from modules.dynamic.gdb_analyzer import DynamicAnalyzer
        da = DynamicAnalyzer(binary_path)
        return da.analyze_crash(input_data)

    def dynamic_find_offset(self, binary_path: str,
                             length: int = 200) -> Dict:
        """Trouver l'offset BOF d'un binaire."""
        from modules.dynamic.gdb_analyzer import DynamicAnalyzer
        da = DynamicAnalyzer(binary_path)
        return da.find_bof_offset(max_length=length)

    def dynamic_generate_exploit(self, binary_path: str,
                                  offset: int,
                                  ret_addr: int,
                                  rop_chain: list = None) -> str:
        """Générer un script exploit pwntools."""
        from modules.dynamic.gdb_analyzer import DynamicAnalyzer
        da = DynamicAnalyzer(binary_path)
        return da.generate_exploit_script(offset, ret_addr, rop_chain)

    def dynamic_gdb_script(self, binary_path: str,
                            mode: str = 'debug',
                            breakpoints: list = None) -> str:
        """Générer un script GDB."""
        from modules.dynamic.gdb_analyzer import DynamicAnalyzer
        da = DynamicAnalyzer(binary_path)
        return da.generate_gdb_script(mode=mode, breakpoints=breakpoints)



    def status(self) -> Dict:
        """Retourner le statut complet de l'installation."""
        return {
            "version":       "4.3.0",
            "layers":        self.layers,
            "tools":         self.tools,
            "ai_provider":   self.ai.provider if self.ai.available else "none",
            "ai_model":      self.ai.model    if self.ai.available else "none",
            "expert_mode":   self.intelligence is not None,
            "db_path":       str(self.db.conn.database) if hasattr(self.db.conn, "database") else "~/.r3con/analysis.db",
        }

    # ── Helpers ───────────────────────────────────────────────

    def _new_id(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]

    def _active_layers(self) -> List[int]:
        return [num for num, info in self.layers.items() if info["available"]]


