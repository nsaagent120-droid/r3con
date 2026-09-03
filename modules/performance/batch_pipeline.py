"""
r3con - Batch Pipeline
Pipeline automatique pour analyser plusieurs cibles en séquence.
Orchestre toutes les couches : analyse → enrichissement → rapport.
"""

import os
import json
import time
from pathlib import Path
from typing import List, Dict
from datetime import datetime


class BatchPipeline:
    """
    Pipeline automatique d'analyse.
    Orchestre : discovery → analysis → enrichment → reporting.
    """

    def __init__(self, expert_mode: bool = True,
                 use_cache: bool = True,
                 max_workers: int = 4):
        os.environ['R3CON_EXPERT_MODE'] = 'true' if expert_mode else 'false'

        from r3con_core import R3con
        from modules.performance.parallel_analyzer import ParallelAnalyzer
        from modules.reporting.sarif_export import SARIFExporter
        from modules.reporting.bugbounty_report import BugBountyReportGenerator
        from modules.deps.dependency_scanner import DependencyScanner
        from modules.yara.yara_engine import YARAEngine
        from modules.cache.incremental_cache import IncrementalCache

        self.r3con       = R3con(verbose=False)
        self.parallel    = ParallelAnalyzer(max_workers=max_workers)
        self.sarif       = SARIFExporter()
        self.bounty      = BugBountyReportGenerator()
        self.dep_scanner = DependencyScanner()
        self.yara        = YARAEngine()
        self.cache       = IncrementalCache()
        self.use_cache   = use_cache

        self.output_dir = Path.home() / '.r3con' / 'batch'
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self, target: str,
            scan_deps: bool = True,
            scan_yara: bool = True,
            generate_sarif: bool = True,
            generate_bounty: bool = True,
            bounty_platform: str = 'generic') -> Dict:
        """
        Lancer le pipeline complet sur une cible.

        Args:
            target:           Fichier ou répertoire à analyser
            scan_deps:        Scanner les dépendances
            scan_yara:        Scanner avec YARA
            generate_sarif:   Générer un fichier SARIF
            generate_bounty:  Générer des rapports bug bounty
            bounty_platform:  Plateforme (hackerone/bugcrowd/generic)

        Returns:
            Dict complet avec tous les résultats
        """
        start    = time.time()
        target_p = Path(target)
        ts       = datetime.now().strftime('%Y%m%d_%H%M%S')

        print(f"\n\033[36m{'='*56}\033[0m")
        print(f"  r3con Batch Pipeline — {target_p.name}")
        print(f"\033[36m{'='*56}\033[0m\n")

        pipeline_result = {
            'target':    target,
            'timestamp': ts,
            'stages':    {},
            'outputs':   {},
            'summary':   {},
        }

        # ── Stage 1 : Source Analysis ──────────────────────────
        print("  \033[36m[1/5]\033[0m Source analysis...")
        stage1 = self._stage_source(target_p)
        pipeline_result['stages']['source_analysis'] = stage1
        all_findings = stage1.get('findings', [])
        print(f"        → {len(all_findings)} findings")

        # ── Stage 2 : Dependency Scan ──────────────────────────
        if scan_deps:
            print("  \033[36m[2/5]\033[0m Dependency scan...")
            stage2 = self._stage_deps(target_p)
            pipeline_result['stages']['dependency_scan'] = stage2
            dep_findings = stage2.get('findings', [])
            all_findings += dep_findings
            print(f"        → {len(dep_findings)} vulnerable dependencies")
        else:
            print("  \033[33m[2/5]\033[0m Dependency scan skipped")

        # ── Stage 3 : YARA Scan ────────────────────────────────
        if scan_yara:
            print("  \033[36m[3/5]\033[0m YARA scan...")
            stage3 = self._stage_yara(target_p)
            pipeline_result['stages']['yara_scan'] = stage3
            yara_findings = stage3.get('findings', [])
            all_findings += yara_findings
            print(f"        → {len(yara_findings)} YARA matches")
        else:
            print("  \033[33m[3/5]\033[0m YARA scan skipped")

        # ── Stage 4 : SARIF Export ─────────────────────────────
        if generate_sarif:
            print("  \033[36m[4/5]\033[0m SARIF export...")
            sarif_path = str(self.output_dir / f"r3con_{ts}.sarif")
            self.sarif.export(all_findings, target=target, output_path=sarif_path)
            pipeline_result['outputs']['sarif'] = sarif_path
            print(f"        → {sarif_path}")
        else:
            print("  \033[33m[4/5]\033[0m SARIF export skipped")

        # ── Stage 5 : Bug Bounty Reports ──────────────────────
        if generate_bounty:
            print("  \033[36m[5/5]\033[0m Bug bounty reports...")
            bounty_path = str(self.output_dir / f"bounty_{bounty_platform}_{ts}.md")
            critical_high = [f for f in all_findings
                             if f.get('severity') in ('CRITICAL', 'HIGH')]
            if critical_high:
                self.bounty.generate(
                    critical_high, target=target,
                    program=bounty_platform,
                    output_path=bounty_path
                )
                pipeline_result['outputs']['bounty_report'] = bounty_path
                print(f"        → {bounty_path} ({len(critical_high)} findings)")
            else:
                print("        → No CRITICAL/HIGH findings for bounty report")
        else:
            print("  \033[33m[5/5]\033[0m Bug bounty reports skipped")

        # ── Summary ────────────────────────────────────────────
        elapsed  = round(time.time() - start, 2)
        by_sev   = {}
        for f in all_findings:
            s = f.get('severity', 'INFO')
            by_sev[s] = by_sev.get(s, 0) + 1

        pipeline_result['summary'] = {
            'total_findings':   len(all_findings),
            'by_severity':      by_sev,
            'critical':         by_sev.get('CRITICAL', 0),
            'high':             by_sev.get('HIGH', 0),
            'elapsed_seconds':  elapsed,
            'outputs_generated': len(pipeline_result['outputs']),
        }
        pipeline_result['all_findings'] = all_findings

        # Sauvegarder le résumé JSON
        summary_path = str(self.output_dir / f"pipeline_{ts}.json")
        with open(summary_path, 'w') as f:
            json.dump({k: v for k, v in pipeline_result.items()
                       if k != 'all_findings'}, f, indent=2)
        pipeline_result['outputs']['summary_json'] = summary_path

        self._print_summary(pipeline_result['summary'])

        return pipeline_result

    def run_batch(self, targets: List[str], **kwargs) -> List[Dict]:
        """
        Lancer le pipeline sur plusieurs cibles.

        Args:
            targets: Liste de fichiers/répertoires à analyser
            **kwargs: Options passées à run()

        Returns:
            Liste des résultats pour chaque cible
        """
        results = []
        total   = len(targets)

        print(f"\n\033[36m r3con Batch Mode — {total} targets\033[0m\n")

        for i, target in enumerate(targets, 1):
            print(f"\033[36m[{i}/{total}]\033[0m {target}")
            try:
                result = self.run(target, **kwargs)
                results.append(result)
            except Exception as e:
                results.append({'target': target, 'error': str(e)})

        # Rapport global
        self._print_batch_summary(results)
        return results

    def _stage_source(self, target_p: Path) -> Dict:
        """Stage 1 : Analyse du code source."""
        if target_p.is_file():
            try:
                code   = target_p.read_text(errors='ignore')
                result = self.r3con.analyze_source(
                    code, filename=str(target_p), save_to_db=True)
                return result
            except Exception as e:
                return {'error': str(e), 'findings': []}

        elif target_p.is_dir():
            return self.parallel.analyze_directory(
                str(target_p), use_cache=self.use_cache)

        return {'findings': []}

    def _stage_deps(self, target_p: Path) -> Dict:
        """Stage 2 : Scan des dépendances."""
        try:
            if target_p.is_dir():
                return self.dep_scanner.scan_directory(str(target_p))
            # Chercher les fichiers de deps dans le parent
            parent = target_p.parent
            return self.dep_scanner.scan_directory(str(parent))
        except Exception as e:
            return {'error': str(e), 'findings': []}

    def _stage_yara(self, target_p: Path) -> Dict:
        """Stage 3 : Scan YARA."""
        try:
            if target_p.is_file():
                findings = self.yara.scan_file(str(target_p))
                return {'findings': findings}
            elif target_p.is_dir():
                return self.yara.scan_directory(str(target_p))
        except Exception as e:
            return {'error': str(e), 'findings': []}
        return {'findings': []}

    def _print_summary(self, summary: Dict):
        """Afficher le résumé du pipeline."""
        print(f"\n  \033[36m{'─'*44}\033[0m")
        print("  \033[1mPipeline Summary\033[0m")
        print(f"  \033[36m{'─'*44}\033[0m")
        print(f"  Total findings:  {summary['total_findings']}")
        print(f"  Critical:        \033[31m{summary['critical']}\033[0m")
        print(f"  High:            \033[33m{summary['high']}\033[0m")
        print(f"  Elapsed:         {summary['elapsed_seconds']}s")
        print(f"  Outputs:         {summary['outputs_generated']} files")
        print(f"  \033[36m{'─'*44}\033[0m\n")

    def _print_batch_summary(self, results: List[Dict]):
        """Afficher le résumé du mode batch."""
        total_findings = sum(r.get('summary', {}).get('total_findings', 0)
                             for r in results)
        total_critical = sum(r.get('summary', {}).get('critical', 0)
                             for r in results)
        errors         = sum(1 for r in results if 'error' in r)

        print(f"\n\033[36m{'='*56}\033[0m")
        print(f"  \033[1mBatch Complete — {len(results)} targets\033[0m")
        print(f"  Total findings: {total_findings}")
        print(f"  Critical:       \033[31m{total_critical}\033[0m")
        print(f"  Errors:         {errors}")
        print(f"\033[36m{'='*56}\033[0m\n")
