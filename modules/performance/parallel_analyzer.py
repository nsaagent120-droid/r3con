"""
r3con - Parallel Analyzer
Analyse plusieurs fichiers en parallèle avec multi-threading.
"""

import os
import time
from pathlib import Path
from typing import List, Dict, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


class ParallelAnalyzer:
    """Analyse plusieurs fichiers en parallèle."""

    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or min(os.cpu_count() or 4, 8)
        self.lock        = Lock()
        self.results     = {}
        self.errors      = {}
        self.skipped     = []
        self.progress    = 0
        self.total       = 0

    def _get_analyzers(self):
        """Lazy load analyzers pour éviter les circular imports."""
        from modules.audit.static_analyzer    import StaticAnalyzer
        from modules.advanced.heap_analyzer   import HeapAnalyzer
        from modules.advanced.crypto_checker  import CryptoChecker
        from modules.advanced.kernel_patterns import KernelPatternScanner
        from modules.cache.incremental_cache  import IncrementalCache
        return (StaticAnalyzer(), HeapAnalyzer(),
                CryptoChecker(), KernelPatternScanner(), IncrementalCache())

    @property
    def cache(self):
        from modules.cache.incremental_cache import IncrementalCache
        return IncrementalCache()

    @property
    def static(self):
        from modules.audit.static_analyzer import StaticAnalyzer
        return StaticAnalyzer()

    def analyze_directory(self, directory: str,
                          recursive: bool = True,
                          use_cache: bool = True,
                          extensions: List[str] = None,
                          callback: Optional[Callable] = None) -> Dict:
        """Analyser tous les fichiers d'un répertoire en parallèle."""
        if extensions is None:
            extensions = ['.c','.cpp','.h','.py','.java','.go','.rs','.js','.ts','.php']

        base  = Path(directory)
        files = []
        pattern = '**/*' if recursive else '*'
        for ext in extensions:
            files.extend(base.glob(f"{pattern}{ext}"))
        files = [f for f in files if f.is_file() and f.stat().st_size < 5*1024*1024]

        # Cache check
        cache = self.cache
        if use_cache:
            scan             = cache.scan_directory(directory, 'parallel_audit')
            to_analyze_set   = set(scan['to_analyze'])
            files_to_analyze = [f for f in files if str(f) in to_analyze_set]
            self.skipped     = [str(f) for f in files if str(f) not in to_analyze_set]
        else:
            files_to_analyze = files
            self.skipped     = []

        self.total    = len(files_to_analyze)
        self.progress = 0
        start_time    = time.time()
        all_findings  = []
        stats_per_file = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self._analyze_single, f, use_cache): f
                for f in files_to_analyze
            }
            for future in as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    result = future.result(timeout=60)
                    with self.lock:
                        self.results[str(filepath)] = result
                        self.progress += 1
                        all_findings.extend(result.get('findings', []))
                        stats_per_file[str(filepath)] = result.get('stats', {})
                    if callback:
                        callback(str(filepath), result, self.progress, self.total)
                except Exception as e:
                    with self.lock:
                        self.errors[str(filepath)] = str(e)
                        self.progress += 1

        elapsed = time.time() - start_time
        return self._aggregate(all_findings, stats_per_file, elapsed, directory)

    def analyze_files(self, filepaths: List[str], use_cache: bool = True) -> Dict:
        """Analyser une liste de fichiers en parallèle."""
        self.total    = len(filepaths)
        self.progress = 0
        start_time    = time.time()
        all_findings  = []
        stats_per_file = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self._analyze_single, Path(fp), use_cache): fp
                for fp in filepaths
            }
            for future in as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    result = future.result(timeout=60)
                    with self.lock:
                        self.results[filepath] = result
                        self.progress += 1
                        all_findings.extend(result.get('findings', []))
                        stats_per_file[filepath] = result.get('stats', {})
                except Exception as e:
                    with self.lock:
                        self.errors[filepath] = str(e)
                        self.progress += 1

        elapsed = time.time() - start_time
        return self._aggregate(all_findings, stats_per_file, elapsed, 'files')

    def _analyze_single(self, filepath: Path, use_cache: bool) -> Dict:
        """Analyser un fichier (dans un thread)."""
        path_str = str(filepath)

        # Lazy load pour thread safety
        from modules.audit.static_analyzer    import StaticAnalyzer
        from modules.advanced.heap_analyzer   import HeapAnalyzer
        from modules.advanced.crypto_checker  import CryptoChecker
        from modules.advanced.kernel_patterns import KernelPatternScanner
        from modules.cache.incremental_cache  import IncrementalCache

        cache = IncrementalCache()

        if use_cache:
            cached = cache.get(path_str, 'parallel_audit')
            if cached:
                return {**cached, 'from_cache': True}

        try:
            code  = filepath.read_text(errors='ignore')
            lang  = self._detect_lang(filepath.suffix)

            findings  = []
            findings += StaticAnalyzer().analyze(code, focus='all')
            findings += HeapAnalyzer().analyze(code)
            findings += CryptoChecker().analyze(code)
            if lang in ('c', 'cpp'):
                findings += KernelPatternScanner().analyze(code)

            for f in findings:
                f['file'] = path_str

            result = {
                'file':     path_str,
                'lang':     lang,
                'findings': findings,
                'stats': {
                    'total':    len(findings),
                    'critical': sum(1 for f in findings if f.get('severity') == 'CRITICAL'),
                    'high':     sum(1 for f in findings if f.get('severity') == 'HIGH'),
                    'medium':   sum(1 for f in findings if f.get('severity') in ('MED','MEDIUM')),
                    'low':      sum(1 for f in findings if f.get('severity') == 'LOW'),
                }
            }

            if use_cache:
                cache.set(path_str, result, 'parallel_audit')

            return result

        except Exception as e:
            return {'file': path_str, 'error': str(e), 'findings': [], 'stats': {}}

    def _detect_lang(self, ext: str) -> str:
        return {'.c':'c','.h':'c','.cpp':'cpp','.py':'python',
                '.java':'java','.go':'go','.rs':'rust',
                '.js':'javascript','.ts':'typescript','.php':'php'}.get(ext, 'auto')

    def _aggregate(self, all_findings, stats_per_file, elapsed, directory) -> Dict:
        by_severity = {}
        for f in all_findings:
            s = f.get('severity', 'INFO')
            by_severity[s] = by_severity.get(s, 0) + 1

        top_files = sorted(
            [(fp, s.get('critical',0)*10 + s.get('high',0)*5 + s.get('medium',0))
             for fp, s in stats_per_file.items()],
            key=lambda x: x[1], reverse=True
        )[:10]

        sev_order = {'CRITICAL':0,'HIGH':1,'MED':2,'MEDIUM':2,'LOW':3,'INFO':4}
        all_findings.sort(key=lambda x: sev_order.get(x.get('severity','INFO'), 5))

        return {
            'directory':      directory,
            'files_analyzed': len(self.results),
            'files_skipped':  len(self.skipped),
            'files_errors':   len(self.errors),
            'total_files':    len(self.results) + len(self.skipped),
            'elapsed_seconds': round(elapsed, 2),
            'findings':       all_findings,
            'by_severity':    by_severity,
            'top_vulnerable_files': [fp for fp, _ in top_files],
            'stats': {
                'total_findings': len(all_findings),
                'critical':       by_severity.get('CRITICAL', 0),
                'high':           by_severity.get('HIGH', 0),
                'medium':         by_severity.get('MED', 0) + by_severity.get('MEDIUM', 0),
                'low':            by_severity.get('LOW', 0),
                'files_per_second': round(len(self.results)/elapsed, 1) if elapsed > 0 else 0,
            },
            'errors': self.errors,
        }
