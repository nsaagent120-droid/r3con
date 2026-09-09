"""
r3con - Parallel Analyzer - FIXED P2
Fixes: symlink protection, binary detection, path validation, memory guard, thread-safe cache, timeouts
"""

import os
import time
import threading
from pathlib import Path
from typing import List, Dict, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_TOTAL_FILES = 10000
MAX_DIR_DEPTH = 20


def _is_binary_file(filepath: Path, blocksize: int = 1024) -> bool:
    """Detect if file is binary (contains null bytes or non-text)."""
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(blocksize)
            if b'\x00' in chunk:
                return True
            # Check for high proportion of non-printable
            if chunk:
                non_printable = sum(1 for b in chunk if b < 9 or (b > 13 and b < 32 and b != 27) or b > 126)
                if non_printable / len(chunk) > 0.3:
                    return True
    except (OSError, IOError):
        return True
    return False


class ParallelAnalyzer:
    """Analyse plusieurs fichiers en parallèle - FIXED."""

    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or min(os.cpu_count() or 4, 8)
        self.lock = Lock()
        self.results = {}
        self.errors = {}
        self.skipped = []
        self.progress = 0
        self.total = 0
        self._cache_lock = threading.RLock()

    def _get_analyzers(self):
        """Lazy load analyzers pour éviter les circular imports."""
        from modules.audit.static_analyzer import StaticAnalyzer
        from modules.advanced.heap_analyzer import HeapAnalyzer
        from modules.advanced.crypto_checker import CryptoChecker
        from modules.advanced.kernel_patterns import KernelPatternScanner
        from modules.cache.incremental_cache import IncrementalCache
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

    def _validate_directory(self, directory: str) -> bool:
        """Validate directory path."""
        if not directory or len(directory) > 1024:
            return False
        if ".." in directory:
            return False
        p = Path(directory)
        try:
            # Resolve to prevent traversal
            resolved = p.resolve()
            if not resolved.exists() or not resolved.is_dir():
                return False
            # Prevent scanning sensitive dirs
            sensitive = ["/etc", "/root", "/proc", "/sys", "/dev"]
            for s in sensitive:
                if str(resolved).startswith(s):
                    return False
        except (OSError, RuntimeError):
            return False
        return True

    def _collect_files(self, directory: Path, extensions: List[str], recursive: bool) -> List[Path]:
        """Collect files with symlink protection and depth limit."""
        files = []
        visited_inodes = set()
        base_resolved = directory.resolve()

        def walk(current: Path, depth: int):
            if depth > MAX_DIR_DEPTH:
                return
            if len(files) >= MAX_TOTAL_FILES:
                return
            try:
                for item in current.iterdir():
                    if len(files) >= MAX_TOTAL_FILES:
                        break
                    try:
                        # Skip symlinked dirs to prevent loops
                        if item.is_symlink():
                            try:
                                real = item.resolve()
                                if real.is_dir():
                                    continue
                                # Prevent escaping outside base
                                try:
                                    real.relative_to(base_resolved)
                                except ValueError:
                                    continue
                                # For symlink files, check target
                                if not real.is_file():
                                    continue
                            except (OSError, RuntimeError):
                                continue

                        if item.is_dir() and recursive:
                            # Check inode
                            try:
                                stat = item.stat()
                                inode = (stat.st_dev, stat.st_ino)
                                if inode in visited_inodes:
                                    continue
                                visited_inodes.add(inode)
                            except OSError:
                                continue
                            walk(item, depth + 1)
                        elif item.is_file():
                            if item.suffix not in extensions:
                                continue
                            try:
                                stat = item.stat()
                                inode = (stat.st_dev, stat.st_ino)
                                if inode in visited_inodes:
                                    continue
                                visited_inodes.add(inode)
                                if stat.st_size > MAX_FILE_SIZE or stat.st_size == 0:
                                    continue
                            except OSError:
                                continue

                            # Binary detection for code files (skip binaries for static analysis)
                            if item.suffix in ('.c', '.cpp', '.h', '.py', '.java', '.go', '.rs', '.js', '.ts', '.php'):
                                if _is_binary_file(item):
                                    continue

                            files.append(item)
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                pass

        walk(directory, 0)
        return files

    def analyze_directory(self, directory: str,
                          recursive: bool = True,
                          use_cache: bool = True,
                          extensions: List[str] = None,
                          callback: Optional[Callable] = None) -> Dict:
        """Analyser tous les fichiers d'un répertoire en parallèle - FIXED."""
        if extensions is None:
            extensions = ['.c','.cpp','.h','.py','.java','.go','.rs','.js','.ts','.php']

        if not self._validate_directory(directory):
            return {
                'directory': directory,
                'error': 'invalid_directory',
                'files_analyzed': 0,
                'files_skipped': 0,
                'files_errors': 0,
                'total_files': 0,
                'elapsed_seconds': 0,
                'findings': [],
                'by_severity': {},
                'top_vulnerable_files': [],
                'stats': {'total_findings': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'files_per_second': 0},
                'errors': {},
            }

        base = Path(directory)
        files = self._collect_files(base, extensions, recursive)

        # Cache check
        cache = self.cache
        if use_cache:
            try:
                scan = cache.scan_directory(directory, 'parallel_audit')
                to_analyze_set = set(scan['to_analyze'])
                files_to_analyze = [f for f in files if str(f) in to_analyze_set]
                self.skipped = [str(f) for f in files if str(f) not in to_analyze_set]
            except Exception:
                files_to_analyze = files
                self.skipped = []
        else:
            files_to_analyze = files
            self.skipped = []

        self.total = len(files_to_analyze)
        self.progress = 0
        self.results = {}
        self.errors = {}
        start_time = time.time()
        all_findings = []
        stats_per_file = {}

        # Limit workers based on file count
        workers = min(self.max_workers, max(1, len(files_to_analyze)))

        with ThreadPoolExecutor(max_workers=workers) as executor:
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
                        try:
                            callback(str(filepath), result, self.progress, self.total)
                        except Exception:
                            pass
                except Exception as e:
                    with self.lock:
                        self.errors[str(filepath)] = str(e)[:500]
                        self.progress += 1

        elapsed = time.time() - start_time
        return self._aggregate(all_findings, stats_per_file, elapsed, directory)

    def analyze_files(self, filepaths: List[str], use_cache: bool = True) -> Dict:
        """Analyser une liste de fichiers en parallèle - FIXED."""
        # Validate filepaths
        validated = []
        for fp in filepaths:
            if not fp or len(fp) > 1024 or ".." in fp:
                continue
            p = Path(fp)
            try:
                if not p.exists() or not p.is_file():
                    continue
                if p.stat().st_size > MAX_FILE_SIZE:
                    continue
                if _is_binary_file(p) and p.suffix in ('.c','.cpp','.h','.py','.java','.go','.rs','.js','.ts','.php'):
                    continue
            except (OSError, PermissionError):
                continue
            validated.append(fp)
            if len(validated) >= MAX_TOTAL_FILES:
                break

        self.total = len(validated)
        self.progress = 0
        self.results = {}
        self.errors = {}
        start_time = time.time()
        all_findings = []
        stats_per_file = {}

        workers = min(self.max_workers, max(1, len(validated)))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_file = {
                executor.submit(self._analyze_single, Path(fp), use_cache): fp
                for fp in validated
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
                        self.errors[filepath] = str(e)[:500]
                        self.progress += 1

        elapsed = time.time() - start_time
        return self._aggregate(all_findings, stats_per_file, elapsed, 'files')

    def _analyze_single(self, filepath: Path, use_cache: bool) -> Dict:
        """Analyser un fichier (dans un thread) - FIXED thread-safe."""
        path_str = str(filepath)

        if not path_str or len(path_str) > 1024:
            return {'file': path_str, 'error': 'invalid_path', 'findings': [], 'stats': {}}

        # Lazy load pour thread safety
        from modules.audit.static_analyzer import StaticAnalyzer
        from modules.advanced.heap_analyzer import HeapAnalyzer
        from modules.advanced.crypto_checker import CryptoChecker
        from modules.advanced.kernel_patterns import KernelPatternScanner
        from modules.cache.incremental_cache import IncrementalCache

        # Thread-safe cache access
        with self._cache_lock:
            cache = IncrementalCache()
            if use_cache:
                try:
                    cached = cache.get(path_str, 'parallel_audit')
                    if cached:
                        return {**cached, 'from_cache': True}
                except Exception:
                    pass

        try:
            # Double-check file still exists and size
            try:
                if not filepath.exists() or filepath.stat().st_size > MAX_FILE_SIZE:
                    return {'file': path_str, 'error': 'file_too_large_or_missing', 'findings': [], 'stats': {}}
            except OSError:
                return {'file': path_str, 'error': 'stat_failed', 'findings': [], 'stats': {}}

            code = filepath.read_text(errors='ignore')
            # Limit code size in memory
            if len(code) > 2 * 1024 * 1024:  # 2MB text limit
                code = code[:2*1024*1024]

            lang = self._detect_lang(filepath.suffix)

            findings = []
            try:
                findings += StaticAnalyzer().analyze(code, focus='all')
            except Exception:
                pass
            try:
                findings += HeapAnalyzer().analyze(code)
            except Exception:
                pass
            try:
                findings += CryptoChecker().analyze(code)
            except Exception:
                pass
            if lang in ('c', 'cpp'):
                try:
                    findings += KernelPatternScanner().analyze(code)
                except Exception:
                    pass

            for f in findings:
                f['file'] = path_str

            result = {
                'file': path_str,
                'lang': lang,
                'findings': findings,
                'stats': {
                    'total': len(findings),
                    'critical': sum(1 for f in findings if f.get('severity') == 'CRITICAL'),
                    'high': sum(1 for f in findings if f.get('severity') == 'HIGH'),
                    'medium': sum(1 for f in findings if f.get('severity') in ('MED','MEDIUM')),
                    'low': sum(1 for f in findings if f.get('severity') == 'LOW'),
                }
            }

            if use_cache:
                with self._cache_lock:
                    try:
                        cache.set(path_str, result, 'parallel_audit')
                    except Exception:
                        pass

            return result

        except Exception as e:
            return {'file': path_str, 'error': str(e)[:500], 'findings': [], 'stats': {}}

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
        try:
            all_findings.sort(key=lambda x: sev_order.get(x.get('severity','INFO'), 5))
        except Exception:
            pass

        return {
            'directory': directory,
            'files_analyzed': len(self.results),
            'files_skipped': len(self.skipped),
            'files_errors': len(self.errors),
            'total_files': len(self.results) + len(self.skipped),
            'elapsed_seconds': round(elapsed, 2),
            'findings': all_findings[:1000],  # Limit to 1000 to prevent OOM
            'by_severity': by_severity,
            'top_vulnerable_files': [fp for fp, _ in top_files],
            'stats': {
                'total_findings': len(all_findings),
                'critical': by_severity.get('CRITICAL', 0),
                'high': by_severity.get('HIGH', 0),
                'medium': by_severity.get('MED', 0) + by_severity.get('MEDIUM', 0),
                'low': by_severity.get('LOW', 0),
                'files_per_second': round(len(self.results)/elapsed, 1) if elapsed > 0 else 0,
            },
            'errors': self.errors,
        }
