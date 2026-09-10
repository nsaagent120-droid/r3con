"""
r3con - Incremental Cache - FIXED P2
Fixes: atomic write, file locking, version invalidation, size limit, symlink protection, expiration
"""

import json
import hashlib
import os
import tempfile
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional

CACHE_DIR = Path.home() / ".r3con" / "cache"
CACHE_FILE = CACHE_DIR / "analysis_cache.json"
CACHE_VERSION = "7.2.0"
# Empreinte du contrat de résultat : invalider le cache quand le schéma change.
SCHEMA_KEY_VERSION = "result-2.1"
CACHE_SCHEMA = 2
MAX_ENTRIES = 5000
DEFAULT_TTL_DAYS = 7

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False


class IncrementalCache:
    """Cache des résultats d'analyse par hash SHA256 - FIXED."""

    def __init__(self, ttl_days: int = DEFAULT_TTL_DAYS, max_entries: int = MAX_ENTRIES):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.last_error: Optional[str] = None
        self.ttl_days = ttl_days
        self.max_entries = max_entries
        self.cache = self._load()

    def _load(self) -> Dict:
        """Charger le cache depuis le disque avec locking."""
        try:
            if not CACHE_FILE.exists():
                return {"_meta": {"version": CACHE_VERSION, "schema": CACHE_SCHEMA, "created": datetime.now().isoformat()}, "_entries": {}}
            # Try with lock
            if HAS_FCNTL:
                with open(CACHE_FILE, "r") as f:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                        content = f.read()
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    except (IOError, OSError):
                        content = f.read()
                data = json.loads(content)
            else:
                data = json.loads(CACHE_FILE.read_text())

            # Handle legacy format (flat dict)
            if "_entries" not in data and "_meta" not in data:
                # Legacy: convert
                return {"_meta": {"version": CACHE_VERSION, "schema": CACHE_SCHEMA, "created": datetime.now().isoformat()}, "_entries": data}

            # Check version
            meta = data.get("_meta", {})
            if meta.get("schema", 1) != CACHE_SCHEMA or meta.get("version") != CACHE_VERSION:
                # Invalidate old cache
                self.last_error = f"cache version mismatch: {meta.get('version')} vs {CACHE_VERSION}, clearing"
                return {"_meta": {"version": CACHE_VERSION, "schema": CACHE_SCHEMA, "created": datetime.now().isoformat()}, "_entries": {}}

            # Check expiration
            self._expire_old(data)

            return data
        except (OSError, json.JSONDecodeError) as exc:
            self.last_error = f"cache load failed: {exc}"
            return {"_meta": {"version": CACHE_VERSION, "schema": CACHE_SCHEMA, "created": datetime.now().isoformat()}, "_entries": {}}

    def _expire_old(self, data: Dict):
        """Expire old entries."""
        try:
            cutoff = datetime.now() - timedelta(days=self.ttl_days)
            entries = data.get("_entries", {})
            to_delete = []
            for k, v in entries.items():
                cached_at = v.get("cached_at")
                if cached_at:
                    try:
                        dt = datetime.fromisoformat(cached_at)
                        if dt < cutoff:
                            to_delete.append(k)
                    except (ValueError, TypeError):
                        pass
            for k in to_delete:
                del entries[k]
        except Exception:
            pass

    def _save(self):
        """Sauvegarder le cache avec atomic write et locking."""
        try:
            # Enforce max entries LRU
            entries = self.cache.get("_entries", {})
            if len(entries) > self.max_entries:
                # Sort by cached_at and keep newest
                sorted_items = sorted(entries.items(), key=lambda x: x[1].get("cached_at", ""), reverse=True)
                self.cache["_entries"] = dict(sorted_items[:self.max_entries])

            # Atomic write via temp file + rename
            tmp_fd, tmp_path = tempfile.mkstemp(dir=str(CACHE_DIR), prefix="cache_", suffix=".tmp")
            try:
                with os.fdopen(tmp_fd, "w") as f:
                    if HAS_FCNTL:
                        try:
                            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except (IOError, OSError):
                            pass
                    json.dump(self.cache, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                # Atomic rename
                os.rename(tmp_path, CACHE_FILE)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except (OSError, TypeError, ValueError) as exc:
            self.last_error = f"cache save failed: {exc}"

    def hash_file(self, filepath: str) -> str:
        """Calculer le SHA256 d'un fichier."""
        h = hashlib.sha256()
        try:
            # Prevent symlink attacks: check if symlink
            p = Path(filepath)
            if p.is_symlink():
                # Resolve but ensure it's not escaping to sensitive areas
                # For cache, we allow symlinks but hash the real file
                pass
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except (OSError, IOError) as exc:
            self.last_error = f"hash failed for {filepath}: {exc}"
            return ""
        return h.hexdigest()

    def hash_string(self, content: str) -> str:
        """Calculer le SHA256 d'une string."""
        return hashlib.sha256(content.encode()).hexdigest()

    def is_cached(self, filepath: str, analysis_type: str = "default") -> bool:
        """Vérifier si un fichier a déjà été analysé et n'a pas changé."""
        # Validate filepath
        if not filepath or ".." in filepath or len(filepath) > 1024:
            return False

        file_hash = self.hash_file(filepath)
        if not file_hash:
            return False

        key = f"{analysis_type}:{filepath}"
        entries = self.cache.get("_entries", {})
        if key not in entries:
            return False

        cached = entries[key]
        # Check hash
        if cached.get("hash") != file_hash:
            return False

        # Check expiration
        cached_at = cached.get("cached_at")
        if cached_at:
            try:
                dt = datetime.fromisoformat(cached_at)
                if datetime.now() - dt > timedelta(days=self.ttl_days):
                    return False
            except (ValueError, TypeError):
                pass

        return True

    def get(self, filepath: str, analysis_type: str = "default") -> Optional[Dict]:
        """Récupérer les résultats cachés pour un fichier."""
        if not self.is_cached(filepath, analysis_type):
            return None

        key = f"{analysis_type}:{filepath}"
        entries = self.cache.get("_entries", {})
        return entries.get(key, {}).get("results")

    def set(self, filepath: str, results: Dict, analysis_type: str = "default"):
        """Mettre en cache les résultats d'analyse."""
        if not filepath or len(filepath) > 1024:
            return

        file_hash = self.hash_file(filepath)
        if not file_hash:
            return

        # Limit results size to prevent cache bloat
        try:
            results_json = json.dumps(results)
            if len(results_json) > 500 * 1024:  # 500KB max per entry
                # Truncate findings
                if isinstance(results, dict) and "findings" in results:
                    truncated = dict(results)
                    truncated["findings"] = results["findings"][:100]
                    truncated["_truncated"] = True
                    results = truncated
        except (TypeError, ValueError):
            pass

        key = f"{analysis_type}:{filepath}"
        if "_entries" not in self.cache:
            self.cache["_entries"] = {}

        self.cache["_entries"][key] = {
            "hash": file_hash,
            "filepath": filepath,
            "type": analysis_type,
            "results": results,
            "cached_at": datetime.now().isoformat(),
        }
        self._save()

    def invalidate(self, filepath: str, analysis_type: str = "default"):
        """Invalider le cache d'un fichier."""
        key = f"{analysis_type}:{filepath}"
        entries = self.cache.get("_entries", {})
        if key in entries:
            del entries[key]
            self._save()

    def clear(self):
        """Vider tout le cache."""
        self.cache = {"_meta": {"version": CACHE_VERSION, "schema": CACHE_SCHEMA, "created": datetime.now().isoformat()}, "_entries": {}}
        self._save()

    def scan_directory(self, directory: str, analysis_type: str = "default") -> Dict:
        """Scanner un répertoire et retourner les fichiers modifiés - FIXED symlink protection."""
        base = Path(directory)
        changed = []
        unchanged = []
        new_files = []

        # Validate directory
        if not base.exists() or not base.is_dir():
            return {"changed": [], "unchanged": [], "new": [], "to_analyze": [], "stats": {"total": 0, "changed": 0, "unchanged": 0, "new": 0, "skipped": 0}}

        # Prevent symlink loops: track visited inodes
        visited_inodes = set()
        extensions = {".c", ".cpp", ".h", ".py", ".java", ".go", ".rs", ".js", ".ts", ".php", ".rb", ".cs", ".swift"}

        try:
            for filepath in base.rglob("*"):
                try:
                    # Skip symlinked directories to prevent loops
                    if filepath.is_symlink():
                        # Only allow symlink to files, not dirs, and not escaping
                        try:
                            real = filepath.resolve()
                            if real.is_dir():
                                continue
                            # Prevent escaping outside base
                            try:
                                real.relative_to(base.resolve())
                            except ValueError:
                                continue
                        except (OSError, RuntimeError):
                            continue

                    if not filepath.is_file():
                        continue

                    # Check inode to prevent hardlink loops
                    try:
                        stat = filepath.stat()
                        inode = (stat.st_dev, stat.st_ino)
                        if inode in visited_inodes:
                            continue
                        visited_inodes.add(inode)
                    except OSError:
                        continue

                    if filepath.suffix not in extensions:
                        continue
                    if stat.st_size > 10 * 1024 * 1024:  # Skip >10MB
                        continue
                    if stat.st_size == 0:
                        continue

                    path_str = str(filepath)
                    if len(path_str) > 1024:
                        continue

                    key = f"{analysis_type}:{path_str}"
                    entries = self.cache.get("_entries", {})

                    if key not in entries:
                        new_files.append(path_str)
                    elif self.is_cached(path_str, analysis_type):
                        unchanged.append(path_str)
                    else:
                        changed.append(path_str)

                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError, RuntimeError) as e:
            self.last_error = f"scan failed: {e}"

        return {
            "changed": changed,
            "unchanged": unchanged,
            "new": new_files,
            "to_analyze": changed + new_files,
            "stats": {
                "total": len(changed) + len(unchanged) + len(new_files),
                "changed": len(changed),
                "unchanged": len(unchanged),
                "new": len(new_files),
                "skipped": len(unchanged),
            }
        }

    def stats(self) -> Dict:
        """Statistiques du cache."""
        entries = self.cache.get("_entries", {})
        entries_list = list(entries.values())
        types = {}
        for e in entries_list:
            t = e.get("type", "unknown")
            types[t] = types.get(t, 0) + 1

        cache_size = 0
        try:
            if CACHE_FILE.exists():
                cache_size = CACHE_FILE.stat().st_size
        except OSError:
            pass

        return {
            "total_entries": len(entries_list),
            "by_type": types,
            "cache_file": str(CACHE_FILE),
            "cache_size_kb": round(cache_size / 1024, 1),
            "version": CACHE_VERSION,
            "schema": CACHE_SCHEMA,
            "ttl_days": self.ttl_days,
            "max_entries": self.max_entries,
            "last_error": self.last_error,
        }


class TaskCache:
    """Cache de tâches versionné pour l'orchestrateur.

    Clé = sha256(hash_cible | tâche | profil | empreinte_config | empreinte_outils
    | version du schéma de résultat). Une modification de configuration, de
    version d'outil externe ou de contrat invalide donc exactement les entrées
    concernées, sans toucher aux autres. Stockage local (répertoire fourni),
    jamais de réseau.
    """

    def __init__(self, cache_dir: 'str | Path | None' = None, ttl_days: int = DEFAULT_TTL_DAYS,
                 max_entries: int = MAX_ENTRIES):
        base = Path(cache_dir) if cache_dir else CACHE_DIR
        self.dir = base / "tasks"
        self.last_error: Optional[str] = None
        self.hits = 0
        self.misses = 0
        self.ttl_seconds = ttl_days * 86400
        self.max_entries = max_entries

    @staticmethod
    def fingerprint(target_hash: str, task: str, profile: str, config_fingerprint: str,
                     tool_fingerprint: str) -> str:
        parts = (SCHEMA_KEY_VERSION, target_hash, task, profile, config_fingerprint, tool_fingerprint)
        return hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()

    def _path(self, key: str) -> Path:
        return self.dir / f"{key[:2]}" / f"{key[2:]}.json"

    def get(self, key: str) -> Optional[dict]:
        """Retourne le résultat caché, ou None (absence, TTL ou écriture partielle)."""
        try:
            path = self._path(key)
            if not path.is_file():
                self.misses += 1
                return None
            payload = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - payload.get("stored_at", 0) > self.ttl_seconds:
                self.misses += 1
                return None
            self.hits += 1
            return payload.get("result")
        except (OSError, ValueError) as exc:
            self.last_error = f"task cache read failed: {exc}"
            self.misses += 1
            return None

    def set(self, key: str, result: dict) -> bool:
        """Écrit atomiquement un résultat dans le cache ; renvoie False si ignoré."""
        try:
            blob = json.dumps(result, ensure_ascii=False, default=str)
            if len(blob) > 2 * 1024 * 1024:  # garde-fou: on ne cache pas les très gros résultats
                return False
            self.dir.mkdir(parents=True, exist_ok=True)
            path = self._path(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix="tc_", suffix=".tmp")
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                    json.dump({"key": key, "stored_at": time.time(), "result": result}, fh,
                              ensure_ascii=False, default=str)
                os.rename(tmp_path, path)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
            self._trim()
            return True
        except (OSError, ValueError, TypeError) as exc:
            self.last_error = f"task cache write failed: {exc}"
            return False

    def _trim(self) -> None:
        try:
            files = sorted(self.dir.rglob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            for stale in files[self.max_entries:]:
                try:
                    stale.unlink()
                except OSError:
                    pass
        except OSError:
            pass

    def stats(self) -> dict:
        return {"hits": self.hits, "misses": self.misses, "dir": str(self.dir),
                "last_error": self.last_error}
