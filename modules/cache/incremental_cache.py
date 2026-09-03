"""
r3con - Incremental Cache
Cache les résultats d'analyse par hash de fichier.
Ne réanalyse que les fichiers modifiés depuis la dernière fois.
Gain de temps énorme sur les gros projets.
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional


CACHE_DIR  = Path.home() / ".r3con" / "cache"
CACHE_FILE = CACHE_DIR / "analysis_cache.json"


class IncrementalCache:
    """Cache des résultats d'analyse par hash SHA256."""

    def __init__(self):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.last_error: Optional[str] = None
        self.cache = self._load()

    def _load(self) -> Dict:
        """Charger le cache depuis le disque."""
        try:
            if CACHE_FILE.exists():
                return json.loads(CACHE_FILE.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            self.last_error = f"cache load failed: {exc}"
        return {}

    def _save(self):
        """Sauvegarder le cache sur le disque."""
        try:
            CACHE_FILE.write_text(json.dumps(self.cache, indent=2))
        except (OSError, TypeError, ValueError) as exc:
            self.last_error = f"cache save failed: {exc}"

    def hash_file(self, filepath: str) -> str:
        """Calculer le SHA256 d'un fichier."""
        h = hashlib.sha256()
        try:
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
        """
        Vérifier si un fichier a déjà été analysé et n'a pas changé.

        Args:
            filepath: Chemin du fichier
            analysis_type: Type d'analyse (audit, apk, firmware...)

        Returns:
            True si le cache est valide
        """
        file_hash = self.hash_file(filepath)
        if not file_hash:
            return False

        key = f"{analysis_type}:{filepath}"
        if key not in self.cache:
            return False

        cached = self.cache[key]
        return cached.get("hash") == file_hash

    def get(self, filepath: str, analysis_type: str = "default") -> Optional[Dict]:
        """
        Récupérer les résultats cachés pour un fichier.

        Returns:
            Résultats cachés ou None si pas de cache valide
        """
        if not self.is_cached(filepath, analysis_type):
            return None

        key = f"{analysis_type}:{filepath}"
        return self.cache[key].get("results")

    def set(self, filepath: str, results: Dict, analysis_type: str = "default"):
        """
        Mettre en cache les résultats d'analyse.

        Args:
            filepath: Chemin du fichier analysé
            results: Résultats de l'analyse
            analysis_type: Type d'analyse
        """
        file_hash = self.hash_file(filepath)
        if not file_hash:
            return

        key = f"{analysis_type}:{filepath}"
        self.cache[key] = {
            "hash":     file_hash,
            "filepath": filepath,
            "type":     analysis_type,
            "results":  results,
            "cached_at": datetime.now().isoformat(),
        }
        self._save()

    def invalidate(self, filepath: str, analysis_type: str = "default"):
        """Invalider le cache d'un fichier."""
        key = f"{analysis_type}:{filepath}"
        if key in self.cache:
            del self.cache[key]
            self._save()

    def clear(self):
        """Vider tout le cache."""
        self.cache = {}
        self._save()

    def scan_directory(self, directory: str,
                       analysis_type: str = "default") -> Dict:
        """
        Scanner un répertoire et retourner les fichiers modifiés.

        Returns:
            Dict avec fichiers modifiés, non changés, et nouveaux
        """
        base    = Path(directory)
        changed = []
        unchanged = []
        new_files = []

        extensions = {".c", ".cpp", ".h", ".py", ".java", ".go", ".rs",
                      ".js", ".ts", ".php", ".rb", ".cs", ".swift"}

        for filepath in base.rglob("*"):
            if not filepath.is_file():
                continue
            if filepath.suffix not in extensions:
                continue
            if filepath.stat().st_size > 10 * 1024 * 1024:  # Skip >10MB
                continue

            path_str = str(filepath)
            key      = f"{analysis_type}:{path_str}"

            if key not in self.cache:
                new_files.append(path_str)
            elif self.is_cached(path_str, analysis_type):
                unchanged.append(path_str)
            else:
                changed.append(path_str)

        return {
            "changed":   changed,
            "unchanged": unchanged,
            "new":       new_files,
            "to_analyze": changed + new_files,
            "stats": {
                "total":     len(changed) + len(unchanged) + len(new_files),
                "changed":   len(changed),
                "unchanged": len(unchanged),
                "new":       len(new_files),
                "skipped":   len(unchanged),
            }
        }

    def stats(self) -> Dict:
        """Statistiques du cache."""
        entries    = list(self.cache.values())
        types      = {}
        for e in entries:
            t = e.get("type", "unknown")
            types[t] = types.get(t, 0) + 1

        return {
            "total_entries":  len(entries),
            "by_type":        types,
            "cache_file":     str(CACHE_FILE),
            "cache_size_kb":  round(CACHE_FILE.stat().st_size / 1024, 1)
                              if CACHE_FILE.exists() else 0,
        }
