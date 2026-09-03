"""
r3con - Couche 1 : Foundation
Toujours présente. Zero dépendances externes.
Base de tout le projet.
"""

import os
import hashlib
import platform
import subprocess
from pathlib import Path
from datetime import datetime


VERSION = "5.0.0"
R3CON_HOME = Path.home() / ".r3con"


class Foundation:
    """Base fondamentale de r3con — toujours disponible."""

    def __init__(self):
        R3CON_HOME.mkdir(parents=True, exist_ok=True)
        (R3CON_HOME / "reports").mkdir(exist_ok=True)
        (R3CON_HOME / "sessions").mkdir(exist_ok=True)

    # ── Détection de ce qui est disponible ────────────────────

    def detect_layers(self) -> dict:
        """Détecter automatiquement les couches disponibles."""
        layers = {
            1: {"name": "Foundation",    "available": True,  "reason": "Always on"},
            2: {"name": "Analysis Core", "available": True,  "reason": "Built-in patterns"},
            3: {"name": "Intelligence",  "available": False, "reason": ""},
            4: {"name": "AI Enhancement","available": False, "reason": ""},
        }

        # Couche 3 : Expert System
        if os.environ.get("R3CON_EXPERT_MODE", "").lower() in ("1","true","yes"):
            layers[3]["available"] = True
            layers[3]["reason"]    = "R3CON_EXPERT_MODE=true"
        else:
            layers[3]["reason"] = "Set R3CON_EXPERT_MODE=true to enable"

        # Couche 4 : IA disponible ?
        ai_provider = self._detect_ai()
        if ai_provider:
            layers[4]["available"] = True
            layers[4]["reason"]    = f"Provider: {ai_provider}"
        else:
            layers[4]["reason"] = "No AI configured (optional)"

        return layers

    def _detect_ai(self) -> str:
        """Détecter quel provider IA est disponible."""
        # Cloud APIs
        if os.environ.get("ANTHROPIC_API_KEY"):  return "Anthropic Claude"
        if os.environ.get("DEEPSEEK_API_KEY"):   return "DeepSeek"
        if os.environ.get("GEMINI_API_KEY"):      return "Google Gemini"
        if os.environ.get("GROQ_API_KEY"):        return "Groq"
        if os.environ.get("TOGETHER_API_KEY"):    return "Nemotron (Together AI)"
        if os.environ.get("LOCAL_AI_URL"):        return "Local AI (custom URL)"

        # Local AI auto-detect
        for url in ["http://localhost:11434", "http://localhost:1234",
                    "http://localhost:8000", "http://localhost:8080"]:
            try:
                import urllib.request
                urllib.request.urlopen(url, timeout=1)
                return f"Local AI at {url}"
            except Exception:
                pass

        return ""

    # ── Utilitaires ───────────────────────────────────────────

    def hash_file(self, path: str) -> dict:
        """Hash d'un fichier (MD5, SHA256)."""
        # MD5 est conservé uniquement pour compatibilité d’identification, jamais pour la sécurité.
        h_md5    = hashlib.md5(usedforsecurity=False)
        h_sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h_md5.update(chunk)
                h_sha256.update(chunk)
        return {
            "md5":    h_md5.hexdigest(),
            "sha256": h_sha256.hexdigest(),
            "size":   os.path.getsize(path),
        }

    def file_info(self, path: str) -> dict:
        """Informations basiques sur un fichier."""
        p = Path(path)
        return {
            "name":      p.name,
            "extension": p.suffix,
            "size":      p.stat().st_size,
            "modified":  datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
            "path":      str(p.resolve()),
            "exists":    p.exists(),
        }

    def tool_available(self, tool: str) -> bool:
        """Vérifier si un outil externe est disponible."""
        try:
            subprocess.run([tool, "--version"],
                           capture_output=True, timeout=3)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def available_tools(self) -> dict:
        """Lister les outils externes disponibles."""
        tools = {
            "capstone":   self._python_available("capstone"),
            "lief":       self._python_available("lief"),
            "binwalk":    self.tool_available("binwalk"),
            "objdump":    self.tool_available("objdump"),
            "strings":    self.tool_available("strings"),
            "file":       self.tool_available("file"),
            "nm":         self.tool_available("nm"),
            "readelf":    self.tool_available("readelf"),
            "jadx":       self.tool_available("jadx"),
            "apktool":    self.tool_available("apktool"),
            "frida":      self._python_available("frida"),
            "unicorn":    self._python_available("unicorn"),
            "flask":      self._python_available("flask"),
            "openai":     self._python_available("openai"),
            "together":   self._python_available("together"),
            "anthropic":  self._python_available("anthropic"),
            "genai":      self._python_available("google.generativeai"),
        }
        return tools

    def _python_available(self, module: str) -> bool:
        try:
            __import__(module)
            return True
        except ImportError:
            return False

    def system_info(self) -> dict:
        return {
            "os":       platform.system(),
            "arch":     platform.machine(),
            "python":   platform.python_version(),
            "r3con":    VERSION,
            "home":     str(R3CON_HOME),
        }
