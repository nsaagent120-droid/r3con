"""
r3con v6.0 - Fuzzing Adapters
Adapters pour AFL++, libFuzzer, honggfuzz, Radamsa
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Any


class FuzzingAdapterBase:
    def __init__(self, target: str, timeout: int = 60):
        self.target = target
        self.timeout = timeout

    def is_available(self) -> bool:
        return False

    def fuzz(self, corpus_dir: str, output_dir: str, **kwargs) -> dict[str, Any]:
        raise NotImplementedError

class AFLAdapter(FuzzingAdapterBase):
    def is_available(self) -> bool:
        return bool(shutil.which("afl-fuzz"))

    def fuzz(self, corpus_dir: str, output_dir: str, *, timeout_ms: int = 1000,
             memory_mb: int = 200, max_runtime_s: int = 0, resume: bool = False,
             **kwargs) -> dict[str, Any]:
        """Construit la commande AFL++ avec limites de ressources (dry-run).

        - ``timeout_ms``/-t borne la durée d'un exec (anti-hang) ;
        - ``memory_mb``/-m borne l'empreinte de chaque instance ;
        - ``max_runtime_s``/-V arrête la campagne automatiquement ;
        - ``resume`` reprend l'arborescence ``-o`` existante (AFL le fait
          nativement quand le dossier contient déjà l'état).
        Aucune exécution n'est déclenchée ici : c'est un plan, pas une action.
        """
        from modules.fuzzing.triage import detect_resume
        state = detect_resume(output_dir)
        if not self.is_available():
            return {"status": "error", "error": "afl-fuzz not found",
                    "fallback": "plan disponible ; installez afl++ (apt install afl++) pour exécuter",
                    "resumable": state["resumable"]}
        cmd = ["afl-fuzz", "-i", corpus_dir, "-o", output_dir,
               "-t", f"{timeout_ms}+", "-m", str(memory_mb)]
        if max_runtime_s:
            cmd += ["-V", str(max_runtime_s)]
        if resume and state["resumable"]:
            cmd += ["-S", "resume0"]
        cmd += ["--", self.target, "@@"]
        return {
            "status": "ready",
            "engine": "afl",
            "argv": cmd,
            "command": " ".join(cmd),
            "resumable": state["resumable"],
            "resume_note": state["note"],
            "limits": {"timeout_ms": timeout_ms, "memory_mb": memory_mb,
                       "max_runtime_s": max_runtime_s},
            "note": "Lance manuellement pour fuzzing continu. Pour test rapide, utilise r3con fuzzing corpus --generate",
        }

class HonggfuzzAdapter(FuzzingAdapterBase):
    def is_available(self) -> bool:
        return bool(shutil.which("honggfuzz"))

    def fuzz(self, corpus_dir: str, output_dir: str, *, timeout_ms: int = 1000,
             memory_mb: int = 200, max_runtime_s: int = 0, **kwargs) -> dict[str, Any]:
        if not self.is_available():
            return {"status": "error", "error": "honggfuzz not found",
                    "fallback": "plan sans exécution ; installez honggfuzz pour fuzzing réel"}
        cmd = ["honggfuzz", "--input", corpus_dir, "--output", f"{output_dir}/crashes",
               "--timeout", str(max(1, timeout_ms // 1000)),
               "--memlimit", str(memory_mb), "--memlimit-exec", str(memory_mb)]
        if max_runtime_s:
            cmd += ["--run", str(max_runtime_s)]
        cmd += ["--", self.target, "___FILE___"]
        return {"status": "ready", "engine": "honggfuzz", "argv": cmd,
                "command": " ".join(cmd),
                "limits": {"timeout_ms": timeout_ms, "memory_mb": memory_mb,
                           "max_runtime_s": max_runtime_s}}

class RadamsaAdapter(FuzzingAdapterBase):
    def is_available(self) -> bool:
        return bool(shutil.which("radamsa"))

    def mutate(self, input_file: str, count: int = 10) -> dict[str, Any]:
        if not self.is_available():
            return {"status": "error", "error": "radamsa not found"}
        try:
            results = []
            for _ in range(count):
                proc = subprocess.run(["radamsa", input_file], capture_output=True, timeout=5)
                if proc.stdout:
                    results.append(proc.stdout[:100])
            return {"status": "ok", "engine": "radamsa", "mutated": len(results)}
        except Exception as e:
            return {"status": "error", "error": str(e)}
