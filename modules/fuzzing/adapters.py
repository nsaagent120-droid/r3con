"""
r3con v6.0 - Fuzzing Adapters
Adapters pour AFL++, libFuzzer, honggfuzz, Radamsa
"""
from __future__ import annotations
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

class FuzzingAdapterBase:
    def __init__(self, target: str, timeout: int = 60):
        self.target = target
        self.timeout = timeout

    def is_available(self) -> bool:
        return False

    def fuzz(self, corpus_dir: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        raise NotImplementedError

class AFLAdapter(FuzzingAdapterBase):
    def is_available(self) -> bool:
        return bool(shutil.which("afl-fuzz"))

    def fuzz(self, corpus_dir: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        if not self.is_available():
            return {"status": "error", "error": "afl-fuzz not found"}
        # Dry-run: show command that would be executed
        cmd = ["afl-fuzz", "-i", corpus_dir, "-o", output_dir, "--", self.target, "@@"]
        return {
            "status": "ready",
            "engine": "afl",
            "command": " ".join(cmd),
            "note": "Lance manuellement pour fuzzing continu. Pour test rapide, utilise r3con fuzzing corpus --generate",
        }

class HonggfuzzAdapter(FuzzingAdapterBase):
    def is_available(self) -> bool:
        return bool(shutil.which("honggfuzz"))

    def fuzz(self, corpus_dir: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        if not self.is_available():
            return {"status": "error", "error": "honggfuzz not found"}
        cmd = ["honggfuzz", "--input", corpus_dir, "--output", f"{output_dir}/crashes", "--", self.target, "___FILE___"]
        return {"status": "ready", "engine": "honggfuzz", "command": " ".join(cmd)}

class RadamsaAdapter(FuzzingAdapterBase):
    def is_available(self) -> bool:
        return bool(shutil.which("radamsa"))

    def mutate(self, input_file: str, count: int = 10) -> Dict[str, Any]:
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
