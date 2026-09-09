"""
r3con v7.1 - Decompiler Engine PRO
Ghidra headless + RetDec + objdump + pseudo-code generation
"""
from __future__ import annotations
import os
import re
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

def _run(cmd: List[str], timeout: int = 60) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=min(timeout, 300))
        output = result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else ""
        if not output and result.stderr.strip():
            output = result.stderr.strip()
        return output[:2*1024*1024] if output else None
    except Exception:
        return None

def _validate_path(path: str) -> bool:
    if not path or len(path) > 1024 or "\x00" in path:
        return False
    p = Path(path)
    try:
        return p.exists() and p.is_file() and p.stat().st_size <= 200*1024*1024
    except Exception:
        return False

class GhidraDecompiler:
    """Ghidra headless decompiler PRO."""

    def __init__(self, binary_path: str):
        self.path = Path(binary_path)
        self.ghidra_home = os.environ.get("GHIDRA_HOME", "")
        self.available = self._detect_ghidra()

    def _detect_ghidra(self) -> bool:
        possible_paths = [
            self.ghidra_home,
            "/opt/ghidra",
            "/usr/local/ghidra",
            str(Path.home() / "ghidra"),
            "/opt/ghidra_11.0",
            "/opt/ghidra_10.4",
        ]
        for p in possible_paths:
            if p and Path(p).exists() and (Path(p) / "ghidraRun").exists():
                self.ghidra_home = p
                return True
            if p and Path(p).exists() and (Path(p) / "support" / "analyzeHeadless").exists():
                self.ghidra_home = p
                return True
        # Check if analyzeHeadless in PATH
        if shutil.which("analyzeHeadless"):
            return True
        return False

    def decompile(self, function_name: str = None) -> Dict[str, Any]:
        if not self.available:
            return {"status": "unsupported", "tool": "ghidra", "install": "Download from https://ghidra-sre.org/ and set GHIDRA_HOME"}

        if not _validate_path(str(self.path)):
            return {"status": "invalid", "error": "invalid_path"}

        # Create temp project
        with tempfile.TemporaryDirectory(prefix="r3con-ghidra-") as tmpdir:
            project_dir = Path(tmpdir) / "project"
            project_dir.mkdir()

            # Find analyzeHeadless
            headless = None
            if self.ghidra_home:
                possible = [
                    Path(self.ghidra_home) / "support" / "analyzeHeadless",
                    Path(self.ghidra_home) / "analyzeHeadless",
                ]
                for p in possible:
                    if p.exists():
                        headless = str(p)
                        break
            else:
                headless = shutil.which("analyzeHeadless")

            if not headless:
                return {"status": "error", "tool": "ghidra", "error": "analyzeHeadless not found"}

            # Create ghidra script to decompile
            script_dir = Path(tmpdir) / "scripts"
            script_dir.mkdir()
            script_path = script_dir / "DecompileToFile.java"

            # Java ghidra script that decompiles to file
            script_content = '''
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import java.io.*;

public class DecompileToFile extends ghidra.app.script.GhidraScript {
    public void run() throws Exception {
        Program program = getCurrentProgram();
        Listing listing = program.getListing();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);

        FunctionManager fm = program.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);

        PrintWriter writer = new PrintWriter(new FileWriter("/tmp/ghidra_decompile.c"));

        int count = 0;
        while (funcs.hasNext() && count < 50) {
            Function func = funcs.next();
            DecompiledFunction decompiled = decompiler.decompileFunction(func, 30, monitor);
            if (decompiled != null) {
                writer.println("// Function: " + func.getName() + " @ " + func.getEntryPoint());
                writer.println(decompiled.getC());
                writer.println("\\n---\\n");
                count++;
            }
        }

        writer.close();
        decompiler.dispose();
    }
}
'''
            script_path.write_text(script_content)

            cmd = [
                headless,
                str(project_dir),
                "r3con_project",
                "-import", str(self.path),
                "-scriptPath", str(script_dir),
                "-postScript", "DecompileToFile",
                "-deleteProject",
            ]

            out = _run(cmd, timeout=120)

            # Try to read decompiled file
            decompiled_file = Path("/tmp/ghidra_decompile.c")
            if decompiled_file.exists():
                content = decompiled_file.read_text(errors="ignore")[:200000]
                decompiled_file.unlink(missing_ok=True)
                return {
                    "status": "ok",
                    "tool": "ghidra",
                    "decompiled": content,
                    "function_count": content.count("// Function:"),
                    "raw_output": out[:5000] if out else "",
                }

            return {"status": "partial", "tool": "ghidra", "output": out[:5000] if out else "", "note": "Check /tmp/ghidra_decompile.c"}

    def get_functions(self) -> Dict[str, Any]:
        """Get function list via Ghidra."""
        if not self.available:
            return {"status": "unsupported", "tool": "ghidra"}

        # Use r2 as fallback for function list
        try:
            from modules.integration.reverse_adapters import R2Adapter
            r2 = R2Adapter(str(self.path))
            if hasattr(r2, 'analyze'):
                result = r2.analyze()
                return {"status": "ok", "tool": "ghidra_fallback_r2", "functions": result.get("functions", [])[:100]}
        except Exception:
            pass

        return {"status": "error", "tool": "ghidra", "error": "Failed to get functions"}

class RetDecDecompiler:
    """RetDec decompiler wrapper."""

    def __init__(self, binary_path: str):
        self.path = Path(binary_path)
        self.bin = shutil.which("retdec-decompiler") or shutil.which("retdec")

    def decompile(self) -> Dict[str, Any]:
        if not self.bin:
            return {"status": "unsupported", "tool": "retdec", "install": "https://github.com/avast/retdec"}

        if not _validate_path(str(self.path)):
            return {"status": "invalid", "error": "invalid_path"}

        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as tf:
            output = tf.name

        try:
            cmd = [self.bin, str(self.path), "-o", output]
            out = _run(cmd, timeout=180)

            if Path(output).exists():
                content = Path(output).read_text(errors="ignore")[:200000]
                Path(output).unlink(missing_ok=True)
                return {
                    "status": "ok",
                    "tool": "retdec",
                    "decompiled": content,
                    "raw": out[:5000] if out else "",
                }
            else:
                return {"status": "error", "tool": "retdec", "output": out[:5000] if out else ""}
        finally:
            try:
                Path(output).unlink(missing_ok=True)
            except Exception:
                pass

class PseudoCodeGenerator:
    """Pseudo-code generator from disassembly (fallback)."""

    def __init__(self, binary_path: str):
        self.path = Path(binary_path)

    def generate(self) -> Dict[str, Any]:
        """Generate pseudo-code from disassembly."""
        try:
            from modules.disasm.capstone_engine import DisasmEngine
            engine = DisasmEngine(str(self.path), max_instructions=500)
            asm = engine.disasm_main() if hasattr(engine, 'disasm_main') else ""

            # Convert ASM to pseudo-code heuristically
            pseudo = self._asm_to_pseudo(asm[:50000])

            return {
                "status": "ok",
                "tool": "pseudo_generator",
                "pseudo_code": pseudo,
                "asm": asm[:20000],
            }
        except Exception as e:
            return {"status": "error", "tool": "pseudo_generator", "error": str(e)[:500]}

    def _asm_to_pseudo(self, asm: str) -> str:
        """Heuristic ASM to pseudo-code."""
        lines = asm.splitlines()[:200]
        pseudo = "// Pseudo-code generated by r3con v7.1\n"
        pseudo += "// This is heuristic, not accurate decompilation\n\n"

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Simple translations
            if "call" in line.lower():
                # Extract function
                match = re.search(r"call\s+([a-zA-Z_][\w@]*)", line, re.IGNORECASE)
                if match:
                    func = match.group(1)
                    pseudo += f"  {func}();  // {line[:60]}\n"
            elif "mov" in line.lower():
                pseudo += f"  // {line[:80]}\n"
            elif "jmp" in line.lower() or "je" in line.lower() or "jne" in line.lower():
                pseudo += f"  // branch: {line[:80]}\n"
            elif "ret" in line.lower():
                pseudo += f"  return;  // {line[:60]}\n"
            else:
                pseudo += f"  // {line[:80]}\n"

        pseudo += "\n// End pseudo-code\n"
        return pseudo

class DecompilerManager:
    """Manager for all decompilers."""

    def __init__(self, binary_path: str):
        self.path = binary_path

    def detect_all(self) -> Dict[str, bool]:
        return {
            "ghidra": GhidraDecompiler(self.path).available,
            "retdec": RetDecDecompiler(self.path).bin is not None,
            "pseudo": True,  # Always available
        }

    def decompile_all(self) -> Dict[str, Any]:
        results = {}

        # Ghidra
        try:
            results["ghidra"] = GhidraDecompiler(self.path).decompile()
        except Exception as e:
            results["ghidra"] = {"status": "error", "error": str(e)[:500]}

        # RetDec
        try:
            results["retdec"] = RetDecDecompiler(self.path).decompile()
        except Exception as e:
            results["retdec"] = {"status": "error", "error": str(e)[:500]}

        # Pseudo
        try:
            results["pseudo"] = PseudoCodeGenerator(self.path).generate()
        except Exception as e:
            results["pseudo"] = {"status": "error", "error": str(e)[:500]}

        # Pick best
        best = None
        for name in ["ghidra", "retdec", "pseudo"]:
            if results.get(name, {}).get("status") == "ok":
                best = name
                break

        results["best"] = best
        results["decompiled"] = results.get(best, {}).get("decompiled") or results.get(best, {}).get("pseudo_code", "") if best else ""

        return results
