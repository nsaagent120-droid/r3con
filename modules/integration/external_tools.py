"""
r3con - External Tools Integration
Wrappers pour Ghidra, Radare2, GDB, AFL++, strings, file, nm.
Détecte automatiquement les outils disponibles.
100% optionnel — r3con fonctionne sans.
"""

import os
import subprocess
import tempfile
import json
from pathlib import Path
from typing import List, Dict, Optional


def _run(cmd: List[str], timeout: int = 30,
         input_data: str = None) -> Optional[str]:
    """Exécuter une commande et retourner stdout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        # Parfois le résultat utile est dans stderr
        if result.stderr.strip():
            return result.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def tool_exists(name: str) -> bool:
    """Vérifier si un outil est disponible."""
    try:
        subprocess.run([name, '--version'],
                       capture_output=True, timeout=3)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def detect_tools() -> Dict[str, bool]:
    """Détecter tous les outils externes disponibles."""
    tools = {
        # Analyse binaire
        "ghidra":    _ghidra_available(),
        "radare2":   tool_exists("r2"),
        "r2":        tool_exists("r2"),
        "rizin":     tool_exists("rizin"),
        "gdb":       tool_exists("gdb"),
        "objdump":   tool_exists("objdump"),
        "nm":        tool_exists("nm"),
        "strings":   tool_exists("strings"),
        "readelf":   tool_exists("readelf"),
        "file":      tool_exists("file"),
        "hexdump":   tool_exists("hexdump"),
        # Fuzzing
        "afl++":     tool_exists("afl-fuzz"),
        "afl-fuzz":  tool_exists("afl-fuzz"),
        "libfuzzer": _libfuzzer_available(),
        # APK
        "apktool":   tool_exists("apktool"),
        "jadx":      tool_exists("jadx"),
        "aapt":      tool_exists("aapt"),
        # Firmware
        "binwalk":   tool_exists("binwalk"),
        "foremost":  tool_exists("foremost"),
        # Décompilation
        "retdec":    tool_exists("retdec-decompiler"),
        # Build
        "gcc":       tool_exists("gcc"),
        "clang":     tool_exists("clang"),
        "make":      tool_exists("make"),
    }
    return tools


def _ghidra_available() -> bool:
    """Vérifier si Ghidra est disponible."""
    ghidra_paths = [
        os.environ.get("GHIDRA_HOME", ""),
        "/opt/ghidra",
        "/usr/local/ghidra",
        str(Path.home() / "ghidra"),
    ]
    return any(
        Path(p).exists() and (Path(p) / "ghidraRun").exists()
        for p in ghidra_paths if p
    )


def _libfuzzer_available() -> bool:
    """Vérifier si libFuzzer est disponible."""
    try:
        result = subprocess.run(
            ["clang", "-fsanitize=fuzzer", "-x", "c", "-", "-o", "/dev/null"],
            input="int LLVMFuzzerTestOneInput(const unsigned char *d, int s){return 0;}",
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


# ── Radare2 Wrapper ───────────────────────────────────────────

class Radare2Wrapper:
    """
    Wrapper Radare2/Rizin pour analyse avancée de binaires.
    Radare2 offre une analyse beaucoup plus profonde que Capstone seul.
    """

    def __init__(self, binary_path: str):
        self.path    = binary_path
        self.r2_cmd  = "rizin" if tool_exists("rizin") else "r2"
        self.available = tool_exists(self.r2_cmd)

    def _r2(self, commands: List[str], timeout: int = 30) -> Optional[str]:
        """Exécuter des commandes r2 et retourner le résultat."""
        if not self.available:
            return None
        cmd_str = "\n".join(commands + ["q"])
        return _run([self.r2_cmd, "-q", self.path],
                    timeout=timeout, input_data=cmd_str)

    def get_info(self) -> Dict:
        """Informations complètes sur le binaire."""
        if not self.available:
            return {"error": "radare2/rizin not installed"}

        # Utiliser 'ij' pour JSON info
        out = _run([self.r2_cmd, "-q", "-c", "ij", self.path], timeout=15)
        if out:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                pass

        return {"raw": out or ""}

    def list_functions(self) -> List[Dict]:
        """Lister toutes les fonctions (analyse complète)."""
        if not self.available:
            return []

        out = _run([self.r2_cmd, "-q", "-A",
                    "-c", "aflj", self.path], timeout=60)
        if out:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                pass
        return []

    def disassemble_function(self, func_name: str,
                              max_insn: int = 200) -> str:
        """Désassembler une fonction via r2 (résultat de qualité)."""
        if not self.available:
            return "radare2/rizin not available"

        out = _run([
            self.r2_cmd, "-q", "-A",
            "-c", f"pdf @ sym.{func_name}",
            self.path
        ], timeout=30)
        return out or f"Function '{func_name}' not found"

    def find_strings(self, min_len: int = 6) -> List[Dict]:
        """Extraire les strings via r2 (meilleure classification)."""
        if not self.available:
            return []

        out = _run([self.r2_cmd, "-q", "-c",
                    "izzj", self.path], timeout=20)
        if out:
            try:
                strings = json.loads(out)
                return [s for s in strings
                        if len(s.get("string", "")) >= min_len]
            except json.JSONDecodeError:
                pass
        return []

    def find_rop_gadgets(self) -> List[Dict]:
        """Trouver les gadgets ROP via r2."""
        if not self.available:
            return []

        out = _run([self.r2_cmd, "-q", "-c",
                    "/Rj", self.path], timeout=60)
        if out:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                return [{"gadget": line} for line in out.splitlines()[:100]]
        return []

    def get_imports(self) -> List[Dict]:
        """Lister les imports via r2."""
        if not self.available:
            return []

        out = _run([self.r2_cmd, "-q", "-c",
                    "iij", self.path], timeout=15)
        if out:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                pass
        return []

    def get_entropy(self) -> Dict:
        """Calculer l'entropie du binaire."""
        if not self.available:
            return {}
        out = _run([self.r2_cmd, "-q", "-c",
                    "ph entropy", self.path], timeout=10)
        return {"entropy": out} if out else {}


# ── GDB Wrapper ───────────────────────────────────────────────

class GDBWrapper:
    """
    Wrapper GDB pour analyse dynamique basique.
    Génère des scripts GDB et les exécute.
    """

    def __init__(self, binary_path: str):
        self.path      = binary_path
        self.available = tool_exists("gdb")

    def _gdb(self, commands: List[str],
             timeout: int = 30) -> Optional[str]:
        """Exécuter des commandes GDB."""
        if not self.available:
            return None

        args = ["gdb", "-q", "--batch"]
        for c in commands:
            args += ["-ex", c]
        args.append(self.path)
        return _run(args, timeout=timeout)

    def get_info(self) -> Dict:
        """Informations sur le binaire via GDB."""
        if not self.available:
            return {"error": "GDB not installed"}

        output = self._gdb(["info file", "info functions"])
        return {"raw": output or ""}

    def list_functions(self) -> List[str]:
        """Lister les fonctions via GDB."""
        if not self.available:
            return []

        out = self._gdb(["info functions"])
        if out:
            funcs = []
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith("All") and "0x" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        funcs.append(parts[-1].rstrip(";"))
            return funcs[:100]
        return []

    def disassemble_function(self, func_name: str) -> str:
        """Désassembler une fonction via GDB."""
        if not self.available:
            return "GDB not available"
        out = self._gdb([f"disassemble {func_name}"])
        return out or f"Could not disassemble {func_name}"

    def generate_exploit_script(self, offset: int,
                                 ret_addr: str) -> str:
        """Générer un script GDB pour tester un BOF."""
        return f"""# r3con GDB exploit test script
# Usage: gdb -x exploit_test.gdb ./binary
set pagination off
set logging on exploit_test.log

# Run with overflow payload
run $(python3 -c "print('A'*{offset} + '\\x{ret_addr[2:].zfill(16)}')")

# Check if we controlled RIP
info registers rip
bt
"""

    def analyze_crash(self, crash_input_file: str) -> Dict:
        """Analyser un crash avec une entrée spécifique."""
        if not self.available:
            return {"error": "GDB not available"}

        script = [
            "set pagination off",
            f"run < {crash_input_file}",
            "info registers",
            "bt",
            "info frame",
        ]
        out = self._gdb(script, timeout=15)
        return {"gdb_output": out or ""}


# ── Strings Wrapper ───────────────────────────────────────────

class StringsWrapper:
    """
    Wrapper amélioré pour l'extraction de strings.
    Utilise 'strings' système + analyse custom.
    """

    def __init__(self, binary_path: str):
        self.path = binary_path

    def extract(self, min_len: int = 6,
                encoding: str = "all") -> List[Dict]:
        """Extraire les strings avec catégorisation."""
        strings = []

        # Via 'strings' système
        sys_strings = self._strings_cmd(min_len, encoding)
        strings.extend(sys_strings)

        # Si strings non dispo, lecture directe
        if not sys_strings:
            strings = self._extract_manual(min_len)

        return strings

    def _strings_cmd(self, min_len: int,
                      encoding: str) -> List[Dict]:
        """Utiliser la commande 'strings'."""
        if not tool_exists("strings"):
            return []

        args = ["strings", f"-n{min_len}"]
        if encoding in ("unicode", "all"):
            args += ["-e", "l"]

        out = _run(args + [self.path], timeout=20)
        if not out:
            # Retry sans unicode
            out = _run(["strings", f"-n{min_len}", self.path], timeout=20)

        if not out:
            return []

        results = []
        for line in out.splitlines():
            s = line.strip()
            if len(s) >= min_len:
                results.append({
                    "value":    s,
                    "category": self._categorize(s),
                    "source":   "strings",
                })
        return results

    def _extract_manual(self, min_len: int) -> List[Dict]:
        """Extraction manuelle des strings ASCII/UTF-8."""
        results  = []
        printable = set(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}
        try:
            with open(self.path, "rb") as f:
                # Pour gros fichiers, chunks
                current = []
                offset  = 0
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    for b in chunk:
                        if b in printable:
                            current.append(chr(b))
                        else:
                            if len(current) >= min_len:
                                s = "".join(current)
                                results.append({
                                    "value":    s,
                                    "category": self._categorize(s),
                                    "offset":   offset - len(current),
                                    "source":   "manual",
                                })
                            current = []
                        offset += 1
        except Exception:
            pass
        return results[:2000]

    def _categorize(self, s: str) -> str:
        """Catégoriser une string."""
        s_low = s.lower()
        if any(k in s_low for k in ["password","passwd","secret","key","token","api_key"]):
            return "credential"
        if s.startswith(("http://","https://","ftp://")):
            return "url"
        if any(s_low.startswith(p) for p in ["/etc/","/proc/","/sys/","/var/","/usr/"]):
            return "path"
        if any(k in s_low for k in ["debug","error","warning","trace","log"]):
            return "debug"
        if s.count(".") == 3 and all(
            p.isdigit() and 0 <= int(p) <= 255
            for p in s.split(".")
        ):
            return "ip_addr"
        if "cve-" in s_low:
            return "cve_ref"
        return "generic"


# ── AFL++ Wrapper ─────────────────────────────────────────────

class AFLWrapper:
    """
    Wrapper AFL++ pour le fuzzing intégré.
    Génère les harnais et gère les campagnes de fuzzing.
    """

    def __init__(self, target_path: str,
                 output_dir: str = None):
        self.target    = target_path
        self.output    = output_dir or tempfile.mkdtemp(prefix="r3con-afl-")
        self.available = tool_exists("afl-fuzz")

    def generate_harness(self, target_func: str = None,
                          input_type: str = "stdin") -> str:
        """
        Générer un harnais AFL++ pour le target.
        """
        func_call = f"{target_func}(data, size);" if target_func \
                    else "/* Call your target function here */"

        if input_type == "file":
            harness = f"""/* r3con AFL++ Harness — File input */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include your target headers here
// #include "target.h"

int main(int argc, char *argv[]) {{
    if (argc < 2) return 1;

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    unsigned char *data = malloc(size + 1);
    if (!data) {{ fclose(f); return 1; }}
    fread(data, 1, size, f);
    data[size] = 0;
    fclose(f);

    // Target call
    {func_call}

    free(data);
    return 0;
}}
/* Compile: gcc -o harness harness.c -fsanitize=address,undefined */
/* Fuzz:    afl-fuzz -i seeds/ -o {self.output}/ ./harness @@ */
"""
        else:
            harness = f"""/* r3con AFL++ Harness — Stdin input */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Include your target headers here
// #include "target.h"

int main(void) {{
    unsigned char data[65536];
    ssize_t size = read(STDIN_FILENO, data, sizeof(data));
    if (size <= 0) return 1;

    // Target call
    {func_call}

    return 0;
}}
/* Compile: gcc -o harness harness.c -fsanitize=address,undefined */
/* Fuzz:    afl-fuzz -i seeds/ -o {self.output}/ ./harness */
"""

        return harness

    def generate_libfuzzer_harness(self,
                                    target_func: str = None) -> str:
        """Générer un harnais libFuzzer."""
        func_call = f"{target_func}(Data, Size);" if target_func \
                    else "/* Call your target function here */"
        return f"""/* r3con libFuzzer Harness */
#include <stdint.h>
#include <stddef.h>

// Include your target headers here
// #include "target.h"

extern "C" int LLVMFuzzerTestOneInput(
    const uint8_t *Data, size_t Size) {{

    if (Size < 4) return 0;  // Minimum input size

    // Target call
    {func_call}

    return 0;
}}
/* Compile: clang++ -fsanitize=fuzzer,address -o fuzzer harness.cpp target.cpp */
/* Run:     ./fuzzer -max_total_time=3600 corpus/ */
"""

    def create_seed_corpus(self, output_dir: str,
                            seed_strings: List[str] = None) -> str:
        """Créer un corpus de seeds pour AFL++."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        default_seeds = [
            b"A" * 100,
            b"\x00" * 64,
            b"\xff" * 64,
            b"AAAA\x00\x00\x00\x00",
            b"%n%n%n%n",
            b"/../../../etc/passwd",
            b"<script>alert(1)</script>",
            b"' OR '1'='1",
            b"\x7fELF",
            bytes(range(256)),
        ]

        if seed_strings:
            default_seeds.extend(
                s.encode() if isinstance(s, str) else s
                for s in seed_strings
            )

        for i, seed in enumerate(default_seeds):
            seed_file = Path(output_dir) / f"seed_{i:04d}"
            seed_file.write_bytes(seed)

        return output_dir

    def run_campaign(self, harness_path: str,
                     seeds_dir: str,
                     timeout_seconds: int = 300) -> Dict:
        """
        Lancer une campagne AFL++ (si disponible).
        """
        if not self.available:
            return {
                "available": False,
                "message":   "AFL++ not installed. Install: apt install afl++",
                "install":   "sudo apt install afl++ / brew install afl++",
            }

        Path(self.output).mkdir(parents=True, exist_ok=True)

        cmd = [
            "afl-fuzz",
            "-i", seeds_dir,
            "-o", self.output,
            "-t", "1000",      # 1s timeout per input
            harness_path
        ]

        return {
            "available": True,
            "command":   " ".join(cmd),
            "output_dir": self.output,
            "message":   f"Run: {' '.join(cmd)} (timeout: {timeout_seconds}s)",
        }

    def analyze_crashes(self, crashes_dir: str = None) -> List[Dict]:
        """Analyser les crashes trouvés par AFL++."""
        crashes_path = Path(crashes_dir or self.output) / "default" / "crashes"
        if not crashes_path.exists():
            return []

        crashes = []
        for crash_file in list(crashes_path.iterdir())[:20]:
            if crash_file.is_file() and crash_file.name != "README.txt":
                crashes.append({
                    "file":    str(crash_file),
                    "size":    crash_file.stat().st_size,
                    "name":    crash_file.name,
                    "content": crash_file.read_bytes()[:64].hex(),
                })

        return crashes
