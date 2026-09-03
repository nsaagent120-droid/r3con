"""
r3con - Binary Parser v2
Parser ELF/PE/MachO amélioré.
Nouvelles capacités:
  - Détection complète des métadonnées
  - Extraction strings améliorée avec offset
  - Détection des sections suspectes
  - Anti-debug patterns
  - Checksums de sécurité
  - Support gros fichiers par chunks
"""

import os
import re
import struct
import subprocess
from typing import List, Dict, Optional

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


# Fonctions dangereuses à flaguer
DANGEROUS_IMPORTS = {
    "gets":      ("CRITICAL", "No bounds check — stack BOF"),
    "strcpy":    ("HIGH",     "No bounds check — use strncpy"),
    "strcat":    ("HIGH",     "No bounds check — use strncat"),
    "sprintf":   ("HIGH",     "Use snprintf with size limit"),
    "vsprintf":  ("HIGH",     "Use vsnprintf with size limit"),
    "scanf":     ("HIGH",     "Use scanf with width limit"),
    "system":    ("CRITICAL", "Command injection risk"),
    "popen":     ("CRITICAL", "Command injection risk"),
    "execve":    ("HIGH",     "Code execution — validate args"),
    "execl":     ("HIGH",     "Code execution — validate args"),
    "printf":    ("MEDIUM",   "Potential format string if user-controlled"),
    "fprintf":   ("MEDIUM",   "Potential format string"),
    "malloc":    ("LOW",      "Check return value and size"),
    "realloc":   ("LOW",      "Check return value"),
    "free":      ("LOW",      "Ensure no double-free / UAF"),
    "memcpy":    ("MEDIUM",   "Validate size parameter"),
    "memmove":   ("MEDIUM",   "Validate size parameter"),
    "rand":      ("LOW",      "Weak PRNG — not cryptographically safe"),
    "srand":     ("LOW",      "Weak PRNG seed"),
    "atoi":      ("MEDIUM",   "No error handling — use strtol"),
    "atol":      ("MEDIUM",   "No error handling — use strtol"),
}

# Patterns strings suspects
SUSPICIOUS_STRING_PATTERNS = [
    (r"password\s*=\s*\S+",          "credential",   "HIGH"),
    (r"passwd\s*=\s*\S+",            "credential",   "HIGH"),
    (r"api[_-]?key\s*=\s*\S+",       "credential",   "HIGH"),
    (r"secret\s*=\s*\S+",            "credential",   "HIGH"),
    (r"token\s*=\s*\S+",             "credential",   "MEDIUM"),
    (r"https?://\S+",                 "url",          "INFO"),
    (r"/etc/(passwd|shadow|sudoers)", "sensitive_path","HIGH"),
    (r"(nc|ncat|netcat)\s+-[le]",     "backdoor",     "CRITICAL"),
    (r"/bin/(sh|bash)\s*$",           "shell",        "HIGH"),
    (r"chmod\s+[0-7]*7[0-7]*",        "permission",   "MEDIUM"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+", "c2_addr", "MEDIUM"),
]


class BinaryParser:
    def __init__(self, binary_path: str):
        self.path      = binary_path
        self._binary   = None
        self._filesize = 0
        self._setup()

    def _setup(self):
        try:
            self._filesize = os.path.getsize(self.path)
        except Exception:
            pass
        if LIEF_AVAILABLE:
            try:
                self._binary = lief.parse(self.path)
            except Exception:
                pass

    # ── Parse ─────────────────────────────────────────────────

    def parse(self) -> Dict:
        """Informations complètes sur le binaire."""
        info = {
            "path":        self.path,
            "size":        self._filesize,
            "size_human":  self._human_size(self._filesize),
            "format":      "unknown",
            "arch":        "unknown",
            "bits":        0,
            "endian":      "unknown",
            "entry":       0,
            "type":        "unknown",
            "sections":    [],
            "symbols":     [],
            "libraries":   [],
            "compiler":    "",
            "stripped":    None,
            "pie":         None,
            "nx":          None,
            "canary":      None,
            "relro":       None,
            "checksec":    {},
        }

        if self._binary and LIEF_AVAILABLE:
            self._parse_lief(info)
            # LIEF peut retourner un objet partiel pour un en-tête tronqué ou
            # une architecture qu’il ne reconnaît pas. Revenir au parseur brut
            # lorsque les métadonnées essentielles n’ont pas été remplies.
            if info["format"] == "ELF" and info["arch"] == "unknown":
                self._parse_raw(info)
        else:
            self._parse_raw(info)

        # Checksec : une seule source de vérité pour éviter les divergences.
        checks = self._checksec()
        info["checksec"] = checks
        for key in ("pie", "nx", "canary", "relro", "stripped"):
            info[key] = checks.get(key)

        return info

    def _parse_lief(self, info: Dict):
        """Parser via LIEF (meilleur résultat)."""
        b = self._binary
        fmt = type(b).__name__
        # LIEF récent expose souvent lief._lief.ELF.Binary : le nom court
        # n’est pas « ELF ». Utiliser les attributs structurels plutôt que
        # dépendre d’un nom d’implémentation.
        is_elf = (hasattr(b, "header") and hasattr(b, "sections")
                  and hasattr(b.header, "machine_type"))
        hasattr(b, "optional_header") and hasattr(b, "imports")

        if is_elf:
            info["format"] = "ELF"
            try:
                info["arch"]    = b.header.machine_type.name
                class_name = str(getattr(b.header.identity_class, "name", b.header.identity_class))
                data_name = str(getattr(b.header.identity_data, "name", b.header.identity_data))
                info["bits"]    = 64 if "64" in class_name else 32
                info["endian"]  = "little" if "LSB" in data_name else "big"
                info["entry"]   = b.header.entrypoint
                info["type"]    = b.header.file_type.name
                info["stripped"] = not bool(getattr(b, "has_debug_info", False))
                info["pie"]      = bool(getattr(b, "is_pie", False))
                info["nx"]       = bool(getattr(b, "has_nx", False))
                info["sections"] = [
                    {"name": s.name, "size": s.size, "addr": hex(s.virtual_address)}
                    for s in b.sections
                ]
                info["libraries"] = [str(l) for l in b.libraries]
                info["symbols"]   = [
                    {"name": sym.name, "addr": hex(sym.value)}
                    for sym in b.symbols
                    if sym.name and sym.value > 0
                ][:100]
            except Exception:
                pass

        elif "PE" in fmt:
            info["format"] = "PE"
            try:
                info["arch"]   = b.header.machine.name
                info["bits"]   = 64 if "64" in b.header.machine.name else 32
                info["entry"]  = b.optional_header.addressof_entrypoint
                info["sections"] = [
                    {"name": s.name, "size": s.size, "addr": hex(s.virtual_address)}
                    for s in b.sections
                ]
                info["libraries"] = [i.name for i in b.imports]
            except Exception:
                pass

        elif "MachO" in fmt:
            info["format"] = "MachO"
            try:
                info["arch"]  = b.header.cpu_type.name
                info["entry"] = b.entrypoint
            except Exception:
                pass

    def _parse_raw(self, info: Dict):
        """Parser via lecture des headers bruts."""
        try:
            with open(self.path, "rb") as f:
                header = f.read(64)

            if header[:4] == b"\x7fELF":
                info["format"] = "ELF"
                info["bits"]   = 64 if header[4] == 2 else 32
                endian_prefix = "<" if header[5] == 1 else ">"
                info["endian"] = "little" if header[5] == 1 else "big"
                e_machine = struct.unpack_from(endian_prefix + "H", header, 18)[0]
                machine_map = {
                    0x03:"x86", 0x3e:"x86_64", 0x28:"ARM",
                    0xb7:"AArch64", 0x08:"MIPS", 0xf3:"RISC-V"
                }
                info["arch"] = machine_map.get(e_machine, f"0x{e_machine:x}")
                if info["bits"] == 64:
                    info["entry"] = struct.unpack_from(endian_prefix + "Q", header, 24)[0]
                else:
                    info["entry"] = struct.unpack_from(endian_prefix + "I", header, 24)[0]

            elif header[:2] == b"MZ":
                info["format"] = "PE"
                info["arch"]   = "x86_64"

            elif header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                                  b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
                info["format"] = "MachO"

        except Exception:
            pass

        # Fallback: file command
        out = self._run_tool(["file", self.path])
        if out:
            info["file_type_raw"] = out
            if "ELF" in out and info["format"] == "unknown":
                info["format"] = "ELF"
            if "PE" in out or "Windows" in out:
                info["format"] = "PE"

    def _checksec(self) -> Dict:
        """Vérifier les protections avec une sémantique tri-state.

        ``None`` signifie « inconnu/non vérifiable », jamais « protection absente ».
        Les champs sont dérivés des sorties readelf/file lorsque disponibles.
        """
        checks = {"pie": None, "nx": None, "canary": None,
                  "relro": None, "stripped": None}

        try:
            file_out = self._run_tool(["file", self.path]) or ""
            phdr = self._run_tool(["readelf", "-W", "-l", self.path]) or ""
            dyn = self._run_tool(["readelf", "-W", "-d", self.path]) or ""
            syms = self._run_tool(["readelf", "-W", "-s", self.path]) or ""
            sections = self._run_tool(["readelf", "-W", "-S", self.path]) or ""

            if "ELF" in file_out:
                checks["pie"] = "Type:                              DYN" in (self._run_tool(["readelf", "-W", "-h", self.path]) or "")
                stack_lines = [line for line in phdr.splitlines() if "GNU_STACK" in line]
                if stack_lines:
                    checks["nx"] = " E " not in stack_lines[0].replace("  ", " ")
                checks["canary"] = "__stack_chk_fail" in syms
                has_relro = "GNU_RELRO" in phdr
                has_bind_now = "BIND_NOW" in dyn or "(FLAGS)" in dyn and "NOW" in dyn
                checks["relro"] = "full" if has_relro and has_bind_now else ("partial" if has_relro else "none")
                if sections:
                    checks["stripped"] = ".symtab" not in sections
            elif file_out:
                checks["stripped"] = "stripped" in file_out.lower() and "not stripped" not in file_out.lower()
        except Exception:
            pass

        return checks

    # ── Strings ───────────────────────────────────────────────

    def extract_strings(self, min_len: int = 6,
                         pattern: str = None) -> List[Dict]:
        """
        Extraire les strings avec catégorisation et offset.
        Optimisé pour gros fichiers.
        """
        strings = []

        # Via 'strings' système si disponible
        sys_strings = self._strings_cmd(min_len)
        if sys_strings:
            strings = sys_strings
        else:
            strings = self._extract_strings_manual(min_len)

        # Filtrer par pattern si demandé
        if pattern:
            try:
                rx = re.compile(pattern, re.IGNORECASE)
                strings = [s for s in strings if rx.search(s["value"])]
            except re.error:
                pass

        return strings[:3000]

    def _strings_cmd(self, min_len: int) -> List[Dict]:
        """Extraire via commande 'strings'."""
        out = self._run_tool(["strings", f"-n{min_len}", "-t", "x", self.path],
                              timeout=30)
        if not out:
            return []

        results = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                try:
                    offset = int(parts[0], 16)
                    value  = parts[1]
                except ValueError:
                    continue
                if len(value) >= min_len:
                    results.append({
                        "offset":   offset,
                        "hex":      hex(offset),
                        "value":    value,
                        "category": self._categorize_string(value),
                    })

        return results

    def _extract_strings_manual(self, min_len: int) -> List[Dict]:
        """Extraction manuelle ASCII depuis le binaire."""
        results  = []
        printable = set(range(0x20, 0x7f)) | {0x09, 0x0a}

        try:
            with open(self.path, "rb") as f:
                chunk_size = 65536
                offset     = 0
                current    = []
                cur_offset = 0

                # Pour gros fichiers: max 20MB analysés
                max_bytes = min(self._filesize, 20 * 1024 * 1024)

                while offset < max_bytes:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    for b in chunk:
                        if b in printable:
                            if not current:
                                cur_offset = offset
                            current.append(chr(b))
                        else:
                            if len(current) >= min_len:
                                s = "".join(current)
                                results.append({
                                    "offset":   cur_offset,
                                    "hex":      hex(cur_offset),
                                    "value":    s,
                                    "category": self._categorize_string(s),
                                })
                            current = []
                        offset += 1

                    if len(results) > 3000:
                        break

        except Exception:
            pass

        return results

    def _categorize_string(self, s: str) -> str:
        """Catégoriser une string."""
        s_low = s.lower()
        for pattern, category, _ in SUSPICIOUS_STRING_PATTERNS:
            if re.search(pattern, s, re.IGNORECASE):
                return category
        if s.startswith(("http://","https://","ftp://")):
            return "url"
        if any(s_low.startswith(p) for p in ["/etc/","/proc/","/sys/","/var/","/usr/","/bin/"]):
            return "path"
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
            return "ip_addr"
        if "cve-" in s_low:
            return "cve_ref"
        if any(k in s_low for k in ["error","warning","debug","trace","fatal"]):
            return "log"
        return ""

    # ── Imports ───────────────────────────────────────────────

    def get_imports(self) -> List[Dict]:
        """Lister les imports avec annotations de danger."""
        imports = []

        if self._binary and LIEF_AVAILABLE:
            try:
                fmt = type(self._binary).__name__
                is_elf = (hasattr(self._binary, "header")
                          and hasattr(self._binary, "imported_symbols"))
                if is_elf:
                    for sym in self._binary.imported_symbols:
                        name = sym.name
                        danger = DANGEROUS_IMPORTS.get(name.lower(), None)
                        entry = {
                            "name":    name,
                            "library": str(sym.binding) if hasattr(sym,'binding') else "",
                        }
                        if danger:
                            entry["danger_level"] = danger[0]
                            entry["danger_reason"] = danger[1]
                        imports.append(entry)

                elif "PE" in fmt:
                    for imp in self._binary.imports:
                        lib = imp.name
                        for func in imp.entries:
                            name   = func.name
                            danger = DANGEROUS_IMPORTS.get(name.lower(), None)
                            entry  = {"name": name, "library": lib}
                            if danger:
                                entry["danger_level"]  = danger[0]
                                entry["danger_reason"] = danger[1]
                            imports.append(entry)
            except Exception:
                pass

        if not imports:
            imports = self._imports_fallback()

        return imports[:200]

    def _imports_fallback(self) -> List[Dict]:
        """Fallback via nm/objdump."""
        imports = []
        out = self._run_tool(["nm", "-D", "--undefined-only", self.path])
        if out:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    name   = parts[-1]
                    danger = DANGEROUS_IMPORTS.get(name.lower(), None)
                    entry  = {"name": name, "library": ""}
                    if danger:
                        entry["danger_level"]  = danger[0]
                        entry["danger_reason"] = danger[1]
                    imports.append(entry)
        return imports[:200]

    # ── Functions ─────────────────────────────────────────────

    def get_function_list(self) -> List[str]:
        """Lister toutes les fonctions."""
        funcs = []

        if self._binary and LIEF_AVAILABLE:
            try:
                if hasattr(self._binary, 'functions'):
                    return [f.name for f in self._binary.functions if f.name][:200]
                if hasattr(self._binary, 'exported_functions'):
                    return [f.name for f in self._binary.exported_functions][:200]
            except Exception:
                pass

        # Fallback: nm
        out = self._run_tool(["nm", "-n", "--defined-only", self.path])
        if out:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ("T", "t"):
                    funcs.append(parts[2])
        return funcs[:200]

    def get_suspicious_strings(self) -> List[Dict]:
        """Retourner uniquement les strings suspectes."""
        all_strings = self.extract_strings(min_len=4)
        suspicious  = []

        for s in all_strings:
            cat = s.get("category", "")
            if cat in ("credential", "backdoor", "shell", "c2_addr",
                       "sensitive_path", "suspicious"):
                sev = "HIGH"
                for pattern, category, severity in SUSPICIOUS_STRING_PATTERNS:
                    if cat == category:
                        sev = severity
                        break
                suspicious.append({**s, "severity": sev})

        return suspicious

    def get_security_score(self) -> Dict:
        """Score de sécurité global du binaire."""
        checksec   = self._checksec()
        score      = 100
        penalties  = []

        if not checksec.get("pie"):
            score -= 20
            penalties.append("No PIE (-20)")
        if not checksec.get("nx"):
            score -= 25
            penalties.append("No NX/DEP (-25)")
        if not checksec.get("canary"):
            score -= 15
            penalties.append("No stack canary (-15)")
        if checksec.get("relro") == "none":
            score -= 10
            penalties.append("No RELRO (-10)")
        if checksec.get("stripped"):
            score -= 5
            penalties.append("Stripped binary (-5)")

        # Vérifier imports dangereux
        imports  = self.get_imports()
        crit_imp = [i for i in imports if i.get("danger_level") == "CRITICAL"]
        if crit_imp:
            penalty = min(len(crit_imp) * 5, 25)
            score  -= penalty
            penalties.append(f"{len(crit_imp)} dangerous imports (-{penalty})")

        score = max(score, 0)
        if score >= 80:  rating = "GOOD"
        elif score >= 60: rating = "FAIR"
        elif score >= 40: rating = "POOR"
        else:             rating = "CRITICAL"

        return {
            "score":    score,
            "rating":   rating,
            "checksec": checksec,
            "penalties": penalties,
        }

    # ── Utils ─────────────────────────────────────────────────

    def _run_tool(self, cmd: List[str], timeout: int = 20) -> Optional[str]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout if r.returncode == 0 else None
        except Exception:
            return None

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ["B","KB","MB","GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
