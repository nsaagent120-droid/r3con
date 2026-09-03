"""
r3con - Disassembly Engine v2
Désassembleur multi-arch amélioré pour gros binaires.
Nouvelles capacités:
  - Analyse par sections (pas en bloc)
  - Détection automatique des fonctions
  - Limite configurable d'instructions
  - Statistiques d'instructions
  - Détection de patterns dangereux dans l'ASM
  - Fallback objdump amélioré
  - Support gros binaires (>10MB)
"""

import subprocess
import struct
import os
from typing import List, Dict, Tuple

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


# Patterns dangereux dans l'ASM
DANGEROUS_ASM_PATTERNS = {
    "shellcode_nop_sled":     (b"\x90" * 8,          "HIGH",     "NOP sled — possible shellcode"),
    "int3_breakpoint":        (b"\xcc\xcc\xcc",       "MEDIUM",   "INT3 breakpoints — debug artifact or shellcode"),
    "syscall_sequence":       (b"\x0f\x05",           "INFO",     "Direct syscall instruction"),
    "ret2stack":              (b"\xff\xe4",            "HIGH",     "JMP ESP — classic stack exploit"),
    "ret2reg":                (b"\xff\xe0",            "HIGH",     "JMP EAX — code exec gadget"),
}

def _cs_arch(arch: str):
    if not CAPSTONE_AVAILABLE:
        return None, None
    MAP = {
        "x86":    (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
        "x86_64": (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
        "arm":    (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
        "arm64":  (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        "mips":   (capstone.CS_ARCH_MIPS,  capstone.CS_MODE_MIPS32),
        "riscv":  (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64),
    }
    return MAP.get(arch, (None, None))


class DisasmEngine:
    def __init__(self, binary_path: str, arch: str = "auto",
                 max_instructions: int = 2000):
        self.path             = binary_path
        self.arch             = arch
        self.max_instructions = max_instructions
        self._binary          = None
        self._cs              = None
        self._data            = None
        self._file_size       = 0
        self._setup()

    def _setup(self):
        """Initialize LIEF + Capstone."""
        # Taille du fichier
        try:
            self._file_size = os.path.getsize(self.path)
        except Exception:
            pass

        if LIEF_AVAILABLE:
            try:
                self._binary = lief.parse(self.path)
            except Exception:
                pass

        if self.arch == "auto":
            self.arch = self._detect_arch()

        if CAPSTONE_AVAILABLE:
            cs_arch, cs_mode = _cs_arch(self.arch)
            if cs_arch is not None:
                self._cs = capstone.Cs(cs_arch, cs_mode)
                self._cs.detail = True
                self._cs.skipdata = True  # Skip invalid bytes

    def _detect_arch(self) -> str:
        """Détecter l'architecture depuis les headers binaires."""
        if self._binary:
            # Via LIEF
            fmt = type(self._binary).__name__
            if "ELF" in fmt:
                m = self._binary.header.machine_type
                arch_map = {
                    lief.ELF.ARCH.x86_64: "x86_64",
                    lief.ELF.ARCH.i386:   "x86",
                    lief.ELF.ARCH.ARM:    "arm",
                    lief.ELF.ARCH.AARCH64:"arm64",
                    lief.ELF.ARCH.MIPS:   "mips",
                } if LIEF_AVAILABLE else {}
                for k, v in arch_map.items():
                    if m == k:
                        return v

        # Via header bytes bruts
        try:
            with open(self.path, "rb") as f:
                header = f.read(20)
            if header[:4] == b"\x7fELF":
                header[4]
                e_machine  = struct.unpack_from("<H", header, 18)[0]
                machine_map = {
                    0x03: "x86",
                    0x3e: "x86_64",
                    0x28: "arm",
                    0xb7: "arm64",
                    0x08: "mips",
                    0xf3: "riscv",
                }
                return machine_map.get(e_machine, "x86_64")
        except Exception:
            pass

        return "x86_64"

    def _load_section(self, section_name: str = ".text") -> Tuple[bytes, int]:
        """Charger une section spécifique du binaire."""
        if self._binary and LIEF_AVAILABLE:
            try:
                section = self._binary.get_section(section_name)
                if section:
                    return bytes(section.content), section.virtual_address
            except Exception:
                pass

        # Fallback : lire le fichier entier (limité)
        try:
            with open(self.path, "rb") as f:
                # Pour les gros fichiers, lire par chunks
                if self._file_size > 50 * 1024 * 1024:  # >50MB
                    f.seek(0x1000)  # Skip headers
                    data = f.read(4 * 1024 * 1024)  # 4MB max
                else:
                    data = f.read()
            return data, 0x1000
        except Exception:
            return b"", 0

    def _load_all_sections(self) -> List[Tuple[str, bytes, int]]:
        """Charger toutes les sections de code."""
        sections = []

        if self._binary and LIEF_AVAILABLE:
            try:
                for section in self._binary.sections:
                    name = section.name
                    # Sections de code et de données intéressantes
                    if any(x in name for x in ['.text', '.plt', '.init', '.fini',
                                                'CODE', 'code', 'exec']):
                        content = bytes(section.content)
                        if content:
                            sections.append((name, content, section.virtual_address))
            except Exception:
                pass

        if not sections:
            data, addr = self._load_section(".text")
            if data:
                sections.append((".text", data, addr))

        return sections

    def disasm_main(self, max_insn: int = None) -> str:
        """
        Désassembler les sections de code principales.
        Optimisé pour les gros binaires.
        """
        limit = max_insn or self.max_instructions
        sections = self._load_all_sections()

        if not sections:
            return self._fallback_objdump(max_insn=limit)

        lines    = []
        total    = 0

        for section_name, data, base_addr in sections:
            if total >= limit:
                break

            lines.append(f"\n; ── Section: {section_name} "
                          f"(size: {len(data)} bytes, "
                          f"base: 0x{base_addr:08x}) ──")

            section_limit = min(limit - total, limit // max(1, len(sections)))
            section_lines = self._disasm_bytes(data, base_addr, section_limit)
            lines.extend(section_lines)
            total += len(section_lines)

        if not lines:
            return self._fallback_objdump(max_insn=limit)

        # Ajouter résumé
        lines.append(f"\n; Total: {total} instructions analysées")
        if total >= limit:
            lines.append(f"; [LIMITE ATTEINTE — augmenter max_instructions "
                          f"pour voir plus ({self._file_size//1024}KB binaire)]")

        return "\n".join(lines)

    def disasm_function(self, func_name: str = None,
                        address: int = None) -> str:
        """
        Désassembler une fonction spécifique.
        Cherche par nom ou adresse.
        """
        # Chercher par nom via LIEF
        if func_name and self._binary and LIEF_AVAILABLE:
            try:
                for func in self._binary.functions:
                    if func.name == func_name or func_name in func.name:
                        data, _ = self._load_section(".text")
                        if data:
                            # Calculer l'offset de la fonction
                            offset  = func.address
                            size    = max(func.size, 64)
                            chunk   = data[offset:offset + size]
                            lines   = self._disasm_bytes(chunk, func.address, 500)
                            return f"; Function: {func.name} @ 0x{func.address:x}\n" + \
                                   "\n".join(lines)
            except Exception:
                pass

        # Chercher par adresse
        if address:
            data, base = self._load_section(".text")
            if data:
                offset = address - base
                if 0 <= offset < len(data):
                    chunk = data[offset:offset + 512]
                    lines = self._disasm_bytes(chunk, address, 100)
                    return f"; @ 0x{address:x}\n" + "\n".join(lines)

        # Fallback : objdump avec grep
        if func_name:
            return self._fallback_objdump_function(func_name)

        return self.disasm_main(max_insn=200)

    def _disasm_bytes(self, data: bytes, base_addr: int,
                      max_insn: int = 500) -> List[str]:
        """Désassembler des bytes bruts."""
        if not data:
            return []

        if self._cs:
            return self._disasm_capstone(data, base_addr, max_insn)
        else:
            return self._disasm_simple(data, base_addr, max_insn)

    def _disasm_capstone(self, data: bytes, base_addr: int,
                          max_insn: int) -> List[str]:
        """Désassemblage via Capstone."""
        lines = []
        count = 0

        try:
            for insn in self._cs.disasm(data, base_addr):
                if count >= max_insn:
                    break

                # Formatage instruction
                hex_bytes = " ".join(f"{b:02x}" for b in insn.bytes[:8])
                line = f"  0x{insn.address:08x}:  {hex_bytes:<24}  {insn.mnemonic} {insn.op_str}"

                # Annotations de sécurité
                annotation = self._annotate_instruction(insn)
                if annotation:
                    line += f"  ; ⚠ {annotation}"

                lines.append(line)
                count += 1

        except Exception as e:
            lines.append(f"  ; Capstone error: {e}")

        return lines

    def _disasm_simple(self, data: bytes, base_addr: int,
                        max_insn: int) -> List[str]:
        """Désassemblage simple (sans Capstone) — patterns x86."""
        lines = []
        # Montre les bytes bruts avec patterns connus
        x86_one_byte = {
            0x55: "push rbp",
            0x5d: "pop rbp",
            0xc3: "ret",
            0x90: "nop",
            0xcc: "int3",
        }
        x86_two_byte = {
            (0xff, 0xe4): "jmp rsp",
            (0xff, 0xe0): "jmp rax",
            (0x0f, 0x05): "syscall",
        }

        i = 0
        count = 0
        while i < len(data) and count < max_insn:
            addr     = base_addr + i
            byte     = data[i]
            hex_byte = f"{byte:02x}"

            if i + 1 < len(data):
                two = (byte, data[i+1])
                if two in x86_two_byte:
                    lines.append(f"  0x{addr:08x}:  {hex_byte} {data[i+1]:02x}"
                                  f"                    {x86_two_byte[two]}")
                    i += 2
                    count += 1
                    continue

            if byte in x86_one_byte:
                lines.append(f"  0x{addr:08x}:  {hex_byte}"
                              f"                      {x86_one_byte[byte]}")
                count += 1
            elif count < 20:
                lines.append(f"  0x{addr:08x}:  {hex_byte}                      db 0x{byte:02x}")
                count += 1

            i += 1

        if not lines:
            lines.append("  ; Install capstone for full disassembly: pip install capstone")

        return lines

    def _annotate_instruction(self, insn) -> str:
        """Annoter les instructions dangereuses."""
        mnem = insn.mnemonic.lower()
        ops  = insn.op_str.lower()

        # Appels dangereux
        if mnem == "call":
            if "gets" in ops or "strcpy" in ops:
                return "DANGEROUS — no bounds check"
            if "system" in ops:
                return "Code execution risk"

        # Sauts vers registres (gadgets ROP)
        if mnem == "jmp" and any(r in ops for r in ["rsp", "esp", "rax", "eax"]):
            return "ROP gadget — jump to register"

        # Syscalls
        if mnem in ("syscall", "sysenter", "int"):
            if "0x80" in ops or mnem in ("syscall", "sysenter"):
                return "Direct syscall"

        # NOP sled
        if mnem == "nop":
            return None  # Annoté séparément

        return None

    def get_functions(self) -> List[Dict]:
        """Lister toutes les fonctions détectées dans le binaire."""
        functions = []

        if self._binary and LIEF_AVAILABLE:
            try:
                for func in self._binary.functions:
                    functions.append({
                        "name":    func.name,
                        "address": hex(func.address),
                        "size":    func.size,
                    })
                return functions
            except Exception:
                pass

        # Fallback : nm
        try:
            result = subprocess.run(
                ["nm", "-n", "--defined-only", self.path],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ("T", "t"):
                    functions.append({
                        "name":    parts[2],
                        "address": "0x" + parts[0],
                        "size":    0,
                    })
        except Exception:
            pass

        return functions[:200]

    def get_statistics(self) -> Dict:
        """
        Statistiques du binaire et des instructions.
        Très utile pour les gros binaires.
        """
        stats = {
            "file_size_bytes": self._file_size,
            "file_size_human": self._human_size(self._file_size),
            "arch":            self.arch,
            "sections":        [],
            "instruction_mix": {},
            "dangerous_patterns": [],
            "function_count":  0,
        }

        # Sections
        if self._binary and LIEF_AVAILABLE:
            try:
                for s in self._binary.sections:
                    stats["sections"].append({
                        "name":    s.name,
                        "size":    s.size,
                        "address": hex(s.virtual_address),
                    })
            except Exception:
                pass

        # Nombre de fonctions
        stats["function_count"] = len(self.get_functions())

        # Analyser les patterns dangereux dans les bytes bruts
        try:
            # Pour les gros fichiers, échantillonner
            with open(self.path, "rb") as f:
                if self._file_size > 20 * 1024 * 1024:
                    # Analyser par chunks de 1MB
                    sample_size = 1024 * 1024
                    f.seek(0x1000)
                    data = f.read(sample_size)
                else:
                    data = f.read()

            for name, pattern, sev, desc in [
                (k, v[0], v[1], v[2])
                for k, v in DANGEROUS_ASM_PATTERNS.items()
            ]:
                count = data.count(pattern)
                if count > 0:
                    stats["dangerous_patterns"].append({
                        "name":        name,
                        "count":       count,
                        "severity":    sev,
                        "description": desc,
                    })
        except Exception:
            pass

        # Mix d'instructions (via Capstone si dispo)
        if self._cs:
            try:
                data, base = self._load_section(".text")
                if data:
                    mix = {}
                    sample = data[:min(len(data), 50000)]  # 50KB d'instructions
                    for insn in self._cs.disasm(sample, base):
                        m = insn.mnemonic
                        mix[m] = mix.get(m, 0) + 1

                    # Top 10 mnemonics
                    stats["instruction_mix"] = dict(
                        sorted(mix.items(), key=lambda x: x[1], reverse=True)[:10]
                    )
            except Exception:
                pass

        return stats

    def build_cfg(self) -> str:
        """
        Construire un Control Flow Graph basique.
        Détecte les blocs de base et les branchements.
        """
        if not self._cs:
            return "; CFG requires Capstone: pip install capstone"

        data, base = self._load_section(".text")
        if not data:
            return "; No .text section found"

        # Analyser maximum 20KB pour le CFG
        sample   = data[:20000]
        blocks   = []
        cur_block = {"start": base, "insns": [], "type": "normal"}
        branches  = []
        BRANCH_MNEMS = {"jmp","je","jne","jz","jnz","jl","jle","jg","jge",
                         "jb","ja","call","ret","retq"}

        count = 0
        for insn in self._cs.disasm(sample, base):
            if count > 1000:
                break

            cur_block["insns"].append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

            if insn.mnemonic.lower() in BRANCH_MNEMS:
                cur_block["type"] = insn.mnemonic.lower()
                blocks.append(cur_block)
                branches.append({
                    "from":  insn.address,
                    "mnem":  insn.mnemonic,
                    "op":    insn.op_str,
                })
                cur_block = {
                    "start": insn.address + insn.size,
                    "insns": [],
                    "type": "normal"
                }

            count += 1

        if cur_block["insns"]:
            blocks.append(cur_block)

        # Formater le CFG
        lines = [f"; CFG — {len(blocks)} basic blocks, {len(branches)} branches\n"]
        for i, block in enumerate(blocks[:30]):
            lines.append(f"; ── Block {i+1} @ 0x{block['start']:x} "
                          f"({len(block['insns'])} insns, ends: {block['type']}) ──")
            lines.extend(f"  {insn}" for insn in block["insns"][-5:])

        lines.append(f"\n; Branches detected: {len(branches)}")
        for b in branches[:20]:
            lines.append(f";   0x{b['from']:x}: {b['mnem']} {b['op']}")

        return "\n".join(lines)

    def scan_for_vulnerabilities(self) -> List[Dict]:
        """
        Scanner le binaire pour des patterns de vulnérabilités
        directement dans le code machine.
        """
        findings  = []
        data, base = self._load_section(".text")
        if not data:
            return findings

        # Patterns dangereux dans les bytes
        for name, pattern, sev, desc in [
            (k, v[0], v[1], v[2])
            for k, v in DANGEROUS_ASM_PATTERNS.items()
        ]:
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                findings.append({
                    "type":        f"Binary Pattern: {name}",
                    "severity":    sev,
                    "offset":      hex(base + idx),
                    "description": desc,
                    "pattern":     pattern.hex(),
                    "recommendation": "Investigate this code region manually.",
                })
                offset = idx + 1
                if len(findings) > 50:
                    break

        return findings

    def _fallback_objdump(self, max_insn: int = 500) -> str:
        """Fallback via objdump."""
        try:
            result = subprocess.run(
                ["objdump", "-d", "-M", "intel",
                 "--no-show-raw-insn", self.path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                # Filtrer les lignes utiles
                useful = [l for l in lines
                          if l.strip() and not l.startswith("Disassembly")]
                return "\n".join(useful[:max_insn])
        except Exception:
            pass

        return "; objdump not available. Install: apt install binutils"

    def _fallback_objdump_function(self, func_name: str) -> str:
        """Fallback objdump pour une fonction."""
        try:
            result = subprocess.run(
                ["objdump", "-d", "-M", "intel", self.path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                lines    = result.stdout.splitlines()
                in_func  = False
                out      = []
                for line in lines:
                    if f"<{func_name}" in line:
                        in_func = True
                    if in_func:
                        out.append(line)
                        if len(out) > 200:
                            break
                    if in_func and line.strip() == "":
                        break
                if out:
                    return "\n".join(out)
        except Exception:
            pass
        return f"; Function '{func_name}' not found"

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Convertir bytes en taille lisible."""
        for unit in ["B","KB","MB","GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
