"""
r3con - ROP Gadget Finder
Trouve les gadgets ROP/JOP dans les binaires pour évaluer l'exploitabilité.
Fonctionne sans dépendances externes (fallback si Capstone absent).
"""

import struct
from typing import List, Dict


# ── Gadgets recherchés ───────────────────────────────────────

# Format: (nom, bytes_pattern, arch, description, utilité)
GADGET_SIGNATURES = {
    "x86_64": [
        # Control flow
        (b"\xc3",             "ret",              "Return — base de toute ROP chain"),
        (b"\xc2",             "ret N",            "Return with stack cleanup"),
        (b"\xff\xe0",         "jmp rax",          "Jump to register — code exec"),
        (b"\xff\xe1",         "jmp rcx",          "Jump to register"),
        (b"\xff\xe4",         "jmp rsp",          "Jump to stack — stack pivot"),
        (b"\xff\xd0",         "call rax",         "Call register — code exec"),

        # Pop gadgets (pour contrôler les registres)
        (b"\x58\xc3",         "pop rax; ret",     "Contrôle rax"),
        (b"\x5b\xc3",         "pop rbx; ret",     "Contrôle rbx"),
        (b"\x59\xc3",         "pop rcx; ret",     "Contrôle rcx — arg3 syscall"),
        (b"\x5a\xc3",         "pop rdx; ret",     "Contrôle rdx — arg3 func"),
        (b"\x5e\xc3",         "pop rsi; ret",     "Contrôle rsi — arg2 func"),
        (b"\x5f\xc3",         "pop rdi; ret",     "Contrôle rdi — arg1 func ← CRITIQUE"),
        (b"\x41\x5f\xc3",     "pop r15; ret",     "Contrôle r15"),
        (b"\x41\x5e\xc3",     "pop r14; ret",     "Contrôle r14"),

        # System call gadgets
        (b"\x0f\x05",         "syscall",          "Syscall direct — execve/etc"),
        (b"\x0f\x34",         "sysenter",         "Sysenter (32-bit compat)"),
        (b"\xcd\x80",         "int 0x80",         "Legacy syscall"),

        # Stack pivots
        (b"\x94\xc3",         "xchg rsp,rax; ret","Stack pivot via rax"),
        (b"\x87\xdc\xc3",     "xchg rbx,rbx",     "Stack pivot candidate"),

        # Write gadgets
        (b"\x89\x07\xc3",     "mov [rdi], rax; ret","Write-what-where primitive ← CRITIQUE"),
        (b"\x89\x06\xc3",     "mov [rsi], rax; ret","Write-what-where via rsi"),
        (b"\x48\x89\x07\xc3", "mov [rdi], rax; ret","64-bit write primitive"),

        # Read gadgets
        (b"\x8b\x07\xc3",     "mov rax, [rdi]; ret","Read-what-where primitive"),
        (b"\x48\x8b\x07\xc3", "mov rax, [rdi]; ret","64-bit read primitive"),

        # Useful combinations
        (b"\x31\xc0\xc3",     "xor eax, eax; ret","Zero rax — null arg"),
        (b"\x48\x31\xc0\xc3", "xor rax, rax; ret","Zero rax (64-bit)"),
        (b"\x50\xc3",         "push rax; ret",    "Push + ret — stack manipulation"),
    ],
    "x86": [
        (b"\xc3",             "ret",              "Return"),
        (b"\xff\xe4",         "jmp esp",          "Jump to stack — shellcode exec"),
        (b"\xff\xe0",         "jmp eax",          "Jump to register"),
        (b"\x5f\xc3",         "pop edi; ret",     "Contrôle edi"),
        (b"\x5e\xc3",         "pop esi; ret",     "Contrôle esi"),
        (b"\x5d\xc3",         "pop ebp; ret",     "Contrôle ebp — stack pivot"),
        (b"\x5b\xc3",         "pop ebx; ret",     "Contrôle ebx"),
        (b"\x58\xc3",         "pop eax; ret",     "Contrôle eax"),
        (b"\xcd\x80",         "int 0x80",         "Linux syscall"),
        (b"\x89\x07\xc3",     "mov [edi], eax; ret","Write primitive"),
    ],
    "arm": [
        (b"\x1e\xff\x2f\xe1", "bx lr",            "Return (ARM)"),
        (b"\x00\x80\xbd\xe8", "pop {pc}",         "Pop PC — code exec"),
        (b"\x04\xf0\x9d\xe4", "pop {r4, pc}",     "Pop r4 + PC"),
        (b"\x70\x47",         "bx lr",            "Return (Thumb)"),
        (b"\x00\xbd",         "pop {pc}",         "Pop PC (Thumb)"),
    ],
    "arm64": [
        (b"\xc0\x03\x5f\xd6", "ret",              "Return (AArch64)"),
        (b"\x00\x02\x1f\xd6", "br x16",           "Branch to register"),
        (b"\x00\x00\x1f\xd6", "br x0",            "Branch to x0 — code exec"),
    ],
}

# Classification des gadgets par utilité
GADGET_CLASSES = {
    "ret":                "chain_base",
    "pop rdi; ret":       "arg_control_critical",
    "pop rsi; ret":       "arg_control",
    "pop rdx; ret":       "arg_control",
    "syscall":            "syscall",
    "int 0x80":           "syscall",
    "jmp rsp":            "stack_pivot",
    "mov [rdi], rax; ret":"write_primitive",
    "mov rax, [rdi]; ret":"read_primitive",
    "jmp rax":            "code_exec",
    "jmp esp":            "code_exec",
    "xor rax, rax; ret":  "null_gadget",
}


class ROPGadgetFinder:
    """Find ROP/JOP gadgets in binary files."""

    def __init__(self):
        self.capstone = self._try_import_capstone()

    def _try_import_capstone(self):
        """Try to import Capstone disassembler."""
        try:
            import capstone
            return capstone
        except ImportError:
            return None

    def find_gadgets(self, binary_path: str,
                     arch: str = "auto") -> Dict:
        """
        Find ROP gadgets in a binary file.

        Args:
            binary_path: Path to binary file
            arch: Architecture (auto/x86/x86_64/arm/arm64)

        Returns:
            Dict with gadgets, analysis, and exploitability assessment
        """
        try:
            with open(binary_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return {"error": str(e)}

        # Auto-detect architecture
        if arch == "auto":
            arch = self._detect_arch(data)

        # Find gadgets
        if self.capstone:
            gadgets = self._find_with_capstone(data, arch)
        else:
            gadgets = self._find_with_patterns(data, arch)

        # Analyze exploitability
        analysis = self._analyze_exploitability(gadgets)

        # Find useful chains
        chains = self._suggest_chains(gadgets)

        return {
            "binary":          binary_path,
            "arch":            arch,
            "total_gadgets":   len(gadgets),
            "gadgets":         gadgets[:100],   # Top 100
            "analysis":        analysis,
            "suggested_chains": chains,
            "findings":        self._gadgets_to_findings(gadgets, analysis, binary_path),
        }

    def find_gadgets_bytes(self, data: bytes, arch: str = "x86_64") -> Dict:
        """Find gadgets in raw bytes."""
        if self.capstone:
            gadgets = self._find_with_capstone(data, arch)
        else:
            gadgets = self._find_with_patterns(data, arch)
        return {
            "total_gadgets": len(gadgets),
            "gadgets":       gadgets[:100],
            "analysis":      self._analyze_exploitability(gadgets),
        }

    def _detect_arch(self, data: bytes) -> str:
        """Detect architecture from ELF header."""
        if len(data) < 20:
            return "x86_64"

        # ELF magic
        if data[:4] == b"\x7fELF":
            ei_class   = data[4]   # 1=32bit, 2=64bit
            e_machine  = struct.unpack_from("<H", data, 18)[0]

            machine_map = {
                0x03: "x86",
                0x3e: "x86_64",
                0x28: "arm",
                0xb7: "arm64",
                0x08: "mips",
            }
            arch = machine_map.get(e_machine, "x86_64")
            if ei_class == 1 and arch == "x86_64":
                arch = "x86"
            return arch

        # PE magic
        if data[:2] == b"MZ":
            return "x86_64"

        return "x86_64"

    def _find_with_capstone(self, data: bytes, arch: str) -> List[Dict]:
        """Find gadgets using Capstone disassembler."""
        cs     = self.capstone
        gadgets = []

        # Configure Capstone
        arch_map = {
            "x86":    (cs.CS_ARCH_X86, cs.CS_MODE_32),
            "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
            "arm":    (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
            "arm64":  (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
        }

        cs_arch, cs_mode = arch_map.get(arch, (cs.CS_ARCH_X86, cs.CS_MODE_64))
        md = cs.Cs(cs_arch, cs_mode)

        # Find ret instructions and work backwards
        ret_bytes = {
            "x86_64": [b"\xc3", b"\xc2"],
            "x86":    [b"\xc3", b"\xc2"],
            "arm":    [b"\x1e\xff\x2f\xe1"],
            "arm64":  [b"\xc0\x03\x5f\xd6"],
        }.get(arch, [b"\xc3"])

        for ret_byte in ret_bytes:
            pos = 0
            while True:
                idx = data.find(ret_byte, pos)
                if idx == -1:
                    break

                # Try disassembling up to 5 instructions before ret
                for start_offset in range(1, 20):
                    start = max(0, idx - start_offset)
                    chunk = data[start:idx + len(ret_byte)]

                    insns = list(md.disasm(chunk, start))
                    if not insns:
                        continue

                    # Build gadget string
                    gadget_str = "; ".join(
                        f"{i.mnemonic} {i.op_str}".strip()
                        for i in insns
                    )

                    if gadget_str and len(insns) <= 5:
                        gadgets.append({
                            "offset":  idx,
                            "hex":     f"0x{idx:08x}",
                            "gadget":  gadget_str,
                            "size":    len(chunk),
                            "insn_count": len(insns),
                            "class":   GADGET_CLASSES.get(gadget_str, "other"),
                        })
                        break

                pos = idx + 1

        return self._deduplicate_gadgets(gadgets)

    def _find_with_patterns(self, data: bytes, arch: str) -> List[Dict]:
        """Find gadgets using byte pattern matching (no Capstone needed)."""
        gadgets   = []
        sigs      = GADGET_SIGNATURES.get(arch, GADGET_SIGNATURES["x86_64"])

        for pattern, name, description in sigs:
            pos = 0
            while True:
                idx = data.find(pattern, pos)
                if idx == -1:
                    break

                gadgets.append({
                    "offset":      idx,
                    "hex":         f"0x{idx:08x}",
                    "gadget":      name,
                    "description": description,
                    "size":        len(pattern),
                    "insn_count":  name.count(";") + 1,
                    "class":       GADGET_CLASSES.get(name, "other"),
                })

                pos = idx + 1

        return self._deduplicate_gadgets(gadgets)

    def _deduplicate_gadgets(self, gadgets: List[Dict]) -> List[Dict]:
        """Remove duplicate gadgets (same instruction sequence)."""
        seen  = set()
        unique = []
        for g in gadgets:
            key = g["gadget"]
            if key not in seen:
                seen.add(key)
                unique.append(g)
        return unique

    def _analyze_exploitability(self, gadgets: List[Dict]) -> Dict:
        """Analyze what exploitation primitives are available."""
        gadget_names = {g["gadget"] for g in gadgets}
        {g.get("class", "other") for g in gadgets}

        # Check for key primitives
        has_ret          = any("ret" in g for g in gadget_names)
        has_syscall      = any(g in gadget_names for g in ["syscall","int 0x80","sysenter"])
        has_arg_control  = any("pop rdi" in g or "pop edi" in g for g in gadget_names)
        has_write_prim   = any("mov [" in g for g in gadget_names)
        has_read_prim    = any("mov rax, [" in g or "mov eax, [" in g for g in gadget_names)
        has_stack_pivot  = any("jmp rsp" in g or "jmp esp" in g or "xchg rsp" in g
                               for g in gadget_names)
        has_code_exec    = any("jmp rax" in g or "jmp eax" in g or "call rax" in g
                               for g in gadget_names)

        # Compute exploitability score
        score = 0
        if has_ret:          score += 20
        if has_syscall:      score += 25
        if has_arg_control:  score += 20
        if has_write_prim:   score += 15
        if has_read_prim:    score += 10
        if has_stack_pivot:  score += 15
        if has_code_exec:    score += 20

        if score >= 70:   rating = "HIGH — Full ROP chain likely possible"
        elif score >= 40: rating = "MEDIUM — Partial exploitation possible"
        elif score >= 20: rating = "LOW — Limited gadgets"
        else:             rating = "MINIMAL — Very few useful gadgets"

        return {
            "score":          min(score, 100),
            "rating":         rating,
            "has_ret":        has_ret,
            "has_syscall":    has_syscall,
            "has_arg_control": has_arg_control,
            "has_write_primitive": has_write_prim,
            "has_read_primitive":  has_read_prim,
            "has_stack_pivot": has_stack_pivot,
            "has_code_exec":  has_code_exec,
            "total_gadgets":  len(gadgets),
        }

    def _suggest_chains(self, gadgets: List[Dict]) -> List[Dict]:
        """Suggest useful ROP chains based on available gadgets."""
        chains    = []

        # Chain 1: execve("/bin/sh") via syscall
        pop_rdi = next((g["hex"] for g in gadgets if "pop rdi" in g["gadget"]), None)
        pop_rsi = next((g["hex"] for g in gadgets if "pop rsi" in g["gadget"]), None)
        pop_rdx = next((g["hex"] for g in gadgets if "pop rdx" in g["gadget"]), None)
        pop_rax = next((g["hex"] for g in gadgets if "pop rax" in g["gadget"]), None)
        syscall = next((g["hex"] for g in gadgets if g["gadget"] == "syscall"), None)

        if pop_rdi and syscall:
            steps = [
                f"pop rdi; ret @ {pop_rdi}   → address of '/bin/sh'",
            ]
            if pop_rsi: steps.append(f"pop rsi; ret @ {pop_rsi}   → 0")
            if pop_rdx: steps.append(f"pop rdx; ret @ {pop_rdx}   → 0")
            if pop_rax: steps.append(f"pop rax; ret @ {pop_rax}   → 59 (execve)")
            steps.append(f"syscall @ {syscall}")

            chains.append({
                "name":  "execve('/bin/sh') via syscall",
                "steps": steps,
                "complete": bool(pop_rdi and pop_rsi and pop_rdx and pop_rax and syscall),
            })

        # Chain 2: ret2libc (system("/bin/sh"))
        if pop_rdi:
            chains.append({
                "name": "ret2libc: system('/bin/sh')",
                "steps": [
                    f"pop rdi; ret @ {pop_rdi}   → address of '/bin/sh' in libc",
                    "ret (alignment padding)",
                    "address of system() in libc",
                ],
                "complete": True,
            })

        # Chain 3: Write primitive chain
        write_prim = next((g for g in gadgets if "mov [rdi]" in g["gadget"]), None)
        if write_prim and pop_rdi:
            chains.append({
                "name": "Arbitrary write primitive",
                "steps": [
                    f"pop rdi; ret @ {pop_rdi}   → target address",
                    f"pop rax; ret @ {pop_rax or '?'}   → value to write",
                    f"mov [rdi], rax; ret @ {write_prim['hex']}",
                ],
                "complete": bool(write_prim and pop_rdi and pop_rax),
            })

        return chains

    def _gadgets_to_findings(self, gadgets: List[Dict],
                              analysis: Dict,
                              filepath: str) -> List[Dict]:
        """Convert gadget analysis to r3con findings."""
        findings = []
        score    = analysis.get("score", 0)

        if score >= 70:
            sev = "CRITICAL"
        elif score >= 40:
            sev = "HIGH"
        elif score >= 20:
            sev = "MEDIUM"
        else:
            return []

        # Main finding
        primitives = []
        if analysis.get("has_syscall"):      primitives.append("syscall")
        if analysis.get("has_arg_control"):  primitives.append("arg control")
        if analysis.get("has_write_primitive"): primitives.append("write-what-where")
        if analysis.get("has_read_primitive"):  primitives.append("read-what-where")
        if analysis.get("has_stack_pivot"):     primitives.append("stack pivot")

        findings.append({
            "severity":    sev,
            "type":        "ROP Gadgets Available",
            "file":        filepath,
            "line":        None,
            "description": (
                f"{len(gadgets)} ROP gadgets found. "
                f"Exploitability score: {score}/100. "
                f"Primitives available: {', '.join(primitives) or 'basic ret'}. "
                f"{analysis['rating']}"
            ),
            "recommendation": (
                "Enable ASLR, PIE, and stack canaries. "
                "Consider CFI (Control Flow Integrity) for critical binaries."
            ),
            "gadget_count": len(gadgets),
            "exploit_score": score,
        })

        return findings
