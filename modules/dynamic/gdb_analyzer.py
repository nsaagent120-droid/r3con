"""
r3con - Dynamic Analysis Engine
Analyse dynamique avec GDB + pwndbg/pwnGDB en temps réel.
"""

import os
import re
import subprocess
import tempfile
import struct
from pathlib import Path
from typing import List, Dict, Optional


def _tool_available(name: str) -> bool:
    try:
        subprocess.run([name, '--version'], capture_output=True, timeout=3)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_gdb(script: str, binary: str = None, timeout: int = 30) -> Optional[str]:
    if not _tool_available('gdb'):
        return None
    gdb_cmd = ['gdb', '-q', '--batch']
    if binary:
        gdb_cmd.append(binary)
    script = "set style enabled off\n" + script
    with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
        f.write(script)
        script_path = f.name
    try:
        gdb_cmd += ['-x', script_path]
        result = subprocess.run(gdb_cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        output = re.sub(r"\\x1b\\[[0-9;]*[A-Za-z]", "", output)
        return output.strip() if output.strip() else None
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"
    finally:
        try: os.unlink(script_path)
        except: pass


def _detect_framework() -> str:
    gdb_init = Path.home() / '.gdbinit'
    if gdb_init.exists():
        content = gdb_init.read_text(errors='ignore').lower()
        for fw in ('pwndbg','peda','gef'):
            if fw in content:
                return fw
    return 'vanilla'


def generate_cyclic_pattern(length: int = 200) -> bytes:
    """Générer un pattern cyclique unique (chaque 4 bytes est unique)."""
    pattern = []
    for i in range(length):
        a = i // (26 * 26) % 26
        b = i // 26 % 26
        c = i % 26
        pattern.append(ord('A') + a)
        pattern.append(ord('a') + b)
        pattern.append(ord('A') + c)
        pattern.append(ord('a') + (c + 1) % 26)
    return bytes(pattern[:length])


def find_cyclic_offset(value: int, pattern_len: int = 500) -> int:
    """Trouver l'offset d'une valeur dans le pattern cyclique."""
    pattern = generate_cyclic_pattern(pattern_len)
    try:
        packed = struct.pack('<I', value & 0xFFFFFFFF)
        idx = pattern.find(packed)
        if idx != -1:
            return idx
        packed64 = struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF)
        idx = pattern.find(packed64)
        if idx != -1:
            return idx
    except struct.error:
        pass
    return -1


class DynamicAnalyzer:
    """Analyse dynamique GDB + pwndbg."""

    def __init__(self, binary_path: str):
        self.binary    = binary_path
        self.available = _tool_available('gdb')
        self.framework = _detect_framework()

    def status(self) -> Dict:
        return {
            'gdb_available':    self.available,
            'framework':        self.framework,
            'binary':           self.binary,
            'binary_exists':    Path(self.binary).exists() if self.binary else False,
            'pwndbg_available': self.framework == 'pwndbg',
            'peda_available':   self.framework == 'peda',
            'gef_available':    self.framework == 'gef',
        }

    def get_binary_info(self) -> Dict:
        if not self.available:
            return self._offline_result("get_binary_info")
        script = f"set pagination off\nfile {self.binary}\ninfo file\ninfo functions\nquit\n"
        output = _run_gdb(script, timeout=15)
        return {
            'raw_output': output,
            'functions':  self._parse_functions(output),
            'sections':   self._parse_sections(output),
        }

    def analyze_crash(self, input_data: str, timeout: int = 15) -> Dict:
        if not self.available:
            return self._offline_result("analyze_crash")
        heap_cmd = {'pwndbg':'context\nheap\n','peda':'context\n','gef':'context\n'}.get(self.framework,'')
        input_file = tempfile.NamedTemporaryFile(mode='w', suffix='.stdin',
                                                  delete=False, encoding='utf-8')
        input_file.write(input_data)
        input_file.write('\n')
        input_file.close()
        script = (
            f"set pagination off\nset disassembly-flavor intel\n"
            f"handle SIGSEGV stop\nhandle SIGABRT stop\nhandle SIGILL stop\n"
            f"file {self.binary}\nrun < {input_file.name}\n"
            f"{heap_cmd}\ninfo registers\nx/20wx $rsp\nbacktrace 10\nquit\n"
        )
        try:
            output = _run_gdb(script, timeout=timeout)
        finally:
            try:
                os.unlink(input_file.name)
            except OSError:
                pass
        result = {
            'input_tested': input_data[:50],
            'raw_output':   output,
            'crashed':      False,
            'signal':       None,
            'registers':    {},
            'exploitability': 'UNKNOWN',
            'controlled_ip': False,
            'ip_value':     None,
            'backtrace':    [],
            'primitives':   [],
        }
        if output:
            result['crashed']       = self._detect_crash(output)
            result['signal']        = self._extract_signal(output)
            result['registers']     = self._parse_registers(output)
            result['backtrace']     = self._parse_backtrace(output)
            result['ip_value']      = (result['registers'].get('rip') or
                                       result['registers'].get('eip'))
            result['controlled_ip'] = self._check_controlled_ip(result['ip_value'])
            result['exploitability'] = self._assess_exploitability(result)
            result['primitives']    = self._detect_primitives(output, result)
        return result

    def find_bof_offset(self, max_length: int = 300) -> Dict:
        if not self.available:
            return self._offline_result("find_bof_offset")
        pattern = generate_cyclic_pattern(max_length).decode('latin-1')
        script  = (
            f"set pagination off\nhandle SIGSEGV stop\n"
            f"file {self.binary}\nrun <<< '{pattern}'\n"
            f"info registers rip rsp rbp\nquit\n"
        )
        output = _run_gdb(script, timeout=15)
        result = {
            'pattern_length': max_length,
            'raw_output': output,
            'crashed': False,
            'offset': -1,
            'register_value': None,
            'controlled': False,
        }
        if output:
            result['crashed'] = self._detect_crash(output)
            regs = self._parse_registers(output)
            # Avant l’instruction ret, RIP peut encore pointer vers ret alors
            # que RBP ou le mot au sommet de la pile contient le pattern.
            candidates = [("rip", regs.get('rip')), ("eip", regs.get('eip')),
                          ("rbp", regs.get('rbp')), ("ebp", regs.get('ebp'))]
            for reg_name, value in candidates:
                if not value:
                    continue
                value_int = None
                try:
                    value_int = int(value, 16) if isinstance(value, str) else int(value)
                except (ValueError, TypeError):
                    continue
                offset = find_cyclic_offset(value_int, max_length)
                if offset != -1:
                    result['register_value'] = value
                    result['register_name'] = reg_name
                    result['offset'] = offset
                    result['controlled'] = True
                    break
            if not result['controlled']:
                rip = regs.get('rip') or regs.get('eip')
                if rip:
                    result['register_value'] = rip
                    result['register_name'] = 'instruction_pointer'
                    rip_str = rip if isinstance(rip, str) else hex(rip)
                    if any(c in rip_str.lower() for c in ['6161','4141','6262']):
                        result['controlled'] = True
        return result

    def analyze_heap(self) -> Dict:
        if not self.available:
            return self._offline_result("analyze_heap")
        if self.framework == 'vanilla':
            return {
                'status': 'unsupported',
                'framework': 'vanilla',
                'raw_output': None,
                'heap_info': {},
                'message': 'Heap inspection requires pwndbg, GEF or PEDA.'
            }
        heap_cmd = {
            'pwndbg': 'heap\ntcachebins\nfastbins\nsmallbins\n',
            'gef':    'heap chunks\nheap bins\n',
            'peda':   'xinfo $rsp\n',
            'vanilla': 'info heap\n',
        }.get(self.framework, 'info heap\n')
        script = f"set pagination off\nfile {self.binary}\nstart\n{heap_cmd}\nquit\n"
        output = _run_gdb(script, timeout=20)
        return {
            'raw_output': output,
            'framework':  self.framework,
            'heap_info':  self._parse_heap_info(output),
        }

    def find_rop_gadgets_live(self) -> Dict:
        if not self.available:
            return self._offline_result("find_rop_gadgets_live")
        script = (
            f"set pagination off\nfile {self.binary}\nstart\n"
            f"info proc mappings\n"
            f"find /b 0x400000, 0x500000, 0xc3\n"
            f"find /b 0x400000, 0x500000, 0x5f, 0xc3\n"
            f"find /b 0x400000, 0x500000, 0x0f, 0x05\n"
            f"quit\n"
        )
        output = _run_gdb(script, timeout=20)
        return {'raw_output': output, 'gadgets': self._parse_live_gadgets(output)}

    def analyze_function(self, func_name: str) -> Dict:
        if not self.available:
            return self._offline_result("analyze_function")
        script = (
            f"set pagination off\nfile {self.binary}\n"
            f"break {func_name}\nrun\n"
            f"info args\ninfo locals\ndisassemble\ninfo registers\n"
            f"backtrace\nfinish\nquit\n"
        )
        output = _run_gdb(script, timeout=20)
        return {
            'function': func_name,
            'raw_output': output,
            'registers': self._parse_registers(output),
            'backtrace': self._parse_backtrace(output),
        }

    def trace_execution(self, func_name: str = "main", steps: int = 20) -> Dict:
        """Trace un nombre limité d’instructions depuis une fonction locale."""
        if not self.available:
            return self._offline_result("trace_execution")
        steps = max(1, min(int(steps), 500))
        script = (
            f"set pagination off\nset disassembly-flavor intel\nfile {self.binary}\n"
            f"break {func_name}\nrun\ndisplay/i $pc\nstepi {steps}\n"
            f"info registers\nbacktrace 10\nquit\n"
        )
        output = _run_gdb(script, timeout=max(20, steps))
        trace = []
        for line in (output or "").splitlines():
            if "=>" in line or re.search(r"0x[0-9a-fA-F]+.*(mov|push|pop|call|ret|jmp|lea|cmp|test|sub|add)", line):
                trace.append(line.strip())
        return {
            "function": func_name,
            "steps_requested": steps,
            "steps_observed": len(trace),
            "trace": trace[:steps],
            "raw_output": output,
            "registers": self._parse_registers(output),
            "backtrace": self._parse_backtrace(output),
        }

    def get_memory_maps(self) -> Dict:
        """Collecte les mappings du processus au point d’entrée du programme."""
        if not self.available:
            return self._offline_result("get_memory_maps")
        script = f"set pagination off\nfile {self.binary}\nstart\ninfo proc mappings\nquit\n"
        output = _run_gdb(script, timeout=20)
        maps = []
        for line in (output or "").splitlines():
            if re.search(r"0x[0-9a-fA-F]+.*0x[0-9a-fA-F]+", line):
                maps.append(line.strip())
        return {"maps": maps, "map_count": len(maps), "raw_output": output}

    def analyze_core_dump(self, core_path: str) -> Dict:
        if not self.available:
            return self._offline_result("analyze_core_dump")
        if not Path(core_path).exists():
            return {'error': f"Core dump not found: {core_path}"}
        extra = {'pwndbg':'context\n','gef':'context\n'}.get(self.framework,'')
        script = (
            f"set pagination off\nfile {self.binary}\n"
            f"core-file {core_path}\n{extra}\n"
            f"info registers\nwhere\nbacktrace full\nx/40wx $rsp\nquit\n"
        )
        output = _run_gdb(script, timeout=20)
        result = {
            'core_path': core_path,
            'raw_output': output,
            'registers': {},
            'backtrace': [],
            'crash_addr': None,
            'exploitability': 'UNKNOWN',
            'controlled_ip': False,
        }
        if output:
            result['registers']     = self._parse_registers(output)
            result['backtrace']     = self._parse_backtrace(output)
            rip = (result['registers'].get('rip') or
                   result['registers'].get('eip'))
            result['crash_addr']    = rip
            result['controlled_ip'] = self._check_controlled_ip(rip)
            result['exploitability'] = (
                'EXPLOITABLE — Controlled IP' if result['controlled_ip']
                else f'INVESTIGATE — Crash at {rip}'
            )
        return result

    def set_watchpoint(self, address: str, watch_type: str = 'write') -> Dict:
        if not self.available:
            return self._offline_result("set_watchpoint")
        watch_cmd = {'write':f'watch *{address}',
                     'read':f'rwatch *{address}',
                     'access':f'awatch *{address}'}.get(watch_type, f'watch *{address}')
        script = (
            f"set pagination off\nfile {self.binary}\nstart\n"
            f"{watch_cmd}\ncontinue\ninfo registers\nbacktrace\nquit\n"
        )
        output = _run_gdb(script, timeout=20)
        return {
            'address': address,
            'watch_type': watch_type,
            'raw_output': output,
            'triggered': 'Hardware watchpoint' in (output or ''),
            'registers': self._parse_registers(output),
        }

    # ── Script Generators ─────────────────────────────────────

    def generate_gdb_script(self, mode: str = 'debug',
                              breakpoints: List[str] = None) -> str:
        bp_str = "\n".join(f"break {bp}" for bp in (breakpoints or []))
        base = (
            f"# r3con GDB script — mode: {mode}\n"
            f"# Binary: {self.binary}\n"
            f"# Framework: {self.framework}\n\n"
            f"set pagination off\nset disassembly-flavor intel\n"
            f"set follow-fork-mode parent\nset print pretty on\n"
            f"handle SIGSEGV stop print\nhandle SIGABRT stop print\n"
            f"handle SIGILL  stop print\n\nfile {self.binary}\n{bp_str}\n"
        )
        scripts = {
            'debug':  base + "start\ninfo registers\nbacktrace\nquit\n",
            'heap': base + {
                'pwndbg':'start\nheap\ntcachebins\nfastbins\nsmallbins\nlargebins\nquit\n',
                'gef':   'start\nheap chunks\nheap bins\nheap arenas\nquit\n',
                'peda':  'start\nxinfo $rsp\nquit\n',
                'vanilla':'start\ninfo heap\nquit\n',
            }.get(self.framework, 'start\nquit\n'),
            'rop': base + {
                'pwndbg':'start\nrop --grep "pop rdi" --grep "ret"\nquit\n',
                'gef':   'start\nropper -- --search "pop rdi"\nquit\n',
                'peda':  'start\nROPgadget\nquit\n',
                'vanilla':'start\n# ROPgadget --binary ' + self.binary + '\nquit\n',
            }.get(self.framework, 'start\nquit\n'),
            'crash': (base +
                f"run <<< '{generate_cyclic_pattern(200).decode('latin-1')}'\n"
                "info registers\nbacktrace\ninfo frame\nx/40wx $rsp\nquit\n"),
            'follow': base + "start\ndisplay/i $rip\nstepi 50\ninfo registers\nquit\n",
        }
        return scripts.get(mode, base + "run\ninfo registers\nbacktrace\nquit\n")

    def generate_exploit_script(self, offset: int, ret_addr: int,
                                  rop_chain: List[int] = None) -> str:
        rop_str = ""
        if rop_chain:
            chain_lines = "\n".join(
                f"    p64(0x{addr:016x}),  # gadget" for addr in rop_chain)
            rop_str = f"\nrop_chain = flat(\n{chain_lines}\n)"
        return (
            f"#!/usr/bin/env python3\n"
            f"# r3con Auto-generated exploit — {self.binary}\n"
            f"from pwn import *\n\n"
            f"binary  = ELF('{self.binary}')\n"
            f"context.binary = binary\n"
            f"context.log_level = 'debug'\n\n"
            f"p = process(binary.path)\n"
            f"# p = remote('host', port)\n\n"
            f"offset  = {offset}\n"
            f"padding = b'A' * offset\n"
            f"ret     = p64(0x{ret_addr:016x})\n"
            f"{rop_str}\n\n"
            f"payload = padding + ret\n"
            f"# payload = padding + rop_chain  # if using ROP\n\n"
            f"log.info(f'Sending payload ({{len(payload)}} bytes)')\n"
            f"p.sendline(payload)\n"
            f"p.interactive()\n"
        )

    def generate_pwndbg_cheatsheet(self) -> str:
        return """
# ═══════════════════════════════════════════════════════
#   r3con — pwndbg/GDB Cheat Sheet
# ═══════════════════════════════════════════════════════

# ── Infos binaire ────────────────────────────────────
checksec                      # Protections (PIE/NX/canary/RELRO)
info file                     # Sections
info functions                # Fonctions
info proc mappings            # Mémoire virtuelle
vmmap                         # (pwndbg) mémoire

# ── Exécution ─────────────────────────────────────────
run                           # Lancer
run <<< $(python3 -c "print('A'*100)")  # stdin
continue  /  ni  /  si        # Continue / next / step
finish                        # Terminer la fonction

# ── Breakpoints ───────────────────────────────────────
b main  /  b *0x401234        # Breakpoints
watch *0x601080               # Watchpoint write
delete                        # Supprimer tous

# ── Registres & Mémoire ───────────────────────────────
info registers                # Tous les registres
x/20gx $rsp                  # 20 qwords depuis RSP
x/20i $rip                   # 20 instructions
x/s 0x404000                 # String à adresse
telescope $rsp                # (pwndbg) stack annoté

# ── Heap ─────────────────────────────────────────────
heap                          # (pwndbg) état heap
tcachebins / fastbins         # (pwndbg) bins
vis_heap_chunks               # (pwndbg) visuel heap
heap chunks  /  heap bins     # (gef) heap

# ── Stack ─────────────────────────────────────────────
stack 30                      # (pwndbg) 30 frames
backtrace  /  info frame      # Backtrace

# ── ROP ──────────────────────────────────────────────
rop --grep "pop rdi"          # (pwndbg) gadgets
ropper -- --search "pop rdi"  # (gef)
ROPgadget --binary ./binary   # standalone

# ── BOF offset ───────────────────────────────────────
cyclic 200                    # (pwndbg) pattern
cyclic -l 0x61616164          # (pwndbg) trouver offset
pattern create 200            # (gef)
pattern offset $rip           # (gef) offset

# ── Automation ───────────────────────────────────────
source script.gdb             # Charger script
set logging file /tmp/gdb.log # Logger
python print(gdb.parse_and_eval('$rip'))  # Python

# ── r3con CLI ─────────────────────────────────────────
# python -m modules.dynamic.gdb_cli status
# python -m modules.dynamic.gdb_cli crash  --binary ./v --input 'AAAA...'
# python -m modules.dynamic.gdb_cli offset --binary ./v --length 200
# python -m modules.dynamic.gdb_cli heap   --binary ./v
# python -m modules.dynamic.gdb_cli rop    --binary ./v
# python -m modules.dynamic.gdb_cli script --binary ./v --mode crash -o out.gdb
# python -m modules.dynamic.gdb_cli exploit --binary ./v --offset 72 --retaddr 0xdeadbeef
# python -m modules.dynamic.gdb_cli pattern --length 200
# python -m modules.dynamic.gdb_cli pattern --find 0x61616164
# python -m modules.dynamic.gdb_cli core   --binary ./v --core core
"""

    # ── Parsers ───────────────────────────────────────────────

    def _parse_registers(self, output: str) -> Dict:
        if not output: return {}
        regs = {}
        for pat, name in [
            (r'rip\s+0x([0-9a-fA-F]+)', 'rip'),
            (r'rsp\s+0x([0-9a-fA-F]+)', 'rsp'),
            (r'rbp\s+0x([0-9a-fA-F]+)', 'rbp'),
            (r'rax\s+0x([0-9a-fA-F]+)', 'rax'),
            (r'rdi\s+0x([0-9a-fA-F]+)', 'rdi'),
            (r'rsi\s+0x([0-9a-fA-F]+)', 'rsi'),
            (r'rdx\s+0x([0-9a-fA-F]+)', 'rdx'),
            (r'eip\s+0x([0-9a-fA-F]+)', 'eip'),
            (r'esp\s+0x([0-9a-fA-F]+)', 'esp'),
            (r'ebp\s+0x([0-9a-fA-F]+)', 'ebp'),
        ]:
            m = re.search(pat, output, re.IGNORECASE)
            if m: regs[name] = '0x' + m.group(1)
        return regs

    def _parse_backtrace(self, output: str) -> List[Dict]:
        if not output: return []
        frames = []
        pat = re.compile(
            r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+([\w?<>:~]+(?:\s+[\w?<>:~]+)*)'
            r'(?:\s+\(([^)]*)\))?'
            r'(?:\s+at\s+([\w/.]+):(\d+))?'
        )
        for m in pat.finditer(output):
            frames.append({
                'frame':    int(m.group(1)),
                'address':  m.group(2),
                'function': m.group(3).strip(),
                'args':     m.group(4) or '',
                'file':     m.group(5) or '',
                'line':     int(m.group(6)) if m.group(6) else 0,
            })
        return frames[:20]

    def _parse_functions(self, output: str) -> List[str]:
        if not output: return []
        funcs = []
        for line in output.splitlines():
            m = re.search(r'0x[0-9a-fA-F]+\s+(\w+)$', line)
            if m and m.group(1) not in ('??',):
                funcs.append(m.group(1))
        return funcs[:100]

    def _parse_sections(self, output: str) -> List[Dict]:
        if not output: return []
        sections = []
        for line in output.splitlines():
            m = re.search(r'(0x[0-9a-fA-F]+)\s+-\s+(0x[0-9a-fA-F]+)\s+is\s+(\S+)', line)
            if m:
                sections.append({'start':m.group(1),'end':m.group(2),'name':m.group(3)})
        return sections

    def _parse_heap_info(self, output: str) -> Dict:
        if not output: return {}
        info = {}
        for key, pat in [('tcache',r'tcachebins\s*\n(.*?)(?=\n\n|\Z)'),
                          ('fastbins',r'fastbins\s*\n(.*?)(?=\n\n|\Z)')]:
            m = re.search(pat, output, re.DOTALL)
            if m: info[key] = m.group(1).strip()
        return info

    def _parse_live_gadgets(self, output: str) -> List[Dict]:
        if not output:
            return []
        gadgets = []
        for line in output.splitlines():
            raw = line.strip()
            # Rejeter les en-têtes et plages de `info proc mappings`.
            if not raw or 'Start Addr' in raw or 'Perms' in raw:
                continue
            if re.search(r'0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+', raw):
                continue
            # Les sorties attendues contiennent un symbole entre <> ou un
            # séparateur instruction (:). Une adresse seule n’est pas un gadget.
            m = re.match(r'^(0x[0-9a-fA-F]+)\s+(?=.*(?:<[^>]+>|:))(.+)$', raw)
            if m:
                gadgets.append({'address': m.group(1), 'gadget': m.group(2).strip()})
        return gadgets[:50]

    def _detect_crash(self, output: str) -> bool:
        signals = ['SIGSEGV','SIGABRT','SIGILL','SIGFPE',
                   'Segmentation fault','Aborted','Program received signal']
        return any(s in (output or '') for s in signals)

    def _extract_signal(self, output: str) -> Optional[str]:
        for sig in ['SIGSEGV','SIGABRT','SIGILL','SIGFPE','SIGTRAP']:
            if sig in (output or ''): return sig
        return None

    def _check_controlled_ip(self, ip_value: str) -> bool:
        if not ip_value: return False
        ip_clean = str(ip_value).replace('0x','').lower()
        return any(p in ip_clean for p in
                   ['4141414141414141','41414141','6161616161616161',
                    '61616161','4242424242424242','deadbeef','deadbabe'])

    def _assess_exploitability(self, result: Dict) -> str:
        if result.get('controlled_ip'):
            return 'EXPLOITABLE — Controlled instruction pointer (RIP/EIP overwritten)'
        sig = result.get('signal')
        if sig in ('SIGSEGV','SIGILL'):
            regs = result.get('registers',{})
            if any('4141' in str(v).lower() for v in regs.values()):
                return 'LIKELY EXPLOITABLE — Stack pointer corrupted'
            return 'POSSIBLY EXPLOITABLE — Crash requires manual analysis'
        if sig == 'SIGABRT':
            return 'INVESTIGATE — Heap corruption detected (abort)'
        if result.get('crashed'):
            return 'CRASH DETECTED — Exploitability requires manual verification'
        return 'NO CRASH — Input did not trigger vulnerability'

    def _detect_primitives(self, output: str, result: Dict) -> List[str]:
        prims = []
        if result.get('controlled_ip'):
            prims += ['rip_control','full_code_execution']
        regs = result.get('registers',{})
        if any('4141' in str(v).lower() for v in regs.values()):
            prims.append('stack_control')
        out = output or ''
        if 'SIGABRT' in out and ('malloc' in out or 'free' in out):
            prims.append('heap_corruption')
        if 'cannot access memory at address' in out.lower():
            prims.append('arbitrary_write_attempt')
        return prims

    def _offline_result(self, operation: str) -> Dict:
        return {
            'error':     'GDB not available',
            'operation': operation,
            'available': False,
            'install':   'sudo apt install gdb',
            'pwndbg':    'git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh',
            'tip': (f"Install GDB for {operation}:\n"
                    "  sudo apt install gdb\n"
                    "  git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh"),
        }
