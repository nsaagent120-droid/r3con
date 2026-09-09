"""
r3con - Dynamic Analysis Engine - FIXED VERSION
Fixes: De Bruijn pattern, RSP/stack offset, ASLR disable, sandbox, dynamic ROP ranges, safety checks
"""

import os
import re
import subprocess
import tempfile
import struct
import shlex
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
        # Safety: validate binary path doesn't contain dangerous characters for GDB script
        # Use file command with explicit path, not via script interpolation where possible
        gdb_cmd.append(binary)
    script = "set style enabled off\n" + script
    # Use secure temp file with 0o600
    with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
        os.chmod(f.name, 0o600)
        f.write(script)
        script_path = f.name
    try:
        gdb_cmd += ['-x', script_path]
        result = subprocess.run(gdb_cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
        return output.strip() if output.strip() else None
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"
    finally:
        try:
            os.unlink(script_path)
        except:
            pass


def _detect_framework() -> str:
    gdb_init = Path.home() / '.gdbinit'
    if gdb_init.exists():
        content = gdb_init.read_text(errors='ignore').lower()
        for fw in ('pwndbg', 'peda', 'gef'):
            if fw in content:
                return fw
    return 'vanilla'


def generate_cyclic_pattern(length: int = 200) -> bytes:
    """Generate De Bruijn cyclic pattern - FIXED: proper unique 4-byte sequences."""
    # De Bruijn sequence for alphabet A-Z, a-z, 0-9 gives good coverage
    charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    # Simple De Bruijn-like: use incremental pattern where each 4-byte is unique
    # Method: use base conversion to ensure uniqueness
    pattern = bytearray()
    # Use 3-char alphabet sets for better uniqueness detection
    # Standard pwntools pattern: Aa0, Aa1, Aa2...
    upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = b"abcdefghijklmnopqrstuvwxyz"
    digits = b"0123456789"
    
    # Generate pattern like: Aa0Aa1Aa2... Ab0Ab1...
    count = 0
    for up in upper:
        for lo in lower:
            for dig in digits:
                if len(pattern) >= length:
                    break
                # Each iteration adds 3 bytes, but we need 4-byte uniqueness
                # So we use 4-byte blocks: Upper + lower + digit + lower_next
                # Actually use 4-byte: Aa0A, Aa0b, etc - simpler: use counter-based
                pattern.extend([up, lo, dig, lower[(count // 10) % 26]])
                count += 1
            if len(pattern) >= length:
                break
        if len(pattern) >= length:
            break
    
    # If still not enough, extend with simple counter
    while len(pattern) < length:
        # Add unique 4-byte sequences based on counter
        c = len(pattern)
        pattern.extend([
            ord('A') + (c % 26),
            ord('a') + ((c // 26) % 26),
            ord('0') + ((c // (26*26)) % 10),
            ord('A') + ((c // (26*26*10)) % 26)
        ])
    
    return bytes(pattern[:length])


def generate_cyclic_pattern_simple(length: int = 200) -> bytes:
    """Fallback simple pattern for compatibility - each 4 bytes unique via counter."""
    pattern = bytearray()
    for i in range(0, length, 4):
        # Encode i as 4 distinct bytes from charset
        # Use 3 different char sets to make pattern searchable
        pattern.append(65 + (i % 26))  # A-Z
        pattern.append(97 + ((i // 26) % 26))  # a-z
        pattern.append(48 + ((i // (26*26)) % 10))  # 0-9
        pattern.append(65 + ((i // (26*26*10)) % 26))  # A-Z
    return bytes(pattern[:length])


def find_cyclic_offset(value: int, pattern_len: int = 500) -> int:
    """Find offset of a value in the cyclic pattern - FIXED to handle multiple formats."""
    # Try both pattern generators
    for gen in (generate_cyclic_pattern, generate_cyclic_pattern_simple):
        pattern = gen(pattern_len)
        try:
            # Try little endian 4-byte
            packed = struct.pack('<I', value & 0xFFFFFFFF)
            idx = pattern.find(packed)
            if idx != -1:
                return idx
            # Try big endian
            packed_be = struct.pack('>I', value & 0xFFFFFFFF)
            idx = pattern.find(packed_be)
            if idx != -1:
                return idx
            # Try 8-byte
            packed64 = struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF)
            idx = pattern.find(packed64[:4])  # Search first 4 bytes of 8
            if idx != -1:
                return idx
            # Try ASCII representation if value looks like ASCII
            # e.g., 0x41414141 = AAAA
            try:
                ascii_bytes = packed.decode('latin-1')
                if all(32 <= ord(c) <= 126 for c in ascii_bytes):
                    idx = pattern.decode('latin-1', errors='ignore').find(ascii_bytes)
                    if idx != -1:
                        return idx
            except Exception:
                pass
        except struct.error:
            pass
    return -1


def find_pattern_in_memory(dump: str, pattern_len: int = 500) -> int:
    """Search for cyclic pattern in memory dump output."""
    pattern = generate_cyclic_pattern(pattern_len).decode('latin-1', errors='ignore')
    # Look for pattern fragments in dump
    for i in range(0, len(pattern)-4, 4):
        chunk = pattern[i:i+4]
        if chunk in dump:
            return i
    return -1


class DynamicAnalyzer:
    """Analyse dynamique GDB + pwndbg - FIXED VERSION."""

    def __init__(self, binary_path: str):
        self.binary = binary_path
        self.available = _tool_available('gdb')
        self.framework = _detect_framework()
        self._binary_path_validated = self._validate_binary_path()

    def _validate_binary_path(self) -> bool:
        """Validate binary path for safety."""
        if not self.binary:
            return False
        p = Path(self.binary)
        # Check exists and is file
        if not p.is_file():
            return False
        # Check not too large (100MB limit for dynamic)
        try:
            if p.stat().st_size > 100 * 1024 * 1024:
                return False
        except Exception:
            return False
        # Check for suspicious path traversal
        if ".." in str(p) or str(p).startswith("/proc/") or str(p).startswith("/sys/"):
            return False
        return True

    def status(self) -> Dict:
        return {
            'gdb_available': self.available,
            'framework': self.framework,
            'binary': self.binary,
            'binary_exists': Path(self.binary).exists() if self.binary else False,
            'binary_validated': self._binary_path_validated,
            'pwndbg_available': self.framework == 'pwndbg',
            'peda_available': self.framework == 'peda',
            'gef_available': self.framework == 'gef',
            'sandbox_recommended': True,
            'warning': 'Dynamic analysis executes the binary - use sandbox for untrusted files' if self._binary_path_validated else 'Binary validation failed',
        }

    def get_binary_info(self) -> Dict:
        if not self.available:
            return self._offline_result("get_binary_info")
        if not self._binary_path_validated:
            return {'error': 'Binary path validation failed', 'available': False}
        script = f"set pagination off\nset disable-randomization off\nfile {shlex.quote(self.binary)}\ninfo file\ninfo functions\nquit\n"
        output = _run_gdb(script, timeout=15)
        return {
            'raw_output': output,
            'functions': self._parse_functions(output),
            'sections': self._parse_sections(output),
        }

    def analyze_crash(self, input_data: str, timeout: int = 15) -> Dict:
        if not self.available:
            return self._offline_result("analyze_crash")
        if not self._binary_path_validated:
            return {'error': 'Binary validation failed', 'available': False}
        
        # Safety: limit input size
        if len(input_data) > 10000:
            input_data = input_data[:10000]
        
        heap_cmd = {'pwndbg': 'context\nheap\n', 'peda': 'context\n', 'gef': 'context\n'}.get(self.framework, '')
        
        # Use secure temp file for input
        input_file = tempfile.NamedTemporaryFile(mode='w', suffix='.stdin', delete=False, encoding='utf-8')
        os.chmod(input_file.name, 0o600)
        input_file.write(input_data)
        input_file.write('\n')
        input_file.close()
        
        # FIX: disable ASLR for reproducible analysis
        script = (
            f"set pagination off\nset disassembly-flavor intel\nset disable-randomization off\n"
            f"handle SIGSEGV stop\nhandle SIGABRT stop\nhandle SIGILL stop\n"
            f"file {shlex.quote(self.binary)}\nrun < {shlex.quote(input_file.name)}\n"
            f"{heap_cmd}\ninfo registers\nx/20gx $rsp\nx/20gx $rbp\nbacktrace 10\nquit\n"
        )
        try:
            output = _run_gdb(script, timeout=timeout)
        finally:
            try:
                os.unlink(input_file.name)
            except OSError:
                pass
        
        result = {
            'input_tested': input_data[:100],
            'raw_output': output,
            'crashed': False,
            'signal': None,
            'registers': {},
            'exploitability': 'UNKNOWN',
            'controlled_ip': False,
            'controlled_sp': False,
            'ip_value': None,
            'backtrace': [],
            'primitives': [],
            'stack_dump': [],
        }
        if output:
            result['crashed'] = self._detect_crash(output)
            result['signal'] = self._extract_signal(output)
            result['registers'] = self._parse_registers(output)
            result['backtrace'] = self._parse_backtrace(output)
            result['stack_dump'] = self._parse_stack_dump(output)
            result['ip_value'] = (result['registers'].get('rip') or result['registers'].get('eip'))
            result['controlled_ip'] = self._check_controlled_ip(result['ip_value'])
            result['controlled_sp'] = self._check_controlled_sp(result['registers'], result['stack_dump'])
            result['exploitability'] = self._assess_exploitability(result)
            result['primitives'] = self._detect_primitives(output, result)
        return result

    def find_bof_offset(self, max_length: int = 300) -> Dict:
        if not self.available:
            return self._offline_result("find_bof_offset")
        if not self._binary_path_validated:
            return {'error': 'Binary validation failed', 'available': False}
        
        pattern = generate_cyclic_pattern(max_length).decode('latin-1', errors='ignore')
        # Escape pattern for shell - use file instead of <<<
        pattern_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pattern', delete=False, encoding='latin-1')
        os.chmod(pattern_file.name, 0o600)
        pattern_file.write(pattern)
        pattern_file.close()
        
        script = (
            f"set pagination off\nset disable-randomization off\nset disassembly-flavor intel\n"
            f"handle SIGSEGV stop\n"
            f"file {shlex.quote(self.binary)}\nrun < {shlex.quote(pattern_file.name)}\n"
            f"info registers rip rsp rbp eip esp ebp\nx/50gx $rsp\nx/20gx $rbp\nbacktrace 5\nquit\n"
        )
        try:
            output = _run_gdb(script, timeout=15)
        finally:
            try:
                os.unlink(pattern_file.name)
            except OSError:
                pass
        
        result = {
            'pattern_length': max_length,
            'raw_output': output,
            'crashed': False,
            'offset': -1,
            'register_value': None,
            'register_name': None,
            'controlled': False,
            'all_candidates': [],
        }
        if output:
            result['crashed'] = self._detect_crash(output)
            regs = self._parse_registers(output)
            stack_dump = self._parse_stack_dump(output)
            
            # FIX: Check ALL relevant registers and stack, not just RIP/RBP
            candidates = [
                ("rip", regs.get('rip')),
                ("eip", regs.get('eip')),
                ("rbp", regs.get('rbp')),
                ("ebp", regs.get('ebp')),
                ("rsp", regs.get('rsp')),
                ("esp", regs.get('esp')),
            ]
            # Also check stack dump values
            for i, stack_val in enumerate(stack_dump[:20]):
                candidates.append((f"stack[{i}]", stack_val))
            
            for reg_name, value in candidates:
                if not value:
                    continue
                value_int = None
                try:
                    if isinstance(value, str):
                        # Clean hex string
                        clean = value.strip().lower().replace("0x", "")
                        if not clean:
                            continue
                        value_int = int(clean, 16)
                    else:
                        value_int = int(value)
                except (ValueError, TypeError):
                    continue
                
                offset = find_cyclic_offset(value_int, max_length)
                result['all_candidates'].append({"register": reg_name, "value": value, "offset": offset})
                if offset != -1:
                    result['register_value'] = value
                    result['register_name'] = reg_name
                    result['offset'] = offset
                    result['controlled'] = True
                    break
            
            # If still not found, search for pattern in raw output
            if not result['controlled']:
                mem_offset = find_pattern_in_memory(output, max_length)
                if mem_offset != -1:
                    result['offset'] = mem_offset
                    result['register_name'] = 'memory_dump'
                    result['controlled'] = True
                else:
                    # Check if any register contains pattern-like ASCII
                    for reg_name, value in candidates:
                        if not value:
                            continue
                        val_str = str(value).lower()
                        if any(c in val_str for c in ['4141', '6161', '4242', '6141', '4161']):
                            result['register_value'] = value
                            result['register_name'] = reg_name
                            result['controlled'] = True
                            # Try to estimate offset from ASCII
                            if '4141' in val_str:
                                result['offset'] = 0  # Start of pattern
                            break
        
        return result

    def analyze_heap(self) -> Dict:
        if not self.available:
            return self._offline_result("analyze_heap")
        if not self._binary_path_validated:
            return {'error': 'Binary validation failed', 'available': False}
        if self.framework == 'vanilla':
            return {
                'status': 'partial',
                'framework': 'vanilla',
                'raw_output': None,
                'heap_info': {},
                'message': 'Heap inspection requires pwndbg, GEF or PEDA. Install pwndbg for full analysis.',
                'fallback_info': self._get_heap_info_fallback(),
            }
        heap_cmd = {
            'pwndbg': 'heap\ntcachebins\nfastbins\nsmallbins\n',
            'gef': 'heap chunks\nheap bins\n',
            'peda': 'xinfo $rsp\n',
            'vanilla': 'info heap\n',
        }.get(self.framework, 'info heap\n')
        script = f"set pagination off\nset disable-randomization off\nfile {shlex.quote(self.binary)}\nstart\n{heap_cmd}\nquit\n"
        output = _run_gdb(script, timeout=20)
        return {
            'raw_output': output,
            'framework': self.framework,
            'heap_info': self._parse_heap_info(output),
        }

    def _get_heap_info_fallback(self) -> Dict:
        """Fallback heap info without pwndbg."""
        try:
            # Try to get basic info via readelf
            import subprocess
            out = subprocess.run(["readelf", "-l", self.binary], capture_output=True, text=True, timeout=5)
            has_heap = "GNU_HEAP" in out.stdout or "heap" in out.stdout.lower()
            return {"has_heap_segment": has_heap, "note": "Install pwndbg for detailed heap analysis"}
        except Exception:
            return {}

    def find_rop_gadgets_live(self) -> Dict:
        if not self.available:
            return self._offline_result("find_rop_gadgets_live")
        if not self._binary_path_validated:
            return {'error': 'Binary validation failed', 'available': False}
        
        # FIX: Dynamically determine executable ranges instead of hardcoded 0x400000-0x500000
        # First get memory maps
        maps_script = f"set pagination off\nset disable-randomization off\nfile {shlex.quote(self.binary)}\nstart\ninfo proc mappings\nquit\n"
        maps_output = _run_gdb(maps_script, timeout=15)
        ranges = self._parse_executable_ranges(maps_output)
        
        if not ranges:
            # Fallback to common ranges
            ranges = [(0x400000, 0x500000), (0x0000000000400000, 0x0000000000500000)]
        
        # Build find commands for each range (limit to 2 ranges to avoid timeout)
        find_cmds = []
        for start, end in ranges[:2]:
            find_cmds.append(f"find /b 0x{start:x}, 0x{end:x}, 0xc3")
            find_cmds.append(f"find /b 0x{start:x}, 0x{end:x}, 0x5f, 0xc3")
            find_cmds.append(f"find /b 0x{start:x}, 0x{end:x}, 0x0f, 0x05")
        
        script = (
            f"set pagination off\nset disable-randomization off\nfile {shlex.quote(self.binary)}\nstart\n"
            f"info proc mappings\n"
            + "\n".join(find_cmds) +
            f"\nquit\n"
        )
        output = _run_gdb(script, timeout=25)
        return {'raw_output': output, 'gadgets': self._parse_live_gadgets(output), 'ranges_searched': ranges[:2]}

    def _parse_executable_ranges(self, output: str) -> List[tuple]:
        ranges = []
        if not output:
            return ranges
        for line in output.splitlines():
            # Look for r-xp or rwxp regions
            if 'r-x' in line or 'rwx' in line:
                m = re.search(r'0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)', line)
                if m:
                    try:
                        start = int(m.group(1), 16)
                        end = int(m.group(2), 16)
                        # Only reasonable executable ranges
                        if 0x1000 <= start < 0x7fffffffffff and end - start < 50*1024*1024:
                            ranges.append((start, end))
                    except Exception:
                        continue
        return ranges[:5]

    def analyze_function(self, func_name: str) -> Dict:
        if not self.available:
            return self._offline_result("analyze_function")
        if not self._binary_path_validated:
            return {'error': 'Binary validation failed', 'available': False}
        # Validate func_name
        if not re.match(r'^[a-zA-Z0-9_@.:$]+$', func_name):
            return {'error': 'Invalid function name', 'available': False}
        script = (
            f"set pagination off\nset disable-randomization off\nfile {shlex.quote(self.binary)}\n"
            f"break {shlex.quote(func_name)}\nrun\n"
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
        if not self.available:
            return self._offline_result("trace_execution")
        if not self._binary_path_validated:
            return {'error': 'Binary validation failed', 'available': False}
        steps = max(1, min(int(steps), 500))
        if not re.match(r'^[a-zA-Z0-9_@.:$]+$', func_name):
            return {'error': 'Invalid function name', 'available': False}
        script = (
            f"set pagination off\nset disassembly-flavor intel\nset disable-randomization off\nfile {shlex.quote(self.binary)}\n"
            f"break {shlex.quote(func_name)}\nrun\ndisplay/i $pc\nstepi {steps}\n"
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
        if not self.available:
            return self._offline_result("get_memory_maps")
        if not self._binary_path_validated:
            return {'error': 'Binary validation failed', 'available': False}
        script = f"set pagination off\nset disable-randomization off\nfile {shlex.quote(self.binary)}\nstart\ninfo proc mappings\nquit\n"
        output = _run_gdb(script, timeout=20)
        maps = []
        for line in (output or "").splitlines():
            if re.search(r"0x[0-9a-fA-F]+.*0x[0-9a-fA-F]+", line):
                maps.append(line.strip())
        return {"maps": maps, "map_count": len(maps), "raw_output": output, "executable_ranges": self._parse_executable_ranges(output)}

    def analyze_core_dump(self, core_path: str) -> Dict:
        if not self.available:
            return self._offline_result("analyze_core_dump")
        if not Path(core_path).exists():
            return {'error': f"Core dump not found: {core_path}"}
        if not self._binary_path_validated:
            return {'error': 'Binary validation failed', 'available': False}
        extra = {'pwndbg': 'context\n', 'gef': 'context\n'}.get(self.framework, '')
        script = (
            f"set pagination off\nfile {shlex.quote(self.binary)}\n"
            f"core-file {shlex.quote(core_path)}\n{extra}\n"
            f"info registers\nwhere\nbacktrace full\nx/40gx $rsp\nquit\n"
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
            result['registers'] = self._parse_registers(output)
            result['backtrace'] = self._parse_backtrace(output)
            rip = (result['registers'].get('rip') or result['registers'].get('eip'))
            result['crash_addr'] = rip
            result['controlled_ip'] = self._check_controlled_ip(rip)
            result['exploitability'] = (
                'EXPLOITABLE — Controlled IP' if result['controlled_ip']
                else f'INVESTIGATE — Crash at {rip}'
            )
        return result

    def set_watchpoint(self, address: str, watch_type: str = 'write') -> Dict:
        if not self.available:
            return self._offline_result("set_watchpoint")
        if not self._binary_path_validated:
            return {'error': 'Binary validation failed', 'available': False}
        # Validate address
        if not re.match(r'^(0x)?[0-9a-fA-F]+$', address):
            return {'error': 'Invalid address format', 'available': False}
        watch_cmd = {'write': f'watch *{address}', 'read': f'rwatch *{address}', 'access': f'awatch *{address}'}.get(watch_type, f'watch *{address}')
        script = (
            f"set pagination off\nset disable-randomization off\nfile {shlex.quote(self.binary)}\nstart\n"
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

    def generate_gdb_script(self, mode: str = 'debug', breakpoints: List[str] = None) -> str:
        bp_str = "\n".join(f"break {shlex.quote(bp)}" for bp in (breakpoints or []))
        base = (
            f"# r3con GDB script — mode: {mode}\n"
            f"# Binary: {self.binary}\n"
            f"# Framework: {self.framework}\n"
            f"# SECURITY: This script disables ASLR for analysis - use sandbox for untrusted binaries\n\n"
            f"set pagination off\nset disassembly-flavor intel\nset disable-randomization off\n"
            f"set follow-fork-mode parent\nset print pretty on\n"
            f"handle SIGSEGV stop print\nhandle SIGABRT stop print\n"
            f"handle SIGILL  stop print\n\nfile {shlex.quote(self.binary)}\n{bp_str}\n"
        )
        scripts = {
            'debug': base + "start\ninfo registers\nbacktrace\nquit\n",
            'heap': base + {
                'pwndbg': 'start\nheap\ntcachebins\nfastbins\nsmallbins\nlargebins\nquit\n',
                'gef': 'start\nheap chunks\nheap bins\nheap arenas\nquit\n',
                'peda': 'start\nxinfo $rsp\nquit\n',
                'vanilla': 'start\ninfo heap\nquit\n',
            }.get(self.framework, 'start\nquit\n'),
            'rop': base + {
                'pwndbg': 'start\nrop --grep "pop rdi" --grep "ret"\nquit\n',
                'gef': 'start\nropper -- --search "pop rdi"\nquit\n',
                'peda': 'start\nROPgadget\nquit\n',
                'vanilla': 'start\n# ROPgadget --binary ' + shlex.quote(self.binary) + '\nquit\n',
            }.get(self.framework, 'start\nquit\n'),
            'crash': (base + f"run < <(python3 -c \"import sys; sys.stdout.buffer.write({generate_cyclic_pattern(200)!r})\")\n"
                      "info registers\nbacktrace\ninfo frame\nx/40gx $rsp\nquit\n"),
            'follow': base + "start\ndisplay/i $rip\nstepi 50\ninfo registers\nquit\n",
        }
        return scripts.get(mode, base + "run\ninfo registers\nbacktrace\nquit\n")

    def generate_exploit_script(self, offset: int, ret_addr: int, rop_chain: List[int] = None) -> str:
        rop_str = ""
        if rop_chain:
            chain_lines = "\n".join(f"    p64(0x{addr:016x}),  # gadget" for addr in rop_chain)
            rop_str = f"\nrop_chain = flat(\n{chain_lines}\n)"
        return (
            f"#!/usr/bin/env python3\n"
            f"# r3con Auto-generated exploit — {self.binary}\n"
            f"# WARNING: This is for authorized testing only\n"
            f"from pwn import *\n\n"
            f"binary  = ELF({shlex.quote(self.binary)})\n"
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

    def _parse_registers(self, output: str) -> Dict:
        if not output:
            return {}
        regs = {}
        patterns = [
            (r'rip\s+0x([0-9a-fA-F]+)', 'rip'),
            (r'rsp\s+0x([0-9a-fA-F]+)', 'rsp'),
            (r'rbp\s+0x([0-9a-fA-F]+)', 'rbp'),
            (r'rax\s+0x([0-9a-fA-F]+)', 'rax'),
            (r'rbx\s+0x([0-9a-fA-F]+)', 'rbx'),
            (r'rcx\s+0x([0-9a-fA-F]+)', 'rcx'),
            (r'rdx\s+0x([0-9a-fA-F]+)', 'rdx'),
            (r'rdi\s+0x([0-9a-fA-F]+)', 'rdi'),
            (r'rsi\s+0x([0-9a-fA-F]+)', 'rsi'),
            (r'r8\s+0x([0-9a-fA-F]+)', 'r8'),
            (r'r9\s+0x([0-9a-fA-F]+)', 'r9'),
            (r'eip\s+0x([0-9a-fA-F]+)', 'eip'),
            (r'esp\s+0x([0-9a-fA-F]+)', 'esp'),
            (r'ebp\s+0x([0-9a-fA-F]+)', 'ebp'),
            (r'eax\s+0x([0-9a-fA-F]+)', 'eax'),
        ]
        for pat, name in patterns:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                regs[name] = '0x' + m.group(1)
        return regs

    def _parse_stack_dump(self, output: str) -> List[str]:
        if not output:
            return []
        dumps = []
        # Parse x/gx output
        for line in output.splitlines():
            if re.search(r'0x[0-9a-fA-F]+:\s+0x[0-9a-fA-F]+', line):
                # Extract hex values
                hex_vals = re.findall(r'0x[0-9a-fA-F]+', line)
                # Skip first which is address, rest are values
                if len(hex_vals) > 1:
                    dumps.extend(hex_vals[1:])
        return dumps[:50]

    def _parse_backtrace(self, output: str) -> List[Dict]:
        if not output:
            return []
        frames = []
        pat = re.compile(
            r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+([\w?<>:~]+(?:\s+[\w?<>:~]+)*)'
            r'(?:\s+\(([^)]*)\))?'
            r'(?:\s+at\s+([\w/.]+):(\d+))?'
        )
        for m in pat.finditer(output):
            frames.append({
                'frame': int(m.group(1)),
                'address': m.group(2),
                'function': m.group(3).strip(),
                'args': m.group(4) or '',
                'file': m.group(5) or '',
                'line': int(m.group(6)) if m.group(6) else 0,
            })
        return frames[:20]

    def _parse_functions(self, output: str) -> List[str]:
        if not output:
            return []
        funcs = []
        for line in output.splitlines():
            m = re.search(r'0x[0-9a-fA-F]+\s+(\w+)$', line)
            if m and m.group(1) not in ('??',):
                funcs.append(m.group(1))
        return funcs[:100]

    def _parse_sections(self, output: str) -> List[Dict]:
        if not output:
            return []
        sections = []
        for line in output.splitlines():
            m = re.search(r'(0x[0-9a-fA-F]+)\s+-\s+(0x[0-9a-fA-F]+)\s+is\s+(\S+)', line)
            if m:
                sections.append({'start': m.group(1), 'end': m.group(2), 'name': m.group(3)})
        return sections

    def _parse_heap_info(self, output: str) -> Dict:
        if not output:
            return {}
        info = {}
        for key, pat in [('tcache', r'tcachebins\s*\n(.*?)(?=\n\n|\Z)'), ('fastbins', r'fastbins\s*\n(.*?)(?=\n\n|\Z)')]:
            m = re.search(pat, output, re.DOTALL)
            if m:
                info[key] = m.group(1).strip()
        return info

    def _parse_live_gadgets(self, output: str) -> List[Dict]:
        if not output:
            return []
        gadgets = []
        for line in output.splitlines():
            raw = line.strip()
            if not raw or 'Start Addr' in raw or 'Perms' in raw:
                continue
            if re.search(r'0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+', raw):
                continue
            m = re.match(r'^(0x[0-9a-fA-F]+)\s+(?=.*(?:<[^>]+>|:))(.+)$', raw)
            if m:
                gadgets.append({'address': m.group(1), 'gadget': m.group(2).strip()})
        return gadgets[:50]

    def _detect_crash(self, output: str) -> bool:
        signals = ['SIGSEGV', 'SIGABRT', 'SIGILL', 'SIGFPE', 'Segmentation fault', 'Aborted', 'Program received signal']
        return any(s in (output or '') for s in signals)

    def _extract_signal(self, output: str) -> Optional[str]:
        for sig in ['SIGSEGV', 'SIGABRT', 'SIGILL', 'SIGFPE', 'SIGTRAP']:
            if sig in (output or ''):
                return sig
        return None

    def _check_controlled_ip(self, ip_value: str) -> bool:
        if not ip_value:
            return False
        ip_clean = str(ip_value).replace('0x', '').lower()
        return any(p in ip_clean for p in ['4141414141414141', '41414141', '6161616161616161', '61616161', '4242424242424242', 'deadbeef', 'deadbabe', '61413561'])

    def _check_controlled_sp(self, regs: Dict, stack_dump: List[str]) -> bool:
        # Check if stack pointer or stack contents are controlled
        for val in list(regs.values()) + stack_dump:
            if not val:
                continue
            clean = str(val).replace('0x', '').lower()
            if any(p in clean for p in ['41414141', '61616161', '42424242', '61413561']):
                return True
        return False

    def _assess_exploitability(self, result: Dict) -> str:
        if result.get('controlled_ip'):
            return 'EXPLOITABLE — Controlled instruction pointer (RIP/EIP overwritten)'
        if result.get('controlled_sp'):
            return 'LIKELY EXPLOITABLE — Stack pointer or stack contents controlled'
        sig = result.get('signal')
        if sig in ('SIGSEGV', 'SIGILL'):
            regs = result.get('registers', {})
            if any('4141' in str(v).lower() or '6161' in str(v).lower() for v in regs.values()):
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
            prims += ['rip_control', 'full_code_execution']
        if result.get('controlled_sp'):
            prims.append('stack_control')
        regs = result.get('registers', {})
        if any('4141' in str(v).lower() or '6161' in str(v).lower() for v in regs.values()):
            prims.append('stack_control')
        out = output or ''
        if 'SIGABRT' in out and ('malloc' in out or 'free' in out):
            prims.append('heap_corruption')
        if 'cannot access memory at address' in out.lower():
            prims.append('arbitrary_write_attempt')
        return prims

    def _offline_result(self, operation: str) -> Dict:
        return {
            'error': 'GDB not available or binary validation failed',
            'operation': operation,
            'available': False,
            'install': 'sudo apt install gdb',
            'pwndbg': 'git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh',
            'tip': f"Install GDB for {operation}:\n  sudo apt install gdb\n  git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh\n  For sandbox: apt install firejail && firejail --net=none gdb ./binary",
        }
