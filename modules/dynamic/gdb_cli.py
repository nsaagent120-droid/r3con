"""
r3con - GDB CLI Runner
Interface ligne de commande pour l'analyse dynamique.
Usage: python -m modules.dynamic.gdb_cli --binary ./vuln [options]
"""

import sys
import os
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.dynamic.gdb_analyzer import (
    DynamicAnalyzer,
    generate_cyclic_pattern,
    find_cyclic_offset,
)


def cmd_status(args):
    """Afficher l'état de l'environnement."""
    da = DynamicAnalyzer(args.binary or "")
    s  = da.status()
    print("\n\033[36m r3con Dynamic Analysis — Environment Status\033[0m\n")
    print(f"  GDB available  : {'\033[32m✓\033[0m' if s['gdb_available'] else '\033[31m✗ Not installed\033[0m'}")
    print(f"  Framework      : \033[33m{s['framework']}\033[0m")
    print(f"  pwndbg         : {'\033[32m✓\033[0m' if s['pwndbg_available'] else '✗'}")
    print(f"  peda           : {'\033[32m✓\033[0m' if s['peda_available'] else '✗'}")
    print(f"  gef            : {'\033[32m✓\033[0m' if s['gef_available'] else '✗'}")
    if args.binary:
        print(f"  Binary         : {args.binary}")
        print(f"  Binary exists  : {'\033[32m✓\033[0m' if s['binary_exists'] else '\033[31m✗\033[0m'}")

    if not s['gdb_available']:
        print("\n  \033[33mInstall GDB:\033[0m")
        print("    sudo apt install gdb")
        print("    git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh")
    print()


def cmd_crash(args):
    """Analyser un crash."""
    da = DynamicAnalyzer(args.binary)

    print(f"\n\033[36m[*] Analyzing crash: {args.binary}\033[0m")
    print(f"    Input: {repr(args.input[:40])}...")

    result = da.analyze_crash(args.input, timeout=args.timeout)

    print(f"\n  Crashed          : {'Yes' if result.get('crashed') else 'No'}")
    print(f"  Signal           : {result.get('signal', 'N/A')}")
    print(f"  Controlled IP    : {'YES ← CRITICAL' if result.get('controlled_ip') else 'No'}")
    print(f"  \033[33mExploitability   : {result.get('exploitability', 'UNKNOWN')}\033[0m")

    regs = result.get('registers', {})
    if regs:
        print("\n  Registers:")
        for reg, val in regs.items():
            print(f"    {reg:6s} = {val}")

    primitives = result.get('primitives', [])
    if primitives:
        print(f"\n  Primitives: {', '.join(primitives)}")

    bt = result.get('backtrace', [])
    if bt:
        print("\n  Backtrace:")
        for frame in bt[:5]:
            print(f"    #{frame['frame']} {frame['address']} in {frame['function']}()")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n  Saved to: {args.output}")


def cmd_offset(args):
    """Trouver l'offset BOF."""
    da = DynamicAnalyzer(args.binary)

    print(f"\n\033[36m[*] Finding BOF offset: {args.binary}\033[0m")
    print(f"    Pattern length: {args.length}")

    result = da.find_bof_offset(max_length=args.length)

    print(f"\n  Crashed    : {'Yes' if result.get('crashed') else 'No'}")
    print(f"  RIP value  : {result.get('register_value', 'N/A')}")
    offset = result.get('offset', -1)
    if offset != -1:
        print(f"  \033[32mOffset     : {offset} bytes ← Use this!\033[0m")
        print("\n  To verify:")
        print(f"    payload = b'A' * {offset} + p64(0xdeadbeef)")
    else:
        print("  Offset     : Not found (crash may need larger pattern or manual analysis)")
        print(f"\n  Try: --length {args.length * 2}")


def cmd_heap(args):
    """Analyser la heap."""
    da = DynamicAnalyzer(args.binary)

    print(f"\n\033[36m[*] Heap analysis: {args.binary}\033[0m")

    result = da.analyze_heap()

    if result.get('error'):
        print(f"\n  Error: {result['error']}")
        print(f"  {result.get('tip', '')}")
        return

    print(f"  Framework: {result.get('framework')}")
    heap_info = result.get('heap_info', {})
    if heap_info.get('tcache'):
        print(f"\n  TCacheBins:\n{heap_info['tcache']}")
    if heap_info.get('fastbins'):
        print(f"\n  FastBins:\n{heap_info['fastbins']}")
    if result.get('raw_output'):
        print(f"\n  Raw output:\n{result['raw_output'][:1000]}")


def cmd_rop(args):
    """Chercher des gadgets ROP en live."""
    da = DynamicAnalyzer(args.binary)

    print(f"\n\033[36m[*] Live ROP gadget search: {args.binary}\033[0m")

    result = da.find_rop_gadgets_live()

    gadgets = result.get('gadgets', [])
    print(f"\n  Found {len(gadgets)} gadgets")
    for g in gadgets[:20]:
        print(f"    {g['address']}  {g['gadget']}")

    if result.get('raw_output') and not gadgets:
        print(f"\n  Raw output:\n{result['raw_output'][:500]}")


def cmd_script(args):
    """Générer un script GDB."""
    da = DynamicAnalyzer(args.binary)

    script = da.generate_gdb_script(
        mode=args.mode,
        breakpoints=args.breakpoints.split(',') if args.breakpoints else None
    )

    if args.output:
        with open(args.output, 'w') as f:
            f.write(script)
        print(f"✓ GDB script saved: {args.output}")
        print(f"  Run: gdb -q -x {args.output} {args.binary}")
    else:
        print(script)


def cmd_exploit(args):
    """Générer un script pwntools."""
    da = DynamicAnalyzer(args.binary)

    rop_chain = None
    if args.rop:
        try:
            rop_chain = [int(x, 16) for x in args.rop.split(',')]
        except ValueError:
            pass

    script = da.generate_exploit_script(
        offset=args.offset,
        ret_addr=args.retaddr,
        rop_chain=rop_chain,
    )

    if args.output:
        with open(args.output, 'w') as f:
            f.write(script)
        os.chmod(args.output, 0o755)
        print(f"✓ Exploit script saved: {args.output}")
        print(f"  Run: python3 {args.output}")
    else:
        print(script)


def cmd_pattern(args):
    """Générer / analyser un pattern cyclique."""
    if args.find:
        try:
            value   = int(args.find, 16) if args.find.startswith('0x') \
                      else int(args.find)
            offset  = find_cyclic_offset(value, args.length)
            if offset != -1:
                print(f"\n  \033[32mOffset: {offset} bytes\033[0m")
                print(f"  Pattern value 0x{value:x} found at byte {offset}")
            else:
                print(f"\n  Offset not found for 0x{value:x}")
                print(f"  Try a longer pattern: --length {args.length * 2}")
        except ValueError:
            print(f"  Invalid value: {args.find}")
    else:
        pattern = generate_cyclic_pattern(args.length)
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(pattern)
            print(f"✓ Pattern written to {args.output} ({args.length} bytes)")
        else:
            print(pattern.decode('latin-1'))


def cmd_core(args):
    """Analyser un core dump."""
    da = DynamicAnalyzer(args.binary)

    print("\n\033[36m[*] Core dump analysis\033[0m")
    print(f"    Binary : {args.binary}")
    print(f"    Core   : {args.core}")

    result = da.analyze_core_dump(args.core)

    if result.get('error'):
        print(f"\n  Error: {result['error']}")
        return

    print(f"\n  Crash address  : {result.get('crash_addr', 'N/A')}")
    print(f"  Controlled IP  : {'YES' if result.get('controlled_ip') else 'No'}")
    print(f"  Exploitability : {result.get('exploitability', 'UNKNOWN')}")

    regs = result.get('registers', {})
    if regs:
        print("\n  Registers:")
        for reg, val in regs.items():
            print(f"    {reg:6s} = {val}")

    bt = result.get('backtrace', [])
    if bt:
        print("\n  Backtrace:")
        for frame in bt[:5]:
            print(f"    #{frame['frame']} {frame['address']} in {frame['function']}()")


def cmd_cheatsheet(args):
    """Afficher le cheatsheet pwndbg."""
    da = DynamicAnalyzer(args.binary or "")
    print(da.generate_pwndbg_cheatsheet())


def main():
    parser = argparse.ArgumentParser(
        description='r3con Dynamic Analysis — GDB + pwndbg',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m modules.dynamic.gdb_cli status
  python -m modules.dynamic.gdb_cli crash  --binary ./vuln --input 'AAAA...'
  python -m modules.dynamic.gdb_cli offset --binary ./vuln --length 200
  python -m modules.dynamic.gdb_cli heap   --binary ./vuln
  python -m modules.dynamic.gdb_cli rop    --binary ./vuln
  python -m modules.dynamic.gdb_cli script --binary ./vuln --mode crash -o crash.gdb
  python -m modules.dynamic.gdb_cli exploit --binary ./vuln --offset 72 --retaddr 0xdeadbeef
  python -m modules.dynamic.gdb_cli pattern --length 200
  python -m modules.dynamic.gdb_cli pattern --find 0x61616164
  python -m modules.dynamic.gdb_cli core   --binary ./vuln --core core
  python -m modules.dynamic.gdb_cli cheatsheet
        """
    )

    parser.add_argument('--binary', '-b', help='Binary to analyze')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--timeout', '-t', type=int, default=15, help='GDB timeout (seconds)')

    sub = parser.add_subparsers(dest='command')

    # status
    sub.add_parser('status', help='Show environment status')

    # crash
    p_crash = sub.add_parser('crash', help='Analyze a crash')
    p_crash.add_argument('--input', '-i', default='A'*200, help='Input to send to binary')

    # offset
    p_offset = sub.add_parser('offset', help='Find BOF offset')
    p_offset.add_argument('--length', '-l', type=int, default=200, help='Pattern length')

    # heap
    sub.add_parser('heap', help='Analyze heap state')

    # rop
    sub.add_parser('rop', help='Find ROP gadgets live')

    # script
    p_script = sub.add_parser('script', help='Generate GDB script')
    p_script.add_argument('--mode', '-m', default='debug',
                           choices=['debug','heap','rop','crash','follow'],
                           help='Script mode')
    p_script.add_argument('--breakpoints', help='Comma-separated breakpoints')

    # exploit
    p_exploit = sub.add_parser('exploit', help='Generate pwntools exploit')
    p_exploit.add_argument('--offset', type=int, required=True, help='BOF offset')
    p_exploit.add_argument('--retaddr', type=lambda x: int(x,16),
                            required=True, help='Return address (hex)')
    p_exploit.add_argument('--rop', help='ROP chain (comma-separated hex addresses)')

    # pattern
    p_pattern = sub.add_parser('pattern', help='Cyclic pattern operations')
    p_pattern.add_argument('--length', '-l', type=int, default=200, help='Pattern length')
    p_pattern.add_argument('--find', '-f', help='Find offset for register value (hex)')

    # core
    p_core = sub.add_parser('core', help='Analyze core dump')
    p_core.add_argument('--core', '-c', required=True, help='Core dump file path')

    # cheatsheet
    sub.add_parser('cheatsheet', help='Show pwndbg cheatsheet')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Add binary and output to subparsers
    args.binary = getattr(args, 'binary', None) or \
                  (parser.parse_known_args()[0].binary if hasattr(args,'binary') else None)

    dispatch = {
        'status':     cmd_status,
        'crash':      cmd_crash,
        'offset':     cmd_offset,
        'heap':       cmd_heap,
        'rop':        cmd_rop,
        'script':     cmd_script,
        'exploit':    cmd_exploit,
        'pattern':    cmd_pattern,
        'core':       cmd_core,
        'cheatsheet': cmd_cheatsheet,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
