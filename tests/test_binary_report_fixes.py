import os
from modules.disasm.binary_parser import BinaryParser
from modules.integration.reverse_adapters import R2Adapter, GhidraAdapter
from modules.orchestration.orchestrator import run_analysis

TARGET = '/home/ubuntu/re-lab/build/protected-check'

def main():
    os.environ.setdefault('GHIDRA_HOME', '/home/ubuntu/tools/ghidra_12.1.3_PUBLIC')
    info = BinaryParser(TARGET).parse()
    for key in ('pie', 'nx', 'canary', 'relro', 'stripped'):
        assert info[key] == info['checksec'][key], key
    r2 = R2Adapter(TARGET, timeout=120).analyze()
    assert r2.get('status') in ('ok', 'partial')
    assert r2.get('engine') in ('radare2', 'rizin')
    gh = GhidraAdapter(TARGET, timeout=360).analyze()
    assert gh.get('status') in ('ok', 'partial')
    obs = gh.get('observations', {})
    assert obs.get('function_count', 0) > 0
    assert any(f.get('decompiled') for f in obs.get('functions', []))
    report = run_analysis(TARGET, profile='binary', timeout=360)
    assert report['status'] in ('ok', 'partial')
    r2_obs = report['results']['radare2']['observations']
    assert r2_obs.get('disassembly')
    assert r2_obs.get('pseudocode')
    print('binary report fixes passed')

if __name__ == '__main__':
    main()
