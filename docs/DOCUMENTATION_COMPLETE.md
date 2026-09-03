# r3con v6.0 — Documentation Complète

> Outil de recherche en sécurité avancé  
> Binary · APK · Firmware · Code Source · Analyse Dynamique GDB  
> 100% offline par défaut · Architecture en couches · 6 providers IA

---

## Table des matières

1. [Installation](#1-installation)
2. [Architecture](#2-architecture)
3. [Démarrage rapide](#3-démarrage-rapide)
4. [Analyse de code source](#4-analyse-de-code-source)
5. [Analyse binaire](#5-analyse-binaire)
6. [Analyse APK Android](#6-analyse-apk-android)
7. [Analyse Firmware IoT](#7-analyse-firmware-iot)
8. [Analyse dynamique GDB + pwndbg](#8-analyse-dynamique-gdb--pwndbg)
9. [Heap Analysis](#9-heap-analysis)
10. [Crypto Audit](#10-crypto-audit)
11. [Kernel Security](#11-kernel-security)
12. [Call Graph Analysis](#12-call-graph-analysis)
13. [ROP Gadgets](#13-rop-gadgets)
14. [Crash Analysis](#14-crash-analysis)
15. [YARA Engine](#15-yara-engine)
16. [Dependency Scanner](#16-dependency-scanner)
17. [SARIF Export & CI/CD](#17-sarif-export--cicd)
18. [Bug Bounty Reports](#18-bug-bounty-reports)
19. [Performance & Pipeline](#19-performance--pipeline)
20. [Configuration IA](#20-configuration-ia)
21. [Expert System](#21-expert-system)
22. [Base de données SQLite](#22-base-de-données-sqlite)
23. [Dashboard Web](#23-dashboard-web)
24. [API Python](#24-api-python)
25. [Intégration outils externes](#25-intégration-outils-externes)

---

## 1. Installation

```bash
# Cloner
# Depuis une copie locale du projet
cd r3con_v4.3.0

# Installation minimale (analyse statique)
pip install click rich

# Installation recommandée (+ binaire)
pip install click rich capstone lief

# Installation complète
pip install -r requirements.txt

# Pour l'analyse dynamique
sudo apt install gdb
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
pip install pwntools
```

### Dépendances optionnelles

| Package | Usage | Installation |
|---------|-------|-------------|
| `capstone` | Désassemblage multi-arch | `pip install capstone` |
| `lief` | Parsing ELF/PE/MachO | `pip install lief` |
| `binwalk` | Extraction firmware | `pip install binwalk` |
| `flask` | Dashboard web | `pip install flask` |
| `pwntools` | Exploitation scripts | `pip install pwntools` |
| `yara-python` | YARA natif | `pip install yara-python` |
| `together` | Nemotron AI | `pip install together` |
| `anthropic` | Claude AI | `pip install anthropic` |
| `openai` | DeepSeek/Groq | `pip install openai` |

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────┐
│  Couche 4 : AI Enhancement          (optionnel)     │
│  6 providers cloud + IA locale                      │
├─────────────────────────────────────────────────────┤
│  Couche 3 : Intelligence            (optionnel)     │
│  Expert System + CVSS + CWE + Priority              │
├─────────────────────────────────────────────────────┤
│  Couche 2 : Analysis Core           (toujours)      │
│  Statique · Dynamique · Binaire · APK · Firmware    │
├─────────────────────────────────────────────────────┤
│  Couche 1 : Foundation              (toujours)      │
│  CLI · SQLite · Rapports · Dashboard · Sessions     │
└─────────────────────────────────────────────────────┘
```

---

## 3. Démarrage rapide

```bash
# Activer Expert System (recommandé)
export R3CON_EXPERT_MODE=true

# Analyse d'un fichier C
r3con audit file ./vuln.c

# Analyse binaire complète
r3con disasm file ./binary --arch auto

# Analyse APK
r3con apk analyze ./app.apk

# Analyse firmware
r3con firmware analyze ./firmware.bin

# Analyse dynamique (nécessite GDB)
r3con dynamic analyze ./binary --input 'AAAA'

# Shell interactif
r3con interactive
```

---

## 4. Analyse de code source

### 4.1 Audit statique

```bash
# Audit complet
r3con audit file ./vuln.c
r3con audit file ./vuln.c --depth deep --report

# Focus spécifique
r3con audit file ./code.c --focus memory    # Mémoire uniquement
r3con audit file ./code.c --focus crypto    # Crypto uniquement
r3con audit file ./code.c --focus kernel    # Kernel uniquement
r3con audit file ./code.c --focus race      # Race conditions

# Audit récursif d'un répertoire
r3con audit dir ./src/ --recursive --report

# Langages supportés
r3con audit file ./code.py  --lang python
r3con audit file ./App.java --lang java
r3con audit file ./main.go  --lang go
r3con audit file ./lib.rs   --lang rust
```

### 4.2 Vulnérabilités détectées

**C/C++ :**
| Type | CWE | Sévérité |
|------|-----|---------|
| Stack/Heap Buffer Overflow | CWE-121/122 | CRITICAL |
| Use-After-Free | CWE-416 | CRITICAL |
| Double Free | CWE-415 | CRITICAL |
| Integer Overflow in malloc | CWE-190 | CRITICAL |
| Off-by-One | CWE-193 | HIGH |
| Format String | CWE-134 | HIGH |
| Command Injection (system) | CWE-78 | CRITICAL |
| Type Confusion | CWE-843 | HIGH |
| Dangling Pointer | CWE-825 | HIGH |
| TOCTOU Race | CWE-367 | HIGH |

**Go :**
| Type | Sévérité |
|------|---------|
| SQL Injection (string concat) | HIGH |
| Command Injection (exec.Command) | CRITICAL |
| Weak PRNG (math/rand) | HIGH |
| Weak Hash (MD5/SHA-1) | HIGH |
| TLS InsecureSkipVerify | CRITICAL |
| Unbounded Read (ioutil.ReadAll) | LOW |

**Java :**
| Type | Sévérité |
|------|---------|
| Command Injection (Runtime.exec) | CRITICAL |
| SQL Injection (Statement) | HIGH |
| Insecure Deserialization | CRITICAL |
| Weak PRNG (java.util.Random) | HIGH |
| Deprecated SSL (SSLContext) | HIGH |
| Hostname Verification Disabled | CRITICAL |

**Rust :**
| Type | Sévérité |
|------|---------|
| Unsafe Block | HIGH |
| unwrap() Panic | MEDIUM |
| Type Transmutation (mem::transmute) | CRITICAL |
| Unchecked UTF-8 | HIGH |

### 4.3 API Python

```python
import os
from r3con_core import R3con

os.environ['R3CON_EXPERT_MODE'] = 'true'
r = R3con()

code = open('./vuln.c').read()
result = r.analyze_source(code, lang='c', filename='vuln.c')

# Résultats
for finding in result['findings']:
    print(f"[{finding['severity']}] {finding['type']} L{finding['line']}")
    print(f"  CWE: {finding['cwe']} | CVSS: {finding['cvss']}")
    print(f"  Fix: {finding['fix']}")

# Taint flows
for flow in result['taint_flows']:
    print(f"Source L{flow['source_line']} → Sink L{flow['sink_line']}")

# Risk rating
print(f"Risk: {result['risk_rating']['rating']} ({result['risk_rating']['score']}/100)")
```

---

## 5. Analyse binaire

### 5.1 Désassemblage

```bash
# Désassembler un binaire
r3con disasm file ./binary
r3con disasm file ./binary --arch auto
r3con disasm file ./binary --arch x86_64

# Architectures supportées
# x86, x86_64, arm, arm64, mips, riscv

# Désassembler une fonction spécifique
r3con disasm file ./binary --function parse_input
r3con disasm file ./binary --function *0x401234

# Extraire les strings
r3con disasm strings ./binary --min-len 6

# Analyser les imports
r3con disasm imports ./binary --vuln-check
```

### 5.2 Security Score

```python
from modules.disasm.binary_parser import BinaryParser

bp    = BinaryParser('./binary')
info  = bp.parse()
score = bp.get_security_score()

print(f"Format: {info['format']} {info['arch']} {info['bits']}-bit")
print(f"Score: {score['score']}/100 — {score['rating']}")
print(f"PIE: {score['checksec']['pie']}")
print(f"NX:  {score['checksec']['nx']}")
print(f"Canary: {score['checksec']['canary']}")
print(f"RELRO:  {score['checksec']['relro']}")
print(f"Pénalités: {score['penalties']}")

# Strings suspectes
suspicious = bp.get_suspicious_strings()
for s in suspicious:
    print(f"[{s['severity']}] {s['category']}: {s['value']}")

# Imports dangereux
imports = bp.get_imports()
for imp in imports:
    if imp.get('danger_level'):
        print(f"[{imp['danger_level']}] {imp['name']}: {imp['danger_reason']}")
```

### 5.3 DisasmEngine avancé

```python
from modules.disasm.capstone_engine import DisasmEngine

de = DisasmEngine('./binary', arch='auto', max_instructions=2000)

# Désassembler
asm = de.disasm_main(max_insn=500)
print(asm)

# Statistiques
stats = de.get_statistics()
print(f"Taille: {stats['file_size_human']}")
print(f"Sections: {stats['sections']}")
print(f"Patterns dangereux: {stats['dangerous_patterns']}")
print(f"Mix instructions: {stats['instruction_mix']}")

# CFG
cfg = de.build_cfg()

# Scanner les vulnérabilités binaires
vulns = de.scan_for_vulnerabilities()
for v in vulns:
    print(f"[{v['severity']}] {v['type']} @ {v['offset']}")
```

---

## 6. Analyse APK Android

```bash
# Analyse complète
r3con apk analyze ./app.apk --report

# Manifest uniquement
r3con apk manifest ./app/AndroidManifest.xml

# Permissions avec niveau de risque
r3con apk permissions ./app.apk
```

### Vulnérabilités détectées

| Type | Risque |
|------|--------|
| Permissions dangereuses (READ_SMS, SEND_SMS) | HIGH |
| debuggable=true en production | HIGH |
| allowBackup=true | MEDIUM |
| Composants exportés sans permission | HIGH |
| SSL validation désactivée | CRITICAL |
| Secrets hardcodés dans le DEX | CRITICAL |
| Injection SQL dans le bytecode | HIGH |
| Certificate pinning absent | MEDIUM |

```python
from modules.apk.apk_analyzer import APKAnalyzer

apk = APKAnalyzer('./app.apk')
apk.load()

manifest_findings = apk.analyze_manifest()
smali_findings    = apk.analyze_smali()
string_findings   = apk.analyze_strings()
components        = apk.get_components()
summary           = apk.get_file_summary()
```

---

## 7. Analyse Firmware IoT

```bash
# Analyse complète
r3con firmware analyze ./firmware.bin --report

# Extraction filesystem
r3con firmware extract ./firmware.bin --output ./extracted/

# Strings par catégorie
r3con firmware strings ./firmware.bin --category credential
r3con firmware strings ./firmware.bin --category debug
r3con firmware strings ./firmware.bin --category url

# Carte d'entropie
r3con firmware entropy ./firmware.bin --block-size 4096
```

### Ce qui est détecté

```python
from modules.firmware.firmware_analyzer import FirmwareAnalyzer

fw = FirmwareAnalyzer('./firmware.bin')
fw.load()

ident   = fw.identify()      # Architecture, format, compression
vulns   = fw.scan_vulns()    # Backdoors, credentials, debug
entropy = fw.entropy_map()   # Zones chiffrées/compressées
paths   = fw.find_interesting_paths()  # /etc/passwd, /bin/sh
strings = fw.extract_strings()
summary = fw.get_summary()
```

---

## 8. Analyse dynamique GDB + pwndbg

> Nécessite GDB installé. pwndbg recommandé pour le maximum de fonctionnalités.

### 8.1 Installation GDB + pwndbg

```bash
# GDB
sudo apt install gdb

# pwndbg (recommandé — framework le plus complet)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Alternatives
# peda: git clone https://github.com/longld/peda ~/.peda
# gef:  bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# pwntools (pour les scripts exploit)
pip install pwntools
```

### 8.2 CLI dynamique

```bash
# État de l'environnement
r3con dynamic status
# ou:
python -m modules.dynamic.gdb_cli status

# Analyse complète (statique + dynamique)
r3con dynamic analyze ./vuln
r3con dynamic analyze ./vuln --input 'AAAA...'     # Tester un crash
r3con dynamic analyze ./vuln --offset               # Trouver offset BOF
r3con dynamic analyze ./vuln --heap                 # Analyser heap
r3con dynamic analyze ./vuln --report               # Générer rapport

# Analyser un crash
r3con dynamic crash --binary ./vuln --input 'AAAA...'
# Résultat: crashed, signal, controlled_ip, exploitabilité, registres, backtrace

# Trouver l'offset BOF (buffer overflow)
r3con dynamic offset --binary ./vuln --length 200
# Résultat: offset exact en bytes, valeur du RIP

# Analyser la heap (tcache, fastbins, smallbins)
r3con dynamic heap --binary ./vuln

# Chercher des gadgets ROP
r3con dynamic rop --binary ./vuln

# Générer un script GDB
r3con dynamic script --binary ./vuln --mode debug   -o debug.gdb
r3con dynamic script --binary ./vuln --mode heap    -o heap.gdb
r3con dynamic script --binary ./vuln --mode rop     -o rop.gdb
r3con dynamic script --binary ./vuln --mode crash   -o crash.gdb
r3con dynamic script --binary ./vuln --mode follow  -o follow.gdb
# Avec breakpoints:
r3con dynamic script --binary ./vuln --mode debug --breakpoints main,strcpy,*0x401234

# Générer un exploit pwntools
r3con dynamic exploit --binary ./vuln --offset 72 --retaddr 0x401234
# Avec ROP chain:
r3con dynamic exploit --binary ./vuln --offset 72 --retaddr 0x401234 \
      --rop 0x401234,0x401256,0x401278 -o exploit.py

# Pattern cyclique (trouver offset sans GDB)
r3con dynamic pattern --length 200            # Générer
r3con dynamic pattern --length 200 -o pat.bin # Sauvegarder
r3con dynamic pattern --find 0x61616164       # Trouver offset

# Analyser un core dump
r3con dynamic core --binary ./vuln ./core

# Cheatsheet pwndbg
r3con dynamic cheatsheet
```

### 8.3 API Python

```python
from modules.dynamic.gdb_analyzer import (
    DynamicAnalyzer,
    generate_cyclic_pattern,
    find_cyclic_offset,
)

da = DynamicAnalyzer('./vuln')

# 1. État de l'environnement
status = da.status()
print(f"GDB: {status['gdb_available']}")
print(f"Framework: {status['framework']}")  # pwndbg/peda/gef/vanilla

# 2. Analyser un crash
result = da.analyze_crash('A' * 200)
print(f"Crashed: {result['crashed']}")
print(f"Signal: {result['signal']}")
print(f"Controlled IP: {result['controlled_ip']}")
print(f"Exploitability: {result['exploitability']}")
print(f"Registres: {result['registers']}")
print(f"Primitives: {result['primitives']}")
# ex: ['rip_control', 'full_code_execution']

# 3. Trouver l'offset BOF
offset_result = da.find_bof_offset(max_length=300)
print(f"Offset: {offset_result['offset']} bytes")

# 4. Pattern cyclique
pattern = generate_cyclic_pattern(200)

# 5. Trouver offset depuis un registre crashé
import struct
rip_value = 0x6161616461616161  # valeur du RIP
offset = find_cyclic_offset(rip_value, 200)
print(f"Offset: {offset}")

# 6. Analyser la heap
heap = da.analyze_heap()
print(heap['heap_info'])

# 7. Gadgets ROP live
rop = da.find_rop_gadgets_live()
for g in rop['gadgets'][:10]:
    print(f"{g['address']}  {g['gadget']}")

# 8. Core dump
core = da.analyze_core_dump('./core')
print(f"Crash addr: {core['crash_addr']}")
print(f"Exploitability: {core['exploitability']}")

# 9. Watchpoint
wp = da.set_watchpoint('0x601080', watch_type='write')
print(f"Triggered: {wp['triggered']}")

# 10. Générer un script GDB
script = da.generate_gdb_script(
    mode='heap',
    breakpoints=['main', 'malloc', 'free']
)
with open('analyze_heap.gdb', 'w') as f:
    f.write(script)
# Utiliser: gdb -q -x analyze_heap.gdb ./vuln

# 11. Générer un exploit pwntools
exploit = da.generate_exploit_script(
    offset=72,
    ret_addr=0xdeadbeef,
    rop_chain=[0x401234, 0x401256, 0x401278]
)
with open('exploit.py', 'w') as f:
    f.write(exploit)
# Utiliser: python3 exploit.py

# 12. Via l'orchestrateur R3con
from r3con_core import R3con
r = R3con()

# Analyse complète statique + dynamique
result = r.analyze_binary_dynamic(
    './vuln',
    input_data   = 'A' * 200,
    find_offset  = True,
    analyze_heap = True,
)
print(f"Findings: {len(result['findings'])}")
print(f"Dynamic: {result['dynamic'].keys()}")
```

### 8.4 Workflow complet d'exploitation

```python
from modules.dynamic.gdb_analyzer import DynamicAnalyzer, find_cyclic_offset

da = DynamicAnalyzer('./vuln')

# Étape 1: Vérifier si le binaire crashe
result = da.analyze_crash('A' * 300)
if result['crashed']:
    print(f"[+] Crash: {result['signal']}")
    print(f"[+] Exploitable: {result['exploitability']}")

# Étape 2: Trouver l'offset exact
offset_res = da.find_bof_offset(max_length=300)
if offset_res['offset'] != -1:
    offset = offset_res['offset']
    print(f"[+] Offset: {offset} bytes")

# Étape 3: Chercher les gadgets ROP
from modules.binary.rop_gadgets import ROPGadgetFinder
rop = ROPGadgetFinder()
rop_res = rop.find_gadgets('./vuln')
print(f"[+] Gadgets: {rop_res['total_gadgets']}")
print(f"[+] Score: {rop_res['analysis']['score']}/100")
for chain in rop_res['suggested_chains']:
    print(f"[+] Chain: {chain['name']}")

# Étape 4: Générer l'exploit
exploit = da.generate_exploit_script(
    offset=offset,
    ret_addr=0x401234,  # adresse trouvée avec ROP
    rop_chain=[0x401100, 0x401200]
)
with open('exploit.py', 'w') as f:
    f.write(exploit)
print("[+] Exploit saved: exploit.py")
```

---

## 9. Heap Analysis

```python
from modules.advanced.heap_analyzer import HeapAnalyzer

# Allocateurs supportés: glibc, jemalloc, tcmalloc
ha = HeapAnalyzer(allocator='glibc')

code = open('./vuln.c').read()
findings = ha.analyze(code)

for f in findings:
    print(f"[{f['severity']}] {f['type']} L{f['line']}")
    print(f"  CWE: {f['cwe']}")
    print(f"  Exploitability: {f['exploitability']}")
    print(f"  Primitive: {f['primitive']}")
    # ex: heap_corruption, arbitrary_read_write, tcache_poisoning
    print(f"  Note {ha.allocator}: {f['allocator_note']}")
    if f.get('chain_hint'):
        print(f"  Chain: {f['chain_hint']}")
```

### Primitives détectées

| Primitive | Signification |
|-----------|--------------|
| `heap_corruption` | Double free → corrompre les métadonnées |
| `arbitrary_read_write` | UAF → lire/écrire où on veut |
| `heap_overflow` | Overflow → déborder dans le chunk suivant |
| `undersized_allocation` | Integer overflow → alloc trop petite |
| `tcache_poisoning` | Empoisonner le tcache → alloc arbitraire |
| `type_confusion` | Confusion de type → hijack vtable |
| `dangling_pointer` | Pointeur suspendu → potential UAF |

---

## 10. Crypto Audit

```python
from modules.advanced.crypto_checker import CryptoChecker

cc = CryptoChecker()
findings = cc.analyze(code)

for f in findings:
    print(f"[{f['severity']}] {f['type']} L{f['line']}")
    print(f"  CWE: {f['cwe']} | CVSS: {f['cvss']}")
    print(f"  Fix: {f['recommendation']}")
```

### Vulnérabilités détectées

| Type | CWE | CVSS |
|------|-----|------|
| MD5 (broken) | CWE-328 | 7.5 |
| SHA-1 (broken) | CWE-328 | 5.5 |
| DES (56-bit) | CWE-327 | 9.0 |
| RC4 (biased) | CWE-327 | 7.5 |
| ECB mode | CWE-327 | 7.4 |
| memcmp timing attack | CWE-208 | 5.9 |
| rand() PRNG | CWE-338 | 7.4 |
| srand(time()) seed | CWE-337 | 7.5 |
| Hardcoded key/IV | CWE-321 | 9.1 |
| Zero/static IV | CWE-329 | 7.5 |
| Nonce/IV reuse | CWE-329 | 9.1 |
| Padding oracle (CBC) | CWE-696 | 7.4 |
| Missing KDF | CWE-916 | 7.5 |
| TLS 1.0/SSL 3.0 | CWE-327 | 7.4 |
| RSA 512/1024-bit | CWE-326 | 7.5 |

---

## 11. Kernel Security

```bash
r3con advanced kernel ./driver.c --type driver
r3con advanced kernel ./module.c --type module
```

```python
from modules.advanced.kernel_patterns import KernelPatternScanner

kps = KernelPatternScanner()
findings = kps.analyze(code, ktype='driver')

# Détecte:
# - Integer overflow avant kmalloc (CRITICAL)
# - Kernel pointer leak via printk(%p) (HIGH)
# - commit_creds(prepare_kernel_cred(0)) (CRITICAL)
# - copy_from_user sans validation (HIGH)
# - Missing copy_from_user (CRITICAL)
# - Race conditions dans le kernel (HIGH)
# - IOCTL sans validation de taille (HIGH)
```

---

## 12. Call Graph Analysis

```python
from modules.callgraph.call_graph import CallGraphAnalyzer

cg  = CallGraphAnalyzer()
res = cg.analyze(code, 'vuln.c')

print(f"Fonctions: {res['stats']['total_functions']}")
print(f"Chemins dangereux: {res['stats']['dangerous_paths']}")

# Chemins source → sink cross-function
for path in res['dangerous_paths']:
    chain = ' → '.join(path['path'])
    print(f"[{path['severity']}] {chain}")
    print(f"  Sink: {path['sink']}() — {path['sink_description']}")

# Visualisation Graphviz
dot = cg.visualize_dot()
with open('callgraph.dot', 'w') as f:
    f.write(dot)
# dot -Tpng callgraph.dot -o callgraph.png

# Trouver un chemin entre deux fonctions
chain = cg.get_call_chain('main', 'strcpy')
if chain:
    print(' → '.join(chain))
```

---

## 13. ROP Gadgets

```python
from modules.binary.rop_gadgets import ROPGadgetFinder

rop = ROPGadgetFinder()
res = rop.find_gadgets('./binary', arch='auto')

print(f"Total gadgets: {res['total_gadgets']}")
print(f"Score: {res['analysis']['score']}/100")
print(f"Rating: {res['analysis']['rating']}")

# Primitives disponibles
a = res['analysis']
print(f"ret: {a['has_ret']}")
print(f"syscall: {a['has_syscall']}")
print(f"arg control (pop rdi): {a['has_arg_control']}")
print(f"write primitive: {a['has_write_primitive']}")
print(f"read primitive: {a['has_read_primitive']}")
print(f"stack pivot: {a['has_stack_pivot']}")

# Chaînes suggérées
for chain in res['suggested_chains']:
    print(f"\n{chain['name']} ({'COMPLETE' if chain['complete'] else 'PARTIAL'})")
    for step in chain['steps']:
        print(f"  {step}")
```

---

## 14. Crash Analysis

```python
from modules.binary.crash_analyzer import CrashAnalyzer

ca = CrashAnalyzer()

# Depuis un output ASAN
asan_output = open('crash.log').read()
result = ca.analyze(asan_output)

# Depuis un fichier
result = ca.analyze_file('./crash.log')

print(f"Type: {result['crash_type']}")
print(f"Exploitability: {result['exploitability']['rating']}")
# EXPLOITABLE / LIKELY EXPLOITABLE / POSSIBLY EXPLOITABLE / NOT EXPLOITABLE

# Primitives trouvées
print(f"Primitives: {result['exploitability']['primitives']}")
print(f"Controlled IP: {result['exploitability']['controlled_ip']}")

# Backtrace
for frame in result['backtrace']:
    print(f"#{frame['frame']} {frame['address']} in {frame['function']}()")

# Recommendation
print(result['recommendation'])
```

### Formats supportés

- **ASAN** — heap-buffer-overflow, use-after-free, double-free, null-deref
- **UBSAN** — integer overflow, index out of bounds, type mismatch
- **GDB** — SIGSEGV, SIGABRT, controlled RIP
- **Valgrind** — Invalid read/write, definitely lost

---

## 15. YARA Engine

```python
from modules.yara.yara_engine import YARAEngine

ye = YARAEngine()

# Scanner un fichier
findings = ye.scan_file('./binary')

# Scanner des bytes
findings = ye.scan_bytes(data, source='firmware.bin')

# Scanner un répertoire
result = ye.scan_directory('./project/', extensions=['.c','.py','.bin'])

for f in findings:
    print(f"[{f['severity']}] Rule: {f['rule']}")
    print(f"  {f['description']}")
    print(f"  Match: {f['matched']}")
    print(f"  Offset: {f['offset']}")
```

### Règles intégrées

| Catégorie | Règles |
|-----------|--------|
| Malware | Mirai, Shellcode NOP sled, ELF backdoor, Ransomware, Credential harvester |
| Exploit | Heap spray, Stack overflow test, ROP ret, Format string |
| Backdoor | Hardcoded creds, Remote shell, Debug backdoor, Telnet |
| Crypto | Weak constants, Private key material, SSL bypass |

---

## 16. Dependency Scanner

```bash
# Scanner un projet
r3con deps scan ./my_project/

# Scanner un fichier spécifique
r3con deps scan ./requirements.txt
r3con deps scan ./package.json
r3con deps scan ./pom.xml
```

```python
from modules.deps.dependency_scanner import DependencyScanner

ds = DependencyScanner()

# Scanner un répertoire
result = ds.scan_directory('./project')
print(f"Total deps: {result['stats']['total_dependencies']}")
print(f"Vulnerable: {result['stats']['vulnerable']}")

for f in result['findings']:
    print(f"[{f['severity']}] {f['package']} {f['version']}")
    print(f"  CVE: {f['cve']}")
    print(f"  Fix: {f['recommendation']}")
```

### Formats supportés

- `requirements.txt` (pip)
- `package.json` (npm)
- `pom.xml` (Maven)
- `go.mod` (Go)
- `Cargo.toml` (Rust/Cargo)
- `Gemfile` (Ruby/Bundler)

### CVEs notables dans la base

- Log4Shell (CVE-2021-44228) — log4j-core
- Spring4Shell (CVE-2022-22965) — spring-core
- Text4Shell (CVE-2022-42889) — commons-text
- Prototype pollution — lodash < 4.17.19
- JWT bypass — jsonwebtoken < 9.0.0

---

## 17. SARIF Export & CI/CD

```bash
# Exporter en SARIF (GitHub Actions / GitLab CI)
python r3con_ci.py --target . --format sarif --output results.sarif

# Formats disponibles
python r3con_ci.py --target . --format text
python r3con_ci.py --target . --format json --output report.json
python r3con_ci.py --target . --format all  --output ./reports/

# Fail sur findings critiques (pour CI)
python r3con_ci.py --target . --fail-on CRITICAL
python r3con_ci.py --target . --fail-on HIGH

# Sans cache (toujours réanalyser)
python r3con_ci.py --target . --no-cache

# Workers parallèles
python r3con_ci.py --target . --workers 8
```

### GitHub Actions

```yaml
# .github/workflows/security.yml
- name: r3con Security Scan
  run: |
    pip install click rich capstone lief
    R3CON_EXPERT_MODE=true python r3con_ci.py \
      --target . --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Générer les configs CI/CD

```python
from modules.performance.cicd_integration import CICDIntegration

ci = CICDIntegration()

# Générer tout
outputs = ci.generate_all('./my_project')
# Crée:
# .github/workflows/r3con-security.yml
# .gitlab-ci-security.yml
# .pre-commit-config-security.yaml
# Makefile.security

# Individuel
ci.generate_github_actions('.github/workflows')
ci.generate_gitlab_ci('.gitlab-ci.yml')
ci.generate_pre_commit('.pre-commit.yaml')
ci.generate_makefile_targets('Makefile.security')
```

---

## 18. Bug Bounty Reports

```python
from modules.reporting.bugbounty_report import BugBountyReportGenerator

gen = BugBountyReportGenerator()

# Rapport complet (toutes les plateformes)
path = gen.generate(
    findings,
    target='./vuln_app',
    program='hackerone',       # hackerone / bugcrowd / intigriti / generic
    researcher='Security Researcher',
    output_path='./report_h1.md'
)

# Rapport pour un seul finding
report = gen.generate_single(finding, './vuln', program='hackerone')
print(report)
```

### Ce que contient le rapport

- **Title** — Titre professionnel du bug
- **Severity** — CRITICAL/HIGH/MEDIUM + CVSS score
- **Summary** — Résumé exécutif
- **Technical Details** — Détails techniques (fichier, ligne, CWE)
- **Steps to Reproduce** — Étapes de reproduction
- **Vulnerable Code** — Extrait du code vulnérable
- **Impact** — Impact précis
- **Recommended Fix** — Correction recommandée
- **Estimated Payout** — Estimation du bounty

---

## 19. Performance & Pipeline

### Pipeline automatique

```python
from modules.performance.batch_pipeline import BatchPipeline

bp = BatchPipeline(
    expert_mode=True,
    use_cache=True,
    max_workers=4,
)

# Pipeline complet sur un fichier/répertoire
result = bp.run(
    target='./project',
    scan_deps=True,      # Scanner les dépendances
    scan_yara=True,      # YARA scan
    generate_sarif=True, # Export SARIF
    generate_bounty=True,# Rapports bug bounty
    bounty_platform='hackerone',
)

# Mode batch — plusieurs cibles
results = bp.run_batch(
    targets=['./app1', './app2', './app3'],
    scan_deps=True,
    generate_sarif=True,
)
```

### Analyse parallèle

```python
from modules.performance.parallel_analyzer import ParallelAnalyzer

pa = ParallelAnalyzer(max_workers=8)

# Analyser un répertoire entier en parallèle
result = pa.analyze_directory(
    './large_project',
    recursive=True,
    use_cache=True,
    extensions=['.c', '.cpp', '.py', '.java'],
)

print(f"Fichiers analysés: {result['files_analyzed']}")
print(f"Fichiers du cache: {result['files_skipped']}")
print(f"Temps: {result['elapsed_seconds']}s")
print(f"Vitesse: {result['stats']['files_per_second']} fichiers/s")
print(f"Top vulnérables: {result['top_vulnerable_files'][:5]}")
```

### Cache avancé

```python
from modules.performance.advanced_cache import AdvancedCache

ac = AdvancedCache(ttl_days=30)

# Vérifier le cache
if ac.is_cached('./file.c', 'audit'):
    result = ac.get('./file.c', 'audit')
else:
    result = analyze('./file.c')
    ac.set('./file.c', result, 'audit')

# Fichiers risqués en cache
risky = ac.get_risky_files(min_critical=1)

# Analytics
stats = ac.stats()
an    = ac.analytics()
print(f"Cache hit rate: {an['hit_rate']}%")
```

---

## 20. Configuration IA

```bash
# Option 1 — IA locale gratuite (recommandé)
curl https://ollama.ai/install.sh | sh
ollama pull mistral
ollama serve

# Option 2 — Nemotron gratuit (120B)
export TOGETHER_API_KEY=your_key

# Option 3 — DeepSeek ($0.14/1M tokens)
export DEEPSEEK_API_KEY=sk-...

# Option 4 — Gemini gratuit
export GEMINI_API_KEY=your_key

# Option 5 — Groq gratuit ultra-rapide
export GROQ_API_KEY=gsk-...

# Option 6 — Claude premium
export ANTHROPIC_API_KEY=sk-ant-...

# Multi-AI (plusieurs modèles en parallèle)
export R3CON_MULTI_AI=true
```

| Provider | Coût | Qualité | Vitesse |
|----------|------|---------|---------|
| Ollama local | Gratuit | ⭐⭐⭐⭐ | Dépend du modèle |
| Nemotron (Together) | Gratuit | ⭐⭐⭐⭐⭐ | Rapide |
| DeepSeek | $0.14/1M | ⭐⭐⭐⭐ | Rapide |
| Gemini | Gratuit* | ⭐⭐⭐ | Rapide |
| Groq | Gratuit | ⭐⭐⭐⭐ | Ultra rapide |
| Claude | $0.80/1M | ⭐⭐⭐⭐⭐ | Rapide |

---

## 21. Expert System

```bash
# Activer
export R3CON_EXPERT_MODE=true

# Résultats enrichis:
# - CWE-xxx sur chaque finding
# - CVSS 3.1 score + vecteur
# - Priority P0/P1/P2/P3
# - Fix recommendation précise
# - Expert deductions (règles)
# - Attack scenarios avec étapes
# - Priority matrix triée
# - Executive summary
# - Risk rating CRITICAL/HIGH/MEDIUM/LOW/MINIMAL (0-100)
```

```python
from layers.layer3_intelligence import IntelligenceLayer

il  = IntelligenceLayer()
res = il.enrich({'findings': findings})

# Findings enrichis
for f in res['findings']:
    print(f"CWE: {f['cwe']}")
    print(f"CVSS: {f['cvss']} ({f.get('cvss_vector','')})")
    print(f"Priority: {f['priority']}")
    print(f"Fix: {f['fix']}")

# Expert deductions
for d in res['expert_deductions']:
    print(f"Rule: {d['rule']} (confidence: {d['confidence']})")
    print(f"  → {', '.join(d['conclusions'])}")

# Risk rating
rr = res['risk_rating']
print(f"Risk: {rr['rating']} ({rr['score']}/100)")

# Attack scenarios
for s in res['attack_scenarios']:
    print(f"Scenario: {s['name']}")
    for step in s['steps']:
        print(f"  {step}")
```

---

## 22. Base de données SQLite

```python
from modules.db.database import AnalysisDB

db = AnalysisDB()  # Stocké dans ~/.r3con/analysis.db

# Récupérer une analyse
analysis = db.get_analysis('20260101_120000_abc123')

# Findings
findings = db.get_findings('20260101_120000_abc123')

# Exploit chains
chains = db.get_exploit_chains('20260101_120000_abc123')

# Taint flows
flows = db.get_taint_flows('20260101_120000_abc123')

# Statistiques
stats = db.get_stats('20260101_120000_abc123')
print(f"Total findings: {stats['total_findings']}")
print(f"Critical: {stats['severity_counts'].get('CRITICAL', 0)}")
print(f"Exploitable flows: {stats['exploitable_flows']}")
```

---

## 23. Dashboard Web

```bash
# Installer Flask
pip install flask

# Lancer
python -m modules.web.dashboard

# Ouvrir
# http://localhost:5000
```

**Routes API disponibles :**
- `GET /` — Dashboard HTML
- `GET /api/analysis` — Dernière analyse JSON
- `GET /api/findings` — Tous les findings
- `GET /api/stats` — Statistiques globales

---

## 24. API Python complète

```python
import os
from r3con_core import R3con

os.environ['R3CON_EXPERT_MODE'] = 'true'
r = R3con()

# ── Analyse source ─────────────────────────────────────────
result = r.analyze_source(code, lang='c', filename='vuln.c')

# ── Analyse APK ────────────────────────────────────────────
result = r.analyze_apk('./app.apk')

# ── Analyse Firmware ───────────────────────────────────────
result = r.analyze_firmware('./firmware.bin')

# ── Analyse binaire dynamique ──────────────────────────────
result = r.analyze_binary_dynamic(
    './vuln',
    input_data='A'*200,
    find_offset=True,
    analyze_heap=True,
)

# ── Crash analysis ─────────────────────────────────────────
crash = r.dynamic_crash_analysis('./vuln', 'A'*200)

# ── BOF offset ─────────────────────────────────────────────
offset = r.dynamic_find_offset('./vuln', length=300)

# ── Générer exploit ────────────────────────────────────────
exploit = r.dynamic_generate_exploit(
    './vuln', offset=72, ret_addr=0xdeadbeef,
    rop_chain=[0x401234, 0x401256]
)

# ── Générer script GDB ─────────────────────────────────────
script = r.dynamic_gdb_script(
    './vuln', mode='heap',
    breakpoints=['main', 'malloc']
)

# ── Générer rapport ────────────────────────────────────────
report_path = r.generate_report(result['analysis_id'])

# ── Status ─────────────────────────────────────────────────
status = r.status()
print(f"Expert mode: {status['expert_mode']}")
print(f"AI provider: {status['ai_provider']}")
print(f"Layers: {status['layers']}")
```

---

## 25. Intégration outils externes

```python
from modules.integration.external_tools import (
    detect_tools, Radare2Wrapper, GDBWrapper,
    StringsWrapper, AFLWrapper
)

# Détecter les outils disponibles
tools = detect_tools()
print({k: v for k, v in tools.items() if v})

# Radare2 / Rizin
r2 = Radare2Wrapper('./binary')
if r2.available:
    info    = r2.get_info()
    funcs   = r2.list_functions()
    gadgets = r2.find_rop_gadgets()
    imports = r2.get_imports()
    entropy = r2.get_entropy()
    disasm  = r2.disassemble_function('main')

# GDB Wrapper
gw = GDBWrapper('./binary')
if gw.available:
    funcs  = gw.list_functions()
    disasm = gw.disassemble_function('main')
    crash  = gw.analyze_crash('/tmp/crash_input.txt')
    script = gw.generate_exploit_script(offset=72, ret_addr='0xdeadbeef')

# Strings améliorée
sw      = StringsWrapper('./binary')
strings = sw.extract(min_len=6)
for s in strings:
    print(f"[{s['category']}] @ {s['hex']}: {s['value']}")
# Catégories: credential, url, path, ip_addr, cve_ref, log, generic

# AFL++ Fuzzing
afl = AFLWrapper('./vuln', output_dir='/tmp/afl_out')

# Générer harnais
harness_stdin = afl.generate_harness(input_type='stdin', target_func='parse_input')
harness_file  = afl.generate_harness(input_type='file')
harness_lf    = afl.generate_libfuzzer_harness(target_func='parse_input')

# Créer corpus de seeds
seeds = afl.create_seed_corpus('./seeds', seed_strings=['test', '<xml>'])

# Lancer AFL++
campaign = afl.run_campaign('./harness', './seeds', timeout_seconds=3600)
if campaign['available']:
    os.system(campaign['command'])

# Analyser les crashes
crashes = afl.analyze_crashes('/tmp/afl_out')
```

---

## Commandes de référence rapide

```bash
# Analyse source
r3con audit file ./code.c [--focus memory|crypto|race|kernel] [--depth deep] [--report]
r3con audit dir ./src/ [--recursive] [--report]

# Analyse binaire
r3con disasm file ./binary [--arch auto] [--function main] [--report]
r3con disasm strings ./binary [--min-len 6]
r3con disasm imports ./binary [--vuln-check]

# Analyse dynamique GDB
r3con dynamic status
r3con dynamic analyze ./binary [--input '...'] [--offset] [--heap] [--report]
r3con dynamic crash   --binary ./binary --input '...'
r3con dynamic offset  --binary ./binary --length 200
r3con dynamic heap    --binary ./binary
r3con dynamic rop     --binary ./binary
r3con dynamic script  --binary ./binary --mode debug|heap|rop|crash|follow [-o out.gdb]
r3con dynamic exploit --binary ./binary --offset 72 --retaddr 0x401234 [-o exploit.py]
r3con dynamic pattern [--length 200] [--find 0x61616164]
r3con dynamic core    ./binary ./core
r3con dynamic cheatsheet

# Analyse avancée
r3con advanced heap   ./code.c [--allocator glibc|jemalloc|tcmalloc]
r3con advanced crypto ./code.c
r3con advanced kernel ./code.c [--type driver|module]

# APK Android
r3con apk analyze     ./app.apk [--report]
r3con apk manifest    ./AndroidManifest.xml
r3con apk permissions ./app.apk

# Firmware IoT
r3con firmware analyze ./firmware.bin [--report]
r3con firmware extract ./firmware.bin [--output ./extracted/]
r3con firmware strings ./firmware.bin [--category credential|debug|url]
r3con firmware entropy ./firmware.bin [--block-size 4096]

# Recherche 0day
r3con research hypothesis ./target.c [--context "network daemon"] [--depth deep]
r3con research cve-match  ./code.c [--limit 15]
r3con research variant    CVE-2021-3156 ./src/
r3con research fuzz-hints ./parser.c [--format afl|libfuzzer]

# CI/CD
python r3con_ci.py --target . --format sarif --output results.sarif
python r3con_ci.py --target . --fail-on CRITICAL

# Utilitaires
r3con session --list
r3con session --show <id>
r3con interactive
```

---

*r3con v6.0 — Advanced Security Research Tool*  
*73 modules Python — Analyse statique + dynamique + IA*
