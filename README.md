# r3con v5.0.2

> Outil de recherche en sécurité avancé — Binary · APK · Firmware · Code Source
> 100% offline par défaut · Architecture en couches · 6 providers IA optionnels

```
 ██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗██║
 ██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝╚═╝  ╚═══╝
```

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![Tests: 15 passed](https://img.shields.io/badge/tests-15%20passed-brightgreen.svg)]()
[![Offline ready](https://img.shields.io/badge/offline-100%25-green.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Table des matières

1. [Concept](#concept)
2. [Installation](#installation)
3. [Démarrage rapide](#démarrage-rapide)
4. [Architecture en couches](#architecture-en-couches)
5. [Commandes](#commandes)
6. [Configuration IA](#configuration-ia-optionnel)
7. [Capacités détaillées](#capacités-détaillées)
8. [Exemples concrets](#exemples-concrets)
9. [Tests](#tests)
10. [FAQ](#faq)

---

## Statut des résultats

Chaque détection est sérialisée selon le contrat `Finding` v2.0 avec un identifiant stable, une cible, un outil, une sévérité, une confiance séparée, un statut de revue et une provenance. Les findings équivalents sont dédupliqués ; plusieurs outils indépendants peuvent augmenter la confiance et sont marqués comme corroborés.

Les détections sont des indications à vérifier et ne constituent pas, seules, une preuve de vulnérabilité. `yara-python` est utilisé lorsqu’il est installé ; sinon le scanner intégré est explicitement indiqué comme fallback de patterns et ne prétend pas implémenter toute la grammaire YARA. Le matching CVE local est heuristique ; les rapports doivent distinguer les références de classe d’une correspondance précise produit-version. Le graphe d’appels public utilise l’analyse interprocédurale AST en priorité et un repli regex conservateur.

## Concept

r3con est un outil de **R&D et bug bounty** conçu autour d'un principe simple :

> **L'outil doit être puissant sans rien configurer.
> Chaque couche supplémentaire le rend encore meilleur.**

```
┌─────────────────────────────────────────────────────┐
│  Couche 4 : AI Enhancement          (optionnel)     │
│  Cloud APIs ou IA locale ou Multi-AI                │
├─────────────────────────────────────────────────────┤
│  Couche 3 : Intelligence            (optionnel)     │
│  Expert System + CVSS + Knowledge Base              │
├─────────────────────────────────────────────────────┤
│  Couche 2 : Analysis Core           (toujours)      │
│  Audit · Heap · Crypto · Kernel · APK · Firmware    │
├─────────────────────────────────────────────────────┤
│  Couche 1 : Foundation              (toujours)      │
│  CLI · SQLite · Rapports · Dashboard · Sessions     │
└─────────────────────────────────────────────────────┘
```

---

## Installation

```bash
# Cloner le projet
# Depuis une copie locale du projet
cd r3con_v5.0.0

# Installation minimale (couches 1+2 — 100% fonctionnel)
pip install click rich

# Installation recommandée (+ analyse binaire)
pip install click rich capstone lief

# Installation complète
pip install -r requirements.txt
```

### Dépendances optionnelles

| Outil | Usage | Installation |
|-------|-------|-------------|
| `capstone` | Désassemblage multi-arch | `pip install capstone` |
| `lief` | Parsing ELF/PE/MachO | `pip install lief` |
| `binwalk` | Extraction firmware | `pip install binwalk` |
| `flask` | Dashboard web | `pip install flask` |
| `openai` | DeepSeek + Groq + Nemotron | `pip install openai` |
| `anthropic` | Claude API | `pip install anthropic` |
| `google-generativeai` | Gemini | `pip install google-generativeai` |
| `together` | Nemotron | `pip install together` |

> **Note** : Sans aucune dépendance optionnelle, l'analyse statique fonctionne
> via les fallbacks (objdump, file, nm, strings).

---

## Démarrage rapide

```bash
# Audit d'un fichier C
r3con audit file ./vuln.c

# Analyse APK Android
r3con apk analyze ./app.apk

# Analyse firmware
r3con firmware analyze ./firmware.bin

# Analyse binaire
r3con disasm file ./binary --arch auto

# Recherche de vulnérabilités avancées
r3con research hypothesis ./target.c

# Shell interactif (avec IA si configurée)
r3con interactive
```

---

## Architecture en couches

### Couche 1 — Foundation (toujours active)

Toujours présente. Aucune configuration requise.

- CLI hacker-style (Click + Rich)
- Base de données SQLite (`~/.r3con/analysis.db`)
- Générateur de rapports (Markdown / HTML / JSON)
- Dashboard web (`http://localhost:5000`)
- Gestionnaire de sessions
- Détection automatique des outils disponibles

### Couche 2 — Analysis Core (toujours active)

Toujours présente. L'outil est **déjà complet ici**.

- Audit statique (C/C++/Python/Java/Go/Rust)
- Heap analysis (UAF, double-free, overflow, tcache)
- Crypto analysis (MD5, RC4, timing, side-channel)
- Kernel analysis (race, privesc, IOCTL)
- Taint analysis (source → sink tracking)
- Hypothesis engine (sans IA)
- CVE matching (base locale)
- APK analysis (manifest, Smali, strings DEX)
- Firmware analysis (entropy, extraction, backdoors)
- Exploit chain builder

### Couche 3 — Intelligence (optionnel)

Activer avec : `export R3CON_EXPERT_MODE=true`

Ajoute sur chaque finding :
- **CWE** (CWE-121, CWE-416, CWE-190...)
- **CVSS 3.1** (score + vecteur AV/AC/PR/UI)
- **Priority** (P0/P1/P2/P3)
- **Fix** recommandation précise
- **Techniques** d'exploitation

Ajoute sur l'analyse globale :
- **Expert Rules** : 100+ règles de déduction
- **Attack Scenarios** : scénarios avec étapes concrètes
- **Priority Matrix** : tous les findings triés par urgence
- **Executive Summary** : résumé professionnel
- **Risk Rating** : CRITICAL/HIGH/MEDIUM/LOW/MINIMAL (0-100)

### Couche 4 — AI Enhancement (optionnel)

Activer avec une clé API ou un serveur IA local.

- Pseudo-code (assembleur → C commenté)
- Deep semantic analysis
- Hypothèses 0day avancées
- Shell interactif IA
- Multi-AI consensus

---

## Commandes

### Désassemblage binaire

```bash
# Désassembler avec pseudo-code IA
r3con disasm file ./binary --arch auto --output pseudocode --ai

# Désassembler une fonction spécifique
r3con disasm file ./binary --function parse_input --ai

# Extraire et analyser les strings
r3con disasm strings ./binary --min-len 6 --ai

# Analyser les imports (flaguer les fonctions dangereuses)
r3con disasm imports ./binary --vuln-check
```

### Audit de code source

```bash
# Audit complet d'un fichier
r3con audit file ./vuln.c
r3con audit file ./vuln.c --lang c --focus all --depth deep

# Focus spécifique
r3con audit file ./code.c --focus memory    # Mémoire uniquement
r3con audit file ./code.c --focus crypto    # Crypto uniquement
r3con audit file ./code.c --focus kernel    # Kernel uniquement
r3con audit file ./code.c --focus race      # Race conditions

# Audit récursif d'un répertoire
r3con audit dir ./src/ --recursive --report

# Générer un rapport
r3con audit file ./vuln.c --report
```

### Analyse avancée

```bash
# Heap exploitation primitives
r3con advanced heap ./code.c --allocator glibc
r3con advanced heap ./code.c --allocator jemalloc

# Audit cryptographique
r3con advanced crypto ./impl.c

# Analyse kernel
r3con advanced kernel ./driver.c --type driver
r3con advanced kernel ./module.c --type module

# Détection TOCTOU
r3con advanced toctou ./handler.c

# Analyse protocole
r3con advanced proto ./tls_impl.c --protocol tls
```

### APK Android

```bash
# Analyse complète
r3con apk analyze ./app.apk
r3con apk analyze ./app.apk --report

# Analyser un manifest décodé (après apktool)
apktool d app.apk
r3con apk manifest ./app/AndroidManifest.xml

# Analyse des permissions avec niveau de risque
r3con apk permissions ./app.apk
```

### Firmware

```bash
# Analyse complète
r3con firmware analyze ./firmware.bin
r3con firmware analyze ./firmware.bin --report

# Extraction filesystem (nécessite binwalk)
r3con firmware extract ./firmware.bin --output ./extracted/

# Strings par catégorie
r3con firmware strings ./firmware.bin --category credential
r3con firmware strings ./firmware.bin --category debug
r3con firmware strings ./firmware.bin --category url

# Carte d'entropie
r3con firmware entropy ./firmware.bin --block-size 4096
```

### Recherche avancée

```bash
# Moteur d'hypothèses 0day
r3con research hypothesis ./target.c
r3con research hypothesis ./target.c --context "network daemon" --depth deep

# CVE matching (offline)
r3con research cve-match ./code.c --limit 15

# Recherche de variants d'un CVE
r3con research variant CVE-2021-3156 ./src/
r3con research variant CVE-2016-5195 ./kernel/

# Analyse de patch de sécurité
r3con research patch-diff ./binary_v1.0 ./binary_v1.1

# Stratégie de fuzzing
r3con research fuzz-hints ./parser.c --format afl
r3con research fuzz-hints ./input.c --format libfuzzer
```

### Sessions et rapports

```bash
# Lister les sessions
r3con session --list

# Afficher une session
r3con session --show a1b2c3d4

# Effacer l'historique
r3con session --clear
```

### Dashboard web

```bash
# Lancer le dashboard
python -m modules.web.dashboard
# Ouvrir http://localhost:5000
```

### Shell interactif

```bash
r3con interactive

r3con> Explique cette fonction ASM
r3con> Analyse ce code pour des heap vulns
r3con> Quels CVEs correspondent à ce pattern ?
r3con> Donne-moi une stratégie de fuzzing
r3con> help   # liste des commandes
r3con> exit
```

---

## Configuration IA (optionnel)

L'outil fonctionne **sans aucune IA**. Si vous voulez l'activer :

### Option 1 — IA locale gratuite (recommandé)

```bash
# Installer Ollama
curl https://ollama.ai/install.sh | sh

# Télécharger un modèle
ollama pull llama2       # 7B — rapide
ollama pull mistral      # 7B — meilleur qualité
ollama pull neural-chat  # 7B — optimisé chat

# Lancer le serveur
ollama serve

# r3con détecte automatiquement
r3con audit file ./code.c --ai
```

### Option 2 — NVIDIA Nemotron (gratuit, 120B)

```bash
pip install together
export TOGETHER_API_KEY=...   # https://api.together.ai/
r3con audit file ./code.c --ai
```

### Option 3 — DeepSeek (très bon marché)

```bash
pip install openai
export DEEPSEEK_API_KEY=sk-...   # https://platform.deepseek.com/
# $0.14 par million de tokens
```

### Option 4 — Google Gemini (gratuit avec limites)

```bash
pip install google-generativeai
export GEMINI_API_KEY=...   # https://aistudio.google.com/
# 15 requêtes/minute gratuit
```

### Option 5 — Groq (gratuit, très rapide)

```bash
pip install openai
export GROQ_API_KEY=gsk-...   # https://console.groq.com/
```

### Option 6 — Anthropic Claude (premium)

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...   # https://console.anthropic.com/
```

### Multi-AI (plusieurs modèles en parallèle)

```bash
# Lancer plusieurs serveurs locaux
ollama serve &
# LM Studio sur port 1234

# Activer Multi-AI
export R3CON_MULTI_AI=true
r3con audit file ./code.c --ai
# → consensus de plusieurs modèles
```

### Détection automatique

r3con détecte automatiquement le provider disponible dans cet ordre :

```
1. IA locale (Ollama, LM Studio, vLLM, LocalAI)
2. ANTHROPIC_API_KEY
3. DEEPSEEK_API_KEY
4. GEMINI_API_KEY
5. GROQ_API_KEY
6. TOGETHER_API_KEY
7. Offline (mode par défaut)
```

---

## Capacités détaillées

### Vulnérabilités détectées

#### Mémoire
| Vulnérabilité | CWE | Méthode |
|--------------|-----|---------|
| Stack buffer overflow | CWE-121 | Statique |
| Heap buffer overflow | CWE-122 | Statique |
| Use-After-Free | CWE-416 | Statique + Taint |
| Double-Free | CWE-415 | Statique |
| Off-by-one | CWE-193 | Statique |
| Integer overflow | CWE-190 | Statique |
| Format string | CWE-134 | Statique + Taint |
| Type confusion | CWE-843 | Statique |

#### Cryptographie
| Vulnérabilité | CWE | Méthode |
|--------------|-----|---------|
| MD5 / SHA-1 / DES / RC4 | CWE-327 | Statique |
| Timing side-channel | CWE-208 | Statique |
| Weak PRNG (rand, srand) | CWE-338 | Statique |
| Hardcoded key/IV/nonce | CWE-321 | Statique |
| Zero IV / null nonce | CWE-329 | Statique |
| Padding oracle | CWE-696 | Statique + IA |
| ECB mode | CWE-327 | Statique |

#### Kernel
| Vulnérabilité | CWE | Méthode |
|--------------|-----|---------|
| Integer overflow avant kmalloc | CWE-190 | Statique |
| Missing copy_from_user | CWE-125 | Statique |
| Race condition | CWE-362 | Statique |
| Privilege escalation | CWE-269 | Statique |
| Kernel pointer leak | CWE-200 | Statique |
| IOCTL sans validation | CWE-20 | Statique |

#### Android APK
| Vulnérabilité | Méthode |
|--------------|---------|
| Permissions dangereuses | Manifest |
| Debuggable en production | Manifest |
| AllowBackup | Manifest |
| Composants exportés | Manifest |
| Crypto faible dans bytecode | Smali |
| SSL désactivé | Smali |
| Secrets hardcodés | DEX strings |
| Injection SQL | Smali |

#### Firmware
| Vulnérabilité | Méthode |
|--------------|---------|
| Credentials hardcodés | Strings |
| Credentials par défaut | Strings |
| Backdoors telnet/SSH | Strings |
| Debug interfaces (UART, JTAG) | Strings |
| Mises à jour HTTP non signées | Strings |
| Permissions chmod 777 | Strings |
| Libs vulnérables (OpenSSL 0.x) | Strings |

### Formats supportés

| Format | Module | Fallback |
|--------|--------|---------|
| ELF (Linux) | LIEF | readelf/nm |
| PE (Windows) | LIEF | strings |
| Mach-O (macOS) | LIEF | file |
| APK (Android) | zipfile stdlib | apktool |
| gzip/bzip2/xz | stdlib | - |
| SquashFS | binwalk | - |
| U-Boot | magic bytes | - |
| JFFS2 | magic bytes | - |

### Architectures désassemblées

| Architecture | Capstone | Fallback |
|-------------|---------|---------|
| x86 32-bit | ✓ | objdump |
| x86_64 | ✓ | objdump |
| ARM 32-bit | ✓ | objdump |
| ARM64 (AArch64) | ✓ | objdump |
| MIPS | ✓ | objdump |
| RISC-V | ✓ | objdump |

---

## Exemples concrets

### Exemple 1 — Audit de code vulnérable

```bash
export R3CON_EXPERT_MODE=true

r3con audit file ./vuln.c --depth deep --report
```

Résultat :
```
[CRITICAL] Buffer Overflow à L42
  CWE-121 | CVSS: 9.8 | AV:N/AC:L/PR:N/UI:N
  Priority: P0 — Fix now
  Fix: Use strncpy(dest, src, sizeof(dest)-1)
  Attack: Classic stack smashing → overwrite return address

[HIGH] Integer Overflow à L15
  CWE-190 | CVSS: 8.1
  Priority: P1 — Fix this sprint

Expert Deductions:
  ✓ BOF + user_input → RCE (confidence: 92%)
  ✓ INT_OF → Heap corruption (confidence: 88%)

Risk: CRITICAL (score: 88/100)
Rapport: ~/.r3con/reports/r3con_audit_*.md
```

### Exemple 2 — APK Android

```bash
r3con apk analyze ./suspicious_app.apk --report
```

Résultat :
```
[CRITICAL] Hardcoded API key: "sk-1234567890abcdef"
[HIGH]     READ_SMS permission — can read user SMS
[HIGH]     Debuggable=true in production build
[HIGH]     SSL validation disabled (TrustAllCerts)
[MEDIUM]   AllowBackup=true — ADB data extraction
[MEDIUM]   Exported Activity without permission
```

### Exemple 3 — Firmware IoT

```bash
r3con firmware analyze ./router_firmware.bin --report
```

Résultat :
```
Components: gzip + SquashFS + ELF (ARM)
Architecture: ARM 32-bit little-endian

[CRITICAL] Default credential: admin:admin
[CRITICAL] Telnet backdoor: telnetd -l /bin/sh
[HIGH]     Insecure update: wget http://... (no signature)
[HIGH]     Debug server: gdbserver :1234
[MEDIUM]   World-writable: chmod 777 /tmp/update.sh
[INFO]     OpenSSL 0.9.8 (EOL since 2015)
```

### Exemple 4 — Recherche 0day

```bash
r3con research hypothesis ./network_daemon.c \
  --context "exposed network service" \
  --depth deep
```

### Exemple 5 — Utiliser l'orchestrateur Python

```python
from r3con_core import R3con
import os

os.environ['R3CON_EXPERT_MODE'] = 'true'

r = R3con()

# Analyser un fichier source
with open('./vuln.c') as f:
    code = f.read()

result = r.analyze_source(code, lang='c', filename='vuln.c')

# Accéder aux résultats
for finding in result['findings']:
    print(f"[{finding['severity']}] {finding['type']} — CVSS: {finding['cvss']}")

# Chaînes d'exploitation
for chain in result['exploit_chains']:
    print(f"Chain: {chain['name']}")

# Risk rating
print(f"Risk: {result['risk_rating']['rating']} ({result['risk_rating']['score']}/100)")

# Générer rapport
report_path = r.generate_report(result['analysis_id'])
print(f"Report: {report_path}")
```

---

## Tests

```bash
# Lancer la suite de tests complète
python tests/test_all.py

# Résultat attendu:
# 50 passed  0 failed  / 50 total
# ALL TESTS PASSED ✓
```

Tests couverts :
- StaticAnalyzer C (8 tests)
- StaticAnalyzer Python (3 tests)
- HeapAnalyzer (3 tests)
- CryptoChecker (6 tests)
- KernelPatternScanner (4 tests)
- CVEMatcher (4 tests)
- HypothesisEngine (2 tests)
- APKAnalyzer (5 tests)
- FirmwareAnalyzer (11 tests)
- Integration multi-module (5 tests)

> **Note** : `tests/test_r2_default.py`, `tests/test_orchestration.py` et
> `tests/test_extended.py` référencent des fixtures locales à la machine
> de dev (`/home/ubuntu/...`) non fournies dans cette archive — ils ne
> passent pas tels quels ailleurs. `python tests/test_all.py` reste la
> commande fiable et portable pour valider l'installation.

---

## FAQ

**Q: L'outil fonctionne-t-il sans IA ?**
Oui. Les couches 1 et 2 sont toujours actives. L'analyse statique, APK, firmware, taint, hypothesis engine, CVE matching fonctionnent tous sans IA.

**Q: Quelle IA est recommandée ?**
Pour débuter gratuitement : Ollama local (llama2/mistral) ou NVIDIA Nemotron via Together AI. Pour la meilleure qualité : Anthropic Claude ou DeepSeek.

**Q: Quels langages sont supportés pour l'audit ?**
C, C++, Python, Java, Go, Rust. Extensible via plugins.

**Q: Comment activer l'Expert System ?**
`export R3CON_EXPERT_MODE=true` avant de lancer r3con.

**Q: Où sont sauvegardées les analyses ?**
`~/.r3con/analysis.db` (SQLite), rapports dans `~/.r3con/reports/`.

**Q: Comment lancer le dashboard web ?**
`python -m modules.web.dashboard` puis ouvrir `http://localhost:5000`.

**Q: Fonctionne-t-il sur Windows ?**
Principalement conçu pour Linux. Fonctionne sur macOS. Windows partiel (pas de binwalk, objdump limité).

---

## Licence

MIT License — voir [LICENSE](LICENSE)

---

*r3con v5.0.2 — Advanced Security Research Tool*
*Binary · APK · Firmware · Kernel · 0day Research*

## Analyse réseau et protocoles passive (v2.1)

La version améliorée ajoute l’analyse hors ligne de fichiers PCAP Ethernet/IPv4 avec TCP ou UDP. Elle ne capture pas le trafic, ne scanne pas de réseau et n’émet aucun paquet.

```bash
r3con network analyze ./capture.pcap
r3con network analyze ./capture.pcap --json-output
r3con network analyze ./capture.pcap --max-packets 50000 --max-mb 128
```

Le module résume les flux et signale des indicateurs de protocoles legacy ou en clair comme Telnet, FTP, HTTP, POP3, IMAP, SNMP et LDAP. Ces résultats sont des indicateurs à vérifier, pas une preuve automatique de compromission.

Les correctifs v2.1 incluent la validation des formats avant désassemblage, la compatibilité avec les objets ELF des versions récentes de LIEF, la recherche d’offset BOF via RBP lorsque RIP n’est pas encore écrasé, des statuts explicites pour l’analyse heap sans framework et le filtrage des faux gadgets issus des mappings mémoire. L’installation moderne utilise `pyproject.toml` :

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[full]'
```

## Outils externes optionnels et analyse réseau enrichie

r3con ne remplace pas Ghidra, Wireshark ou Zeek. Il orchestre leurs résultats quand ils sont présents et conserve un moteur interne minimal pour fonctionner sans eux. La détection et le plan d’installation sont séparés de l’installation : aucune commande ne télécharge ou n’installe automatiquement un outil.

```bash
r3con tools status
r3con tools plan
r3con tools plan tshark zeek radare2

# Moteur interne passif
r3con network analyze ./capture.pcap --engine internal

# Décodage TShark sur PCAP existant, si installé
r3con network analyze ./capture.pcap --engine tshark --json-output

# Logs Zeek sur PCAP existant, si installé
r3con network analyze ./capture.pcap --engine zeek --json-output

# Résultats combinés interne + outils disponibles
r3con network analyze ./capture.pcap --engine all --json-output
```

Le plan d’installation doit être lu et approuvé avant toute action système. Pwndbg reste une extension GDB à installer depuis sa documentation officielle, car il n’existe pas de recette système générique suffisamment sûre dans r3con. TShark et Zeek sont utilisés ici en lecture offline de fichiers; la capture live et le scan réseau ne font pas partie de cette intégration.


## Qualité et sécurité — v5.0.0

La CI exécute la compilation Python, Pytest, Pyflakes et Bandit. Le seuil bloquant de Bandit concerne les alertes de haute sévérité ; les alertes moyennes liées aux appels réseau contrôlés, aux sous-processus d’outils locaux et aux répertoires temporaires sont conservées pour revue manuelle.

La suite locale v5.0.0 contient **20 tests réussis et 1 test ignoré** dans l’environnement de validation. La couverture mesurée sur `core`, `modules.audit` et `modules.integration` est de **32 %**. Ce chiffre n’est pas présenté comme une couverture globale : les chemins IA, dashboard, fuzzing et certains adaptateurs externes nécessitent des environnements ou outils spécialisés. Les tests couvrent prioritairement les contrats centraux, les plugins absents, les timeouts, les limites de taille et la normalisation des findings.

Les outils externes restent optionnels. Lorsqu’un exécutable n’est pas installé, le comportement attendu est un résultat structuré `skipped` ou `unsupported`, jamais une installation implicite ni un échec non contrôlé.
