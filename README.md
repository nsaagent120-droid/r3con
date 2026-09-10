# r3con 7.3.0 — Security Research Toolkit (Stable)

> Orchestrateur d'analyses de sécurité **offline-first**, modulaire, explicable et reproductible — binaires, APK, firmwares, sources, malwares, réseau, supply-chain, cloud/conteneurs.

[![Python 3.9–3.13](https://img.shields.io/badge/python-3.9%E2%80%933.13-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-121%20passed%2C%203%20skipped-brightgreen.svg)](tests/)
[![License MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Offline](https://img.shields.io/badge/offline--first-100%25-green.svg)](core/offline.py)

## Statut — La vraie version stable

**7.3.0 (2026-09-10) est la version stable de référence.** Elle fusionne et stabilise toutes les branches précédentes (5.x PRO, 6.x Titan-Omega, 7.2).

- **Contrat Finding v2.1** : localisation précise, exploitabilité normalisée, références CWE/CVE/ATT&CK validées, corroboration multi-outils, fallback explicite.
- **Orchestration explicable** : plan détaillé (`--explain-plan`, `--plan-only`), pré-vérification des outils, cache versionné par empreinte config+outils+schéma, reprise sur panne (`--resume`), métadonnées d'audit complètes.
- **Détection unifiée des cibles** : un seul classifieur (`core/target_types.py`) pour ELF/PE/Mach-O/APK/ZIP/TAR/container/PCAP/firmware/source — plus de divergences.
- **Supply-chain offline** : 7 écosystèmes (Python, npm, Maven/Gradle, Go, Rust, Docker, K8s, Terraform), SBOM CycloneDX 1.5 + SPDX 2.3 déterministes, politique locale avec amorces intégrées.
- **Sandbox isolé** : `dynamic sandbox` — plan sans exécution par défaut, `--execute` requis, réseau coupé via `unshare -n`, tmp 0700, RLIMIT, kill d'arbre, capture crash → findings.
- **Analyse différentielle** : `compare` pour binaires/APK/firmware/source/rapports (JSON/MD/SARIF) + `reports compare` avec détection de findings modifiés et tendance de risque.
- **Explicabilité locale** : `explain`, `summarize`, `ask` — réponses 100% locales, preuves citées, incertitudes listées, IA optionnelle étiquetée non probante.
- **Fuzzing trié** : `fuzzing plan` (limites sans exécution) + `fuzzing export-findings` (clustering par signature, minimisation non destructive).
- **Offline kill-switch** : `R3CON_OFFLINE=1` ou `--offline` bloque toute requête distante (VirusTotal, NVD, etc.), même l'envoi d'un hash.
- **Stabilité** : `python -m compileall -q .` OK sur 3.9+, 121 tests passés, packaging vérifié, CLI 27 groupes / 50+ commandes, 0 commande supprimée depuis 7.2.

> **Principe** : aucun fichier, secret ou donnée n'est envoyé vers un service distant par défaut. Les résultats sont des indications d'analyse à vérifier par un analyste qualifié.

## Architecture fusionnée

```
cli/main.py (lean ~230L) → 27 groupes modulaires <300L
  helpers.py (UI/banner/theme/console)
  power.py   (scan, compare, explain, summarize, ask, doctor, reports)
  analyze.py (analyze, analyze-pro, benchmark, correlate, diff)
  supply.py  (supply-chain)
  disasm.py, audit.py, apk.py, firmware.py, malware.py, network.py,
  web.py, cloud.py, dynamic.py, fuzzing.py, agent.py, exploit.py,
  workspace.py, config.py, tools.py, etc.

core/ (contrats & orchestration)
  result_schema.py  → Finding v2.1 + finding_kind + risk score
  target_types.py   → classifieur unifié (1 seul)
  pipeline.py       → graphe dépendances + tri topo + niveaux + priorités
  cache.py          → IncrementalCache + TaskCache versionné
  explainer.py      → explain/summarize/ask 100% local
  config_manager.py → layered defaults<YAML<env<CLI, 10 profils
  offline.py        → kill-switch R3CON_OFFLINE
  workspace_manager.py, fuzzing_manager.py, agent.py, etc.

modules/ (49 modules, 0 doublon fonctionnel)
  disasm/ (binary_parser, capstone, decompiler)
  audit/ (static_analyzer, secret_scanner, source_scanner)
  apk/, firmware/, malware/ (8 moteurs), network/ (6 analyseurs),
  web_scanner/, cloud/, container/, deps/, supply_chain/ (7 écosystèmes),
  diff/ (differential), dynamic/ (sandboxed_runner, gdb),
  fuzzing/ (adapters + triage), exploitation/ (ROP + AEG),
  analysis_deep/ (symbolic_exec PRO), ai/ (RAG v2 + embeddings),
  reporting/ (SARIF, MD, HTML, JIRA, DefectDojo, MITRE), etc.
  orchestration/unified.py → orchestrateur unique (classic+enhanced+pipeline)
    wrappers legacy conservés sans bruit pour compatibilité

config.yaml / config.pro.yaml → 300+ options, 10 profils
tests/ → 121 tests, 3 skipped conditionnels
docs/ → USER_GUIDE, MANUEL_TECHNIQUE, STABLE_RELEASE, ARCHITECTURE, CAPABILITIES
```

### Fusion réalisée (vrai ménage)

- Suppression des docs legacy `CAPABILITIES_PRO`, `STRUCTURE_PRO`, `STRUCTURE_CLEAN`, `CLEANUP_REPORT`, `WORKSPACE_PRO`, `ROADMAP_V6`, `README_v7.2` — leur contenu utile est fusionné dans `docs/ARCHITECTURE.md` et `docs/CAPABILITIES.md`.
- Unification des 3 classifieurs de cibles → `core/target_types.py`.
- `modules/orchestration/` : 1 seul moteur (`unified.py`), wrappers legacy silencieux.
- `modules/cache/` vs `performance/advanced_cache` → `core/cache.py` unifié (Incremental + TaskCache).
- `modules/analysis/symbolic_exec` wrapper → `analysis_deep` comme source de vérité.
- CLI : `cli/main.py` lean enregistre 27 groupes, pas de monolithe.
- `compileall` OK, tests OK, packaging OK, `r3con --help` OK.

## Installation

```bash
git clone https://github.com/nsaagent120-droid/r3con.git
cd r3con
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

# Vérification
r3con --version
r3con --help
python -m pytest -q
```

Installation complète automatisée (système + venv + extras) :

```bash
bash scripts/install_full.sh --yes
bash scripts/install_full.sh --docker --yes  # avec Docker si dispo
```

Profils optionnels :

```bash
pip install -e '.[binary]'      # capstone, lief
pip install -e '.[reporting]'    # jinja2, yaml
pip install -e '.[web]'          # flask
pip install -e '.[ast,symbolic]' # tree-sitter, z3
pip install -e '.[full]'         # tout Python
pip install -e '.[dev]'          # tests, lint, build
```

## Démarrage rapide

```bash
# Audit source
r3con audit file ./src/vuln.c --report
r3con audit dir ./src --recursive --report

# Binaire
r3con disasm file ./program --arch auto
r3con disasm strings ./program --min-len 6
r3con scan ./program --profile auto --explain-plan
r3con scan ./program --profile binary --json-output report.json --fail-on high

# APK / Firmware
r3con apk analyze ./app.apk --report
r3con firmware analyze ./fw.bin --report

# Réseau / Malware
r3con network analyze ./capture.pcap
r3con malware analyze ./sample --profile full

# Supply-chain (offline)
r3con supply-chain scan ./project --sbom cyclonedx --dependencies --secrets --report sc.json

# Différentiel
r3con compare ./old.bin ./new.bin --format md --output diff.md
r3con reports compare old.json new.json --format md --output trend.md

# Explicabilité
r3con explain FINDING_ID --report report.json
r3con summarize report.json
r3con ask report.json "Quels risques sont corroborés par plusieurs outils ?"

# Outils
r3con tools status
r3con tools doctor --json-output

# Sandbox (plan par défaut, pas d'exécution)
r3con dynamic sandbox ./binary --timeout-ms 5000
r3con dynamic sandbox ./binary --execute --memory-mb 256

# Fuzzing
r3con fuzzing plan mycamp --timeout-ms 1000 --memory-mb 256
r3con fuzzing export-findings mycamp
```

Tout est offline-first. Pour forcer offline global :

```bash
R3CON_OFFLINE=1 r3con scan ./target --offline
```

## Capacités (47+)

| Domaine | Ce qui marche offline | Outils externes optionnels |
|---|---|---|
| Code | C/C++, Python, Java, Go, Rust, JS, PHP — mémoire, injection, secrets, crypto, concurrence | tree-sitter |
| Binaire | ELF/PE/Mach-O, imports, exports, protections, strings, entropie, capstone | capstone, lief, r2, ghidra |
| APK | Manifest, permissions, URLs, secrets, DEX, libs natives | jadx, apktool |
| Firmware | Entropie, strings, extraction, backdoor indicators | binwalk |
| Malware | PE/ELF, IOC, behavior, anti-analyse, unpacking, classifier | yara, capa |
| Réseau | PCAP/pcapng, flux, DNS, HTTP, TLS, beaconing, threat | scapy, tshark |
| Web | SAST 6 cats + Nuclei wrapper | nuclei |
| Cloud/Container | Dockerfile, Compose, K8s, Terraform, image tar, secrets | checkov, trivy |
| Supply-chain | 7 écosystèmes, lockfiles, transitifs, SBOM, policy | - (100% offline) |
| IA/RAG | RAG v2 local, embeddings TF-IDF, agent OODA | openai, together, local |
| Reporting | MD, HTML, PDF fallback, SARIF, JIRA, DefectDojo, MITRE | jinja2, weasyprint |
| Exploitation | ROP, heap primitives, PoC templates | capstone |

## Configuration

- `config.yaml` : base
- `config.pro.yaml` : 300+ options, 10 profils (quick, deep, full, binary, firmware, apk, network, bugbounty, exploit, stealth)
- Stockage local : `~/.r3con/` (SQLite, rapports, cache, sessions)
- Env overrides : `R3CON_*` (ex: `R3CON_OFFLINE=1`, `R3CON_THEME=matrix`)
- `r3con config --help` pour tout voir

## Développement

```bash
make test          # pytest -q
make lint          # ruff + pyflakes + bandit
make format        # black 100 cols
python -m compileall -q .
python -m build
python -m twine check dist/*
```

CI GitHub : compileall, pytest, ruff, pyflakes, bandit (high gate), build.

## Documentation

| Document | Contenu |
|---|---|
| [USER_GUIDE](docs/USER_GUIDE.md) | Install, commandes, workflows par domaine |
| [MANUEL_TECHNIQUE](docs/MANUEL_TECHNIQUE_v7.2.md) | Architecture, modules, contrats |
| [STABLE_RELEASE](docs/STABLE_RELEASE.md) | Critères de stabilité, validation, maintenance |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Structure fusionnée, orchestration, cache, pipeline |
| [CAPABILITIES](docs/CAPABILITIES.md) | Matrice capacités, outils, profils |
| [SECURITY_AUDIT](SECURITY_AUDIT.md) | Limites, menaces, recommandations |
| [CHANGELOG](CHANGELOG.md) | Historique versions |

## Sécurité d'usage

- Analysez uniquement ce que vous êtes autorisé à examiner.
- Isolez les binaires non fiables (VM, sandbox).
- Ne lancez `dynamic sandbox --execute`, `network live`, `fuzzing` que en labo.
- Clés API via env, jamais dans le dépôt.
- Les findings sont des indications — pas des preuves d'exploitabilité sans revue humaine.

## Licence

MIT — voir [LICENSE](LICENSE).
