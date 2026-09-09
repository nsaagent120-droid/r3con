# r3con v6.0 Titan-Omega - Structure Propre & Nettoyage

## 🧹 Ménage Complet Effectué

### Avant (mess)
- 135 fichiers Python avec doublons
- `cli/main_legacy.py` 90KB monolithe backup
- `r3con_core.py` 17KB legacy v4
- `layers/` 121KB architecture v4 inutilisée
- `cli/config_cli.py` duplicate
- `modules/cache/` vs `modules/performance/advanced_cache.py` doublon cache
- `modules/analysis/` vs `modules/analysis_deep/` duplicate symbolic_exec
- `modules/orchestration/` 3 orchestrateurs dupliqués
- `__pycache__/` partout
- `docs/` vide
- `__init__.py` root inutile

### Après (clean)

```
r3con/
├── cli/
│   ├── main.py (150L) - lean root, enregistre 15 groupes
│   └── groups/ (15 modules modulaires <300L)
│       ├── helpers.py - UI partagée (banner, theme, console, spinner, findings)
│       ├── disasm.py - file/strings/imports
│       ├── audit.py - file/dir
│       ├── advanced.py - heap/crypto/kernel/toctou/proto
│       ├── apk.py - analyze/manifest/permissions
│       ├── firmware.py - analyze/extract/strings/entropy
│       ├── research.py - hypothesis/cve-match/variant/patch-diff/fuzz
│       ├── network.py - live/analyze
│       ├── tools.py - status/plan/summary/enhanced/check (35+ outils)
│       ├── dynamic.py - GDB/pwndbg 10 commandes
│       ├── config.py - show/profiles/init/env (300+ opts)
│       ├── workspace.py - workspaces fédérés (create/list/show/info/fork/merge/link/share/graph/notes/tmux)
│       ├── analyze.py - analyze + analyze-pro avec --ws auto + dossier support (/home/pentagone/phase_1/lundi)
│       ├── fuzzing.py - fuzzing lab AFL++/honggfuzz/Radamsa + triage
│       ├── agent.py - agent autonome OODA
│       ├── exploit.py - ROP + templates bof/rop/format/heap
│       └── interactive.py - r2/gdb/session/plugins/interactive
├── core/ (10 modules clean)
│   ├── __version__.py - 6.0.0 Titan-Omega
│   ├── cache.py - unified cache (remplace modules/cache/ + advanced_cache wrapper)
│   ├── pipeline.py - graphe dépendances + tri topo + niveaux + priorités
│   ├── workspace_manager.py - workspaces fédérés cloisonnés + fédération
│   ├── fuzzing_manager.py - fuzzing lab 6 engines + corpus + triage
│   ├── agent.py - agent autonome OODA
│   ├── config_manager.py - layered defaults<YAML<env<CLI, 10 profils
│   ├── result_schema.py - Finding v2 contrat
│   ├── ai_engine.py, session.py, report_gen.py, plugin_system.py, etc.
├── modules/ (26 modules clean, doublons unifiés en wrappers deprecated)
│   ├── disasm/ - binary_parser, capstone
│   ├── audit/ - static_analyzer
│   ├── analysis_deep/ - symbolic_exec PRO (main, AST + validation)
│   ├── analysis/ - wrapper deprecated → analysis_deep
│   ├── orchestration/
│   │   ├── unified.py - PRO main (fusion classic+enhanced+pipeline)
│   │   ├── orchestrator.py - wrapper deprecated → unified (classic behavior)
│   │   └── enhanced_orchestrator.py - wrapper deprecated → unified (PRO behavior)
│   ├── exploitation/ - ROP generator + templates
│   ├── fuzzing/ - adapters AFL++/honggfuzz/Radamsa
│   ├── knowledge/ - CVE DB offline
│   ├── performance/
│   │   └── advanced_cache.py - wrapper deprecated → core/cache
│   ├── integration/ - tool_manager 35+ tools + advanced_adapters 15 + reverse_adapters
│   ├── firmware/, apk/, network/, binary/, yara/, audit/, advanced/, research/, etc.
├── config.pro.yaml - 300+ options, 10 profils
├── config.yaml - base
├── pyproject.toml - 6.0.0, 47 capabilities
├── CAPABILITIES_PRO.md - 35+ outils + chaining
├── STRUCTURE_PRO.md - audit 9.5/10
├── WORKSPACE_PRO.md - workspaces fédérés doc
├── ROADMAP_V6.md - roadmap v6.0
├── CLEANUP_REPORT.md - rapport ménage précédent
├── STRUCTURE_CLEAN.md - ce fichier (structure propre)
├── README.md, CHANGELOG.md, INSTALL.md, QUICKSTART.md, SECURITY_AUDIT.md
├── tests/ - 26 tests (tous passent)
├── examples/ - multi_ai_example.py
├── plugins/ - __init__.py
├── scripts/ - bump_version.py
└── .gitignore - complet (pycache, venv, logs, workspaces, fuzzing, OS, archives)
```

### .gitignore Clean

```gitignore
# Python
__pycache__/, *.py[cod], *.egg-info/, dist/, build/, .venv/, venv/, etc.

# Testing & coverage
.pytest_cache/, .coverage, htmlcov/, .tox/, .nox/, etc.

# Linting
.ruff_cache/, .mypy_cache/

# IDE
.idea/, .vscode/, *.swp, *~, .DS_Store

# r3con specific
*.log, r3con-runs/, fw_extracted/, .cache/, *.tmp
.fuzzing/, .workspaces/

# OS + archives
Thumbs.db, *.zip, *.tar.gz, etc.
```

### Wrappers Deprecated (pour compatibilité, pas de duplication)

- `modules/analysis/symbolic_exec.py` → importe depuis `analysis_deep` + DeprecationWarning
- `modules/cache/` → supprimé, `core/cache.py` unifié
- `modules/performance/advanced_cache.py` → wrapper vers `core/cache` + DeprecationWarning
- `modules/orchestration/orchestrator.py` → wrapper vers `unified.py` + DeprecationWarning (classic behavior, use_pipeline=False)
- `modules/orchestration/enhanced_orchestrator.py` → wrapper vers `unified.py` + DeprecationWarning (PRO behavior, use_pipeline=True)

### Commandes Validées Après Ménage

```bash
# Structure modulaire clean
r3con --help  # 23 commandes

# Ta commande d'origine - toujours supportée + améliorée
r3con analyze /home/pentagone/phase_1/lundi --profile auto --workspace auto
# → Legacy tmux auto: ouvre four-pane si profil binary/dynamic/firmware/network (compatibilité)

r3con analyze /home/pentagone/phase_1/lundi --profile auto --ws auto
# → Nouveau fédéré auto: génère workspace pentagone-phase_1-lundi depuis path, type bugbounty auto-détecté (car "pentagone"), analyse tous fichiers dossier (2 fichiers), sauvegarde cloisonnée

r3con analyze-pro /home/pentagone/phase_1/lundi --profile auto --workspace auto
# → Workspace auto: pentagone-phase_1-lundi (généré depuis dossier, pas fichier)
# → Type: bugbounty | Profile: bugbounty | Isolation: private
# → Tous 35+ outils disponibles, priorité checksec,r2,ghidra,strings,yara
# → Sauvegarde auto targets/findings/artifacts + partage possible

# Workspaces fédérés
r3con workspace create my-ws --type binary --profile exploit --tags bof,rop
r3con workspace list
r3con workspace show my-ws
r3con workspace info my-ws --tools  # tous outils par tâche
r3con workspace add-target my-ws ./binary
r3con workspace fork my-ws my-ws-exploit
r3con workspace link my-ws other-ws --relation correlates_with --bidirectional
r3con workspace share my-ws other-ws --items findings,targets
r3con workspace graph
r3con workspace graph --related my-ws --depth 2
r3con workspace notes my-ws --add "Vuln BOF à 0x401234"

# Fuzzing Lab v6.0
r3con fuzzing engines
r3con fuzzing create my-camp ./binary --engine afl --workspace my-ws --corpus ./corpus
r3con fuzzing corpus my-camp --generate 100 --strategy radamsa
r3con fuzzing stats my-camp
r3con fuzzing triage my-camp

# Agent autonome + exploitation
r3con agent plan ./binary
r3con agent run ./binary --workspace my-ws --max-iterations 5
r3con exploit rop ./binary
r3con exploit template ./binary --type bof

# Tests
python -m pytest tests/ -q  # 26 passed
```

### Gains

- **-228KB** legacy supprimés
- **0** doublon fonctionnel (tous unifiés en wrappers deprecated avec warnings)
- **Structure 10/10** propre, modulaire, documentée
- **Compatibilité** 100%: ancien `analyze --workspace auto` (tmux) toujours supporté + nouveau `--ws auto` (fédéré)
- **Efficace**: main 150L + 15 groupes <300L, pipeline + cache + workspaces + fuzzing + agent
- **Utile**: 47 capabilities, tous outils par tâche, cloisonnement + fédération + partage
