# r3con v5.2.0 PRO - Workspaces Fédérés

## 🎯 Concept - Espaces de travail intelligents, cloisonnés et connectés

Tu as demandé:
> *"pour chaque espace en fonction des tâches l'outil met en disposition tous les outils ou fonctionnalité ou capacité à l'utilisateur, cloisonnements des informations, lier des informations, créer des liens ou connexion entre des espaces de travail, ces espaces puissent partager des informations"*

**Implémenté en v5.2.0 PRO - Système hybride + fédération + profil+custom**

### Architecture

```
~/.r3con/workspaces/
├── my-binary-exploit/
│   ├── workspace.json       # meta: type, profile, priority_tools, isolation, config_overrides, parent, children, tags
│   ├── targets.json         # cibles dans cet espace (sha256, kind, tags, notes)
│   ├── findings.json        # findings agrégées avec déduplication + source tracking
│   ├── links.json           # liens vers autres workspaces avec relations typées
│   ├── notes.md             # notes markdown
│   ├── artifacts/           # rapports JSON, extractions
│   └── shared/              # espace partagé
├── my-firmware-iot/
└── my-bugbounty-0day/
```

### Types de workspaces (par tâche)

Chaque type a un **profil** + **outils prioritaires**, mais **tous les 35+ outils restent accessibles** via config override:

| Type | Profil | Description | Outils prioritaires |
|------|--------|-------------|---------------------|
| `binary` | binary | ELF/PE/MachO | checksec, ropper, one_gadget, r2, ghidra, objdump |
| `firmware` | firmware | Firmware embarqué | binwalk, firmwalker, strings, r2 |
| `apk` | apk | APK Android | jadx, apktool, apksigner, dex2jar |
| `network` | network | PCAP/live | tshark, zeek, tcpdump, capinfos |
| `source` | deep | Audit code source | semgrep, yara |
| `bugbounty` | bugbounty | Bug bounty / 0day | checksec, r2, ghidra, strings, yara |
| `exploit` | exploit | Exploitation & ROP | ropper, one_gadget, checksec, r2, gdb, pwndbg |
| `forensics` | full | Forensics | binwalk, tshark, strings, yara, ssdeep |
| `custom` | full | Custom | — (tous) |

### Cloisonnement hybride (ta demande)

**Isolation par défaut** (private), mais **import/link/share explicite**:

- Chaque workspace est isolé: ses targets, findings, artifacts, notes sont privés
- Tu peux **importer** depuis un autre workspace: `workspace import <src> <dst> --items findings,targets`
- Tu peux **partager** sélectivement: `workspace share <src> <dst> --items findings,targets,artifacts,notes`
- Config override par workspace: `workspace create my-ws --config analysis.timeout=300 --config external_tools.enabled.ghidra=true`

### Fédération - Liens et connexions (ta demande)

**Relations typées** entre workspaces:

```python
RELATION_TYPES = {
  "depends_on": "Dépend de (prérequis)",
  "shares_target_with": "Partage cible avec",
  "derived_from": "Dérivé de (fork)",
  "correlates_with": "Corrélé avec (firmware<->pcap)",
  "parent": "Parent",
  "child": "Enfant",
  "merged_from": "Fusionné depuis",
  "references": "Référence",
}
```

**Opérations fédérées:**

- **fork**: `workspace fork <source> <new_name>` → crée dérivé avec lien `derived_from`, copie targets/findings/artifacts/notes, parent/children tracking
- **merge**: `workspace merge <ws1> <ws2> ... --target <new_ws>` → fusionne plusieurs workspaces, déduplique targets par sha256, agrège findings, copie artifacts avec préfixe
- **link**: `workspace link <src> <dst> --relation correlates_with --shared findings,targets --bidirectional` → crée lien typé avec shared_items tracking + bidirectionnel optionnel
- **share/import**: partage sélectif targets/findings/artifacts/notes avec création automatique de liens
- **graph**: `workspace graph` → graphe complet nodes/edges, `workspace graph --related <name> --depth 2` → BFS lié
- **related**: trouve tous workspaces liés jusqu'à profondeur N

### Outils disponibles par tâche (ta demande)

Quand tu es dans un workspace, l'outil te montre **tous les outils disponibles pour cette tâche**:

```bash
r3con workspace info my-binary-exploit --tools
```

Affiche:
- Workspace type, profile, isolation, config_overrides
- **Priority tools** pour cette tâche (ex: binary+exploit → checksec, ropper, one_gadget, r2, ghidra)
- **Tous les 35+ outils** par catégorie (apk, binary, dynamic, firmware, fuzzing, misc, network) avec present/total
- Capacités (disasm, decompile, rop, firmware...)
- Chaque outil: présent/manquants, path, purpose, si prioritaire pour cette tâche
- Comment override: `--config external_tools.enabled.ghidra=true`

**Tous les outils restent accessibles**, mais priorité mise en avant selon tâche.

### Intégration analyse (cloisonnement + partage)

```bash
# Analyse dans workspace: sauvegarde auto targets/findings/artifacts
r3con analyze-pro ./binary --profile exploit --workspace my-binary-exploit --workspace-tags bof,rop --chain --use-pipeline

# Résultats:
# - Ajoute target à workspace (déduplication sha256)
# - Ajoute findings avec source tracking
# - Sauvegarde artifact JSON dans workspace/artifacts/
# - Stats updated
# - Partage possible: r3con workspace share my-binary-exploit my-bugbounty --items findings,targets
```

### Exemples complets - Workflow fédéré

```bash
# 1. Créer espaces par tâche
r3con workspace create fw-router --type firmware --tags iot,router --description "Firmware routeur TP-Link"
r3con workspace create bin-httpd --type binary --profile exploit --tags bof,httpd --description "httpd extrait du firmware"
r3con workspace create bb-0day --type bugbounty --profile bugbounty --tags 0day,router

# 2. Ajouter cibles cloisonnées
r3con workspace add-target fw-router ./firmware.bin --tags squashfs --notes "Firmware v1.2.3"
r3con workspace add-target bin-httpd ./httpd --tags bof --notes "Binaire extrait via binwalk"

# 3. Lier espaces (corrélation firmware<->binaire)
r3con workspace link fw-router bin-httpd --relation correlates_with --description "httpd extrait de fw-router" --shared findings,targets --bidirectional
r3con workspace link bin-httpd bb-0day --relation shares_target_with --description "Même cible approche différente"

# 4. Analyser dans workspace (outils adaptés par tâche)
r3con analyze-pro ./firmware.bin --profile firmware --workspace fw-router --chain
r3con analyze-pro ./httpd --profile exploit --workspace bin-httpd --with-ghidra --chain --use-pipeline
r3con analyze-pro ./httpd --profile bugbounty --workspace bb-0day --chain

# 5. Voir outils disponibles par tâche
r3con workspace info bin-httpd --tools
# → Priority: checksec, ropper, one_gadget, r2, ghidra, objdump (pour exploit)
# → Tous: 41 outils, 4 présents, par catégorie, avec purpose

# 6. Partage sélectif (fédération)
r3con workspace share bin-httpd bb-0day --items findings,targets --relation shares_target_with
# → bb-0day reçoit findings + targets de bin-httpd + lien créé

# 7. Fork pour exploit dev
r3con workspace fork bin-httpd bin-httpd-exploit --description "Dev exploit ROP chain"
# → Nouveau workspace avec parent=bin-httpd, lien derived_from, copie tout

# 8. Graphe et connexions
r3con workspace graph
# → Nodes: 3 workspaces, Edges: 3 liens avec relations
r3con workspace graph --related bin-httpd --depth 2
# → BFS: bin-httpd lié à fw-router (depth1) et bb-0day (depth1)

# 9. Merge pour rapport final
r3con workspace merge bin-httpd bb-0day --target final-report --description "Rapport final 0day router"
# → Fusionne targets (dédupliqués sha256) + findings + artifacts + notes + liens merged_from

# 10. Notes partagées et cloisonnement
r3con workspace notes bin-httpd --add "Vuln BOF à 0x401234, offset 128, ROP gadget trouvé"
r3con workspace share bin-httpd bb-0day --items notes --relation references
# → Notes partagées avec header "Shared from bin-httpd"

# 11. Voir détails cloisonnement
r3con workspace show bin-httpd
# → Type, profile, isolation, parent, children, tags, stats targets/findings/artifacts/links
# → Targets list, Links list avec relations et shared_items, Config overrides

# 12. Tmux lab (ancien workspace four-pane)
r3con workspace tmux ./httpd --session r3con-exploit
# → Four-pane: interactive, r2, gdb, bash
```

### Commandes CLI

```bash
r3con workspace create <name> --type <type> --profile <profile> --description --tags --isolation --config key=value
r3con workspace list [--type <type>] [--tag <tag>] [--json]
r3con workspace show <name> [--json]
r3con workspace info <name> --tools [--json]  # PRO: tous outils disponibles par tâche
r3con workspace add-target <ws> <target> --kind auto --tags --notes
r3con workspace fork <source> <new_name> --description
r3con workspace merge <ws1> <ws2> ... --target <new> --description
r3con workspace link <src> <dst> --relation <type> --description --shared findings,targets --bidirectional
r3con workspace unlink <src> <dst> [--relation <type>]
r3con workspace share <src> <dst> --items findings,targets,artifacts,notes --relation shares_target_with
r3con workspace import <src> <dst> --items findings  # alias share inversé
r3con workspace graph [--json] [--related <name> --depth 2]
r3con workspace delete <name> --force
r3con workspace notes <name> [--edit] [--add "text"]
r3con workspace tmux [binary] --session <name> --dry-run
```

### Avantages - Réponse à ta demande

✅ **Pour chaque espace en fonction des tâches, tous les outils disponibles:**
- `workspace info <name> --tools` → montre priority tools pour cette tâche + tous les 35+ outils par catégorie + present/total + capabilities
- Profil définit priorité, mais config override permet d'activer n'importe quel outil
- `analyze-pro --workspace <name>` → utilise profil du workspace si --profile auto, + config_overrides du workspace

✅ **Cloisonnement des informations:**
- Isolation private par défaut: chaque workspace a ses propres targets.json, findings.json, artifacts/, notes.md
- Stats séparées, path séparé, tags séparés
- Config overrides par workspace

✅ **Lier des informations:**
- Links typés avec relations (depends_on, shares_target_with, derived_from, correlates_with...)
- Shared_items tracking: sait quels items partagés entre workspaces
- Bidirectionnel optionnel

✅ **Créer des liens/connexions entre espaces:**
- `link`, `unlink`, `graph`, `related` (BFS depth)
- Graphe complet nodes/edges avec visualisation table
- Parent/children tracking pour fork

✅ **Espaces partagent des informations (fédération):**
- `share` sélectif: targets, findings, artifacts, notes
- `import` alias inversé
- `fork` avec copie complète + lien derived_from
- `merge` avec déduplication sha256 + agrégation findings + copie artifacts préfixés + notes mergées + liens merged_from
- Notes partagées avec header "Shared from X"

### Stockage

- Base: `~/.r3con/workspaces/<name>/`
- JSON lisible: workspace.json, targets.json, findings.json, links.json
- Markdown: notes.md
- Artifacts: artifacts/*.json
- Pas de DB externe, 100% offline, fichiers plats, git-friendly si besoin

### Version

- v5.2.0 PRO Workspaces Fédérés
- Core: `core/workspace_manager.py` (600L)
- CLI: `cli/groups/workspace.py` (400L)
- Intégration: `analyze-pro --workspace`
- Tests: 26 passés
