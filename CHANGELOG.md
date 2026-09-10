# Changelog r3con

## 7.3.0 — Contrat v2.1, orchestration explicable, supply chain et analyse différentielle — La vraie version stable fusionnée (2026-09-10)

### Fusion et stabilisation — La vraie version

- **Nettoyage complet** : suppression des docs legacy `CAPABILITIES_PRO`, `STRUCTURE_PRO`, `STRUCTURE_CLEAN`, `CLEANUP_REPORT`, `WORKSPACE_PRO`, `ROADMAP_V6`, `README_v7.2` — contenu fusionné dans `docs/ARCHITECTURE.md` + `docs/CAPABILITIES.md` + `README.md` stable.
- **Détection cible unifiée** : 3 copies divergentes → `core/target_types.py` seul classifieur offline, stdlib, avec correction ZIP non-APK, pcapng, Mach-O fat, ELF invalide → firmware suspect.
- **Orchestration** : 1 seul moteur `modules/orchestration/unified.py` (fusion classic+enhanced+pipeline), wrappers legacy silencieux (warning seulement si `R3CON_WARN_DEPRECATED=1`), `__init__.py` sans warning.
- **Cache** : `modules/cache/` + `performance/advanced_cache` → `core/cache.py` unifié (`IncrementalCache` + `TaskCache` versionné).
- **Symbolic** : `analysis/symbolic_exec` wrapper silencieux → `analysis_deep` source de vérité.
- **CLI** : `main.py` lean ~230L + 27 groupes modulaires <300L, 50+ commandes, `compileall` OK 3.9-3.13.
- **Packaging** : `pyproject.toml` 7.3.0, `Dockerfile` 7.3.0, `requirements.txt` propre, `r3con_ci.py` version dynamique, `helpers.py` fallback 7.3.0.
- **Docs** : `README.md` vrai stable, `INSTALL.md` 7.3.0, `QUICKSTART.md` 7.3.0, `SECURITY_AUDIT.md` 7.3.0, `docs/STABLE_RELEASE.md` 7.3.0 avec validation complète, `docs/ARCHITECTURE.md` et `docs/CAPABILITIES.md` nouveaux.

### Corrections bloquantes (7.3.0)

- `modules/dynamic/gdb_cli.py` : f-string avec antislash invalide sur Python 3.9–3.11 (erreur syntaxe, `compileall` en échec) → réécriture compatible, dépôt compile intégralement sur 3.9+.
- `modules/fuzzing/` sans `__init__.py` → paquet non embarqué dans roues → corrigé.
- Détection type cible 3 copies divergentes → unifiée `core/target_types.py`, incohérences corrigées (ZIP non-APK, pcapng, Mach-O fat). Comportement aligné volontairement : fichier signature ELF mais en-tête invalide → traité comme suspect firmware par `scan` comme par orchestrateur.

### Contrat de résultat v2.1 (`core/result_schema.py`, rétro-compatible v2.0)

- Nouveaux champs : `location` (file/function/line/offset/address), `exploitability` normalisé (unknown/theoretical/possible/likely/confirmed), `references` validées (CWE/CVE/ATT&CK — malformés rejetés), `corroboration` structurée `{tools, count}`, `fallback` explicite.
- Normalisation élargie sévérités et statuts historiques, clés plates anciennes (`file`, `line`, `cwe`…) absorbées auto.
- Déduplication multi-outils améliorée : union références + localisations, fusion corroboration, neutralisation fallback dès qu'outil réel confirme, format v2.0 (`provenance.corroborating_tools` chaîne) conservé.
- Résumé risque 0–100 incluant exploitabilité + corroboration, classification 5 classes explicites : observation, hypothèse, confirmé, faux positif, fallback (`finding_kind`).

### Orchestrateur

- Plan **explicable** : `scan --explain-plan` affiche pourquoi chaque tâche, outil requis, disponibilité, repli interne, conseil install. `--plan-only`/`--dry-run` affiche plan sans exécuter.
- **Pré-vérification outils** : tâches dont outil externe absent et sans repli → `unsupported/tool_unavailable` AVANT exécution, n'empêche plus statut global `ok`.
- **Reprise** : chaque run écrit artifacts par tâche + `state.json`, `scan --resume DIR` réutilise tâches terminées (`resumed: true`).
- **Cache versionné** (`core/cache.TaskCache`) : clé = hash cible + tâche + profil + empreinte config + empreinte versions outils + version schéma. Activé dans orchestrateur, drapeau `--no-cache` et clé `analysis.cache_enabled` désormais réellement câblés.
- Robustesse : tâche qui lève exception/expire/sortie invalide → résultat erreur isolé, orchestrateur ne casse jamais, cible illisible (permission refusée) → `error/permission_denied` structuré.
- Métadonnées rapport (`report_meta`) : version r3con, versions outils, hash cible, profil, date, durée, fallbacks, limites, reprise.

### Nouvelles commandes (7.3.0)

- `r3con scan TARGET --profile auto --explain-plan|--plan-only|--resume DIR|--offline|--fail-on {critical,high,medium}` (formats existants préservés).
- `r3con tools doctor --json-output` : versions + libs optionnelles (texte d'origine conservé).
- `r3con reports compare OLD NEW` : détection findings **modifiés**, tendance risque, `--format md|sarif`.
- `r3con compare OLD NEW --kind auto|binary|apk|firmware|source|report` : diff cibles (protections, fonctions, perms Android, strings, secrets, findings) avec exports JSON/MD/SARIF via `modules/diff/`.
- `r3con supply-chain scan ./project --sbom {cyclonedx,spdx,both} --dependencies --secrets --report F --sbom-output F --policy F --fail-on …` : `modules/supply_chain/` (Python, npm, Maven/Gradle, Go, Rust, Docker, K8s, Terraform, lockfiles, transitifs, SBOM CycloneDX 1.5 + SPDX 2.3 déterministes, politique offline amorces intégrées extensible fichier local).
- `r3con dynamic sandbox TARGET …` : runner isolé (`modules/dynamic/sandboxed_runner.py`) — par défaut plan sans exécution, `--execute` requis, réseau coupé via `unshare -n` (refus explicite si non isolable et `--lenient-network` absent), tmp privé 0700, RLIMIT, timeout mural avec arbre tué, capture stdout/stderr/fichiers/signaux, crashs → findings, profil syscalls via strace optionnel.
- `r3con explain FINDING_ID --report R [--ai]`, `r3con summarize R`, `r3con ask R "question"` : explications et corrélations locales, chaque réponse cite preuves rapport et liste incertitudes, `--ai` ajoute commentaire étiqueté non probant (jamais preuve).
- `r3con fuzzing plan CAMPAGNE --timeout-ms --memory-mb --max-runtime --resume` : fuzzing planifié avec limites (aucune exécution), `r3con fuzzing export-findings CAMPAGNE` : clustering crashs par signature, minimisation non destructive (dossier `.min`), stats + export contrat Finding (statut observation, exploitabilité unknown).

### Durcissement reporting et CI

- SARIF : version driver suit vraie version r3con (fini numéro codé en dur), bloc `metadata` (hash cible, profil, fallbacks, durées) publié dans propriétés run, `location`/`references` v2.1 compris.
- Markdown : sections « Métadonnées d'audit » et « Qualité » (statut, exploitabilité, fallback, corroboration), localisation via `location` en repli clés plates.
- `examples/github-actions/r3con-scan.yml` : gabarit CI sans exfiltration (SBOM seul téléversé par défaut).

### Compatibilité et dépréciations

- Aucune commande supprimée. Payloads JSON gardent clés (ajouts uniquement), `schema_version` résultats passe 2.0 → 2.1.
- Alias historiques (`type`, `provenance.corroborating_tools`, `finding["file"]/["line"]/["cwe"]`) restent acceptés lecture/écriture.
- `--offline` et `--fail-on` ajouts optionnels, sans eux comportement CLI strictement identique.
- `--offline` pose kill-switch global `R3CON_OFFLINE=1` : lookup distants (VirusTotal, MalwareBazaar, NVD) renvoient `skipped/offline_mode` sans requête — même envoi hash bloqué, analyse locale continue.

### Tests

- Suite portée 33 → 121 tests (3 ignorés conditionnels) : contrat v2.1, détection cibles (fixtures minimales ELF/PE/Mach-O/PCAP/APK/ZIP/container/TAR/firmware), plan explicable, pré-vérification, cache versionné, reprise, robustesse (permissions refusées, cible vide/corrompue, taille excessive, tâche explosive), diff rapports/cibles, supply-chain 7 écosystèmes + politique + SBOM + dégradation propre, sandbox (plan vs exécution, crash, timeout, rlimits, iso réseau stricte), triage fuzzing, commandes explain/summarize/ask/fail-on.

## 7.2.0 — 49/49 modules, ML embeddings, dashboard real-time

- Modules OK 46/49 → 49/49 (fix 3 imports manquants)
- ML embeddings 0/10 → 8/10 TF-IDF offline, 9.5/10 avec sentence-transformers
- RAG 7/10 keyword → 9/10 ML hybrid + clustering
- Dashboard 7/10 static → 9/10 WebSocket real-time + 14 tabs
- CLI groupes 25 → 27 (+dashboard, +ml)
- Offline 90% → 95% (TF-IDF 100% offline)

## 5.0.0 — Stabilisation contrat et plugins

- Contrat Finding v2.0 canonique avec id stable, cible, outil, confiance, statut, evidence, timestamp, provenance.
- Normalisation, déduplication, corrélation multi-outils.
- Adaptateurs Radare2/Rizin, Ghidra, Binwalk, GDB dans registre plugins.
- CI GitHub Actions : compilation, Pytest, Pyflakes, Bandit.
- ROADMAP.md pour geler périmètre stabilisation.
- Corrections : 6 avertissements Pyflakes, MD5 non crypto marqué, validation colonnes SQL, alias `finding["type"]`, déduplication 1 passe avec corroboration.
- Vérification : 15 tests réussis, 1 ignoré, compilation OK.
- Durcissement final : tests outils absents, timeouts, adapters reverse indisponibles, fichiers > limite. Suite finale 20 tests, 1 ignoré, couverture 32% sur core/modules.audit/modules.integration, Bandit high 0.
