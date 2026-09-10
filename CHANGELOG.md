# Changelog r3con

## 7.3.0 — Contrat v2.1, orchestration explicable, supply chain et analyse différentielle (EN COURS DE VALIDATION — ne pas tagger sans feu vert)

### Corrections bloquantes

- `modules/dynamic/gdb_cli.py` : les expressions f-string contenant des antislash étaient invalides sur Python 3.9–3.11 (erreur de syntaxe, `compileall` en échec). Réécriture compatible ; le dépôt compile de nouveau intégralement sur 3.9+.
- `modules/fuzzing/` était sans `__init__.py` : le paquet (adaptateurs) n'était pas embarqué dans les roues. Corrigé.
- La détection de type de cible existait en trois copies divergentes (`unified`, `power`, `analyze`) ; elle est unifiée dans `core/target_types.py` et les incohérences (ZIP non-APK traité APK, pcapng non reconnu, Mach-O fat ignoré) sont corrigées. **Comportement volontairement aligné** : un fichier à signature ELF mais en-tête invalide est désormais traité comme suspect firmware par `scan` comme par l'orchestrateur (auparavant divergents).

### Contrat de résultat v2.1 (`core/result_schema.py`, rétro-compatible)

- Nouveaux champs : `location` (fichier/fonction/ligne/offset/adresse), `exploitability` normalisé (unknown/theoretical/possible/likely/confirmed), `references` validées (CWE/CVE/ATT&CK ; les identifiants malformés sont rejetés, pas propagés), `corroboration` structurée `{tools, count}`, `fallback` explicite.
- Normalisation élargie des sévérités et statuts historiques ; clés plates anciennes (`file`, `line`, `cwe`…) absorbées automatiquement.
- Déduplication multi-outils améliorée : union des références et localisations, fusion de la corroboration, neutralisation du marquage fallback dès qu'un outil réel confirme ; format v2.0 (`provenance.corroborating_tools` en chaîne) conservé.
- Résumé de risque 0–100 incluant exploitabilité et corroboration ; classification en cinq classes explicites : observation, hypothèse, confirmé, faux positif, fallback (`finding_kind`).

### Orchestrateur

- Plan d'analyse **explicable** : `scan --explain-plan` affiche pourquoi chaque tâche est là, l'outil requis, sa disponibilité, le repli interne et le conseil d'installation. `--plan-only`/`--dry-run` affiche le plan sans exécuter.
- **Pré-vérification des outils** : les tâches dont l'outil externe est absent et sans repli sont marquées `unsupported/tool_unavailable` AVANT exécution et n'empêchent plus un statut global `ok`.
- **Reprise après interruption** : chaque run écrit des artifacts par tâche + `state.json` ; `scan --resume <répertoire>` réutilise les tâches terminées (`resumed: true`).
- **Cache versionné** (`core/cache.TaskCache`) : clé = hash cible + tâche + profil + empreinte de configuration + empreinte des versions d'outils + version du schéma. Activé dans l'orchestrateur ; le drapeau `--no-cache` et la clé `analysis.cache_enabled` du legacy sont désormais réellement câblés.
- Robustesse : une tâche qui lève une exception, expire ou reçoit une sortie invalide produit un résultat d'erreur isolé ; l'orchestrateur ne casse plus jamais ; cible illisible (permission refusée) → `error/permission_denied` structuré.
- Métadonnées de rapport (`report_meta`) : version r3con, versions des outils, hash cible, profil, date, durée, fallbacks utilisés, limites appliquées, reprise.

### Nouvelles commandes

- `r3con scan TARGET --profile auto --explain-plan|--plan-only|--resume DIR|--offline|--fail-on {critical,high,medium}` (formats existants préservés).
- `r3con tools doctor --json-output` : versions + bibliothèques optionnelles (sortie texte d'origine conservée).
- `r3con reports compare OLD NEW` : ajoute la détection des findings **modifiés**, la tendance de risque, `--format md|sarif`.
- `r3con compare OLD NEW --kind auto|binary|apk|firmware|source|report` : analyse différentielle de cibles (protections, fonctions, permissions Android, strings, secrets, findings) avec exports JSON/Markdown/SARIF, via `modules/diff/`.
- `r3con supply-chain scan ./project --sbom {cyclonedx,spdx,both} --dependencies --secrets --report F --sbom-output F --policy F --fail-on …` : `modules/supply_chain/` (Python, npm, Maven/Gradle, Go, Rust, Docker, Kubernetes, Terraform ; lockfiles et transitifs ; SBOM CycloneDX 1.5 et SPDX 2.3 déterministes ; politique offline à amorces intégrées extensible par fichier local).
- `r3con dynamic sandbox TARGET …` : runner local isolé (`modules/dynamic/sandboxed_runner.py`) — par défaut **plan sans exécution** ; `--execute` requis pour lancer ; réseau coupé via `unshare -n` (refus explicite si non isolationnable et `--lenient-network` absent), tmp privé 0700, RLIMIT CPU/AS/NPROC/FSIZE, timeout mural avec arbre tué, capture stdout/stderr/fichiers/signaux, crashs convertis en findings, profil syscalls optionnel via strace.
- `r3con explain FINDING_ID --report R [--ai]`, `r3con summarize R`, `r3con ask R "question"` : explications et corrélations calculées localement, chaque réponse cite les preuves du rapport et liste les incertitudes ; `--ai` n'ajoute qu'un commentaire étiqueté non probant (jamais une preuve).
- `r3con fuzzing plan CAMPAGNE --timeout-ms --memory-mb --max-runtime --resume` : commande de fuzzing planifiée avec limites (aucune exécution) ; `r3con fuzzing export-findings CAMPAGNE` : clustering des crashs par signature, minimisation non destructive (dossier `.min`), stats et export vers le contrat Finding (statut observation, exploitabilité unknown).

### Durcissement reporting et CI

- SARIF : la version du driver suit la version réelle de r3con (fini le numéro codé en dur) ; le bloc `metadata` (hash cible, profil, fallbacks, durées) est publié dans les propriétés du run ; `location`/`references` du contrat v2.1 compris.
- Markdown : sections « Métadonnées d'audit » et « Qualité » (statut, exploitabilité, fallback, corroboration) ; localisation via `location` en repli des clés plates.
- `examples/github-actions/r3con-scan.yml` : gabarit CI sans exfiltration (SBOM seul téléversé par défaut).

### Compatibilité et dépréciations

- Aucune commande supprimée. Les payloads JSON existants gardent leurs clés (ajouts uniquement) ; `schema_version` des résultats passe de 2.0 à 2.1.
- Les alias historiques (`type`, `provenance.corroborating_tools`, `finding["file"]/["line"]/["cwe"]`) restent acceptés à la lecture comme à l'écriture.
- `--offline` et `--fail-on` sont des ajouts optionnels ; sans eux, comportement CLI strictement identique.
- `--offline` pose le kill-switch global `R3CON_OFFLINE=1` : les lookup distants (VirusTotal,
  MalwareBazaar, NVD) renvoient `skipped/offline_mode` sans émettre la moindre requête —
  même l'envoi d'un hash est bloqué ; l'analyse locale et heuristique continue.

### Tests

- Suite portée de 33 à 121 tests (3 ignorés conditionnels) : contrat v2.1, détection de cibles (fixtures minimales ELF/PE/Mach-O/PCAP/APK/ZIP/conteneur/TAR/firmware), plan explicable, pré-vérification, cache versionné, reprise, robustesse ( Permissions refusées, cible vide/corrompue, taille excessive, tâche explosive), diff de rapports et de cibles, supply chain (7 écosystèmes + politique + SBOM + dégradation propre), sandbox (plan vs exécution, crash, timeout, rlimits, iso réseau stricte), triage fuzzing, commandes explain/summarize/ask/fail-on.

# Changelog r3con

## 5.0.0 — Stabilisation du contrat et des plugins

### Ajouts

- Ajout d’un contrat `Finding` v2.0 canonique avec identifiant stable, cible, outil, confiance, statut, evidence, timestamp et provenance.
- Ajout de normalisation, déduplication et corrélation des observations issues de plusieurs outils.
- Enregistrement des adaptateurs Radare2/Rizin, Ghidra, Binwalk et GDB dans le registre de plugins.
- Ajout d’une CI GitHub Actions exécutant compilation, Pytest, Pyflakes et Bandit.
- Ajout de `ROADMAP.md` pour geler le périmètre de stabilisation.

### Correctifs et optimisations

- Correction des six avertissements Pyflakes existants.
- Empreinte MD5 explicitement limitée à la compatibilité et marquée non cryptographique.
- Validation des colonnes autorisées dans les mises à jour SQL.
- Conservation de la compatibilité avec l’alias historique `finding["type"]`.
- Déduplication effectuée en une passe avec corroboration indépendante et confiance bornée.

### Vérification

- 15 tests réussis, 1 test ignoré dans l’environnement local.
- Compilation Python complète réussie.

### Durcissement final

- Ajout de tests pour les outils absents, les timeouts, les adaptateurs reverse indisponibles et les fichiers dépassant la limite configurée.
- La suite finale compte 20 tests réussis et 1 test ignoré dans l’environnement local.
- La couverture mesurée sur `core`, `modules.audit` et `modules.integration` est de 32 % ; aucun seuil artificiel de 100 % n’est imposé aux modules dépendant d’outils externes.
- Les alertes Bandit de haute sévérité sont nulles. Les alertes moyennes restantes sont documentées comme revue de sécurité non bloquante pour les appels réseau contrôlés, les sous-processus optionnels et les chemins temporaires.
