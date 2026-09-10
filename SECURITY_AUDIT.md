# Audit de sécurité r3con 7.3.0 — Stable

## Résumé

r3con 7.3.0 est audité comme **offline-first, explicable, robuste**. Aucune alerte Bandit haute sévérité. Dépendances minimales (`click`, `rich`) sans CVE connue dans `pip-audit`. Les intégrations réseau sont désactivables globalement via kill-switch.

| Domaine | Statut |
|---|---|
| Bandit high | 0 |
| pip-audit (core) | 0 CVE |
| compileall 3.9-3.13 | OK |
| Tests | 121 passed, 3 skipped |
| Offline par défaut | Oui |
| Secrets dans repo | Non |

## Corrections historiques intégrées (v5 → v7.3)

- Sondes IA locales : uniquement loopback (`localhost`, `127.0.0.1`, `::1`).
- SQL : whitelist colonnes + valeurs paramétrées.
- Scripts GDB générés : `0600` privé.
- Campagnes AFL : tmp privé via `tempfile` si aucun dossier fourni.
- Chemins `/tmp`, `/proc`, `/var/run` dans firmware : motifs recherchés dans l'image, pas fichiers temp r3con.
- Appels OSV/NVD : endpoints HTTPS codés, contrôlés, désactivables offline.
- `gdb_cli.py` f-string backslash invalide sur 3.9-3.11 : réécrit compatible.
- `modules/fuzzing/` sans `__init__.py` : corrigé, embarqué dans roues.
- Détection cible 3 copies divergentes → unifiée `core/target_types.py` (ZIP non-APK, pcapng, Mach-O fat corrigés).

## Modèle de sécurité v7.3

### Runner dynamique isolé (`modules/dynamic/sandboxed_runner.py`)

- Aucune exécution auto : `r3con dynamic sandbox` affiche **plan** par défaut, `--execute` requis.
- Réseau coupé par défaut (`unshare -n`) testé avant exécution. Si isolation impossible → refus explicite `network_isolation_unavailable` sauf `--lenient-network` explicite.
- Tmp privé `0700`, env non propagé (whitelist PATH/LANG/LC_ALL/TERM + HOME/TMPDIR redirigés), RLIMIT CPU/AS/NPROC/FSIZE, timeout mural avec kill arbre, captures tronquées 1 Mo.
- Crash → finding `observation` / `exploitability: unknown`, jamais présenté comme exploitable prouvé.
- Ne lance que le binaire local fourni par l'opérateur.

### Supply-chain (`modules/supply_chain/`)

- 100% local : lecture manifestes/lockfiles, aucun HTTP, aucun client réseau dans module. `--offline` est comportement par défaut, pas dégradé.
- Base d'avis par défaut = amorces intégrées vérifiables. Pour couverture réelle, fournir `--policy` JSON/YAML local (export OSV/VEX offline).
- Correspondances versions heuristiques → findings `hypothesis`, confiance bornée, à confirmer contre source à jour.
- Secrets : réutilise scanner local, aucun secret complet écrit dans rapports (extraits bornés).

### Explication et IA (`core/explainer.py`)

- `explain`/`summarize`/`ask` ne lisent QUE le rapport fourni, aucun réseau, aucune ré-analyse fichier arbitraire.
- Chaque réponse : `citations` (preuves rapport) + `uncertainty` (statut, confiance, fallback, corroboration, exploitabilité).
- `--ai` optionnel : sans fournisseur configuré, commande réussit et indique motif. Texte IA étiqueté « ne constitue pas une preuve ». Aucun contenu cible envoyé — seuls champs déjà dans rapport.

### Kill-switch offline (`core/offline.py`)

- `--offline` sur `scan` ou `R3CON_OFFLINE=1` ou `analysis.offline` dans config désactive **toutes** intégrations distantes : VirusTotal/MalwareBazaar/NVD → `skipped/offline_mode` sans requête. Aucun hash transmis quand kill-switch actif.
- Comportement auparavant silencieux de MalwareBazaar « sans auth » corrigé : bloqué aussi.

### Différentiel, cache, reprise

- `compare` / `reports compare` : fichiers locaux uniquement, écriture uniquement dans chemins explicitement demandés.
- `TaskCache` : stockage disque local versionné, max 2 Mo/entrée, clé = hash cible + tâche + profil + empreinte config + empreinte outils + version schéma. Invalidation précise, pas globale.
- Reprise `--resume` : relit artefacts JSON run antérieur, artefact corrompu ignoré, pas exécuté aveuglément.

### Orchestrateur robuste

- Tâche qui lève exception / timeout / sortie invalide → résultat d'erreur isolé, orchestrateur ne casse jamais.
- Cible illisible (permission refusée) → `error/permission_denied` structuré.
- Pré-vérification outils : tâches sans outil externe et sans repli → `unsupported/tool_unavailable` AVANT exécution, n'empêche pas statut global `ok`.
- Métadonnées rapport (`report_meta`) : version r3con, versions outils, hash cible, profil, date, durée, fallbacks, limites, reprise.

## Limites honnêtes (v7.3)

- Détection supply-chain sans base d'avis fraîche partielle par conception (offline).
- RLIMIT_AS approximative pour runtimes réservant beaucoup de mémoire virtuelle (recommander `--memory-mb` large ou conteneur).
- `strace` pas partout → capture syscalls optionnelle, signalée comme fallback.
- Heuristiques types cibles peuvent se tromper sur images rares → plan explicable permet vérification avant exécution (`--plan-only`).
- `r3con` ne remplace pas revue manuelle, sandbox isolé complet, ou avis professionnel. Résultats = indications à vérifier.

## Recommandations opérationnelles

- N'analysez que cibles autorisées.
- Isolez échantillons non fiables (VM, conteneur, labo réseau coupé).
- Ne lancez `dynamic sandbox --execute`, `network live`, `fuzzing` que en labo contrôlé.
- Protégez rapports (peuvent contenir secrets, chemins, IOC).
- Clés API via env (`R3CON_*`, `OPENAI_API_KEY`, etc.), jamais dans dépôt.
- Marquez faux positifs, confirmez hypothèses, vérifiez exploitabilité avant publication/remédiation.

## Validation stable

```bash
python -m compileall -q .
python -m pytest -q
ruff check core cli modules
pyflakes core cli modules
bandit -r core cli modules -lll -q
python -m build
python -m twine check dist/*
r3con --version
r3con --help
r3con tools doctor
```

Tout doit passer sans erreur bloquante pour une release stable.
