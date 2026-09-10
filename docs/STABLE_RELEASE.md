# Release stable r3con 7.3.0 — La vraie version

## Décision de release

**r3con 7.3.0 (2026-09-10) est la version stable de référence.** Elle fusionne et stabilise toutes les branches précédentes (5.x PRO, 6.x Titan-Omega, 7.2) en une seule base offline-first, explicable et reproductible.

Stabilité signifie :
- Installation minimale (`click`, `rich`) fonctionne sans outil externe.
- CLI 27 groupes / 50+ commandes stable, aucune suppression depuis 7.2.
- Contrats de résultats v2.1 rétro-compatibles v2.0.
- Fallbacks locaux signalés explicitement, jamais confondus avec preuves canoniques.
- Tests de non-régression maintenus (121 passed, 3 skipped).
- Packaging éditable + wheel vérifié.

## Validation effectuée (7.3.0)

| Contrôle | Résultat | Commande |
|---|---|---|
| Compilation 3.9-3.13 | Réussie | `python -m compileall -q .` |
| Suite pytest | 121 réussis, 3 ignorés | `python -m pytest -q` |
| Import CLI | Réussi | `python -c "import cli.main"` |
| `r3con --help` | 27 groupes | `r3con --help` |
| `r3con --version` | 7.3.0 | `r3con --version` |
| `tools doctor` | OK | `r3con tools doctor` |
| `scan --explain-plan` | OK | `r3con scan ./tests --explain-plan` |
| `git diff --check` | Propre | `git diff --check` |
| Pyflakes | 0 erreur | `pyflakes core cli modules` |
| Bandit high | 0 | `bandit -r core cli modules -lll -q` |
| Build + twine | OK | `python -m build && twine check dist/*` |
| Packaging éditable | OK | `pip install -e .` |

## Installation reproductible

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pytest -q -rs
python -m compileall -q .
r3con --version
```

Validation distribution :

```bash
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist/*.whl
r3con --version
r3con tools doctor
```

## Ce qui est stable (interface supportée)

- **CLI** : `scan`, `compare`, `supply-chain`, `dynamic sandbox`, `explain`, `summarize`, `ask`, `reports compare`, `tools doctor`, `audit`, `disasm`, `apk`, `firmware`, `malware`, `network`, `web`, `cloud`, `container`, `decompile`, `secrets`, `report`, `dashboard`, `ml`, `fuzzing`, `agent`, `exploit`, `workspace`, `config`, etc. — documentés dans `README.md` et `docs/USER_GUIDE.md`.
- **Contrat Finding v2.1** : `id` stable, `location`, `exploitability`, `references` validées, `corroboration`, `fallback`, `provenance`, `finding_kind`, risk score 0-100.
- **Détection cible unifiée** : `core/target_types.py` — 1 seul classifieur.
- **Cache versionné** : `core/cache.TaskCache` — clé = hash cible + tâche + profil + config + outils + schéma.
- **Offline kill-switch** : `R3CON_OFFLINE=1` ou `--offline` ou `analysis.offline` — bloque toute requête distante.
- **Rapports** : JSON, MD, SARIF (driver version = vraie version r3con), avec métadonnées d'audit.

Modules internes (`modules/*`, `core/*`) peuvent évoluer sans garantie de compatibilité — seule la CLI et les formats de rapports documentés sont supportés.

## Politique de support

- Correctifs : `7.3.x` — pas de breaking change.
- Mineures : `7.x.0` — ajouts compatibles, nouveaux domaines avec doc dans `USER_GUIDE` + entrée dans matrice dépendances.
- Majeures : `8.0.0` — breaking CLI ou contrat, avec période de dépréciation documentée.
- Chaque correction doit ajouter/mettre à jour un test quand testable.
- Chaque nouveau domaine doit avoir section dans `USER_GUIDE` et entrée dans `CAPABILITIES.md`.
- Versions `core/__version__.py`, `pyproject.toml`, `Dockerfile`, `docs/` doivent rester cohérentes.

## Sécurité opérationnelle

- Pas d'autorisation implicite pour scanner/exploiter. Obtenir autorisation, limiter périmètre, isoler échantillons non fiables, protéger rapports, supprimer secrets exposés.
- Résultats heuristiques à valider avant décision remédiation/publication.
- `dynamic sandbox --execute`, `network live`, `fuzzing` uniquement en labo contrôlé.
- Clés API via env, jamais dans dépôt.

## Procédure de publication

```bash
git status --short
git fetch origin
python -m compileall -q .
python -m pytest -q -rs
ruff check .
pyflakes core cli modules
bandit -r core cli modules -lll -q
python -m build
python -m twine check dist/*
# Si OK
git tag -a v7.3.0 -m "r3con 7.3.0 stable - vraie version fusionnée"
git push origin arena/01a08a21-r3con
git push origin v7.3.0 --tags  # seulement après revue artefacts + CHANGELOG + CI
```

Publication d'un tag = action de release. Ne réaliser qu'après revue artefacts, changelog, résultats CI, et `SECURITY_AUDIT.md`.

## Fusion réalisée pour la vraie version

- Suppression docs legacy root (`CAPABILITIES_PRO`, `STRUCTURE_PRO`, etc.) — contenu fusionné dans `docs/ARCHITECTURE.md` + `docs/CAPABILITIES.md`.
- Unification 3 classifieurs cibles → `core/target_types.py`.
- Orchestration : 1 seul moteur `unified.py`, wrappers legacy silencieux pour compatibilité.
- Cache : `core/cache.py` unifié (Incremental + TaskCache).
- Symbolic : `analysis_deep` source de vérité, `analysis` wrapper.
- CLI lean `main.py` ~230L enregistre 27 groupes.
- `compileall` OK, tests OK, packaging OK, `r3con --help` OK.

## Références

- [Python Packaging](https://packaging.python.org/en/latest/tutorials/packaging-projects/)
- [Semantic Versioning](https://semver.org/)
- `docs/USER_GUIDE.md`, `docs/MANUEL_TECHNIQUE_v7.2.md`, `docs/ARCHITECTURE.md`, `README.md`
