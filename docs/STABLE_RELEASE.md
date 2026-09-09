# Release stable r3con 7.2.0

## Décision de release

r3con 7.2.0 est la version stable de la branche principale. La stabilité signifie que l’installation minimale, la CLI, les chemins de fallback, les contrats de résultats et les tests de régression sont maintenus. Les intégrations externes et les extras Python restent optionnels et peuvent avoir des contraintes propres à leur version.

## Validation effectuée

| Contrôle | Résultat |
|---|---|
| Compilation `python -m compileall -q .` | Réussie |
| Suite pytest | 31 réussis, 2 ignorés pour outils/environnement absents |
| Import de la CLI | Réussi |
| `r3con --help` | Réussi |
| `git diff --check` | Réussi |
| Pyflakes sur le générateur PDF | Réussi |
| Packaging éditable | Réussi |

## Installation reproductible

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pytest -q -rs
```

Pour une validation de distribution :

```bash
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist/*.whl
r3con --version
```

## Politique de support

Les commandes et formats documentés dans `README.md` et `docs/USER_GUIDE.md` constituent l’interface supportée. Les modules internes peuvent évoluer sans compatibilité garantie. Les fournisseurs IA, les outils système et les services externes sont testés lorsqu’ils sont disponibles, mais leur comportement peut changer indépendamment du projet.

## Sécurité opérationnelle

La version stable ne donne pas d’autorisation implicite pour scanner ou exploiter une cible. Les opérateurs doivent obtenir une autorisation, limiter le périmètre, isoler les échantillons non fiables, protéger les rapports et supprimer les secrets exposés. Les résultats heuristiques doivent être validés avant toute décision de remédiation ou publication.

## Maintenance

Chaque correction doit ajouter ou mettre à jour un test lorsque le comportement est testable. Chaque nouveau domaine doit recevoir une section dans le guide utilisateur et une entrée dans la matrice des dépendances. Les versions des images Docker, de la documentation et de `core/__version__.py` doivent rester cohérentes.

Les releases correctives utilisent `7.2.x`. Une modification incompatible de la CLI ou du contrat de résultat doit être planifiée pour une version majeure ou faire l’objet d’une période de dépréciation documentée.

## Procédure de publication

```bash
git status --short
git fetch origin
python -m compileall -q .
python -m pytest -q -rs
ruff check .
python -m build
python -m twine check dist/*
git tag -a v7.2.0 -m "r3con 7.2.0 stable"
git push origin master --tags
```

La publication d’un tag est une action de release. Elle ne doit être réalisée qu’après revue des artefacts, du changelog et des résultats CI.

[1]: https://packaging.python.org/en/latest/tutorials/packaging-projects/ "Python Packaging User Guide"
[2]: https://semver.org/ "Semantic Versioning"
