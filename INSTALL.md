# Installation r3con 7.3.0 — Stable

## Pré-requis

- Python 3.9+ (3.11 recommandé)
- pip, venv
- Outils système optionnels : `file`, `strings`, `binutils`, `binwalk`, `tshark` (selon domaine)

## Méthode 1 — Depuis les sources (recommandé pour la stable)

```bash
git clone https://github.com/nsaagent120-droid/r3con.git
cd r3con
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
r3con --version
r3con --help
python -m pytest -q
```

## Méthode 2 — Installation complète automatisée

Script idempotent qui installe dépendances système (si autorisé), venv, extras `full,dev` et répertoires locaux :

```bash
bash scripts/install_full.sh --yes
bash scripts/install_full.sh --docker --yes   # + Docker si possible
bash scripts/install_full.sh --no-system --yes # sans toucher aux paquets système
```

Options : `--no-extras`, `--no-tests`, `--venv PATH`, `--docker`.

## Méthode 3 — PyPI (quand publié)

```bash
pip install r3con
pip install "r3con[binary]"          # ELF/PE/Mach-O
pip install "r3con[firmware,reporting]"
pip install "r3con[full]"            # tout Python
pip install "r3con[dev]"             # tests + lint
```

## Profils d'installation

| Profil | Commande | Usage |
|---|---|---|
| Base | `pip install -e .` | CLI + fallbacks + reporting de base (offline 100%) |
| Binaire | `pip install -e '.[binary]'` | capstone, lief |
| Reporting | `pip install -e '.[reporting]'` | jinja2, yaml |
| Web | `pip install -e '.[web]'` | flask dashboard |
| AST | `pip install -e '.[ast]'` | tree-sitter |
| Symbolic | `pip install -e '.[symbolic]'` | z3-solver |
| IA | `pip install -e '.[ai-all]'` | openai, together |
| Full | `pip install -e '.[full]'` | tous extras Python |
| Dev | `pip install -e '.[dev]'` | pytest, ruff, black, mypy, bandit, build, twine |

## Docker

```bash
# Build local
docker build -t r3con:7.3.0 -t r3con:latest .
docker run --rm -it r3con:latest --help

# Compose avec ES, PG, Redis, dashboard
docker-compose up -d
docker-compose up r3con-dashboard  # http://localhost:5000

# Analyser un fichier local
docker run --rm -it -v $(pwd):/home/r3con/work r3con:latest scan /home/r3con/work/target --profile auto
```

## Vérification post-install

```bash
r3con --version
r3con tools status
r3con tools doctor
python -m compileall -q .
python -m pytest -q
python -m build
python -m twine check dist/*
```

Attendu : `compileall` OK, 121 tests passed, 3 skipped, `r3con --help` liste 27 groupes.

## Troubleshooting

- `capstone/lief manquant` → `pip install capstone lief` ou `pip install -e '.[binary]'`
- `yara` → `pip install yara-python` (nécessite libyara)
- `z3` → `pip install z3-solver`
- `ModuleNotFoundError: pytest` → `pip install -e '.[dev]'`
- Permission → utilisez venv ou `pipx` ou `--user`
- Outils lourds (Ghidra, JADX, Nuclei, Trivy, Zeek) : installation séparée, listés par `install_full.sh` et `tools doctor`.

## Désinstallation

```bash
pip uninstall r3con -y
# ou
pipx uninstall r3con
rm -rf ~/.r3con/
```

## Publication (maintainers)

```bash
make bump-patch   # 7.3.0 -> 7.3.1
make bump-minor   # 7.3.0 -> 7.4.0
make check-build
git tag v7.3.0 -m "r3con 7.3.0 stable"
git push origin master --tags
```
