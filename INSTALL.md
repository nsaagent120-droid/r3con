# Installation professionnelle - r3con v5.0.3

## PyPI (recommandé)

```bash
# Minimal - 100% offline, fonctionne sans rien
pip install r3con

# Avec analyse binaire (ELF/PE/Mach-O)
pip install "r3con[binary]"

# Firmware + reporting
pip install "r3con[firmware,reporting]"

# Full - tout inclus
pip install "r3con[full]"

# Vérifier
r3con --help
r3con --version
```

## pipx (isolation)

```bash
pipx install r3con
pipx install "r3con[full]"

# Upgrade
pipx upgrade r3con
```

## Docker (officiel)

```bash
# Pull
docker pull ghcr.io/nsaagent120-droid/r3con:latest

# Run
docker run --rm -it ghcr.io/nsaagent120-droid/r3con r3con --help

# Analyser un fichier local
docker run --rm -it -v $(pwd):/home/r3con/work ghcr.io/nsaagent120-droid/r3con r3con audit file /home/r3con/work/vuln.c

# Build local
make docker
docker run --rm -it r3con:latest --help
```

## Depuis les sources

```bash
git clone https://github.com/nsaagent120-droid/r3con
cd r3con

# venv
python3 -m venv .venv
source .venv/bin/activate

# Install dev
make dev
# ou
pip install -e ".[dev,full]"

# Tests
make test
```

## Vérification post-install

```bash
r3con --help
r3con tools status
r3con audit file examples/vuln.c 2>/dev/null || echo "exemple manquant, test avec un fichier C"

# Benchmark (optionnel)
r3con benchmark ./test_binary --profile quick
```

## Mise à jour

```bash
pip install --upgrade "r3con[full]"
# ou
pipx upgrade r3con
```

## Désinstallation

```bash
pip uninstall r3con -y
# ou
pipx uninstall r3con
```

## Troubleshooting

- **capstone/lief manquant** : `pip install capstone lief` ou `pip install "r3con[binary]"`
- **yara** : `pip install yara-python` (nécessite libyara)
- **z3** : `pip install z3-solver`
- **Permission** : utilisez `--user` ou `pipx` ou venv

## Publication (maintainers)

```bash
# Bump version
make bump-patch   # 5.0.3 -> 5.0.4
make bump-minor   # 5.0.3 -> 5.1.0

# Build + check
make check-build

# Tag + push -> déclenche publish PyPI + Docker via GitHub Actions
git tag v5.0.4
git push origin v5.0.4

# Ou manuel
make publish        # PyPI
make publish-test   # TestPyPI
```
