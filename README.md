# r3con 7.3.0 — Security Research Toolkit

> Outil modulaire de recherche en sécurité pour l’audit de code, les binaires, les APK, les firmwares, les réseaux, les malwares, les conteneurs et les rapports.

[![Python 3.9–3.13](https://img.shields.io/badge/python-3.9%E2%80%933.13-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-121%20passed%2C%203%20skipped-brightgreen.svg)](tests/)
[![License MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## Statut de la release

La version **7.3.0** ajoute le contrat de finding v2.1 (localisation, exploitabilité,
références CWE/CVE/ATT&CK, corroboration multi-outils), la détection unifiée des cibles,
le plan d'analyse explicable avec reprise et cache versionné, l'analyse différentielle
(binaires, APK, firmwares, rapports — JSON/Markdown/SARIF), le module `supply-chain`
(manifestes/lockfiles, SBOM CycloneDX et SPDX, politique locale offline), un runner
dynamique isolé (réseau coupé par défaut, limites de ressources, mode simulation),
le triage de fuzzing exporté en findings et les commandes `explain`/`summarize`/`ask`.
La release **7.3.0** (2026-09-10) est la version stable courante ; elle remplace la base 7.2.0. Elle fournit une base offline-first, des dépendances optionnelles par domaine, une CLI Click/Rich, des contrats de résultats normalisés et des tests de non-régression. Les résultats sont des indications d’analyse et doivent être vérifiés par un analyste qualifié. L’outil ne remplace pas une revue manuelle, un bac à sable isolé ou un avis professionnel.

## Capacités principales

| Domaine | Fonctionnalités | Dépendances optionnelles courantes |
|---|---|---|
| Code source | Audit C/C++, Python, Java, Go, Rust, JavaScript et PHP ; mémoire, injection, secrets, crypto, concurrence | tree-sitter, tree-sitter-c |
| Binaires | Parsing ELF/PE/Mach-O, imports, exports, protections, strings, entropie, désassemblage | capstone, lief, radare2/rizin |
| APK | Manifest, permissions, URLs, secrets, DEX et bibliothèques natives | outils Android externes selon le cas |
| Firmware | Entropie, strings, extraction et indicateurs de backdoor | binwalk |
| Malware | Analyse PE/ELF, IOC, comportement, anti-analyse, unpacking et classification | yara-python, capa, outils externes |
| Réseau | PCAP, flux, DNS, HTTP, TLS, menaces, beaconing et capture live | scapy, tshark, tcpdump |
| Web | Analyse SAST et intégration Nuclei | nuclei |
| Cloud/containers | Dockerfile, Compose, Kubernetes, Terraform, images tar et secrets | outils externes selon le cas |
| IA/RAG | Analyse locale, RAG, agent et fournisseurs IA optionnels | openai, together ou serveur local |
| Reporting | Markdown, HTML, PDF fallback, SARIF, JIRA, DefectDojo, MITRE | jinja2, markdown, weasyprint |
| Exploitation contrôlée | ROP, primitives heap et modèles de PoC | capstone, outils de reverse |

## Installation recommandée

```bash
git clone https://github.com/nsaagent120-droid/r3con.git
cd r3con
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Pour une installation automatisée des dépendances système, de l’environnement Python, des extras `full,dev` et des répertoires locaux, utilisez :

```bash
bash scripts/install_full.sh --yes
```

Ajoutez `--docker` pour installer et activer Docker lorsque le gestionnaire de paquets le permet. Le script signale les outils lourds ou spécifiques à la distribution qui restent à installer séparément.

L’installation minimale fournit la CLI et les fallbacks locaux. Pour les fonctionnalités supplémentaires, installez un profil ciblé :

```bash
python -m pip install -e '.[binary]'
python -m pip install -e '.[reporting]'
python -m pip install -e '.[web]'
python -m pip install -e '.[ast,symbolic]'
python -m pip install -e '.[full]'
python -m pip install -e '.[dev]'
```

Vérification :

```bash
r3con --version
r3con --help
python -m pytest -q
```

## Démarrage rapide

```bash
# Audit de code source
r3con audit file ./src/vulnerable.c --report

# Analyse récursive
r3con audit dir ./src --recursive --report

# Binaire
r3con disasm file ./program --arch auto
r3con disasm strings ./program --min-len 6

# APK et firmware
r3con apk analyze ./application.apk --report
r3con firmware analyze ./firmware.bin --report

# PCAP et malware
r3con network analyze ./capture.pcap
r3con malware analyze ./sample --profile full

# Vérifier les outils disponibles
r3con tools status

# v7.3 : plan explicable, supply chain, différentiel, explication citée
r3con scan ./program --profile auto --explain-plan
r3con supply-chain scan ./project --sbom cyclonedx --dependencies --secrets --report supply-chain.json
r3con compare ./old.apk ./new.apk --format md --output diff.md
r3con explain FINDING_ID --report report.json
r3con ask report.json "Quels risques sont corroborés par plusieurs outils ?"
```

Toutes les fonctions v7.3 sont offline-first : aucun fichier, secret ou donnée n'est
envoyé vers un service distant par défaut.

Pour les commandes exactes et les options de chaque groupe, consulter le [guide utilisateur complet](docs/USER_GUIDE.md). Pour l’architecture interne et les contrats de données, consulter le [manuel technique](docs/MANUEL_TECHNIQUE_v7.2.md).

## Principes d’utilisation sûre

Analysez uniquement des cibles que vous êtes autorisé à examiner. Utilisez un environnement isolé pour les exécutables non fiables. N’activez les captures réseau live, les intégrations distantes, les fournisseurs IA ou les fonctions d’exploitation que dans un cadre approuvé. Les clés API doivent être fournies par variables d’environnement et ne doivent jamais être ajoutées au dépôt.

Les résultats distinguent sévérité, confiance, provenance et statut de revue. Un finding de type heuristique, CVE ou YARA ne constitue pas automatiquement une preuve d’exploitabilité. Les fallbacks sont signalés lorsque l’outil spécialisé n’est pas installé.

## Configuration et données locales

Les fichiers de configuration principaux sont `config.yaml` et `config.pro.yaml`. Le stockage local par défaut se trouve sous `~/.r3con/`, notamment pour la base SQLite, les rapports, le cache et les sessions. Les variables `R3CON_*` peuvent remplacer les valeurs de configuration. Utilisez `r3con config --help` pour voir les commandes disponibles.

## Développement et release

```bash
make test
make lint
python -m compileall -q .
python -m build
python -m twine check dist/*
```

La CI GitHub exécute la compilation, les tests, Ruff, Pyflakes, Bandit et la construction du paquet. Les outils externes comme radare2/rizin sont testés séparément lorsqu’ils sont disponibles.

## Documentation

| Document | Contenu |
|---|---|
| [Guide utilisateur](docs/USER_GUIDE.md) | Installation, commandes, workflows et dépannage par domaine |
| [Manuel technique](docs/MANUEL_TECHNIQUE_v7.2.md) | Architecture, modules, configuration et intégrations |
| [Guide de release stable](docs/STABLE_RELEASE.md) | Critères de stabilité, validation et exploitation en production |
| [Sécurité](SECURITY_AUDIT.md) | Limites et recommandations de sécurité |
| [Journal des changements](CHANGELOG.md) | Historique des versions |

## Licence

Ce projet est distribué sous licence MIT. Voir [LICENSE](LICENSE).

[1]: https://github.com/nsaagent120-droid/r3con "Dépôt officiel r3con"
[2]: https://click.palletsprojects.com/ "Documentation Click"
[3]: https://docs.pytest.org/ "Documentation pytest"
