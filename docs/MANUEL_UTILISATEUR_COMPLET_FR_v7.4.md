# Manuel utilisateur complet de r3con 7.4.0

## 1. Présentation

r3con est un outil local et modulaire de recherche en sécurité. Il orchestre plusieurs analyseurs internes et plusieurs outils externes. Il peut examiner du code source, des binaires, des applications Android, des firmwares, des captures réseau, des échantillons suspects, des projets web, des dépendances, des conteneurs et des configurations cloud.

Le fonctionnement par défaut est **offline-first**. Les fichiers ne sont pas envoyés vers un service distant par défaut. Les intégrations réseau, les fournisseurs IA et les scanners distants sont des exceptions qui doivent être activées volontairement.

r3con produit des observations et des findings normalisés. Un finding est un résultat d’analyse qui contient généralement une sévérité, une confiance, une provenance, une localisation et une recommandation. Un finding ne constitue pas automatiquement une preuve d’exploitabilité.

> Utilise r3con uniquement sur des fichiers, applications, réseaux et systèmes pour lesquels tu disposes d’une autorisation explicite.

## 2. Architecture pratique

L’utilisation de r3con repose sur cinq éléments.

| Élément | Rôle |
|---|---|
| **Cible** | Fichier, dossier, APK, firmware, PCAP, projet ou rapport soumis à l’analyse |
| **Profil** | Ensemble d’analyses adaptées au domaine |
| **Run** | Exécution complète d’un pipeline sur une cible |
| **Job** | Processus externe lancé avec des limites |
| **Workspace** | Espace de travail qui regroupe cibles, rapports, journaux et artefacts |

Le scan orchestré utilise le pipeline interne :

```text
Cible
  ↓
Détection du type
  ↓
Choix du profil
  ↓
Plan d’analyse
  ↓
Analyseurs internes et outils externes
  ↓
Findings normalisés
  ↓
Rapport JSON, Markdown ou SARIF
```

Un outil externe est lancé par un workspace d’exécution borné. Le processus reçoit une liste d’arguments. r3con ne crée pas de shell implicite. La durée, la sortie et le nombre de processus sont limités.

## 3. Installation

### 3.1 Prérequis

Une installation Linux avec Python 3.9 à 3.13 est recommandée. Git est nécessaire pour récupérer le dépôt. Les outils spécialisés sont optionnels et dépendent du domaine.

Vérifie l’environnement :

```bash
python3 --version
git --version
uname -a
```

### 3.2 Installation standard

```bash
git clone https://github.com/nsaagent120-droid/r3con.git
cd r3con
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Vérifie ensuite :

```bash
r3con --version
r3con --help
r3con tools status
r3con tools doctor --json-output
```

### 3.3 Installation des profils optionnels

Installe le profil qui correspond à ton besoin. Il est préférable d’éviter l’installation de tous les outils sur une machine de production si tu n’en as pas besoin.

```bash
python -m pip install -e '.[binary]'
python -m pip install -e '.[reporting]'
python -m pip install -e '.[web]'
python -m pip install -e '.[ast,symbolic]'
python -m pip install -e '.[ai-all]'
python -m pip install -e '.[full]'
python -m pip install -e '.[dev]'
```

Le script d’installation complète peut préparer les dépendances et les répertoires :

```bash
bash scripts/install_full.sh --yes
```

Ajoute `--docker` uniquement si Docker est nécessaire et autorisé sur la machine.

### 3.4 Installation Docker

Le Dockerfile fournit une image avec les dépendances système principales. Construis l’image depuis la racine du dépôt :

```bash
docker build -t r3con:7.4.0 .
```

Lance une analyse locale en montant uniquement le dossier nécessaire :

```bash
docker run --rm -it \
  -v "$PWD/targets:/targets:ro" \
  -v "$PWD/reports:/reports" \
  r3con:7.4.0 \
  scan /targets/sample.bin --json-output /reports/sample.json
```

Le montage en lecture seule protège les cibles. Monte un dossier séparé pour les rapports.

## 4. Diagnostic avant une campagne

Avant une analyse importante, exécute :

```bash
r3con tools status
r3con tools doctor --json-output
r3con cache status
r3con cache verify
```

`tools status` fournit une vue rapide. `tools doctor` montre les capacités disponibles et les outils absents. `cache status` montre l’état des caches locaux. `cache verify` vérifie que les données de cache sont lisibles.

Examine aussi la cible :

```bash
file TARGET
sha256sum TARGET
ls -lah TARGET
```

Conserve le hash de la cible dans le dossier de campagne. Cette pratique permet de vérifier que le rapport correspond bien au fichier analysé.

## 5. Choisir une commande

| Besoin | Commande |
|---|---|
| Voir les commandes | `r3con --help` |
| Comprendre le plan | `r3con scan TARGET --explain-plan` |
| Afficher uniquement le plan | `r3con scan TARGET --plan-only` |
| Analyse adaptative | `r3con scan TARGET --profile auto` |
| Analyse rapide | `r3con scan TARGET --profile quick` |
| Analyse complète | `r3con scan TARGET --profile full` |
| Lancer un outil externe borné | `r3con runtime run TOOL ARGS...` |
| Ouvrir la console | `r3con interactive` |
| Voir le cache | `r3con cache status` |
| Voir les jobs | `r3con runtime jobs` |
| Créer un workspace | `r3con workspace create NAME` |
| Comparer deux cibles | `r3con compare OLD NEW` |

Lorsque tu ne connais pas encore les dépendances ou le temps d’exécution, commence par `--plan-only`.

## 6. Scan général

### 6.1 Scan simple

```bash
r3con scan ./target.bin
```

### 6.2 Scan avec profil

```bash
r3con scan ./target.bin --profile auto
r3con scan ./target.bin --profile binary
r3con scan ./project --profile source
r3con scan ./firmware.bin --profile firmware
r3con scan ./capture.pcap --profile network
r3con scan ./sample.exe --profile dynamic
r3con scan ./target.bin --profile full
```

### 6.3 Scan de dossier

```bash
r3con scan ./src --profile source --workers 4
```

r3con sélectionne les fichiers compatibles et applique les limites prévues. Vérifie le plan avant de lancer une grande arborescence.

### 6.4 Limites et cache

```bash
r3con scan ./project \
  --timeout 300 \
  --workers 4 \
  --max-mb 256 \
  --progress
```

Désactive le cache uniquement lorsque cela est nécessaire :

```bash
r3con scan ./project --no-cache
```

Utilise `--offline` pour interdire les intégrations distantes :

```bash
r3con scan ./project --offline
```

### 6.5 Rapport JSON et seuil de sortie

```bash
r3con scan ./project \
  --json-output reports/project.json
```

Pour faire échouer une automatisation lorsqu’un finding atteint un seuil :

```bash
r3con scan ./project --fail-on high
```

Les seuils disponibles sont `critical`, `high` et `medium`. Le code de sortie doit être interprété avec le contenu du rapport.

### 6.6 Reprise

```bash
r3con scan ./project --resume ./reports/project-run
```

La reprise réutilise les tâches terminées lorsque la cible, le profil, la configuration, les outils et le contrat de résultat correspondent encore. Après une modification importante de la cible, lance une nouvelle analyse complète.

## 7. Console interactive

Lance la console :

```bash
r3con interactive
```

Le prompt indique la cible courante :

```text
r3con>
r3con(program.bin)>
```

Commandes courantes :

```text
help
set target ./program.bin
show options
history
sessions
theme cyber
theme matrix
clear
exit
```

La console permet aussi de lancer un job externe borné :

```text
run strings ./program.bin
jobs
stop JOB_ID
```

`run` n’est pas un shell libre. Les arguments sont découpés puis envoyés sans interprétation shell implicite.

## 8. Code source et SAST

SAST signifie **Static Application Security Testing**. Il s’agit d’une analyse statique du code sans exécution de l’application.

### 8.1 Fichier unique

```bash
r3con audit file ./src/parser.c --report
r3con audit file ./src/app.py --report
```

### 8.2 Projet récursif

```bash
r3con audit dir ./src --recursive --report
r3con scan ./src --profile source --json-output reports/source.json
```

Les analyses recherchent notamment les risques mémoire, les injections, les secrets, les erreurs cryptographiques et certains problèmes de concurrence.

### 8.3 Interprétation

Vérifie toujours :

1. le fichier et la ligne signalés ;
2. le contexte d’exécution ;
3. la faisabilité du chemin de données ;
4. l’existence d’une validation en amont ;
5. la présence éventuelle d’un faux positif.

Un motif textuel n’est pas toujours une vulnérabilité exploitable.

## 9. Binaires et reverse engineering

### 9.1 Identification et strings

```bash
r3con disasm file ./program
r3con disasm strings ./program --min-len 6
```

### 9.2 Imports, protections et architecture

```bash
r3con disasm imports ./program --vuln-check
r3con disasm protections ./program
r3con scan ./program --profile binary --explain-plan
```

Selon les outils installés, r3con peut utiliser des parseurs ELF, PE ou Mach-O, Capstone, LIEF, radare2 ou d’autres adaptateurs.

### 9.3 Radare2 et GDB

```bash
r3con r2 ./program
r3con gdb ./program
```

Ces commandes lancent directement un outil de reverse engineering ou de débogage. Utilise-les uniquement dans un environnement autorisé. Un binaire non fiable peut déclencher des comportements dangereux lorsqu’il est exécuté ou débogué.

### 9.4 Comparaison de binaires

```bash
r3con compare ./program-old ./program-new \
  --kind binary \
  --format md \
  --output reports/binary-diff.md
```

Le différentiel aide à localiser les changements. Il ne prouve pas qu’un changement est vulnérable.

## 10. APK et Android

### 10.1 Analyse principale

```bash
r3con apk analyze ./application.apk --report
r3con scan ./application.apk --profile apk
```

### 10.2 Points à examiner

L’analyse Android porte notamment sur :

- le manifeste ;
- les permissions ;
- les composants exportés ;
- les URLs ;
- les secrets ;
- le DEX ;
- les bibliothèques natives ;
- la signature et les paramètres de build.

### 10.3 Outils externes utiles

Selon le besoin, installe `aapt`, `apktool`, `jadx`, `apksigner` et les outils Android SDK. Vérifie leur présence avec `r3con tools doctor`.

Conserve le hash de l’APK original. Ne diffuse pas les certificats, tokens et secrets extraits dans un rapport public.

## 11. Firmware et IoT

### 11.1 Analyse générale

```bash
r3con firmware analyze ./firmware.bin --report
r3con scan ./firmware.bin --profile firmware
```

### 11.2 Extraction

```bash
r3con firmware extract ./firmware.bin --output ./extracted
r3con firmware strings ./firmware.bin --min-len 6
r3con firmware entropy ./firmware.bin
```

L’extraction peut produire beaucoup de fichiers. Utilise un dossier de travail dédié. `binwalk` améliore la reconnaissance des systèmes de fichiers et des formats embarqués.

### 11.3 Recherche manuelle

Après extraction, vérifie les scripts de démarrage, les comptes, les clés, les certificats, les mots de passe, les services réseau et les versions de composants.

L’analyse statique d’un firmware ne remplace pas une émulation contrôlée. Ne démarre pas une image inconnue dans le processus principal de r3con.

## 12. Réseau et PCAP

PCAP désigne un fichier de capture de paquets réseau.

### 12.1 Analyse hors ligne

```bash
r3con network analyze ./capture.pcap
r3con network flow ./capture.pcap
r3con network dns ./capture.pcap
r3con network threat ./capture.pcap
r3con network tools ./capture.pcap
```

### 12.2 Capture live

```bash
r3con network live eth0 --duration 60
```

La capture live peut demander des privilèges. Elle doit être limitée à une interface et une durée approuvées.

### 12.3 Confidentialité

Une capture peut contenir des mots de passe, cookies, tokens, adresses privées et données personnelles. Protège les fichiers PCAP et fixe une durée de conservation.

## 13. Malware et fichiers suspects

### 13.1 Analyse statique

```bash
r3con malware analyze ./sample.exe --profile full
r3con malware pe ./sample.exe
r3con malware elf ./sample
r3con malware ioc ./sample.exe
r3con malware anti ./sample.exe
r3con malware unpack ./sample.exe
```

### 13.2 Exécution contrôlée

Le runner dynamique doit être utilisé dans un laboratoire isolé :

```bash
r3con dynamic sandbox ./sample.exe --plan
r3con dynamic sandbox ./sample.exe --execute --timeout 10 --mem-mb 256
```

Le réseau est coupé par défaut. N’active pas le réseau pour un échantillon inconnu sans environnement de laboratoire, surveillance et autorisation explicite.

Les résultats comportementaux sont limités par la durée et les capacités d’isolation. L’absence d’un événement observé ne prouve pas l’absence du comportement.

## 14. Web et applications

### 14.1 Analyse locale

```bash
r3con audit dir ./web-app --recursive --report
r3con scan ./web-app --profile source
r3con web --help
```

L’analyse locale peut rechercher les injections, secrets, erreurs de configuration et patterns dangereux.

### 14.2 Scanners externes

Les intégrations comme Nuclei doivent être utilisées uniquement sur des cibles autorisées :

```bash
r3con tools status
r3con tools doctor --json-output
```

Ne lance pas de scan distant contre un domaine tiers sans mandat documenté.

## 15. Cloud, conteneurs et supply chain

### 15.1 Dépendances et SBOM

SBOM signifie **Software Bill of Materials**. Il s’agit d’un inventaire des composants logiciels.

```bash
r3con supply-chain scan ./project \
  --sbom cyclonedx \
  --dependencies \
  --secrets \
  --report reports/supply-chain.json
```

Les formats CycloneDX et SPDX permettent de transmettre l’inventaire à d’autres outils.

### 15.2 Docker, Compose, Kubernetes et Terraform

Analyse les Dockerfiles, les fichiers Compose, les manifests Kubernetes et les fichiers Terraform :

```bash
r3con cloud --help
r3con container --help
r3con scan ./infrastructure --profile auto
```

Vérifie les permissions, secrets, images non épinglées, privilèges, volumes, ports et politiques réseau.

### 15.3 Interprétation des dépendances

Une dépendance trouvée dans un manifeste ne suffit pas à démontrer qu’elle est chargée en production. Vérifie le lockfile, le graphe réel et l’environnement de build.

## 16. Fuzzing

Le fuzzing fournit des entrées nombreuses ou mutées à une cible afin de rechercher des crashs et comportements inattendus. Il est réservé aux cibles autorisées.

Commence par un plan :

```bash
r3con fuzzing plan campaign-name \
  --timeout-ms 1000 \
  --memory-mb 256 \
  --max-runtime 60
```

Exporte ensuite les findings :

```bash
r3con fuzzing export-findings campaign-name
```

Définis toujours une limite de temps, une limite mémoire et un dossier d’artefacts. Ne modifie pas la cible originale. Trie et minimise les crashes dans une copie.

## 17. Exploitation contrôlée et recherche

Les fonctionnalités ROP, heap, primitives et templates de PoC sont réservées à un laboratoire autorisé :

```bash
r3con exploit --help
r3con advanced heap ./source.c
r3con advanced crypto ./source.c
r3con advanced kernel ./source.c
```

Les sorties sont des éléments d’étude. Elles ne constituent pas une autorisation d’exploitation contre une cible réelle.

## 18. Outils externes et jobs

### 18.1 Exécution bornée

```bash
r3con runtime run printf "hello"
r3con runtime run strings ./program
r3con runtime run --timeout 60 file ./program
```

Pour analyser une ligne de commande avant exécution :

```bash
r3con runtime parse 'strings -n 8 ./program'
```

### 18.2 Réseau

Pour les outils locaux comme `file`, `strings`, `readelf` ou `gdb`, r3con utilise par défaut un environnement réduit avec le réseau bloqué par variables d’environnement. Si le noyau ou le conteneur interdit `unshare -n`, le job local peut tout de même s’exécuter.

Pour exiger l’isolation réseau Linux stricte et refuser le job lorsque `unshare -n` n’est pas disponible :

```bash
r3con runtime run --strict-network file ./program
```

Pour un laboratoire explicitement autorisé avec réseau :

```bash
r3con runtime run --allow-network outil --option valeur
```

Utilise `--allow-network` avec prudence. `--lenient-network` permet de continuer lorsque l’isolation stricte n’est pas disponible, mais réduit la garantie de sécurité.

### 18.3 Historique des jobs

```bash
r3con runtime jobs
r3con runtime jobs --json-output
r3con runtime show JOB_ID
r3con runtime clean --yes
```

Les sorties sont bornées et les métadonnées sont conservées sous `~/.r3con/jobs/`. La persistance actuelle conserve l’historique d’un job terminé. Elle ne reprend pas un processus vivant après redémarrage.

## 19. Cache et performance

### 19.1 Contrôle du cache

```bash
r3con cache status
r3con cache status --json-output
r3con cache verify
r3con cache clear --yes
```

Le cache de fichiers se trouve généralement sous `~/.r3con/cache/analysis_cache.json`. Le cache de tâches se trouve sous `~/.r3con/cache/tasks/`.

### 19.2 Benchmark

```bash
python scripts/benchmark.py \
  --files 20 \
  --runs 3 \
  --workers 4 \
  --output reports/benchmark.json
```

Le benchmark crée un corpus temporaire déterministe. Il mesure la durée et le pic mémoire Python. Compare uniquement des mesures faites dans des environnements similaires.

### 19.3 Progression

```bash
r3con scan ./project --progress
r3con scan ./project --no-progress
```

La progression est activée par défaut dans un terminal interactif. Elle est désactivée implicitement lorsque la sortie n’est pas interactive afin de préserver les flux JSON et CI.

## 20. Workspaces

Crée un workspace analytique pour isoler une campagne :

```bash
r3con workspace create firmware-audit --type firmware --profile firmware
r3con workspace list
r3con workspace show firmware-audit
r3con workspace info firmware-audit --tools
r3con workspace add-target firmware-audit ./firmware.bin
```

Un workspace doit regrouper les cibles, les paramètres, les rapports et les notes d’une même campagne. Utilise un nom différent pour chaque version importante d’une cible.

Les workspaces d’exécution des jobs sont distincts des workspaces analytiques. Le premier est temporaire et privé. Le second organise la campagne et ses artefacts.

## 21. Rapports et analyse différentielle

### 21.1 Générer un rapport

```bash
r3con scan ./target \
  --json-output reports/target.json
```

### 21.2 Expliquer un finding

```bash
r3con explain FINDING_ID --report reports/target.json
```

### 21.3 Résumer un rapport

```bash
r3con summarize reports/target.json
```

### 21.4 Question locale sur un rapport

```bash
r3con ask reports/target.json \
  "Quels risques sont corroborés par plusieurs outils ?"
```

### 21.5 Comparer deux rapports

```bash
r3con reports compare reports/old.json reports/new.json --format md
```

Garde le rapport, le hash de la cible, la version de r3con, les versions d’outils et les options utilisées.

## 22. CI et automatisation

Exemple de contrôle simple :

```bash
set -o pipefail
r3con scan ./src \
  --profile source \
  --offline \
  --no-progress \
  --json-output reports/ci.json \
  --fail-on high
```

Dans une CI, utilise `--no-progress`, un rapport JSON et des codes de sortie explicites. Ne mets aucune clé API dans les arguments. Utilise des variables secrètes de la CI.

## 23. Sécurité et confidentialité

Analyse uniquement des cibles autorisées. Travaille dans une machine isolée pour les exécutables suspects. Ne mélange pas les rapports publics et les données sensibles.

Protège les répertoires suivants :

```text
~/.r3con/
~/.r3con/cache/
~/.r3con/jobs/
~/.r3con_history
```

Les rapports peuvent contenir du code, des secrets, des URLs internes, des adresses IP et des données personnelles. Définis une politique de conservation.

Les clés de fournisseurs IA doivent être fournies par variables d’environnement :

```bash
export OPENAI_API_KEY='valeur-locale'
```

Ne les ajoute jamais au dépôt, à un rapport, à l’historique du shell ou à une commande enregistrée.

## 24. Comprendre les findings

Un finding doit être évalué sur plusieurs axes.

| Axe | Question |
|---|---|
| Sévérité | Quel serait l’impact si le risque était confirmé ? |
| Confiance | Les éléments observés sont-ils suffisamment précis ? |
| Provenance | Quel analyseur ou outil a produit le résultat ? |
| Corroboration | Plusieurs analyseurs observent-ils le même fait ? |
| Exploitabilité | Existe-t-il un chemin démontré ? |
| Localisation | Le fichier, l’offset ou la fonction sont-ils vérifiables ? |
| Fallback | Une dépendance manquait-elle ? |
| Action | Quelle correction ou vérification est recommandée ? |

Une sévérité élevée ne signifie pas automatiquement que l’exploitation est démontrée. Un finding doit être confirmé dans le contexte de l’application.

## 25. Dépannage

### Commande inconnue

```bash
r3con --help
r3con DOMAIN --help
```

Vérifie que l’environnement virtuel est activé et que le projet est installé en mode éditable.

### Outil absent

```bash
r3con tools doctor --json-output
```

Installe le profil Python ou l’outil système indiqué. Si un fallback existe, vérifie qu’il est indiqué dans le rapport.

### Job qui dépasse le délai

Réduis la cible ou augmente explicitement le délai :

```bash
r3con runtime run --timeout 600 outil cible
```

Un timeout doit rester documenté. Il ne faut pas supprimer les limites uniquement pour faire disparaître une erreur.

### Isolation réseau refusée

Le runner strict peut refuser une exécution si `unshare -n` n’est pas disponible. Vérifie l’environnement. Utilise `--lenient-network` uniquement dans un laboratoire maîtrisé.

### Cache incohérent

```bash
r3con cache verify
r3con cache status
r3con cache clear --yes
```

Après suppression, relance le scan.

### Rapport incomplet

Examine les statuts individuels et les avertissements. Vérifie les outils absents. Utilise `--resume` si le répertoire de reprise est disponible.

### Couleurs absentes

```bash
r3con --no-color --help
R3CON_NO_COLOR=1 r3con interactive
```

La sortie non colorée est préférable pour les journaux et les pipelines CI.

## 26. Développement et validation

Pour travailler sur le dépôt :

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m compileall -q .
python -m build
python -m twine check dist/*
```

Avant un commit, vérifie :

```bash
git diff --check
git status --short
```

## 27. Références du dépôt

- [Guide utilisateur 7.4](USER_GUIDE_v7.4.md) : guide condensé par domaine.
- [Modèle de fonctionnement 7.4](OPERATING_MODEL_v7.4.md) : concepts, états et limites.
- [Guide de release](STABLE_RELEASE.md) : critères de stabilité.
- [Politique de sécurité](../SECURITY_AUDIT.md) : contrôles et limites.
- [Changelog](../CHANGELOG.md) : historique des versions.

## Références externes

[1]: https://github.com/nsaagent120-droid/r3con "Dépôt officiel r3con"
[2]: https://docs.python.org/3/library/venv.html "Documentation Python venv"
[3]: https://docs.python.org/3/library/subprocess.html "Documentation Python subprocess"
[4]: https://click.palletsprojects.com/ "Documentation Click"
[5]: https://rich.readthedocs.io/ "Documentation Rich"
[6]: https://docs.docker.com/ "Documentation Docker"
[7]: https://cyclonedx.org/ "Standard CycloneDX SBOM"
[8]: https://spdx.dev/ "Standard SPDX SBOM"
