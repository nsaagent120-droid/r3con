# Guide utilisateur r3con 7.3.0

## 1. Positionnement et limites

r3con est un orchestrateur d’analyses de sécurité local. Il agrège des analyseurs spécialisés et produit des résultats structurés. Il est adapté au triage, à l’audit de code autorisé, à la recherche, à la préparation de rapports et à l’intégration CI. Il ne garantit ni l’absence de vulnérabilité ni l’exploitabilité d’un finding.

> N’analysez que des systèmes, fichiers, applications et réseaux pour lesquels vous avez une autorisation explicite. Les fonctions réseau live, fuzzing et exploitation doivent être utilisées dans un laboratoire contrôlé.

## 2. Installation et profils

L’installation automatisée complète est disponible dans `scripts/install_full.sh`. Elle est idempotente : elle peut être relancée après une interruption et réutilise le virtualenv existant.

```bash
bash scripts/install_full.sh --yes
bash scripts/install_full.sh --docker --yes
```

Utilisez `--no-system` sur une machine où vous ne souhaitez pas modifier les paquets système, `--no-extras` pour ne pas tenter les outils optionnels, `--no-tests` pour ignorer la validation finale et `--venv PATH` pour choisir le chemin du virtualenv. Le script n’installe pas silencieusement Ghidra, JADX, Nuclei, Trivy ou Zeek : ces outils ont des méthodes de distribution différentes et sont listés dans son rapport final.

La base requiert Python 3.9 ou plus récent, `click` et `rich`. La commande `r3con --help` doit fonctionner sans outil externe.

| Profil | Commande | Usage |
|---|---|---|
| Base | `python -m pip install -e .` | CLI, fallbacks, rapports de base |
| Binaire | `python -m pip install -e '.[binary]'` | Capstone et LIEF |
| Reporting | `python -m pip install -e '.[reporting]'` | Jinja2, YAML et export enrichi |
| Web | `python -m pip install -e '.[web]'` | Dashboard Flask et templates |
| AST | `python -m pip install -e '.[ast]'` | Analyse syntaxique C |
| Symbolique | `python -m pip install -e '.[symbolic]'` | Contraintes avec Z3 |
| IA | `python -m pip install -e '.[ai-all]'` | Fournisseurs compatibles OpenAI/Together |
| Complet | `python -m pip install -e '.[full]'` | Tous les extras Python |
| Développeur | `python -m pip install -e '.[dev]'` | Tests et qualité |

Après installation :

```bash
r3con --version
r3con tools status
python -m pytest -q
```

## 3. Format général des commandes

La plupart des commandes acceptent `--json` ou une option de rapport. Pour automatiser une analyse, privilégiez JSON ou SARIF plutôt que la sortie colorée. Désactivez les couleurs en CI :

```bash
r3con --no-color --no-banner audit file ./src/main.c
```

Consultez toujours l’aide locale, qui reflète exactement la version installée :

```bash
r3con GROUP --help
r3con GROUP COMMAND --help
```

## 4. Audit de code source

Le groupe `audit` recherche des défauts de mémoire, injections, secrets, cryptographie faible, erreurs de concurrence, problèmes web et constructions dangereuses. Les analyseurs AST sont utilisés lorsqu’ils sont disponibles ; sinon un fallback prudent est utilisé.

```bash
r3con audit file ./src/main.c
r3con audit file ./src/main.c --lang c --focus memory --depth deep
r3con audit dir ./src --recursive --report
```

Workflow recommandé : commencez par une analyse complète, relancez les catégories prioritaires, puis vérifiez chaque finding dans le code source. Conservez le rapport et marquez les faux positifs dans votre système de suivi. Les détections de secrets doivent être traitées comme sensibles et les rapports doivent être protégés.

## 5. Binaires et reverse engineering

Le groupe `disasm` combine parsing, strings, imports, protections et désassemblage. Les outils système `file`, `strings`, `nm`, `readelf` et `objdump` servent de fallbacks lorsque Capstone ou LIEF ne sont pas installés.

```bash
r3con disasm file ./bin/app --arch auto
r3con disasm file ./bin/app --arch x86_64 --output pseudocode
r3con disasm strings ./bin/app --min-len 6
r3con disasm imports ./bin/app --vuln-check
r3con tools check capstone
```

Pour une analyse approfondie, utilisez ensuite Ghidra, radare2/rizin ou un débogueur dans un environnement isolé. r3con facilite le triage ; il ne remplace pas une analyse de reverse interactive complète.

## 6. Analyse avancée

Le groupe `advanced` contient les analyses mémoire, crypto, kernel, TOCTOU et protocole :

```bash
r3con advanced heap ./src/allocator.c --allocator glibc
r3con advanced crypto ./src/crypto.c
r3con advanced kernel ./driver.c --type driver
r3con advanced toctou ./src/handler.c
r3con advanced proto ./src/protocol.c --protocol tls
```

Ces commandes produisent des hypothèses et des éléments de preuve. Les primitives d’exploitation et les scénarios doivent être vérifiés manuellement et ne doivent être exécutés que sur une cible de laboratoire.

## 7. APK Android

Le groupe `apk` inspecte le manifest, les permissions, les URLs, les secrets, le DEX et les bibliothèques natives. Les outils Android externes peuvent fournir une décompilation plus complète.

```bash
r3con apk analyze ./app.apk --report
r3con apk permissions ./app.apk
r3con apk manifest ./AndroidManifest.xml
```

Pour un audit mobile sérieux, complétez l’analyse statique par une revue du stockage local, des intents exportés, du TLS, de l’authentification et des composants exécutés. Ne distribuez jamais un APK ou un rapport contenant des secrets sans contrôle d’accès.

## 8. Firmware et IoT

Le groupe `firmware` calcule l’entropie, extrait les chaînes et recherche des indicateurs dans les images firmware. `binwalk` est optionnel pour l’extraction avancée.

```bash
r3con firmware analyze ./router.bin --report
r3con firmware strings ./router.bin --min-len 6
r3con firmware entropy ./router.bin --block-size 4096
r3con firmware extract ./router.bin --output ./extracted
```

Travaillez sur une copie immuable, calculez un hash avant analyse et inspectez les fichiers extraits hors réseau. L’analyse d’un firmware peut révéler des clés, mots de passe et certificats ; traitez les sorties comme des données confidentielles.

## 9. Malware et forensics

Le groupe `malware` propose des analyseurs PE/ELF, IOC, comportement, classification, unpacking et anti-analyse.

```bash
r3con malware analyze ./sample --profile full --json
r3con malware pe ./sample --json
r3con malware elf ./sample --json
r3con malware ioc ./sample --json
r3con malware behavior ./sample --json
```

L’analyse statique doit être réalisée dans un environnement isolé. r3con ne doit pas être considéré comme un sandbox complet. Pour une exécution dynamique, utilisez une VM dédiée avec snapshots, réseau contrôlé et collecte séparée.

## 10. Réseau et PCAP

Le groupe `network` traite les captures offline et peut utiliser des outils système. Les captures live exigent une autorisation et des privilèges adaptés.

```bash
r3con network analyze ./capture.pcap --json
r3con network threat ./capture.pcap --json
r3con network flow ./capture.pcap --json
r3con network dns ./capture.pcap --json
r3con network live --interface eth0 --duration 30
```

Vérifiez le périmètre, la conservation et la destruction des captures. Les adresses, noms DNS, cookies et identifiants peuvent être des données personnelles ou confidentielles.

## 11. Web, cloud et conteneurs

Analyse SAST et wrappers :

```bash
r3con web analyze ./web-project --json
r3con web nuclei https://example.test --severity medium,high,critical
```

Analyse cloud et infrastructure :

```bash
r3con cloud --help
r3con container --help
```

Les commandes cloud doivent être lancées sur des configurations exportées ou des environnements autorisés. Avant une correction, examinez le contexte de déploiement : une règle peut être intentionnellement compensée par un contrôle externe.

## 12. Secrets et décompilation

Les commandes `secrets` recherchent des motifs connus et des valeurs à forte entropie. Une détection n’est pas une preuve qu’une valeur est active, mais elle doit être traitée comme potentiellement compromise.

```bash
r3con secrets --help
r3con decompile --help
```

Après confirmation d’un secret, révoquez-le et remplacez-le hors du dépôt. Ne masquez pas simplement la valeur dans le rapport sans corriger la source et l’historique.

## 13. Recherche, fuzzing et exploitation contrôlée

`research` fournit des hypothèses, correspondances CVE et analyses de variantes. `fuzzing` gère des espaces de travail et des corpus. `exploit` fournit des helpers de reverse et de génération contrôlée.

```bash
r3con research hypothesis ./target.c --depth deep
r3con research cve ./target --limit 20
r3con fuzzing --help
r3con exploit --help
```

Ces fonctionnalités ne doivent être utilisées que sur des cibles autorisées. Commencez par des entrées inoffensives, limitez les ressources et conservez les logs. La génération d’un template ou d’une chaîne ROP ne prouve pas que l’attaque est fiable.

## 14. IA, sessions et workspaces

Le groupe `ai` peut utiliser une IA locale ou un fournisseur configuré. Les données envoyées à un fournisseur externe doivent être explicitement approuvées et nettoyées des secrets.

```bash
r3con ai --help
r3con interactive
r3con session --help
r3con workspace --help
```

Les workspaces séparent les cibles, notes, rapports et relations. Utilisez un workspace par engagement ou projet et exportez régulièrement les résultats importants.

## 15. Rapports et CI

Les rapports peuvent être générés depuis les résultats JSON. Les formats structurés sont recommandés pour l’intégration.

```bash
r3con report --help
r3con report sarif --help
r3con report pdf --help
```

Dans une CI :

```bash
python -m pip install -e '.[dev]'
python -m compileall -q .
python -m pytest -q
ruff check .
```

Conservez les rapports comme artefacts privés. Utilisez SARIF pour les plateformes qui le supportent et ajoutez une revue humaine avant toute publication.

## 16. Dashboard, Docker et configuration

Le dashboard et les intégrations sont optionnels. Vérifiez la configuration avant de lancer un service réseau :

```bash
r3con dashboard --help
docker compose config
docker build -t r3con:7.2.0 .
```

Le conteneur doit être exécuté avec des volumes explicites, sans privilèges inutiles et sans exposer de ports à Internet par défaut. Consultez `docker-compose.yml` et adaptez les secrets à votre gestionnaire de secrets.

## 17. Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| `Missing dependencies: click, rich` | Installation minimale absente | `python -m pip install -e .` |
| Capstone/LIEF absent | Extra binaire non installé | `python -m pip install -e '.[binary]'` |
| Commande externe absente | Outil système non installé | `r3con tools status` puis installer uniquement l’outil requis |
| Rapport PDF non généré | WeasyPrint/Markdown absent ou incompatible | Utiliser le fallback Markdown ou installer `.[reporting]` |
| Test ignoré radare2/rizin | Outil non installé | Installer l’outil dans l’environnement CI si nécessaire |
| Sortie illisible en CI | Couleurs terminal | Ajouter `--no-color --no-banner` |
| Résultats trop nombreux | Profil trop large | Filtrer par domaine, sévérité et confiance |

## 18. Contrat de qualité

Avant toute release ou déploiement :

```bash
python -m compileall -q .
python -m pytest -q -rs
ruff check .
python -m build
python -m twine check dist/*
```

La release est considérée saine lorsque les tests obligatoires passent, les outils optionnels absents sont signalés et aucun secret n’est présent dans les artefacts ou les logs.

## 19. Nouveaux workflows v7.3

### 19.1 Scan adaptatif explicable, reprise et porte de sévérité

```bash
r3con scan TARGET --profile auto --explain-plan     # détection + profil + justification
r3con scan TARGET --plan-only                       # plan détaillé, aucun module exécuté
r3con scan TARGET --resume ~/.cache/r3con/runs/<run_id>   # reprendre un run interrompu
r3con scan TARGET --offline                         # aucune intégration distante
r3con scan TARGET --fail-on high --json-out r.json  # exit 2 si un finding HIGH+ subsiste
```

Le plan explique pour chaque tâche : l’outil utilisé, sa disponibilité, le repli
interne éventuel et le conseil d’installation. Les tâches dont l’outil externe
est absent et sans repli sont **ignorées proprement** (`unsupported`, raison
`tool_unavailable`) et n’échouent pas l’analyse. Les résultats sont mis en cache
par (hash de cible, profil, configuration, versions d’outils, version du
contrat) : modifier l’un de ces éléments invalide uniquement les entrées
concernées.

### 19.2 Diagnostic étendu

```bash
r3con tools doctor --json-output doctor.json
```

Affiche les outils système, leurs versions détectées, les bibliothèques Python
optionnelles et le nombre de fallbacks actifs.

### 19.3 Analyse différentielle

```bash
r3con reports compare OLD.json NEW.json                    # ajoutés / supprimés / modifiés
r3con reports compare OLD.json NEW.json --format md --output diff.md
r3con compare ./v1.0.elf ./v1.1.elf --kind binary          # protections, fonctions, strings
r3con compare ./app-v1.apk ./app-v2.apk                    # permissions et findings
r3con compare OLD NEW --format sarif --output diff.sarif
```

`compare` détecte les findings ajoutés/supprimés/modifiés, les fonctions
modifiées, les permissions Android, les nouveaux secrets (cibles sources) et
les changements de protections. Sorties JSON, Markdown et SARIF, déterministes.

### 19.4 Chaîne d’approvisionnement (SBOM offline)

```bash
r3con supply-chain scan ./project --sbom cyclonedx --dependencies --secrets --report supply-chain.json
r3con supply-chain scan ./project --sbom spdx --sbom-output sbom.spdx.json
r3con supply-chain scan ./project --policy ./ma-politique.json --fail-on high
```

Écosystèmes : Python, npm, Java/Kotlin (Maven/Gradle), Go, Rust, Docker,
Kubernetes, Terraform. Les versions proviennent des lockfiles quand ils
existent (dépendances transitives incluses). **Aucun fichier n’est envoyé vers
un service distant** ; la détection de vulnérabilités utilise une politique
locale (amorces intégrées + votre fichier `--policy`). Les findings de
vulnérabilité sont marqués `hypothesis` : confirmez-les avec votre base d’avis.

### 19.5 Analyse dynamique isolée

```bash
r3con dynamic sandbox ./target-bin --arg input1                 # PLAN uniquement (défaut)
r3con dynamic sandbox ./target-bin --input-file poc.bin --execute
r3con dynamic sandbox ./target-bin --execute --mem-mb 512 --cpu-sec 5 --timeout 10 --strace
```

Par défaut : aucun processus lancé (mode simulation), réseau coupé
(`unshare -n`, exécution refusée si le noya n’autorise pas l’isolation et que
`--lenient-network` n’est pas posé), répertoire temporaire privé `0700`,
limites RLIMIT CPU/mémoire/processus/taille de fichier, capture bornée
(stdout/stderr, fichiers créés, signaux de crash, syscalls si strace existe).

### 19.6 Fuzzing : triage, corpus et export

```bash
r3con fuzzing plan CAMPAGNE --timeout-ms 1500 --memory-mb 128 --max-runtime 3600
r3con fuzzing export-findings CAMPAGNE --json-output findings.json
```

`plan` construit la commande AFL++/honggfuzz/libFuzzer **avec limites de
ressources et détection de reprise**, sans rien exécuter. `export-findings`
regroupe les crashs par signature, les convertit en findings (statut
`observation`, exploitabilité `unknown`) et écrit localement `findings.json`
dans le dossier de campagne. La minimisation de corpus écrit dans un dossier
`.min` séparé, sans jamais modifier le corpus d’origine.

### 19.7 Expliquer, résumer, interroger

```bash
r3con explain FINDING_ID --report r.json            # citations + incertitudes
r3con explain FINDING_ID --report r.json --format json --ai
r3con summarize r.json --json
r3con ask r.json "Quels risques sont corroborés par plusieurs outils ?"
```

Ces commandes sont calculées localement à partir du rapport uniquement :
chaque réponse cite les evidences utilisées et liste les incertitudes
(confiance faible, fallback, statut hypothèse). L’option `--ai` n’ajoute
qu’un commentaire explicitement étiqueté « non probant » si un fournisseur
est configuré ; sans fournisseur, la réponse locale reste complète.

### 19.8 Intégration CI

Un gabarit GitHub Actions sans exfiltration est fourni dans
`examples/github-actions/r3con-scan.yml` (SBOM téléversé par défaut, findings
uniquement en résumé de PR si vous le décommentez).

[1]: https://docs.python.org/3/library/venv.html "Documentation Python venv"
[2]: https://sarifweb.azurewebsites.net/ "SARIF specification"
[3]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning "GitHub SARIF support"
