# Guide utilisateur complet — r3con v5.0.1

> **r3con** est un orchestrateur local d’analyse de sécurité pour code source, binaires, firmware, APK et captures réseau. Il fonctionne offline par défaut et dégrade proprement les fonctions optionnelles lorsque les outils externes ne sont pas installés.

## 1. Avertissement d’utilisation

Utilisez r3con uniquement sur des fichiers, programmes, appareils et réseaux pour lesquels vous disposez d’une autorisation explicite. Une analyse passive de capture, un désassemblage et un audit de code ne donnent pas automatiquement le droit de sonder une infrastructure tierce.

Les résultats sont des **indications à vérifier**, et non des preuves définitives de vulnérabilité. Une détection statique peut être un faux positif ; une absence de détection ne constitue pas une preuve de sécurité.

La version actuelle ne fournit pas de scanner réseau actif intégré. La commande de capture live observe le trafic avec TShark, mais ne scanne pas de ports, ne se connecte pas à des services distants et n’injecte pas de paquets.

## 2. Prérequis

### 2.1 Système

Le projet nécessite Python 3.9 ou une version plus récente. Linux est l’environnement principalement visé. L’installation minimale fonctionne sans les outils d’analyse optionnels.

| Niveau | Composants | Usage |
|---|---|---|
| Minimal | Python, `click`, `rich` | CLI, analyse interne et rapports de base. |
| Recommandé | Capstone, LIEF, PyYAML, Jinja2 | Désassemblage, parsing binaire et rapports enrichis. |
| Code/AST | Tree-sitter, Tree-sitter C, Z3 | Confirmation AST et analyse symbolique selon les modules. |
| Réseau | TShark, Zeek | Analyse PCAP et capture/traitement réseau plus riche. |
| Reverse | Radare2/Rizin, Ghidra | Fonctions, imports, xrefs, pseudo-code et décompilation headless. |
| Dynamique | GDB, pwndbg ou GEF | Debug, registres, crash et analyse dynamique locale. |
| Firmware | Binwalk | Extraction de systèmes de fichiers et signatures. |
| Motifs | YARA ou `yara-python` | Scan de règles YARA. |

## 3. Installation

### 3.1 Depuis GitHub

```bash
git clone https://github.com/nsaagent120-droid/r3con.git
cd r3con
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Le dépôt est privé. Vous devez être authentifié auprès de GitHub pour le cloner.

### 3.2 Installation complète Python

```bash
python -m pip install -e '.[full]'
```

Cette extra installe les dépendances Python optionnelles déclarées dans `pyproject.toml`. Les exécutables tels que Ghidra, GDB, TShark, Zeek, Binwalk, Radare2/Rizin et YARA peuvent nécessiter une installation système séparée.

### 3.3 Vérification de l’installation

```bash
r3con --help
r3con plugins list
python -m pytest -q
```

Si la commande `r3con` n’est pas disponible, utilisez :

```bash
python -m cli.main --help
```

## 4. Principes de fonctionnement

r3con détecte le type de cible et sélectionne un profil d’analyse. Le résultat global est une enveloppe JSON contenant le statut, le profil, les tâches exécutées, les findings, l’inventaire des outils, la durée et les artefacts générés.

Chaque finding suit le contrat `Finding` v2.0. Les champs importants sont les suivants :

| Champ | Signification |
|---|---|
| `id` | Identifiant stable calculé à partir de la cible, du type, de la localisation et de l’outil. |
| `target_hash` | Empreinte SHA-256 de la cible lorsque l’orchestrateur l’a calculée. |
| `tool` | Moteur ayant produit l’observation. |
| `finding_type` / `type` | Type normalisé, avec `type` conservé comme alias historique. |
| `severity` | Gravité indicative : `INFO`, `LOW`, `MED`, `HIGH` ou `CRITICAL`. |
| `confidence` | Confiance bornée entre 0 et 1 ; elle est distincte de la gravité. |
| `status` | `observation`, `hypothesis`, `needs-review`, `confirmed` ou `false-positive`. |
| `evidence` | Localisation, extrait, règle ou contexte observé. |
| `provenance` | Commande, durée, tâche, moteur ou informations de corroboration. |

Les findings équivalents sont dédupliqués. Lorsque deux outils indépendants pointent vers la même observation, r3con conserve un finding et ajoute une corroboration avec une augmentation prudente de la confiance.

## 5. Commande générale `analyze`

### 5.1 Analyse automatique

```bash
r3con analyze ./target
```

Le profil `auto` est utilisé par défaut. Le type est estimé à partir de la signature, du suffixe, de la structure et du contenu de la cible.

### 5.2 Profils disponibles

```bash
r3con analyze ./target --profile auto
r3con analyze ./target --profile quick
r3con analyze ./target --profile binary
r3con analyze ./target --profile source
r3con analyze ./target --profile firmware
r3con analyze ./target --profile apk
r3con analyze ./target --profile network
r3con analyze ./target --profile dynamic
r3con analyze ./target --profile full
```

| Profil | Utilisation habituelle |
|---|---|
| `quick` | Identification et strings. |
| `binary` | Identification, strings, imports et moteur reverse disponible. |
| `source` | Audit statique du code. |
| `firmware` | Identification, strings et entropie. |
| `apk` | Identification et analyse APK dédiée. |
| `network` | Analyse interne PCAP et moteurs TShark/Zeek offline si disponibles. |
| `dynamic` | Statut GDB, informations GDB et analyse de crash locale. |
| `full` | Sélection complète adaptée au type détecté. |

### 5.3 Options d’exécution

```bash
r3con analyze ./target \
  --timeout 120 \
  --max-mb 256 \
  --workers 4 \
  --reverse-engine radare2 \
  --with-ghidra \
  --no-cache \
  --json
```

`--timeout` limite les opérations externes. `--max-mb` empêche l’analyse de fichiers trop volumineux. `--workers` contrôle le parallélisme. `--reverse-engine` accepte notamment `radare2`, `r2` ou `rizin`. `--with-ghidra` active explicitement Ghidra. `--no-cache` désactive le cache. `--json` demande une sortie exploitable par script.

## 6. Plugins

### 6.1 Lister les plugins

```bash
r3con plugins list
```

Le registre v5.0.1 contient :

| Plugin | Fonction |
|---|---|
| `file` | Identifier le type local du fichier. |
| `strings` | Extraire les chaînes imprimables. |
| `readelf` | Inspecter headers et symboles ELF. |
| `semgrep` | Analyse structurelle de code si Semgrep est installé. |
| `yara` | Scanner des règles YARA. |
| `radare2` | Analyse reverse r2/Rizin. |
| `ghidra` | Analyse Ghidra headless. |
| `binwalk` | Scan/extraction firmware. |
| `gdb` | Analyse dynamique GDB. |

### 6.2 Exécuter des plugins

```bash
r3con plugins run ./target.bin --plugin file
r3con plugins run ./target.bin --plugin file --plugin strings
r3con plugins run ./target.bin --plugin radare2 --timeout 120
```

Les résultats sont sauvegardés par défaut dans `./r3con-runs`. Un outil absent renvoie `skipped` ou `unsupported` et ne doit pas provoquer de crash global.

## 7. Audit de code source

### 7.1 Audit d’un fichier

```bash
r3con audit file ./vulnerable.c
r3con audit file ./vulnerable.c --lang c --focus all
r3con audit file ./vulnerable.c --lang c --focus memory
r3con audit file ./vulnerable.c --lang c --focus crypto
r3con audit file ./vulnerable.c --lang c --focus race
r3con audit file ./vulnerable.c --lang c --focus kernel
r3con audit file ./vulnerable.c --report
```

Les langages pris en charge par l’analyseur statique incluent C/C++, Python, Java, Go/Golang et Rust selon les règles disponibles. Les détections principales incluent les fonctions mémoire dangereuses, buffer overflows, format strings, use-after-free, double-free, integer overflows, TOCTOU, crypto faible, PRNG prévisible, secrets hardcodés et appels dangereux.

### 7.2 Audit récursif

```bash
r3con audit dir ./src --recursive --report
```

Commencez par cibler les répertoires de code et excluez les dépendances vendored ou générées lorsque cela est nécessaire. Examinez toujours `evidence`, la ligne signalée et le contexte avant de classer un finding comme confirmé.

## 8. Analyse des binaires

### 8.1 Identification et désassemblage

```bash
r3con disasm file ./program
r3con disasm file ./program --arch auto
r3con disasm file ./program --function main
r3con disasm file ./program --output pseudocode
r3con disasm strings ./program --min-len 6
r3con disasm imports ./program --vuln-check
```

Capstone est utilisé lorsqu’il est disponible. Le parsing interne conserve des fallbacks tels que `file`, `readelf`, `nm`, `objdump` et `strings` selon la commande.

### 8.2 Radare2/Rizin

```bash
r3con r2 ./program
r3con plugins run ./program --plugin radare2 --timeout 120
```

Le wrapper reverse collecte notamment les informations générales, fonctions, imports, strings, sections, xrefs, graphes de contrôle, désassemblage et pseudo-code selon la version de l’outil externe.

### 8.3 Ghidra headless

Ghidra est opt-in afin d’éviter un traitement long et de rendre son absence explicite :

```bash
export GHIDRA_HOME=/opt/ghidra
export R3CON_ENABLE_GHIDRA=true
r3con analyze ./program --profile binary --with-ghidra --timeout 300
```

Le projet Ghidra est créé dans un espace temporaire isolé. Les préférences utilisateur sont également isolées pendant l’exécution.

## 9. Analyse dynamique et GDB

### 9.1 Ouvrir GDB

```bash
r3con gdb ./program
```

Cette commande ouvre GDB directement et conserve la configuration pwndbg/GEF/peda de l’utilisateur.

### 9.2 Commandes dynamiques

```bash
r3con dynamic status --binary ./program
r3con dynamic function --binary ./program --name main
r3con dynamic crash --binary ./program --input 'AAAA'
r3con dynamic heap --binary ./program
r3con dynamic rop --binary ./program
r3con dynamic offset --binary ./program --length 200
r3con dynamic maps --binary ./program
r3con dynamic core --binary ./program --core ./core
```

Les fonctions capables de générer des scripts d’exploitation ou d’analyser des offsets sont destinées exclusivement à des binaires de laboratoire ou à des cibles autorisées. Ne lancez jamais un binaire inconnu hors d’un environnement isolé.

## 10. Analyse firmware

```bash
r3con firmware analyze ./firmware.bin
r3con firmware strings ./firmware.bin
r3con firmware strings ./firmware.bin --category credential
r3con firmware strings ./firmware.bin --category url
r3con firmware entropy ./firmware.bin
r3con firmware entropy ./firmware.bin --block-size 4096
r3con firmware extract ./firmware.bin --output ./extracted
```

L’analyse recherche notamment les credentials hardcodés, chemins sensibles, services de debug, backdoors, interfaces Telnet/SSH, scripts de mise à jour et régions à forte entropie. L’extraction nécessite Binwalk et doit être effectuée dans un répertoire de travail contrôlé.

## 11. Analyse APK Android

```bash
r3con apk analyze ./app.apk
r3con apk analyze ./app.apk --report
r3con apk permissions ./app.apk
r3con apk manifest ./decoded/AndroidManifest.xml
```

Les contrôles portent notamment sur les permissions, `debuggable`, `allowBackup`, les composants exportés, les strings DEX/Smali, les secrets hardcodés, la crypto faible et certaines configurations SSL. Les résultats doivent être recoupés avec `apktool`, `jadx` ou `aapt` lorsqu’ils sont installés.

## 12. Analyse réseau passive

### 12.1 PCAP offline

```bash
r3con network analyze ./capture.pcap
r3con network analyze ./capture.pcap --max-packets 10000 --max-mb 256
```

Le parseur interne traite principalement les captures Ethernet/IPv4 avec TCP et UDP. Il agrège les flux, les protocoles, les ports et les volumes, puis recherche des IOC textuels tels que URLs, domaines et adresses IPv4.

Les protocoles ou ports présentant un risque indicatif incluent FTP, Telnet, HTTP, POP3, IMAP, SNMP et LDAP. Ces observations ne prouvent pas à elles seules une compromission.

### 12.2 Capture live passive

```bash
r3con network live
r3con network live --interface eth0 --duration 30 --max-packets 10000
r3con network live --interface eth0 --filter 'dns or tls' --json
```

La capture live utilise TShark lorsqu’il est installé. Elle collecte des métadonnées de flux, protocoles, IP, ports, DNS, hôtes HTTP et SNI TLS. Elle est bornée par la durée et le nombre de paquets.

### 12.3 TShark et Zeek offline

```bash
r3con network analyze ./capture.pcap --engine tshark
r3con network analyze ./capture.pcap --engine zeek
```

Les moteurs externes enrichissent l’analyse mais restent optionnels. Leur absence est rapportée proprement.

### 12.4 Corrélation firmware-PCAP

```bash
r3con correlate ./firmware.bin ./capture.pcap
```

Cette commande rapproche des indicateurs extraits du firmware et des observations réseau. La corrélation doit être interprétée comme une aide à l’investigation, non comme une attribution automatique.

### 12.5 Ce qui n’est pas implémenté

La version v5.0.1 ne réalise pas de scan TCP/UDP, de découverte de services, de connexion de test, de banner grabbing, de requête HTTP active, de scan Nmap/Masscan ou d’injection de paquets. Une future fonction active devrait être opt-in, limitée par allowlist, débit, timeout, journalisation et confirmation d’autorisation.

## 13. Analyse crypto, kernel et recherche

```bash
r3con advanced crypto ./crypto.c
r3con advanced kernel ./driver.c --type driver
r3con advanced toctou ./handler.c
r3con advanced proto ./parser.c --protocol tls
r3con research hypothesis ./target.c
r3con research cve-match ./target.c --limit 15
r3con research variant CVE-2021-3156 ./src
r3con research patch-diff ./old.bin ./new.bin
r3con research fuzz-hints ./parser.c --format afl
```

Ces commandes produisent des hypothèses, règles ou comparaisons destinées à accélérer l’analyse. Elles ne remplacent pas un reverse engineering manuel, un test dynamique ou une vérification de version affectée.

## 14. IA optionnelle

r3con peut fonctionner sans IA. Pour activer une IA locale ou un fournisseur cloud, consultez les variables documentées dans `docs/MULTI_AI_SETUP.md` et `docs/SETUP_AI_PROVIDERS.md`.

Variables courantes :

```bash
export LOCAL_AI_URL=http://localhost:11434
export ANTHROPIC_API_KEY='...'
export DEEPSEEK_API_KEY='...'
export GEMINI_API_KEY='...'
export GROQ_API_KEY='...'
export TOGETHER_API_KEY='...'
export R3CON_MULTI_AI=true
```

Ne placez jamais de clé API dans le dépôt, les logs, les fixtures ou les rapports publics. Les sondes automatiques de serveurs locaux sont limitées aux adresses loopback autorisées.

## 15. Cache, artefacts et rapports

Le cache peut être désactivé pour une exécution reproductible sans réutilisation :

```bash
r3con analyze ./target --no-cache
```

Le répertoire de cache peut être changé :

```bash
export R3CON_CACHE_DIR=/path/to/r3con-cache
```

Les artefacts d’exécution peuvent être déplacés :

```bash
export R3CON_ARTIFACT_DIR=/path/to/r3con-artifacts
```

Les résultats JSON contiennent les tâches, statuts, findings et informations de provenance. Les rapports Markdown, HTML et SARIF sont adaptés respectivement à la lecture humaine, au partage interne et à l’intégration dans des plateformes de sécurité.

## 16. Interpréter les statuts

| Statut | Signification |
|---|---|
| `ok` | Analyse exécutée normalement. |
| `partial` | Résultat disponible mais incomplet ou avec avertissements. |
| `unsupported` | Fonction non disponible dans l’environnement. |
| `skipped` | Plugin ignoré car son exécutable est absent ou non applicable. |
| `invalid` | Entrée absente, trop volumineuse ou mal formée. |
| `timeout` | Le délai maximal a été atteint. |
| `error` | Erreur d’exécution ou de traitement. |

Un statut `unsupported` pour Ghidra, GDB, Binwalk, TShark, Zeek ou r2 n’est pas nécessairement un bug de r3con : il indique souvent que le programme externe n’est pas installé ou activé.

## 17. Dépannage

### La commande `r3con` est introuvable

Activez l’environnement virtuel puis réinstallez le projet en mode éditable :

```bash
source .venv/bin/activate
python -m pip install -e .
```

### Un plugin est `skipped`

Exécutez :

```bash
r3con plugins list
```

Vérifiez ensuite que l’exécutable est dans le `PATH`. Pour Ghidra, définissez `GHIDRA_HOME` ou utilisez une installation située dans un chemin reconnu.

### Un PCAP est déclaré invalide

Vérifiez qu’il s’agit bien d’un PCAP classique, qu’il n’est pas tronqué et que son lien de couche est supporté. Pour les formats particuliers, utilisez TShark ou Zeek.

### L’analyse est trop lente

Réduisez la taille et le parallélisme, utilisez `quick`, augmentez le timeout uniquement si nécessaire et désactivez les moteurs lourds :

```bash
r3con analyze ./target --profile quick --max-mb 64 --workers 1
```

### Trop de faux positifs dans l’audit source

Installez Tree-sitter et Tree-sitter C, spécifiez le langage, puis inspectez la preuve et le contexte du finding. Les règles regex restent heuristiques pour les langages ou dépendances non disponibles.

### Ghidra ou GDB échoue

Lancez d’abord le plugin en mode statut, vérifiez l’exécutable, les permissions, Java pour Ghidra, puis augmentez le timeout. Ne lancez pas un binaire non fiable sur votre machine principale.

## 18. Développement et qualité

Pour contribuer au projet :

```bash
python -m pip install -e '.[full]'
python -m pytest -q
pyflakes core cli layers modules tests
bandit -q -r core cli layers modules -lll
python -m compileall -q .
```

La CI GitHub exécute ces contrôles sur les pushes et pull requests. Le périmètre de stabilisation est décrit dans `ROADMAP.md`. Les changements de sécurité doivent ajouter un test de régression et documenter les limites ou faux positifs éventuels.

## 19. Exemples de workflows

### Audit rapide d’un binaire

```bash
r3con analyze ./sample.bin --profile quick --json > quick.json
r3con plugins list
```

### Audit source reproductible

```bash
r3con audit file ./src/parser.c --lang c --focus memory --report
r3con analyze ./src/parser.c --profile source --no-cache --json > source-report.json
```

### Firmware

```bash
r3con firmware analyze ./router.bin --report
r3con firmware strings ./router.bin --category credential
r3con firmware entropy ./router.bin --block-size 4096
```

### Investigation réseau passive

```bash
r3con network analyze ./capture.pcap --max-packets 50000 --json > network.json
r3con network live --interface eth0 --duration 60 --max-packets 20000 --json > live.json
```

### Analyse multi-outils locale

```bash
r3con plugins run ./sample.bin \
  --plugin file \
  --plugin strings \
  --plugin readelf \
  --plugin radare2 \
  --timeout 120
```

## 20. Références internes

- `README.md` — présentation et commandes historiques.
- `QUICKSTART.md` — démarrage rapide.
- `ROADMAP.md` — périmètre de stabilisation.
- `SECURITY_AUDIT.md` — audit et corrections de sécurité v5.0.1.
- `docs/PLUGIN_ARCHITECTURE.md` — architecture des plugins.
- `docs/NETWORK_LIVE_ANALYSIS.md` — capture et analyse réseau live.
- `docs/MULTI_AI_SETUP.md` — configuration multi-IA.
- `docs/SETUP_AI_PROVIDERS.md` — fournisseurs IA.
- `CHANGELOG.md` — historique des versions.

**Version documentée :** r3con v5.0.1.
