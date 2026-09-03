# r3con v5.0.2 — Manuel complet d’utilisation

**Auteur :** Manus AI  
**Version documentée :** `v5.0.2`  
**Dépôt :** [github.com/nsaagent120-droid/r3con](https://github.com/nsaagent120-droid/r3con)  
**Public visé :** analystes sécurité, reverse engineers, développeurs, équipes de réponse à incident et étudiants travaillant sur des cibles autorisées.

> **Résumé.** r3con est un orchestrateur local d’analyse de sécurité pour code source, binaires, firmware, APK, captures réseau et sessions de debug. Il combine des moteurs internes avec des outils externes optionnels, normalise leurs résultats dans un contrat `Finding`, applique des limites de taille et de durée, puis produit des rapports reproductibles.

---

## 1. Utilisation autorisée et modèle de sécurité

Utilisez l’outil uniquement sur vos propres fichiers, binaires, appareils, captures et réseaux, ou lorsque vous disposez d’une autorisation explicite. L’analyse passive d’un PCAP est différente d’un sondage réseau actif, mais la confidentialité des données capturées reste votre responsabilité.

r3con est principalement un outil **d’observation, d’audit et de triage**. Il ne transforme pas un finding heuristique en vulnérabilité confirmée. Chaque résultat doit être relu dans son contexte, reproduit lorsque cela est possible et classé par un analyste.

La version `v5.0.2` ne fournit pas de scanner réseau actif intégré. La commande réseau live capture passivement les paquets observés avec TShark ; elle ne scanne pas des ports, ne se connecte pas à des services distants et n’injecte pas de paquets.

Pour un binaire inconnu, utilisez une machine virtuelle ou un conteneur sans données sensibles. Les commandes GDB, les scripts de debug et les wrappers de fuzzing doivent être utilisés dans un laboratoire isolé.

---

## 2. Installation

### 2.1 Prérequis minimaux

| Composant | Rôle |
|---|---|
| Python 3.9 ou plus récent | Exécution de r3con. |
| `click` | Interface CLI. |
| `rich` | Couleurs, panneaux, tableaux, progression et thèmes. |
| Git | Installation depuis GitHub. |

Linux est la plateforme principale. Les outils externes sont facultatifs : l’absence d’un outil doit être indiquée par `unsupported` ou `skipped`, sans empêcher les modules internes de fonctionner.

### 2.2 Installation depuis GitHub

```bash
git clone https://github.com/nsaagent120-droid/r3con.git
cd r3con
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Le dépôt GitHub est privé. Vous devez être authentifié pour le cloner.

### 2.3 Installation complète

```bash
python -m pip install -e '.[full]'
```

L’extra `full` installe les dépendances Python optionnelles déclarées par le projet. Les programmes système doivent être installés séparément.

### 2.4 Vérification initiale

```bash
r3con --version
r3con --help
r3con tools status
r3con plugins list
python -m pytest -q
```

Si la commande `r3con` n’est pas enregistrée dans l’environnement :

```bash
python -m cli.main --help
```

---

## 3. Détection et installation des outils externes

### 3.1 Détection automatique

r3con recherche les exécutables dans le `PATH` du processus, de la même manière que `command -v` :

```bash
command -v gdb
command -v r2
command -v tshark
r3con tools status
```

Le gestionnaire affiche le nom logique, le chemin détecté, la version lorsque celle-ci peut être interrogée, la disponibilité et la fonction de l’outil.

### 3.2 Ajouter un chemin personnalisé

```bash
export PATH="/opt/radare2/bin:/opt/zeek/bin:/opt/ghidra/support:$PATH"
r3con tools status
```

Pour rendre le réglage permanent :

```bash
echo 'export PATH="/opt/radare2/bin:/opt/zeek/bin:/opt/ghidra/support:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Évitez `sudo r3con` lorsque cela n’est pas nécessaire : `sudo` peut utiliser un `PATH` différent. Si un outil doit être lancé avec privilèges, utilisez plutôt son chemin absolu et conservez le `PATH` utilisateur inchangé.

### 3.3 Plan d’installation

```bash
r3con tools plan
```

Cette commande ne modifie pas le système. Elle affiche les paquets possibles selon la famille détectée (`apt`, `dnf`, `brew` ou installation Python) et les éléments nécessitant une installation manuelle.

### 3.4 Outils et méthodes de détection

| Outil | Exécutable ou configuration | Remarque |
|---|---|---|
| Radare2/Rizin | `r2` dans le `PATH` | Le moteur sélectionnable est `radare2` ou `rizin`. |
| GDB | `gdb` dans le `PATH` | pwndbg/GEF/peda sont des enrichissements distincts. |
| pwndbg | `PWNDBG_HOME/gdbinit.py` ou chemins usuels | GDB peut être disponible sans pwndbg. |
| Ghidra | `GHIDRA_HOME/support/analyzeHeadless` | Ghidra est opt-in. |
| Binwalk | `binwalk` dans le `PATH` | Utilisé pour l’extraction firmware. |
| TShark | `tshark` dans le `PATH` | Analyse PCAP et capture live passive. |
| Zeek | `zeek` dans le `PATH` | Analyse PCAP offline et génération de logs. |
| YARA | `yara` ou `yara-python` | Scan de motifs et signatures. |
| Semgrep | `semgrep` dans le `PATH` | Analyse structurelle source optionnelle. |
| AFL++ | `afl-fuzz` dans le `PATH` | Wrapper de fuzzing, non lancé automatiquement. |

Pour Ghidra :

```bash
export GHIDRA_HOME=/opt/ghidra
export PATH="$GHIDRA_HOME/support:$PATH"
r3con tools status
r3con analyze ./programme --profile binary --with-ghidra --timeout 300
```

Pour pwndbg :

```bash
export PWNDBG_HOME="$HOME/pwndbg"
r3con tools status
```

---

## 4. Interface CLI, couleurs et sorties

### 4.1 Thèmes

Le thème par défaut est `cyber`. Les thèmes disponibles sont `cyber`, `matrix`, `amber` et `mono` :

```bash
r3con --theme cyber plugins list
r3con --theme matrix plugins list
r3con --theme amber plugins list
r3con --theme mono plugins list
```

Le choix peut être permanent pour la session :

```bash
export R3CON_THEME=matrix
```

### 4.2 Mode sans couleur et animations

```bash
r3con --no-color --no-banner plugins list
export R3CON_NO_COLOR=1
export R3CON_NO_ANIMATION=1
```

Le mode sans couleur est recommandé pour les logs CI, les redirections vers fichiers et les terminaux qui gèrent mal les séquences ANSI. Les animations sont déjà désactivées automatiquement hors terminal interactif ou en CI.

### 4.3 Bannière

```bash
r3con --no-banner analyze ./target --profile quick
```

### 4.4 Aide intégrée

Chaque groupe et chaque commande possède une aide :

```bash
r3con --help
r3con analyze --help
r3con audit --help
r3con network --help
r3con plugins --help
r3con tools --help
```

---

## 5. Analyse générale avec `analyze`

### 5.1 Premier lancement

```bash
r3con analyze ./target
```

Le profil `auto` est utilisé par défaut. Le type de cible est estimé à partir de la signature, du suffixe, de la structure et du contenu.

### 5.2 Profils

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

| Profil | Contenu habituel | Rapidité |
|---|---|---|
| `auto` | Choix automatique selon la cible. | Variable. |
| `quick` | Identification et contrôles courts. | Rapide. |
| `binary` | Parsing, strings, imports et reverse disponible. | Moyenne. |
| `source` | Audit statique et moteurs source disponibles. | Moyenne. |
| `firmware` | Signatures, strings et entropie. | Moyenne à longue. |
| `apk` | Manifeste, permissions, bytecode et strings. | Moyenne. |
| `network` | PCAP interne et moteurs réseau sélectionnés. | Variable. |
| `dynamic` | Helpers GDB et analyse locale. | Variable. |
| `full` | Ensemble large des modules applicables. | Longue. |

### 5.3 Options importantes

```bash
r3con analyze ./target \
  --profile full \
  --timeout 180 \
  --max-mb 512 \
  --workers 4 \
  --reverse-engine radare2 \
  --with-ghidra \
  --no-cache \
  --cache-dir "$HOME/.cache/r3con" \
  --workspace never \
  --json-output ./reports/target.json
```

| Option | Effet |
|---|---|
| `--profile` | Choisit le profil. |
| `--timeout` | Timeout borné, de 1 à 3600 secondes. |
| `--max-mb` | Taille maximale, de 1 à 4096 MiB. |
| `--workers` | Nombre de workers, de 1 à 8. |
| `--reverse-engine` | `radare2` ou `rizin`. |
| `--with-ghidra` | Ajoute Ghidra explicitement. |
| `--no-cache` | N’utilise pas le cache. |
| `--cache-dir` | Change le répertoire du cache. |
| `--workspace` | `never`, `always` ou `auto`. |
| `--json-output` | Écrit le résultat unifié dans un fichier JSON. |

---

## 6. Plugins

### 6.1 Lister les plugins

```bash
r3con plugins list
```

Les plugins fournis sont `file`, `strings`, `readelf`, `semgrep`, `yara`, `radare2`, `ghidra`, `binwalk` et `gdb`.

### 6.2 Exécuter un plugin

```bash
r3con plugins run ./programme --plugin file
r3con plugins run ./programme --plugin file --plugin strings
r3con plugins run ./programme --plugin readelf --plugin radare2
```

Le lancement crée une exécution reproductible avec les tâches, versions, statuts, findings et artefacts. Pour éviter un traitement long :

```bash
r3con plugins run ./programme --plugin radare2 --timeout 120
```

### 6.3 Statuts d’un plugin

| Statut | Interprétation |
|---|---|
| `ok` | Plugin exécuté normalement. |
| `partial` | Résultat incomplet mais exploitable. |
| `skipped` | Plugin non applicable ou outil absent. |
| `unsupported` | Capacité indisponible dans cet environnement. |
| `invalid` | Entrée incorrecte ou non lisible. |
| `timeout` | Limite de temps atteinte. |
| `error` | Échec d’exécution à examiner. |

---

## 7. Audit de code source

### 7.1 Langages supportés

Le moteur statique possède des chemins dédiés pour **C, C++, Python, Java, Go et Rust**. Le support le plus profond est C/C++, avec confirmation AST Tree-sitter lorsque les dépendances sont disponibles.

JavaScript, TypeScript, PHP et Ruby peuvent être identifiés comme fichiers source dans certaines parties du projet, mais ne disposent pas du même ensemble de règles dédiées dans `StaticAnalyzer`.

### 7.2 Audit d’un fichier

```bash
r3con audit file ./source.c --lang c
r3con audit file ./source.cpp --lang cpp
r3con audit file ./script.py --lang python
r3con audit file ./Application.java --lang java
r3con audit file ./service.go --lang go
r3con audit file ./main.rs --lang rust
```

Le mode automatique est possible :

```bash
r3con audit file ./source.c --lang auto
```

### 7.3 Focaliser l’audit

```bash
r3con audit file ./source.c --lang c --focus all
r3con audit file ./source.c --lang c --focus memory
r3con audit file ./source.c --lang c --focus crypto
r3con audit file ./source.c --lang c --focus race
r3con audit file ./source.c --lang c --focus kernel
r3con audit file ./source.c --lang c --focus proto
```

Les familles principales sont les fonctions mémoire dangereuses, buffer overflows, format strings, use-after-free, double-free, integer overflows, TOCTOU, crypto faible, secrets hardcodés et appels dangereux.

### 7.4 Audit récursif

```bash
r3con audit dir ./src --recursive
r3con audit dir ./src --recursive --lang c
```

Excluez les dépendances vendored et les fichiers générés lorsque cela est nécessaire. Vérifiez toujours la ligne, la preuve et le chemin d’exécution avant de confirmer un finding.

### 7.5 Profondeur et rapports

```bash
r3con audit file ./source.c --lang c --depth quick
r3con audit file ./source.c --lang c --depth deep
r3con audit file ./source.c --lang c --depth full --report
```

Les analyses IA sont optionnelles. La détection statique locale doit rester utilisable sans clé API.

---

## 8. Analyse de binaires et reverse engineering

### 8.1 Désassemblage

```bash
r3con disasm file ./programme
r3con disasm file ./programme --arch auto --output asm
r3con disasm file ./programme --arch x86_64 --output pseudocode
r3con disasm file ./programme --function main
r3con disasm file ./programme --output cfg
```

Architectures disponibles : `auto`, `x86`, `x86_64`, `arm`, `arm64`, `mips` et `riscv`. Sorties disponibles : `asm`, `pseudocode`, `c` et `cfg`.

### 8.2 Strings et imports

```bash
r3con disasm strings ./programme --min-len 6
r3con disasm strings ./programme --filter password
r3con disasm imports ./programme
r3con disasm imports ./programme --vuln-check
```

### 8.3 Radare2/Rizin

```bash
r3con r2 ./programme
r3con analyze ./programme --profile binary --reverse-engine radare2
r3con plugins run ./programme --plugin radare2 --timeout 120
```

Le moteur collecte, selon l’installation, les fonctions, imports, strings, sections, xrefs, graphes de flux, désassemblage et pseudo-code.

### 8.4 Ghidra

```bash
export GHIDRA_HOME=/opt/ghidra
r3con analyze ./programme --profile binary --with-ghidra --timeout 300
```

Ghidra est activé explicitement pour éviter de lancer un traitement lourd sans intention claire.

---

## 9. Analyse dynamique et GDB

### 9.1 Vérifier GDB

```bash
r3con dynamic status --binary ./programme
r3con tools status
```

### 9.2 Commandes dynamiques

```bash
r3con dynamic function --binary ./programme --name main
r3con dynamic crash --binary ./programme --input 'AAAA'
r3con dynamic heap --binary ./programme
r3con dynamic maps --binary ./programme
r3con dynamic core --binary ./programme --core ./core
r3con dynamic offset --binary ./programme --length 200
r3con dynamic rop --binary ./programme
```

Pour ouvrir GDB directement :

```bash
r3con gdb ./programme
```

Les scripts ou sorties liés à l’exploitation doivent être utilisés uniquement dans un laboratoire autorisé et isolé. r3con ne lance pas de binaire inconnu à votre place sans action explicite dans une commande dynamique.

---

## 10. Firmware

### 10.1 Analyse générale

```bash
r3con firmware analyze ./firmware.bin
r3con firmware analyze ./firmware.bin --report
```

L’analyse recherche notamment les credentials hardcodés, chemins sensibles, services de debug, scripts de mise à jour, interfaces Telnet/SSH, signatures de composants et régions à entropie élevée.

### 10.2 Strings catégorisées

```bash
r3con firmware strings ./firmware.bin
r3con firmware strings ./firmware.bin --category credential
r3con firmware strings ./firmware.bin --category url
r3con firmware strings ./firmware.bin --category path
r3con firmware strings ./firmware.bin --category debug
r3con firmware strings ./firmware.bin --category ip_addr
r3con firmware strings ./firmware.bin --category cve_ref
```

### 10.3 Entropie

```bash
r3con firmware entropy ./firmware.bin
r3con firmware entropy ./firmware.bin --block-size 4096
```

Une forte entropie peut correspondre à une compression, un chiffrement ou des données aléatoires. Elle ne permet pas à elle seule de distinguer ces cas.

### 10.4 Extraction

```bash
r3con firmware extract ./firmware.bin --output ./extracted
```

Cette commande nécessite Binwalk. Traitez les fichiers extraits comme non fiables et analysez-les dans un répertoire ou une machine isolée.

---

## 11. APK Android

```bash
r3con apk analyze ./application.apk
r3con apk manifest ./AndroidManifest.xml
r3con apk permissions ./application.apk
```

L’analyse porte notamment sur les permissions, le mode `debuggable`, `allowBackup`, les composants exportés, les strings DEX/Smali, les secrets, la crypto faible et certaines configurations SSL.

Les résultats doivent être recoupés avec les outils Android spécialisés lorsqu’ils sont disponibles, notamment `apktool`, `jadx` et `aapt`.

---

## 12. Analyse réseau passive

### 12.1 PCAP interne

```bash
r3con network analyze ./capture.pcap
r3con network analyze ./capture.pcap --max-packets 10000 --max-mb 256
```

Le parseur interne traite principalement Ethernet/IPv4 avec TCP et UDP. Il agrège les flux, protocoles, IP, ports et volumes, puis extrait des IOC textuels : URLs, domaines et IPv4.

Des observations sont produites pour certains protocoles clairs ou hérités : FTP, Telnet, HTTP, POP3, IMAP, SNMP et LDAP. Une observation n’est pas automatiquement une preuve de compromission.

### 12.2 TShark offline

```bash
r3con network analyze ./capture.pcap --engine tshark
```

TShark enrichit la sortie avec les champs disponibles dans la capture. Il doit être installé et détectable dans le `PATH`.

### 12.3 Zeek offline

```bash
r3con network analyze ./capture.pcap --engine zeek
```

Zeek génère ses logs dans un répertoire temporaire isolé. Les logs peuvent inclure `conn.log`, `dns.log`, `http.log`, `ssl.log` ou `files.log` selon le trafic et la configuration.

### 12.4 Capture live passive

```bash
r3con network live
r3con network live --interface eth0 --duration 30 --max-packets 10000
r3con network live --interface eth0 --filter 'dns or tls'
```

La capture live utilise TShark. Elle collecte des métadonnées de protocole, IP, ports, flux, DNS, hôtes HTTP et SNI TLS. Elle est limitée par la durée et le nombre de paquets.

> `network live` signifie **observer le trafic local**, pas sonder une cible distante.

### 12.5 Corrélation firmware-PCAP

```bash
r3con correlate ./firmware.bin ./capture.pcap
```

La commande rapproche des chaînes ou indicateurs du firmware avec des IOC de la capture. La corrélation aide l’investigation, mais ne constitue pas une attribution automatique.

### 12.6 Limites réseau

La version actuelle ne réalise pas de scan TCP/UDP, de découverte de services, de banner grabbing, de connexion de test, de requête HTTP active, de scan Nmap/Masscan ou d’injection de paquets. Toute future fonction active devrait être explicitement opt-in, limitée par allowlist, débit, timeout et journalisation.

---

## 13. Outils avancés

```bash
r3con advanced crypto ./source.c
r3con advanced heap ./programme
r3con advanced kernel ./driver.c --type driver
r3con advanced proto ./parser.c --protocol tls
r3con advanced toctou ./handler.c
```

Ces commandes approfondissent l’analyse crypto, heap, noyau, protocoles et courses TOCTOU. Elles génèrent des observations et hypothèses qui doivent être vérifiées dans le code ou l’environnement réel.

---

## 14. AFL++ et fuzzing

### 14.1 Vérifier AFL++

```bash
command -v afl-fuzz
r3con tools status
r3con plugins list
```

### 14.2 Rôle du wrapper AFL

r3con intègre un wrapper AFL++ capable de vérifier la disponibilité de `afl-fuzz`, de générer un harness selon une fonction cible et de préparer un répertoire de campagne privé lorsqu’aucun dossier n’est fourni.

Le wrapper **ne lance pas automatiquement une campagne sur toutes les cibles** et ne transforme pas magiquement un binaire arbitraire en cible fuzzable. L’utilisateur doit fournir une cible appropriée, compiler le harness, préparer un corpus initial et définir une durée de campagne.

### 14.3 Règles de sécurité

Lancez le fuzzing dans une VM ou un conteneur. Limitez CPU, mémoire, espace disque et durée. Ne fuzzéz pas une cible connectée à un réseau de production et ne placez pas de secrets dans le corpus.

---

## 15. Recherche, CVE et comparaison de versions

```bash
r3con research hypothesis ./source.c
r3con research cve-match ./source.c
r3con research variant CVE-2021-3156 ./src
r3con research patch-diff ./old.bin ./new.bin
r3con research fuzz-hints ./parser.c --format afl
```

Les fonctions de recherche peuvent utiliser des sources CVE distantes lorsque la configuration l’autorise, mais elles doivent être interprétées comme assistance à l’analyse. Vérifiez toujours la version affectée, la configuration et les conditions d’exploitation.

---

## 16. IA locale et cloud

Le moteur IA est optionnel. Pour rester offline :

```bash
export R3CON_AI_OFFLINE=1
```

Pour sélectionner explicitement un fournisseur :

```bash
export R3CON_AI_PROVIDER=openai
export R3CON_AI_MODEL=gpt-5-mini
export R3CON_AI_REASONING=low
```

Pour une IA locale :

```bash
export LOCAL_AI_URL=http://localhost:11434
```

Les clés de fournisseurs cloud sont fournies par variables d’environnement :

```bash
export ANTHROPIC_API_KEY='...'
export TOGETHER_API_KEY='...'
```

Ne commitez jamais une clé, ne l’imprimez pas dans les rapports et ne l’incluez pas dans une fixture. Les sondes automatiques de serveurs locaux sont limitées aux adresses loopback autorisées.

---

## 17. Cache, sessions et artefacts

### 17.1 Cache

```bash
r3con analyze ./target --no-cache
export R3CON_NO_CACHE=1
export R3CON_CACHE_DIR="$HOME/.cache/r3con"
```

Utilisez `--no-cache` pour vérifier un changement ou obtenir une exécution indépendante d’un ancien résultat.

### 17.2 Artefacts

```bash
export R3CON_ARTIFACT_DIR="$HOME/r3con-artifacts"
```

Les artefacts doivent être traités comme sensibles lorsqu’ils contiennent du code source, des strings, des PCAP ou des chemins internes.

### 17.3 Sessions

```bash
r3con session --help
export R3CON_HISTORY="$HOME/.r3con_history"
```

Protégez le fichier d’historique si vous y tapez des chemins sensibles ou des paramètres internes.

---

## 18. Comprendre un résultat

### 18.1 Schéma `Finding`

Le contrat canonique contient notamment :

| Champ | Utilité |
|---|---|
| `id` | Identifiant stable. |
| `target_hash` | Empreinte de la cible. |
| `tool` | Outil producteur. |
| `finding_type` / `type` | Catégorie de l’observation. |
| `severity` | `INFO`, `LOW`, `MED`, `HIGH` ou `CRITICAL`. |
| `confidence` | Confiance de 0 à 1. |
| `status` | Observation, hypothèse, revue, confirmé ou faux positif. |
| `evidence` | Preuve, ligne, offset, règle ou extrait. |
| `provenance` | Tâche, commande, durée, moteur et corroboration. |

La sévérité exprime l’impact potentiel ; la confiance exprime la qualité de l’évidence. Il ne faut pas confondre un finding `HIGH` à faible confiance avec une vulnérabilité confirmée.

### 18.2 Déduplication et corroboration

Les observations équivalentes sont dédupliquées. Lorsque deux outils indépendants signalent la même cible, le même type et la même localisation, r3con regroupe les résultats et conserve la provenance des outils contributeurs.

### 18.3 Bon processus de validation

Pour chaque résultat important, relisez la ligne ou l’offset, vérifiez le langage et le chemin d’exécution, reproduisez dans un environnement isolé, comparez la sortie d’un second moteur lorsque cela est pertinent, puis classez le résultat.

---

## 19. Workflows pratiques

### 19.1 Triage rapide d’un binaire

```bash
r3con --no-banner analyze ./sample.bin --profile quick \
  --json-output ./reports/quick.json
r3con plugins list
```

### 19.2 Audit source C approfondi

```bash
r3con audit file ./src/parser.c --lang c --focus memory --depth deep --report
r3con audit dir ./src --recursive --lang c
r3con analyze ./src/parser.c --profile source --no-cache \
  --json-output ./reports/parser.json
```

### 19.3 Firmware

```bash
r3con firmware analyze ./router.bin --report
r3con firmware strings ./router.bin --category credential
r3con firmware entropy ./router.bin --block-size 4096
r3con firmware extract ./router.bin --output ./extracted
```

### 19.4 PCAP avec Zeek et TShark

```bash
r3con network analyze ./capture.pcap --engine all
r3con network live --interface eth0 --duration 60 --max-packets 20000
```

### 19.5 Reverse local

```bash
r3con tools status
r3con plugins run ./sample.bin --plugin file --plugin strings --plugin readelf
r3con plugins run ./sample.bin --plugin radare2 --timeout 120
r3con analyze ./sample.bin --profile binary --with-ghidra --timeout 300
```

### 19.6 Préparation fuzzing

```bash
command -v afl-fuzz
r3con plugins list
r3con research fuzz-hints ./src/parser.c --format afl
```

---

## 20. Dépannage

### La commande est introuvable

```bash
source .venv/bin/activate
python -m pip install -e .
python -m cli.main --help
```

### Un outil apparaît `unsupported`

```bash
command -v <outil>
r3con tools status
```

Ajoutez le dossier au `PATH`, puis relancez la commande dans le même terminal.

### Zeek ne s’installe pas sur Kali

Ne rétrogradez pas `libc6`. Si le paquet Kali est ancien et exige une version inférieure à celle de votre système, utilisez une compilation source dans `/opt/zeek` ou l’image Docker officielle. Après installation :

```bash
export PATH="/opt/zeek/bin:/opt/zeek/share/zeek/bin:$PATH"
zeek --version
r3con tools status
```

### Ghidra n’est pas détecté

```bash
export GHIDRA_HOME=/opt/ghidra
ls -l "$GHIDRA_HOME/support/analyzeHeadless"
r3con tools status
```

### Le PCAP est invalide

```bash
file ./capture.pcap
```

Vérifiez le format, la troncature et le lien de couche. Essayez TShark ou Zeek pour les formats que le parseur interne ne couvre pas.

### L’analyse est lente

Commencez par `quick`, réduisez `--max-mb`, baissez `--workers`, augmentez le timeout seulement si nécessaire et désactivez les moteurs lourds non indispensables.

### Trop de faux positifs source

Spécifiez `--lang`, installez Tree-sitter pour C/C++, utilisez un `--focus` ciblé et vérifiez l’évidence. Les règles regex restent heuristiques.

### La sortie contient des caractères étranges

Utilisez :

```bash
r3con --no-color --no-banner plugins list
export R3CON_NO_ANIMATION=1
```

---

## 21. Développement et validation

Avant une contribution :

```bash
python -m compileall -q .
python -m pytest -q
pyflakes core cli layers modules tests
bandit -q -r core cli layers modules -lll
pip-audit -r requirements.txt
```

La CI vérifie la compilation, les tests, Pyflakes et les alertes Bandit de haute sévérité. Toute correction de sécurité doit ajouter une régression lorsque cela est possible et documenter les limites ou faux positifs.

---

## 22. Variables d’environnement de référence

| Variable | Valeur ou exemple | Fonction |
|---|---|---|
| `R3CON_THEME` | `cyber`, `matrix`, `amber`, `mono` | Thème CLI. |
| `R3CON_NO_COLOR` | `1` | Désactive les couleurs. |
| `R3CON_NO_ANIMATION` | `1` | Désactive les animations. |
| `R3CON_CACHE_DIR` | `/chemin/cache` | Cache. |
| `R3CON_ARTIFACT_DIR` | `/chemin/artefacts` | Rapports et artefacts. |
| `R3CON_NO_CACHE` | `1` | Désactive le cache. |
| `R3CON_REVERSE_ENGINE` | `radare2` ou `rizin` | Moteur reverse par défaut. |
| `R3CON_ENABLE_GHIDRA` | `1` | Active Ghidra par défaut. |
| `GHIDRA_HOME` | `/opt/ghidra` | Installation Ghidra. |
| `PWNDBG_HOME` | `$HOME/pwndbg` | Installation pwndbg. |
| `R3CON_EXPERT_MODE` | `true` | Modules avancés. |
| `R3CON_AI_OFFLINE` | `1` | Force le mode IA offline. |
| `R3CON_AI_PROVIDER` | `openai`, etc. | Fournisseur IA. |
| `R3CON_AI_MODEL` | nom du modèle | Modèle IA. |
| `R3CON_AI_REASONING` | `low`, etc. | Niveau de raisonnement. |
| `LOCAL_AI_URL` | `http://localhost:11434` | Serveur IA local. |
| `R3CON_MULTI_AI` | `1` | Mode multi-IA. |
| `R3CON_HISTORY` | chemin fichier | Historique interactif. |

---

## 23. Références du projet

- `README.md` — présentation et démarrage.
- `ROADMAP.md` — périmètre de stabilisation.
- `SECURITY_AUDIT.md` — audit de sécurité.
- `CHANGELOG.md` — historique.
- `docs/PLUGIN_ARCHITECTURE.md` — architecture des plugins.
- `docs/NETWORK_LIVE_ANALYSIS.md` — réseau live.
- `docs/SETUP_AI_PROVIDERS.md` — fournisseurs IA.
- `docs/MULTI_AI_SETUP.md` — multi-IA.
- `tests/` — tests et scénarios de régression.

### Références externes

[1]: https://docs.zeek.org/en/current/install.html "Zeek — Installing Zeek"

[2]: https://www.kali.org/docs/general-use/using-kali-linux/ "Kali Linux — documentation générale"

[3]: https://docs.python.org/3/library/venv.html "Python — venv"

---

## 24. Checklist de démarrage rapide

```bash
# 1. Installer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[full]'

# 2. Vérifier
r3con --version
r3con tools status
r3con plugins list

# 3. Tester un fichier
r3con analyze ./target --profile quick --json-output ./target.json

# 4. Lire l’aide d’un domaine
r3con audit --help
r3con network --help
r3con firmware --help
r3con plugins --help

# 5. Lancer les tests
python -m pytest -q
```

**Fin du manuel — r3con v5.0.2.**
