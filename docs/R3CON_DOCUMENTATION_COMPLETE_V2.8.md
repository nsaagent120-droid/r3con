# r3con v3.9 — Documentation complète

> **r3con** est un orchestrateur local pour l’analyse de binaires, de firmware, de code source, d’APK, de captures réseau et de comportements dynamiques. Il coordonne les outils spécialisés sans chercher à les remplacer.

## 1. Vue d’ensemble

r3con organise une analyse en tâches spécialisées et rassemble les résultats dans un rapport lisible ou JSON. Pour le reverse binaire, **radare2/rizin est le moteur externe principal**. Le désassemblage et la pseudo-décompilation du profil binaire normal viennent de radare2; le module interne de désassemblage intervient seulement comme fallback contrôlé lorsque les moteurs externes ne sont pas disponibles.

Ghidra reste disponible en complément, mais il est **opt-in** : il n’est lancé que si l’utilisateur ajoute `--with-ghidra`. GDB/pwndbg est utilisé pour le dynamique et peut aussi être ouvert directement. Les analyses réseau sont passives par défaut.

| Besoin | Moteur principal |
|---|---|
| Format, architecture, protections | Analyseurs internes r3con |
| Fonctions, désassemblage, pseudo-code binaire | radare2 ou rizin |
| Décompilation complémentaire | Ghidra, sur demande |
| Débogage dynamique | GDB avec pwndbg, GEF, PEDA ou vanilla |
| PCAP et protocoles | Analyseur interne, TShark et Zeek optionnel |
| Firmware | Analyseur interne, Binwalk lorsque disponible |
| Code source | Analyseurs statiques internes |
| APK | Analyse statique manifeste, permissions et composants |

## 2. Principes de sécurité

r3con est conçu pour fonctionner localement. Il ne doit être utilisé que sur des programmes, fichiers, captures et environnements que l’utilisateur est autorisé à analyser. Les commandes dynamiques exécutent réellement la cible locale; utilise donc une machine de laboratoire ou une sandbox pour les programmes inconnus.

L’outil ne lance pas automatiquement une exploitation, ne modifie pas le système pour installer des dépendances et ne contourne pas les contrôles d’accès. Les commandes d’analyse de crash, de heap, de gadgets et de watchpoint sont des instruments de recherche locale; leurs résultats doivent être interprétés avec prudence.

## 3. Installation

Depuis l’archive livrée :

```bash
unzip r3con_v2.8-hybrid-console-final.zip
cd r3con_complete
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Pour les dépendances binaires recommandées :

```bash
python -m pip install 'capstone>=5' 'lief>=0.13'
```

Les dépendances minimales sont `click` et `rich`. Capstone et LIEF sont recommandés pour les informations ELF, les protections et le fallback de désassemblage.

Vérifie ensuite :

```bash
r3con --version
r3con tools status
```

Les outils externes recommandés sont `r2` ou `radare2`, `gdb`, `tshark` et Java/Ghidra si la décompilation Ghidra est souhaitée. `pwndbg`, GEF ou PEDA sont optionnels mais utiles pour le dynamique.

## 4. Vérification des outils

```bash
r3con tools status
```

La sortie indique la présence, la version et le chemin de chaque outil. Un outil `missing` ou incompatible ne rend pas nécessairement toute l’application inutilisable : l’étape concernée reçoit un statut explicite comme `unsupported`, `partial`, `timeout` ou `error`.

Sur une installation Kali classique, vérifie également directement :

```bash
command -v r3con
command -v r2 || command -v radare2
command -v gdb
command -v tshark
command -v java
```

## 5. Console interactive persistante

Pour ne plus taper `r3con` devant chaque commande :

```bash
r3con interactive
```

L’invite ressemble à :

```text
r3con>
```

Définis une cible une seule fois :

```text
set target ./mon_binaire
show options
```

L’invite devient :

```text
r3con(mon_binaire)>
```

Tu peux ensuite exécuter directement les commandes :

```text
analyze --profile binary --json-output static.json
disasm file ./mon_binaire --output asm --function main
disasm file ./mon_binaire --output pseudocode --function main
r2 ./mon_binaire
gdb ./mon_binaire
dynamic status ./mon_binaire
history
sessions
clear
exit
```

La console est hybride. Une entrée qui commence par une commande connue est exécutée par r3con. Une phrase qui ne correspond pas à une commande est envoyée à l’assistant IA conversationnel :

```text
explique le rôle de main
quelles protections dois-je examiner ?
que signifie cet appel à system ?
```

Le contexte IA est conservé pendant la session. `clear` efface l’écran et le contexte IA; `history` montre les commandes tapées; `sessions` affiche les analyses sauvegardées. En mode hors ligne, l’assistant fournit des réponses locales limitées. Un fournisseur IA configuré peut fournir des réponses plus avancées.

## 6. Analyse automatique

La commande générale est :

```bash
r3con analyze ./mon_binaire --profile auto
```

Pour sauvegarder le rapport :

```bash
r3con analyze ./mon_binaire --profile auto --json-output rapport.json
```

Options générales :

| Option | Fonction |
|---|---|
| `--profile` | Choisit le domaine d’analyse |
| `--timeout SECONDS` | Limite de durée par outil |
| `--max-mb MB` | Taille maximale acceptée |
| `--workers N` | Nombre de tâches parallèles |
| `--reverse-engine radare2` | Choisit radare2 |
| `--reverse-engine rizin` | Choisit rizin |
| `--with-ghidra` | Ajoute Ghidra explicitement |
| `--json-output FILE` | Sauvegarde le rapport JSON |

Profils disponibles : `auto`, `quick`, `binary`, `network`, `firmware`, `apk`, `dynamic` et `full`.

## 7. Reverse binaire avec radare2

### 7.1 Analyse complète

```bash
r3con analyze ./mon_binaire --profile binary --json-output binary.json
```

Lorsque `r2` est disponible, le plan normal est :

```text
identify → strings → imports → radare2
```

Le champ `results.radare2.observations` contient les métadonnées, fonctions, imports, désassemblage JSON de la fonction demandée par défaut et pseudo-code r2 de `main`.

### 7.2 Désassemblage direct dans le terminal

```bash
r3con disasm file ./mon_binaire --output asm --function main
```

Pour une autre fonction :

```bash
r3con disasm file ./mon_binaire --output asm --function vulnerable_copy
```

### 7.3 Pseudo-décompilation

```bash
r3con disasm file ./mon_binaire --output pseudocode --function main
```

La sortie est produite par la commande `pdc` de radare2. Elle est utile pour comprendre rapidement le flot, mais elle reste une approximation.

### 7.4 Session radare2 native

```bash
r3con r2 ./mon_binaire
```

Cette commande ouvre directement `r2 -AA`. Dans r2 :

```text
afl                 liste les fonctions
pdf @ main          désassemblage de main
pdc @ main          pseudo-code de main
agf @ main          graphe de contrôle de main
ii                  imports
izz                 chaînes
iI                  informations générales
q                   quitter
```

Pour ouvrir r2 sans analyse automatique :

```bash
r3con r2 ./mon_binaire --no-analysis
```

### 7.5 Fonction inconnue

Commence par :

```bash
r2 -AA ./mon_binaire
```

Puis :

```text
afl
```

Utilise ensuite le nom affiché avec `--function`, par exemple :

```bash
r3con disasm file ./mon_binaire --output pseudocode --function login_system
```

## 8. Ghidra en complément

Ghidra ne remplace pas r2 dans le workflow par défaut. Pour l’ajouter explicitement :

```bash
r3con analyze ./mon_binaire --profile binary --with-ghidra --json-output reverse-complet.json
```

Le pseudo-code Ghidra se trouve dans :

```text
results.ghidra.observations.functions[*].decompiled
```

Si Ghidra n’est pas installé ou ne peut pas démarrer, son résultat sera `unsupported`, `partial` ou `timeout`. Radare2 reste indépendant et continue de fournir le reverse principal.

## 9. Analyse dynamique GDB/pwndbg

### 9.1 Ouvrir GDB directement

```bash
r3con gdb ./mon_binaire
```

La configuration utilisateur de `~/.gdbinit` est conservée. Si pwndbg est déjà configuré, il se charge comme lors d’un lancement normal de GDB.

Commandes GDB utiles :

```text
starti
break main
run
continue
stepi
nexti
info registers
x/20gx $rsp
backtrace
disassemble main
```

Commandes fréquentes pwndbg :

```text
context
regs
stack
vmmap
checksec
```

### 9.2 Profil dynamique orchestré

```bash
r3con analyze ./mon_binaire --profile dynamic --json-output dynamic.json
```

Le profil regroupe le statut GDB/pwndbg, les informations de fonctions et une analyse automatisée de crash.

### 9.3 Commandes dynamiques disponibles

```bash
r3con dynamic status ./mon_binaire
r3con dynamic function ./mon_binaire main
r3con dynamic crash ./mon_binaire --input test
r3con dynamic offset ./mon_binaire --length 300
r3con dynamic heap ./mon_binaire
r3con dynamic rop ./mon_binaire
r3con dynamic core ./mon_binaire ./core.dump
r3con dynamic watchpoint ./mon_binaire 0x404040 --type write
```

| Commande | Résultat |
|---|---|
| `dynamic status` | GDB disponible, framework détecté, cible valide |
| `dynamic function` | Breakpoint, registres, backtrace et informations d’une fonction |
| `dynamic crash` | Signal, crash, registres, IP et backtrace |
| `dynamic offset` | Motif cyclique et offset potentiel |
| `dynamic heap` | Informations heap selon pwndbg/GEF/PEDA |
| `dynamic rop` | Recherche de motifs dans les mappings du processus |
| `dynamic core` | Analyse de registres et backtrace d’un core dump |
| `dynamic watchpoint` | Surveillance lecture/écriture/accès d’une adresse |

Ces commandes automatisent des observations locales; elles ne constituent pas une exploitation automatique.

## 10. Code source

Audit d’un fichier :

```bash
r3con audit file ./programme.c
```

Avec profondeur et rapport :

```bash
r3con audit file ./programme.c --depth deep --report
```

Audit récursif :

```bash
r3con audit dir ./src --recursive --report
```

Les analyseurs recherchent notamment des appels dangereux et motifs suspects comme `gets`, `strcpy`, `system`, chaînes de format, double free, use-after-free, problèmes crypto, désérialisation dangereuse, `eval` et `shell=True` selon le langage et le module.

Ces détections sont statiques et heuristiques. Une alerte doit être vérifiée dans le contexte du programme.

## 11. Firmware

Analyse générale :

```bash
r3con firmware analyze ./firmware.bin --report
```

Extraction :

```bash
r3con firmware extract ./firmware.bin --output ./extracted
```

Chaînes :

```bash
r3con firmware strings ./firmware.bin
```

Entropie :

```bash
r3con firmware entropy ./firmware.bin --block-size 4096
```

L’analyseur peut signaler des signatures ELF, gzip, architectures, zones à forte entropie, identifiants, chemins sensibles, services de debug, Telnet et indices de secrets. Une forte entropie indique seulement une zone potentiellement compressée ou chiffrée; ce n’est pas une preuve de vulnérabilité.

## 12. APK Android

```bash
r3con apk analyze ./application.apk --report
r3con apk manifest ./AndroidManifest.xml
r3con apk permissions ./application.apk
```

Les contrôles couvrent le manifeste, les permissions sensibles, `debuggable`, `allowBackup`, les composants exportés et certains secrets ou configurations dangereuses détectables statiquement.

## 13. Réseau et protocoles

Analyse automatique d’une capture :

```bash
r3con analyze ./capture.pcap --profile network --json-output network.json
```

Le module interne est passif et peut produire un résumé de flux, protocoles, adresses IP, domaines, URL et IOCs.

Pour choisir le moteur réseau :

```bash
r3con network analyze ./capture.pcap --engine internal
r3con network analyze ./capture.pcap --engine tshark
r3con network analyze ./capture.pcap --engine zeek
r3con network analyze ./capture.pcap --engine all
```

TShark est utile pour enrichir les champs protocolaires. Zeek est optionnel et doit être compatible avec la distribution installée.

## 14. Lecture des rapports JSON

Un rapport contient généralement :

```json
{
  "status": "ok",
  "target": {},
  "profile": "binary",
  "plan": [],
  "results": {},
  "findings": [],
  "tool_inventory": [],
  "duration_ms": 0
}
```

Les statuts ont cette signification :

| Statut | Signification |
|---|---|
| `ok` | Étape terminée normalement |
| `partial` | Résultat utile mais incomplet ou avec avertissements |
| `unsupported` | Outil ou capacité indisponible |
| `timeout` | Délai maximal dépassé |
| `error` | Erreur d’exécution |
| `invalid` | Cible invalide ou trop grande |

Dans un rapport binaire, commence par `identify`, puis `imports`, `strings` et `radare2`. Les protections `PIE`, `NX`, `canary` et `RELRO` décrivent le binaire analysé; elles ne représentent pas le statut de r3con.

## 15. Architecture technique

```text
CLI Click/Rich
  ├── Console interactive hybride commandes + IA
  ├── Commandes directes r2 et GDB
  └── Commande analyze
        ├── Orchestrateur et sélection de profil
        ├── Analyseurs internes
        │     ├── LIEF / métadonnées et protections
        │     ├── Capstone / fallback de désassemblage
        │     ├── firmware / APK / source / réseau
        │     └── analyseurs spécialisés
        ├── Adaptateur radare2/rizin
        ├── Adaptateur Ghidra headless opt-in
        ├── Adaptateur GDB/pwndbg
        └── Rapport JSON unifié
```

Les adaptateurs externes utilisent des processus locaux avec arguments séparés, délais d’exécution, provenance de l’exécutable et statuts explicites. Les projets temporaires Ghidra sont isolés et supprimés après analyse.

## 16. Configuration

Choisir r2 par défaut :

```bash
export R3CON_REVERSE_ENGINE=radare2
```

Choisir rizin :

```bash
export R3CON_REVERSE_ENGINE=rizin
```

Activer Ghidra par variable d’environnement pour les appels Python ou orchestrés :

```bash
export R3CON_ENABLE_GHIDRA=1
```

Dans la CLI, l’activation la plus claire est :

```bash
r3con analyze ./mon_binaire --profile binary --with-ghidra
```

Désactiver l’animation :

```bash
export R3CON_NO_ANIMATION=1
```

Supprimer la bannière :

```bash
r3con --no-banner analyze ./mon_binaire --profile binary
```

## 17. Dépannage

### r3con n’est pas trouvé

Vérifie l’installation et le chemin :

```bash
python -m pip install .
command -v r3con
```

### radare2 est absent

`r3con analyze --profile binary` peut encore analyser les métadonnées, chaînes et imports, mais il ne disposera pas du reverse externe. Installe r2/radare2 ou utilise le fallback interne si les dépendances Python sont disponibles.

### Ghidra retourne `partial`

Examine `results.ghidra.observations.logs` et `warnings`. Des bibliothèques externes non résolues ou des stubs PLT/GOT peuvent produire des avertissements sans empêcher l’analyse des fonctions principales.

### GDB ne détecte pas pwndbg

Vérifie que pwndbg est chargé lorsque tu exécutes directement `gdb`. r3con détecte principalement la configuration de `~/.gdbinit`; une configuration atypique peut apparaître comme `vanilla` même si un plugin est installé.

### Zeek est indisponible

Le module réseau interne et TShark peuvent continuer à fonctionner. Ne force pas l’installation d’un paquet Zeek si les dépendances de ta distribution sont incompatibles; utilise `r3con tools status` pour confirmer l’état.

### Rapport `partial`

Lis d’abord le statut de chaque entrée dans `results`. `partial` signifie généralement qu’une étape a fourni des données mais qu’un moteur externe, un symbole ou une partie du fichier n’a pas pu être traité.

## 18. Tests et validation

La version v2.8 a été compilée et validée sur les scénarios disponibles :

```text
50 tests réussis sur 50
```

Les validations couvrent le reverse binaire radare2, Ghidra opt-in, le profil dynamique GDB, le firmware, le code source, l’APK, le réseau, les statuts et la console interactive.

Cette validation signifie que les fonctions couvertes par les fixtures sont opérationnelles. Elle ne garantit pas un résultat complet pour un binaire obfusqué, packé, corrompu, sans symboles, inhabituel ou construit pour une architecture non disponible.

## 19. Routine recommandée

Pour une nouvelle cible locale autorisée :

```bash
r3con tools status
r3con analyze ./cible --profile auto --json-output auto.json
r3con disasm file ./cible --output asm --function main
r3con disasm file ./cible --output pseudocode --function main
r3con dynamic status ./cible
r3con gdb ./cible
```

Pour une session confortable :

```bash
r3con interactive
```

Puis :

```text
set target ./cible
analyze --profile binary --json-output static.json
disasm file ./cible --output pseudocode --function main
dynamic status ./cible
```

## 20. Limites importantes

r3con coordonne les moteurs mais ne remplace pas leur interface experte. Radare2 reste nécessaire pour explorer librement un graphe complexe; GDB/pwndbg reste préférable pour une session interactive détaillée; Ghidra peut produire une décompilation plus riche sur certains programmes; TShark et Zeek ont leurs propres limites protocolaires.

La pseudo-décompilation n’est jamais une preuve du code source original. Les alertes de sécurité sont des indicateurs nécessitant une vérification manuelle. Les résultats dynamiques dépendent de l’entrée, de l’environnement, des bibliothèques chargées, de l’ASLR, des permissions et du comportement réel du programme.

## 21. Références

Les commandes et comportements documentés ici correspondent au code livré dans l’archive r3con v2.8. Pour les manuels des outils externes, consulter également [radare2](https://rada.re/n/), [GDB](https://sourceware.org/gdb/documentation/), [Ghidra](https://ghidra-sre.org/), [Wireshark/TShark](https://www.wireshark.org/docs/man-pages/tshark.html) et [pwndbg](https://pwndbg.re/).

## 22. Optimisations v2.9

La version optimisée synchronise maintenant la version CLI et la version Python sur `2.8.0`. Le profil `full` devient adaptatif : il sélectionne les tâches pertinentes selon le type de cible au lieu d’exécuter des analyseurs réseau, firmware ou binaire inappropriés.

Un cache local par empreinte SHA-256 est disponible pour les tâches statiques répétables. La première exécution marque généralement les tâches avec `cache: "miss"`; une exécution identique peut réutiliser les résultats avec `cache: "hit"`.

```bash
r3con analyze ./mon_binaire --profile binary
```

Désactiver le cache pour une analyse fraîche :

```bash
r3con analyze ./mon_binaire --profile binary --no-cache
```

Choisir un répertoire de cache :

```bash
r3con analyze ./mon_binaire --profile binary --cache-dir ./analysis-cache
```

La variable d’environnement équivalente est :

```bash
export R3CON_CACHE_DIR=$HOME/.cache/r3con
export R3CON_NO_CACHE=1
```

Les analyses dynamiques ne sont pas mises en cache par défaut, car leur résultat dépend de l’état d’exécution. Les résultats cacheables contiennent une enveloppe standard avec `schema_version`, `status`, `engine`, `observations` et l’indicateur `cache`.

## 23. Console terminal améliorée

La console interactive utilise maintenant le support readline du terminal. Les touches fléchées permettent de parcourir l’historique, la touche `Tab` complète les commandes connues et les chemins de fichiers, et les séquences d’échappement ne sont plus affichées sous forme de texte comme `^[[A`.

```bash
r3con interactive
```

Raccourcis utiles :

| Touche | Action |
|---|---|
| Flèche haut | Commande précédente |
| Flèche bas | Commande suivante |
| `Tab` | Complétion de commande ou de chemin |
| `Ctrl+C` | Annuler la ligne courante |
| `Ctrl+D` | Quitter lorsque la ligne est vide |
| `Ctrl+L` | Nettoyer l’écran selon le terminal |

L’historique est conservé dans `~/.r3con_history`. Pour utiliser un autre fichier :

```bash
R3CON_HISTORY=/chemin/vers/historique r3con interactive
```

La saisie readline est utilisée seulement pour la console interactive. Les commandes non interactives et les sorties JSON restent adaptées aux scripts.

## 24. Workspace terminal quatre panneaux

Pour travailler confortablement comme dans Terminator, r3con peut créer un workspace tmux en quatre panneaux :

```bash
r3con workspace ./mon_binaire
```

La disposition est :

| Panneau | Contenu |
|---|---|
| 1 | Console interactive r3con |
| 2 | radare2 avec analyse automatique |
| 3 | GDB/pwndbg sur la cible |
| 4 | Shell libre pour les commandes système et les notes |

Pour voir la disposition sans la lancer :

```bash
r3con workspace ./mon_binaire --dry-run
```

Pour choisir un autre nom de session :

```bash
r3con workspace ./mon_binaire --session mon-lab
```

Pour revenir à une session déjà créée :

```bash
tmux attach -t r3con-lab
```

Raccourcis tmux utiles :

```text
Ctrl+b puis flèche   changer de panneau
Ctrl+b puis z        agrandir/restaurer le panneau courant
Ctrl+b puis d        détacher sans fermer la session
tmux ls              lister les sessions
tmux attach -t NOM  reprendre une session
```

Le workspace ne force pas l’installation de tmux. Si tmux est absent, utilise `r3con interactive` ou installe tmux avec le gestionnaire de paquets de ta distribution. La cible est exécutée localement dans les panneaux r2 et GDB; utilise uniquement une cible autorisée et adaptée à un laboratoire.

## 25. Artefacts et traçabilité par analyse

Chaque exécution de l’orchestrateur crée, lorsque le répertoire est accessible, un dossier de run contenant un fichier JSON par tâche et un `manifest.json`. Le chemin apparaît dans les champs `execution.artifact_dir` et `artifacts.directory` du rapport principal.

Exemple de structure :

```text
~/.cache/r3con/runs/<sha256-prefix>-<timestamp>/
├── identify.json
├── strings.json
├── imports.json
├── radare2.json
└── manifest.json
```

Chaque résultat contient désormais `task` et `duration_ms`. Les tâches servies par le cache indiquent `cache: "hit"`; les nouvelles analyses statiques indiquent généralement `cache: "miss"`.

Pour désactiver complètement le cache tout en gardant les artefacts :

```bash
r3con analyze ./mon_binaire --profile binary --no-cache
```

Pour déplacer les artefacts :

```bash
R3CON_ARTIFACT_DIR=./runs r3con analyze ./mon_binaire --profile binary
```

Les artefacts peuvent contenir des chaînes, des chemins, des noms de fonctions, des sorties d’outils et des informations de débogage. Protège ce répertoire lorsque la cible ou les résultats sont sensibles.

## 26. Workspace automatique par profil

Le workspace quatre panneaux peut être lancé manuellement ou demandé à la commande `analyze`.

```bash
r3con analyze ./mon_binaire --profile binary --workspace always
```

Le mode automatique ouvre le workspace seulement pour les profils adaptés au travail interactif, notamment `binary`, `dynamic`, `firmware` et `network` :

```bash
r3con analyze ./mon_binaire --profile auto --workspace auto
```

Le comportement historique reste disponible avec :

```bash
r3con analyze ./mon_binaire --profile binary --workspace never
```

Le workspace utilise tmux et ouvre quatre panneaux : r3con, radare2, GDB/pwndbg et un shell libre.

## 27. Reverse radare2 enrichi

Les résultats radare2 comprennent maintenant, lorsque la version installée les fournit, les détails de sections, les références croisées et le graphe de contrôle de la fonction ciblée :

```text
results.radare2.observations.section_details
results.radare2.observations.xrefs
results.radare2.observations.control_flow
```

Le désassemblage et le pseudo-code restent dans :

```text
results.radare2.observations.disassembly
results.radare2.observations.pseudocode
```

## 28. Comparer deux binaires

La commande `diff` compare deux versions locales :

```bash
r3con diff ./ancienne_version ./nouvelle_version
```

Pour enregistrer le résultat :

```bash
r3con diff ./ancienne_version ./nouvelle_version \
  --json-output comparaison.json
```

Le rapport indique les fonctions ajoutées, supprimées ou modifiées, ainsi que les protections avant et après. Une fonction est signalée comme modifiée si son offset ou sa taille diffère; cela ne remplace pas une comparaison sémantique complète.

## 29. Nouvelles observations dynamiques

Une trace limitée d’instructions depuis une fonction peut être demandée avec :

```bash
r3con dynamic trace ./mon_binaire main --steps 20
```

Le résultat contient la fonction, le nombre d’étapes demandées, les instructions observées, les registres et la backtrace.

Les mappings mémoire du processus peuvent être collectés après son démarrage avec :

```bash
r3con dynamic maps ./mon_binaire
```

Ces commandes sont des observations automatisées basées sur GDB. Pour un contrôle interactif complet, utilise toujours :

```bash
r2 -d -AA ./mon_binaire
```

ou :

```bash
r3con gdb ./mon_binaire
```

Les sorties GDB automatisées sont nettoyées des séquences de couleur du terminal avant leur insertion dans le JSON.

## 30. Firmware et réseau enrichis

L’identification firmware expose maintenant `component_counts`, `filesystem_hints` et `service_hints`. Ces informations aident à repérer les systèmes de fichiers embarqués et les services comme Telnet, SSH, GDB server, BusyBox, DNSMasq ou HostAPD.

L’extraction Binwalk conserve maintenant son code retour, ses sorties standard et ses erreurs. Une exécution Binwalk qui échoue est signalée comme telle au lieu d’être considérée automatiquement comme réussie.

La corrélation locale firmware-PCAP est disponible avec :

```bash
r3con correlate ./firmware.bin ./capture.pcap
```

Pour enregistrer le rapport :

```bash
r3con correlate ./firmware.bin ./capture.pcap --json-output correlation.json
```

Cette commande extrait les chaînes du firmware, analyse passivement les IOCs du PCAP et signale les valeurs présentes dans les deux sources. Elle ne capture aucun trafic, n’envoie aucun paquet et n’exécute aucun contenu du firmware.

## 31. Analyse source contextuelle et benchmark

Les alertes des analyseurs source contiennent maintenant `evidence`, avec la ligne concernée et une fenêtre de contexte locale, ainsi que `confidence`, une estimation de confiance de l’heuristique. Ces valeurs ne remplacent pas une analyse de flux ou une revue humaine.

Exemple de commande de benchmark statique :

```bash
r3con benchmark ./mon_binaire --profile binary --runs 3
```

Le benchmark produit un JSON propre contenant les durées minimale, maximale et moyenne. Il ne doit pas être utilisé avec un profil dynamique : les exécutions dynamiques doivent rester explicitement contrôlées.

## 32. Compatibilité et qualité

Le parseur brut respecte maintenant l’endianess ELF pour lire correctement l’architecture, l’adresse d’entrée et les champs de l’en-tête des ELF big-endian. Si LIEF retourne un objet partiel ou une architecture non reconnue, r3con revient automatiquement au parseur brut.

Les tests de qualité couvrent notamment les ELF x86-64 big-endian synthétiques, les alertes source avec évidence et confiance, le benchmark JSON, le profil adaptatif et les régressions des moteurs externes.

## 33. Thèmes de l’interface CLI

r3con propose plusieurs palettes terminal :

```bash
r3con --theme cyber interactive
r3con --theme matrix interactive
r3con --theme amber interactive
r3con --theme mono interactive
```

La palette peut aussi être choisie avec `R3CON_THEME=cyber`, `matrix`, `amber` ou `mono`. Dans la console interactive, la commande suivante change la palette à chaud :

```text
theme
theme matrix
theme cyber
theme amber
theme mono
```

Les couleurs servent à distinguer les informations, succès, avertissements et niveaux de gravité. Le mode `mono` est prévu pour les terminaux limités ou les sorties imprimées. Les sorties JSON restent indépendantes du thème.

## 34. Correction des faux positifs d’imports C

La détection des imports utilise désormais une correspondance sur le nom complet de la fonction et non une simple sous-chaîne. Ainsi, `gets` est signalé comme fonction dangereuse, tandis que `fgets` n’est plus incorrectement classé comme `gets`.

Exemple :

```text
gets  → CRITICAL : absence de limitation de taille
fgets → aucune alerte automatique pour le seul nom de la fonction
```

L’usage de `fgets` doit néanmoins être vérifié dans son contexte : la taille fournie doit correspondre à la capacité réelle du tampon et la valeur de retour doit être traitée correctement. Les alertes d’imports restent des indicateurs heuristiques et ne constituent pas, à elles seules, une preuve de vulnérabilité.
