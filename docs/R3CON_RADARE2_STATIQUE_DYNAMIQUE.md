# r3con + radare2 — Manuel pratique d’analyse statique et dynamique

## 1. Objectif du manuel

Ce manuel explique comment utiliser **r3con avec radare2** pour analyser un binaire local, d’abord statiquement puis dynamiquement. Il distingue toujours les deux interfaces :

| Interface | Rôle |
|---|---|
| `r3con analyze` | Orchestration, identification, protections, imports, chaînes et rapport JSON |
| `r3con disasm file` | Désassemblage ou pseudo-code ciblé depuis r3con |
| `r3con r2` | Ouverture directe de radare2 avec analyse interactive |
| `r3con gdb` | Ouverture directe de GDB/pwndbg |
| `r3con dynamic ...` | Helpers dynamiques automatisés principalement basés sur GDB |
| `r2 -d` | Débogage dynamique natif avec radare2 |

Utilise uniquement des fichiers et programmes que tu es autorisé à analyser, de préférence dans une machine de laboratoire isolée.

## 2. Préparer l’environnement

Vérifie les outils :

```bash
r3con tools status
command -v r2 || command -v radare2
r2 -v
```

Vérifie la cible :

```bash
file ./mon_binaire
ls -lh ./mon_binaire
```

Si le fichier n’est pas exécutable :

```bash
chmod u+x ./mon_binaire
```

Pour les scripts et rapports automatisés, désactive l’affichage animé :

```bash
export R3CON_NO_ANIMATION=1
```

## 3. Le workflow recommandé

Le parcours le plus simple est :

```text
r3con tools status
→ r3con analyze --profile binary
→ r3con disasm file --output asm
→ r3con disasm file --output pseudocode
→ r3con r2
→ r2 -d pour le dynamique
→ rapport JSON et notes d’analyse
```

Commence toujours par comprendre le format, l’architecture, les protections et les points d’entrée avant de lancer le programme.

## 4. Analyse statique avec r3con

### 4.1 Analyse générale

```bash
r3con analyze ./mon_binaire \
  --profile binary \
  --json-output rapport-statique.json
```

Avec le profil binaire, radare2 est le moteur reverse principal lorsqu’il est installé. Le plan attendu est :

```text
identify → strings → imports → radare2
```

Pour ajouter Ghidra uniquement en complément :

```bash
r3con analyze ./mon_binaire \
  --profile binary \
  --with-ghidra \
  --json-output rapport-r2-ghidra.json
```

### 4.2 Comprendre le rapport

Les zones importantes sont :

```text
results.identify
results.strings
results.imports
results.radare2.observations.functions
results.radare2.observations.disassembly
results.radare2.observations.pseudocode
findings
plan
```

Les statuts sont interprétés ainsi :

| Statut | Sens |
|---|---|
| `ok` | Étape exécutée normalement |
| `partial` | Résultat utilisable mais incomplet |
| `unsupported` | Outil ou capacité indisponible |
| `timeout` | Délai dépassé |
| `error` | Erreur d’exécution |

### 4.3 Désassemblage ciblé depuis r3con

```bash
r3con disasm file ./mon_binaire \
  --output asm \
  --function main
```

Autre fonction :

```bash
r3con disasm file ./mon_binaire \
  --output asm \
  --function vulnerable_copy
```

Pseudo-code radare2 :

```bash
r3con disasm file ./mon_binaire \
  --output pseudocode \
  --function main
```

La pseudo-décompilation est une reconstruction approximative. Elle ne restitue pas les noms, commentaires, types et intentions exacts du code source.

## 5. Ouvrir radare2 directement

Pour une session interactive :

```bash
r3con r2 ./mon_binaire
```

r3con ouvre radare2 avec l’analyse automatique `-AA`. Pour le lancer sans analyse automatique :

```bash
r3con r2 ./mon_binaire --no-analysis
```

Tu peux aussi lancer r2 directement :

```bash
r2 -AA ./mon_binaire
```

Dans les exemples suivants, l’invite `r2>` désigne la console radare2.

## 6. Commandes statiques essentielles de radare2

### 6.1 Informations du fichier

```text
i                   résumé général
ij                  résumé JSON
iI                  informations détaillées du binaire
iIj                 informations détaillées JSON
iS                  sections
iSj                 sections JSON
iE                  sections exécutables
ie                  adresse d’entrée
iej                 adresse d’entrée JSON
```

### 6.2 Imports, exports et symboles

```text
ii                  imports
iij                 imports JSON
il                  bibliothèques liées
is                  symboles
isj                 symboles JSON
iz                  chaînes dans les sections de données
izz                 chaînes plus largement détectées
izzj                chaînes JSON
```

### 6.3 Analyse des fonctions

```text
aa                  analyse basique
aaa                 analyse plus complète
aac                 analyse des appels
aaf                 analyse des fonctions
aa; aac; aaf       séquence lisible si nécessaire
afl                 liste des fonctions
aflj                fonctions JSON
afll                fonctions avec davantage de détails
afm                 informations de la fonction courante
afvd                variables locales et arguments détectés
afvn                renommer une variable
afn new_name        renommer la fonction courante
```

En pratique, utilise souvent :

```text
aaa
afl
```

Puis sélectionne une fonction avec `s`.

### 6.4 Navigation et adresses

```text
s main              aller à main
s sym.main          aller au symbole main
s 0x401234          aller à une adresse hexadécimale
s                   afficher l’adresse courante
?v                  aide générale
? pdf               aide de la commande pdf
```

### 6.5 Désassemblage

```text
pd 20               afficher 20 instructions
pdf @ main          désassembler toute la fonction main
pdfj @ main         désassemblage JSON de main
pD 64 @ 0x401234    désassembler 64 octets à une adresse
pDj 64 @ 0x401234   même sortie en JSON
pdr                 désassemblage relatif au registre PC/RIP
```

Pour afficher une fonction précise :

```text
pdf @ sym.vulnerable_copy
```

Pour enregistrer la sortie depuis le shell :

```bash
r2 -q -c 'aaa;pdf @ main;q' ./mon_binaire > main.asm
r2 -q -c 'aaa;pdfj @ main;q' ./mon_binaire > main.json
```

### 6.6 Pseudo-décompilation

```text
pdc @ main
```

Selon l’installation, un plugin peut fournir :

```text
pdg @ main
```

`pdc` est un pseudo-décompilateur intégré. `pdg` dépend généralement d’un plugin de décompilation. Si la commande est inconnue, utilise `pdc`, `pdf` ou active Ghidra explicitement depuis r3con.

### 6.7 Références et graphe

```text
axt @ main          références qui arrivent vers main
axtj @ main         même résultat JSON
axf @ main          références sortantes de main
axfj @ main         même résultat JSON
agf @ main          graphe de contrôle de main
agfj @ main         graphe JSON
afC @ main          graphe d’appels selon la version/configuration
```

Pour rechercher les appels à une fonction importée :

```text
axt @ sym.imp.strcpy
```

### 6.8 Recherche de chaînes et octets

```text
/ dangerous         rechercher une chaîne
/x 4889e5           rechercher des octets hexadécimaux
/a jmp rax          rechercher une instruction
/ca                 rechercher des chaînes ASCII
```

Pour vérifier une adresse :

```text
px 64 @ 0x401234
```

## 7. Protections et zones sensibles

r3con fournit les protections générales; radare2 permet de compléter l’examen :

```bash
r3con analyze ./mon_binaire --profile binary
```

Dans r2 :

```text
iI                  format, architecture, bits, entrée
 iS                 sections et permissions; saisir iS sans espace initial
ii                  imports
izz                 chaînes
```

Cherche en particulier :

| Élément | Question à poser |
|---|---|
| `main` | Où commence le flot applicatif ? |
| imports mémoire | Existe-t-il des appels de copie ou formatage dangereux ? |
| `.text` | Quelles fonctions sont exécutables ? |
| `.rodata` | Quelles chaînes ou constantes sont utilisées ? |
| PLT/GOT | Quels appels externes sont résolus ? |
| protections | L’ASLR/PIE, NX, canary et RELRO réduisent-ils certaines classes de risques ? |

Une protection absente n’est pas automatiquement une vulnérabilité. Elle indique seulement une surface de risque à examiner.

## 8. Analyse dynamique avec radare2

### 8.1 Démarrer en mode debug

Depuis r3con :

```bash
r3con r2 ./mon_binaire
```

Dans r2, redémarre ou ouvre la cible en mode debug selon le contexte :

```text
ood
```

La méthode directe est généralement :

```bash
r2 -d ./mon_binaire
```

Pour analyser automatiquement puis déboguer :

```bash
r2 -d -AA ./mon_binaire
```

Le mode debug exécute la cible locale sous le contrôle de radare2. Utilise un programme de laboratoire et une entrée contrôlée.

### 8.2 Arguments du programme

Dans r2 :

```text
ood argument1 argument2
```

Pour réouvrir le programme avec une nouvelle entrée, réutilise `ood`.

### 8.3 Breakpoints

```text
db main
db sym.main       breakpoint sur le symbole main
db 0x401234       breakpoint à une adresse
db                liste des breakpoints
db- 0x401234     supprimer un breakpoint
db-*              supprimer tous les breakpoints selon version
```

Pour éviter les erreurs de copie, les commandes correctes sont :

```text
db main
db 0x401234
db
db- 0x401234
```

### 8.4 Contrôle de l’exécution

```text
dc                  continuer
dcu main            continuer jusqu’à main
dcu 0x401234         continuer jusqu’à une adresse
ds                  step into, une instruction
dso                 step over
dcr                 continuer jusqu’au retour de fonction
```

La forme à saisir ne contient pas d’espace initial : `dcu`, `dso` et `ds`.

### 8.5 Registres et instruction courante

```text
dr                  afficher les registres
drq                 afficher RIP/PC selon architecture
pd 10 @ rip         désassembler autour du compteur courant
px 64 @ rsp         afficher la pile
pxr 64 @ rsp        afficher la pile avec références analysées
```

Sur x86-64, les registres fréquemment examinés sont `rip`, `rsp`, `rbp`, `rax`, `rdi`, `rsi`, `rdx` et `rcx`.

### 8.6 Mémoire et mappings

```text
dm                  mappings mémoire du processus
dmm                 modules/mappings selon version
px 128 @ rsp        afficher 128 octets depuis la pile
px 64 @ rbp         afficher autour de la base de frame
pxw 32 @ 0x401234   afficher des mots
ps @ rdi            afficher une chaîne à l’adresse contenue dans rdi
psz @ 0x402000      afficher une chaîne terminée par zéro
```

### 8.7 Backtrace et état d’arrêt

```text
dbt                backtrace de débogage
dr                  registres
pd 20 @ rip        instructions au point d’arrêt
```

À chaque arrêt, note :

```text
adresse d’arrêt
fonction
RIP/PC
RSP/SP
arguments
backtrace
instructions voisines
```

### 8.8 Watchpoints

Selon la version et le backend :

```text
db 0x404040         breakpoint classique
drw 0x404040        watchpoint écriture, si disponible
drr 0x404040        watchpoint lecture, si disponible
drx 0x404040        watchpoint accès, si disponible
```

Si une commande `drw`, `drr` ou `drx` n’est pas disponible, utilise GDB/pwndbg via :

```bash
r3con gdb ./mon_binaire
```

## 9. Workflow statique complet avec r2

```bash
r2 -AA ./mon_binaire
```

Dans r2 :

```text
iI
iS
ii
izz
afl
s main
pdf @ main
pdc @ main
agf @ main
```

Puis examine les fonctions intéressantes :

```text
pdf @ sym.vulnerable_copy
pdc @ sym.vulnerable_copy
axt @ sym.vulnerable_copy
```

Pour rechercher les appels et données associés :

```text
axt @ sym.imp.strcpy
/ password
/ http
```

## 10. Workflow dynamique complet avec r2

Lance :

```bash
r2 -d -AA ./mon_binaire
```

Dans r2 :

```text
afl
 db main
 db vulnerable_copy
 db
 dc
```

Lorsque l’exécution s’arrête :

```text
dr
dbt
pd 20 @ rip
pxr 96 @ rsp
```

Pour avancer :

```text
ds
dso
dc
```

Pour arrêter de nouveau à une fonction ou une adresse :

```text
db 0x401234
dcu 0x401234
```

Pour redémarrer avec une nouvelle entrée :

```text
ood nouvelle_entree
dc
```

## 11. Utiliser r3con comme console persistante

Lance :

```bash
r3con interactive
```

Puis :

```text
set target ./mon_binaire
analyze --profile binary --json-output static.json
disasm file ./mon_binaire --output asm --function main
r2 ./mon_binaire
dynamic status ./mon_binaire
```

Tu peux ensuite poser une question à l’IA :

```text
explique les appels de main
quelles fonctions dois-je examiner ?
que signifie cette instruction ?
```

Pour le dynamique r2 natif, la commande `r2 ./mon_binaire` ouvre r2; pour démarrer directement en debug avec r3con, utilise aussi le lancement direct `r2 -d` depuis le terminal si l’option debug n’est pas exposée par la commande courte.

## 12. Commandes dynamiques r3con complémentaires

Ces commandes utilisent l’analyseur dynamique intégré, principalement construit autour de GDB et du framework détecté :

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

Utilise ces helpers pour obtenir un résultat JSON automatisé. Utilise `r2 -d` ou GDB/pwndbg lorsque tu veux contrôler manuellement chaque étape.

## 13. Sorties JSON et automatisation

Sortie JSON d’une fonction :

```bash
r2 -q -c 'aaa;pdfj @ main;q' ./mon_binaire > main.json
```

Informations JSON :

```bash
r2 -q -c 'iIj;q' ./mon_binaire > info.json
```

Fonctions JSON :

```bash
r2 -q -c 'aaa;aflj;q' ./mon_binaire > functions.json
```

Rapport r3con :

```bash
r3con analyze ./mon_binaire \
  --profile binary \
  --json-output rapport.json
```

Pour les pipelines :

```bash
R3CON_NO_ANIMATION=1 r3con --no-banner analyze ./mon_binaire --profile binary --json-output rapport.json
```

## 14. Problèmes courants

### `r2` est introuvable

```bash
r3con tools status
command -v r2 || command -v radare2
```

Installe radare2 via le gestionnaire adapté à ta distribution; ne remplace pas arbitrairement les bibliothèques système de Kali.

### `pdc` ou `pdg` est inconnu

Utilise :

```text
pdf @ main
```

`pdc` peut être absent selon la version ou le build. `pdg` demande généralement un plugin supplémentaire. Ghidra peut être demandé séparément avec `--with-ghidra`.

### La fonction `main` n’existe pas

Le binaire peut être stripped, packé ou utiliser un autre nom de symbole. Lance :

```text
aaa
afl
```

Puis utilise une fonction de la liste ou une adresse trouvée avec `iE`, `afl` ou les imports.

### Les adresses sont difficiles à lire

Les sorties JSON affichent souvent des nombres décimaux. Utilise la sortie interactive :

```text
pdf @ main
```

ou convertis les adresses dans tes notes en hexadécimal.

### Le programme se termine immédiatement

Place un breakpoint avant l’exécution :

```text
db main
dc
```

Si `main` n’est pas disponible, place un breakpoint à l’entrée ou à une fonction importée.

### Les watchpoints r2 ne fonctionnent pas

Le support dépend du backend et de l’architecture. Utilise GDB/pwndbg :

```bash
r3con gdb ./mon_binaire
```

### Le binaire est dynamique ou fortement optimisé

Les symboles peuvent être absents, les fonctions fusionnées et les variables difficiles à reconstruire. Compare plusieurs indices : désassemblage, imports, xrefs, chaînes, registres et comportement à l’exécution.

## 15. Limites d’interprétation

Le désassemblage est exact au niveau des octets décodés par l’architecture, mais la compréhension des fonctions reste une interprétation. Le pseudo-code peut perdre les types, les noms, les macros, les commentaires, les structures et les intentions du développeur.

L’analyse dynamique dépend de l’entrée fournie, des bibliothèques chargées, de l’ASLR, des permissions, du système d’exploitation et du chemin d’exécution atteint. Une absence de crash n’est pas une preuve d’absence de vulnérabilité.

## 16. Fiche de commandes rapide

| Action | Commande |
|---|---|
| Analyse r3con | `r3con analyze ./bin --profile binary` |
| Fonction ciblée r3con | `r3con disasm file ./bin --output asm --function main` |
| Pseudo-code r3con | `r3con disasm file ./bin --output pseudocode --function main` |
| Ouvrir r2 | `r3con r2 ./bin` |
| r2 statique | `r2 -AA ./bin` |
| r2 dynamique | `r2 -d -AA ./bin` |
| Sections | `iS` |
| Imports | `ii` |
| Chaînes | `izz` |
| Fonctions | `afl` |
| Désassemblage | `pdf @ main` |
| Pseudo-code | `pdc @ main` |
| Graphe | `agf @ main` |
| Breakpoint | `db main` |
| Continuer | `dc` |
| Step instruction | `ds` |
| Registres | `dr` |
| Backtrace | `dbt` |
| Mémoire pile | `pxr 96 @ rsp` |
| Mappings | `dm` |
| GDB direct | `r3con gdb ./bin` |
| Console persistante | `r3con interactive` |

## 17. Références

Pour les commandes natives et les différences liées à la version installée, consulte le [site officiel radare2](https://rada.re/n/), le [wiki radare2](https://github.com/radareorg/radare2/wiki) et la [documentation des commandes r2](https://book.rada.re/). Pour le débogage complémentaire, consulte la [documentation GDB](https://sourceware.org/gdb/documentation/) et la [documentation pwndbg](https://pwndbg.re/).
