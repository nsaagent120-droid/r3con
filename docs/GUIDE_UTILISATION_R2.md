# Guide simple de r3con avec radare2

## 1. Principe

r3con coordonne plusieurs analyseurs locaux. Pour l’analyse reverse, **radare2 est maintenant le moteur utilisé par défaut**. Ghidra n’est jamais lancé automatiquement; il est exécuté uniquement avec l’option `--with-ghidra`.

Le pipeline normal combine l’identification ELF, les protections, les chaînes, les imports et **radare2 pour le désassemblage et le pseudo-code**. Le module interne Capstone n’est plus utilisé dans le profil binaire normal; il sert uniquement de fallback contrôlé si aucun moteur externe n’est disponible. Le résultat est ensuite regroupé dans un rapport JSON unique.

## 2. Vérifier les outils

```bash
r3con tools status
```

Pour le mode reverse principal, il faut au minimum voir `r2` ou `radare2` comme présent. GDB/pwndbg est utilisé pour les analyses dynamiques lorsqu’un profil dynamique est demandé. TShark intervient pour les captures réseau. Zeek reste optionnel.

## 3. Analyse binaire recommandée

La commande la plus simple est :

```bash
r3con analyze ./mon_binaire --profile binary --json-output rapport.json
```

Cette commande utilise radare2 par défaut. Elle ne lance pas Ghidra.

Pour afficher directement les résultats dans le terminal :

```bash
r3con analyze ./mon_binaire --profile binary
```

## 4. Comprendre le rapport

Dans `rapport.json`, le champ `plan` montre les étapes réellement prévues. Pour le mode normal, il doit contenir `radare2` et ne doit pas contenir `ghidra`.

La section `results.radare2` contient notamment le statut, la version, l’exécutable utilisé, les informations ELF, les fonctions, les imports, le désassemblage de `main` et le pseudo-code r2 de `main`. Les champs `function_count` et `import_count` donnent un résumé rapide; la sortie native complète reste disponible dans `observations.raw`.

Exemple de vérification :

```bash
python3 - <<'PY'
import json
r = json.load(open("rapport.json"))
print("Statut :", r["status"])
print("Plan :", " -> ".join(r["plan"]))
r2 = r["results"].get("radare2", {})
obs = r2.get("observations", {})
print("Moteur :", r2.get("engine"))
print("Version :", r2.get("version"))
print("Fonctions :", obs.get("function_count"))
print("Imports :", obs.get("import_count"))
PY
```

## 5. Utiliser rizin à la place de radare2

Si rizin est installé et doit être choisi explicitement :

```bash
r3con analyze ./mon_binaire --profile binary --reverse-engine rizin
```

Radare2 reste le choix recommandé dans ta configuration actuelle, car `/usr/bin/r2` est déjà installé et validé.

## 6. Activer Ghidra volontairement

Ghidra est complémentaire, pas obligatoire. Pour lancer radare2 **et** Ghidra :

```bash
r3con analyze ./mon_binaire --profile binary --with-ghidra --json-output rapport-complet.json
```

Dans ce cas, le plan contient les deux étapes. Si Ghidra est absent ou incompatible, son résultat sera indiqué `unsupported`, `partial` ou `timeout`; radare2 continuera d’être disponible.

## 7. Profils utiles

| Besoin | Commande |
|---|---|
| Analyse rapide | `r3con analyze ./fichier --profile quick` |
| Reverse binaire avec r2 | `r3con analyze ./fichier --profile binary` |
| Reverse binaire avec r2 + Ghidra | `r3con analyze ./fichier --profile binary --with-ghidra` |
| Analyse dynamique GDB | `r3con analyze ./fichier --profile dynamic` |
| Analyse PCAP passive | `r3con analyze capture.pcap --profile network` |
| Détection automatique | `r3con analyze ./fichier --profile auto` |

## 8. Lire les résultats correctement

`status: ok` signifie que l’étape s’est terminée normalement. `partial` signifie qu’elle a produit des données mais qu’une partie est incomplète. `unsupported` signifie que l’outil demandé n’est pas disponible. Ces statuts ne doivent pas être confondus avec la sécurité du binaire.

Les protections `PIE`, `NX`, `canary` et `RELRO` décrivent les propriétés de compilation du fichier analysé. Par exemple, `canary: false` signifie que ce binaire ne possède pas de canari de pile; ce n’est pas une erreur du programme r3con.

## 9. Commande recommandée pour commencer

```bash
r3con tools status
r3con analyze ./mon_binaire --profile binary --json-output rapport.json
less rapport.json
```

Commence par examiner `identify`, `imports` et `radare2`. Dans `results.radare2.observations`, les champs `disassembly` et `pseudocode` proviennent directement de r2. Utilise ensuite le profil `dynamic` avec GDB/pwndbg si tu veux observer le comportement à l’exécution. Active Ghidra uniquement lorsqu’une seconde opinion ou une décompilation complémentaire est nécessaire.

## 10. Lancer directement les moteurs externes

Pour laisser r3con ouvrir radare2 directement :

```bash
r3con r2 ./mon_binaire
```

r3con lance alors `r2 -AA`; tu peux utiliser `afl`, `pdf @ main`, `pdc @ main` et `q`. Pour ouvrir r2 sans analyse automatique :

```bash
r3con r2 ./mon_binaire --no-analysis
```

Pour ouvrir GDB directement avec la configuration personnelle, notamment pwndbg chargé par `~/.gdbinit` :

```bash
r3con gdb ./mon_binaire
```

Cette commande conserve la configuration GDB de l’utilisateur et ne lance pas une commande d’exploitation automatiquement.

## 11. Commandes dynamiques

Vérifier GDB et le framework détecté :

```bash
r3con dynamic status ./mon_binaire
```

Analyser une fonction à l’exécution :

```bash
r3con dynamic function ./mon_binaire main
```

Tester un comportement de crash local avec une entrée contrôlée :

```bash
r3con dynamic crash ./mon_binaire --input test
```

Inspecter l’offset d’un motif cyclique :

```bash
r3con dynamic offset ./mon_binaire --length 300
```

Inspecter le heap si pwndbg, GEF ou PEDA est disponible :

```bash
r3con dynamic heap ./mon_binaire
```

Analyser les gadgets observés dans l’espace mémoire du processus :

```bash
r3con dynamic rop ./mon_binaire
```

Analyser un core dump :

```bash
r3con dynamic core ./mon_binaire ./core.dump
```

Poser un watchpoint :

```bash
r3con dynamic watchpoint ./mon_binaire 0x404040 --type write
```

Le profil orchestré regroupe également le statut GDB, les fonctions connues, l’analyse de crash, les registres et la backtrace :

```bash
r3con analyze ./mon_binaire --profile dynamic --json-output dynamic.json
```

Les commandes dynamiques exécutent uniquement la cible locale indiquée. Utilise-les exclusivement sur des programmes et environnements que tu es autorisé à analyser.

## 12. Affichage et animations

La bannière interactive présente maintenant les domaines pris en charge, le statut IA, le rôle de radare2, le rôle de GDB/pwndbg et le caractère optionnel de Ghidra. Lorsque r3con est lancé dans un vrai terminal, les étapes de démarrage peuvent afficher une progression animée sobre.

Pour désactiver toutes les animations :

```bash
R3CON_NO_ANIMATION=1 r3con analyze ./mon_binaire --profile binary
```

Pour supprimer complètement la bannière :

```bash
r3con --no-banner analyze ./mon_binaire --profile binary
```

Le mode `--no-banner` et `R3CON_NO_ANIMATION=1` sont recommandés pour les scripts, CI et sorties destinées à être capturées. Les résultats JSON restent séparés de l’affichage visuel.

## 13. Console persistante de type Metasploit

Pour ne plus taper `r3con` avant chaque commande, lance une seule fois :

```bash
r3con interactive
```

Tu obtiens alors une invite persistante :

```text
r3con>
```

Les commandes intégrées principales sont :

```text
help
set target ./mon_binaire
show options
analyze --profile binary --json-output rapport.json
disasm file ./mon_binaire --output pseudocode --function main
r2 ./mon_binaire
gdb ./mon_binaire
dynamic status ./mon_binaire
dynamic function ./mon_binaire main
history
sessions
clear
exit
```

Une cible courante peut être définie une fois :

```text
set target ./mon_binaire
show options
```

Tu peux ensuite lancer les commandes normalement. La cible courante est affichée dans l’invite. Les commandes directes `r2` et `gdb` ouvrent leurs sessions natives; après leur fermeture, la console r3con revient à son invite.

La console conserve un historique de la session avec `history`. La commande `clear` nettoie l’écran sans supprimer les fichiers de rapport. `exit`, `quit` ou `q` ferment la console.

## 14. Console hybride commandes + IA

La console interactive conserve maintenant les deux usages. Si la ligne commence par une commande connue comme `analyze`, `r2`, `gdb`, `disasm`, `dynamic`, `firmware`, `source` ou `network`, r3con exécute la commande. Si la ligne ne correspond pas à une commande, elle est envoyée à l’assistant IA conversationnel.

Exemple :

```text
r3con> set target ./mon_binaire
r3con(mon_binaire)> analyze --profile binary
r3con(mon_binaire)> disasm file ./mon_binaire --output pseudocode --function main
r3con(mon_binaire)> explique le rôle de la fonction main
r3con(mon_binaire)> quelles protections dois-je examiner ?
```

Les questions naturelles utilisent le contexte de la conversation. `clear` réinitialise l’écran et le contexte IA; `history` affiche l’historique des commandes; `sessions` affiche les analyses sauvegardées. En mode hors ligne, l’IA fournit une réponse à base de règles et indique les capacités qui nécessitent un fournisseur IA configuré.
