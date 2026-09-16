# Guide utilisateur r3con 7.4.0

## 1. À qui s’adresse r3con ?

r3con s’adresse aux analystes qui examinent du code, des binaires, des APK, des firmwares, des captures réseau, des échantillons malveillants, des projets web ou des configurations cloud. L’outil est conçu pour travailler d’abord localement, produire des résultats reproductibles et indiquer clairement quand une capacité spécialisée n’est pas disponible.

Utilisez r3con uniquement sur des données et des systèmes que vous êtes autorisé à analyser. Ce guide décrit l’analyse défensive, la validation de sécurité et les travaux de laboratoire. Il ne donne pas d’autorisation pour interagir avec des systèmes tiers.

## 2. Installation et premier diagnostic

### Installation minimale

```bash
git clone https://github.com/nsaagent120-droid/r3con.git
cd r3con
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

### Installation par domaine

Installez uniquement les extras nécessaires lorsque la machine doit rester légère :

| Besoin | Installation |
|---|---|
| Analyse binaire | `python -m pip install -e '.[binary]'` |
| Reporting et templates | `python -m pip install -e '.[reporting]'` |
| Dashboard web | `python -m pip install -e '.[web]'` |
| AST C/C++ et exécution symbolique | `python -m pip install -e '.[ast,symbolic]'` |
| Fournisseurs IA optionnels | `python -m pip install -e '.[ai-all]'` |
| Environnement complet | `python -m pip install -e '.[full]'` |
| Développement et tests | `python -m pip install -e '.[dev]'` |

Le script complet peut installer les extras et préparer les répertoires locaux :

```bash
bash scripts/install_full.sh --yes
```

### Vérification initiale

```bash
r3con --version
r3con --help
r3con tools status
r3con tools doctor --json-output
python -m compileall -q .
python -m pytest -q
```

`tools status` donne une vue rapide. `tools doctor` est préférable avant une campagne, car il expose les versions, les bibliothèques et les capacités manquantes.

## 3. Choisir le bon mode

| Situation | Mode recommandé | Commande de départ |
|---|---|---|
| Comprendre ce que r3con va faire | Plan explicable | `r3con scan TARGET --explain-plan` |
| Audit reproductible complet | Scan orchestré | `r3con scan TARGET --profile auto` |
| Tester un outil externe isolément | Job contrôlé | `r3con runtime run TOOL ARGS...` |
| Lancer plusieurs outils pendant une session | Console interactive | `r3con interactive` |
| Déboguer un binaire local autorisé | Analyse dynamique | `r3con dynamic ...` ou `r3con gdb TARGET` |
| Exécuter un échantillon non fiable | Runner sandboxé | `r3con dynamic sandbox TARGET` puis `--execute` |
| Comparer deux versions | Analyse différentielle | `r3con compare OLD NEW` |
| Auditer les dépendances d’un projet | Supply chain | `r3con supply-chain scan PROJECT ...` |

Commencez par le plan lorsque vous ne connaissez pas encore les dépendances disponibles. Le plan indique les tâches, les outils absents, les fallbacks et les limites.

### Performance et progression

Pour suivre une analyse de répertoire dans un terminal compatible, la progression est active par défaut :

```bash
r3con scan ./project --workers 4 --progress
r3con scan ./project --no-progress
```

Le benchmark local crée un corpus temporaire déterministe et mesure la durée ainsi que le pic mémoire Python. Il ne lit pas les données du projet et ne contacte aucun service distant :

```bash
python scripts/benchmark.py --files 20 --runs 3 --workers 4 --output reports/benchmark.json
```

Conservez les résultats avec la version de r3con, la version de Python et le nombre de workers. Comparez des mesures obtenues dans des environnements similaires ; une valeur isolée ne constitue pas une régression ou une amélioration certaine.

### Contrôler le cache

r3con utilise deux caches locaux complémentaires : le cache de fichiers pour les analyses historiques et le cache de tâches pour l’orchestrateur unifié. Ils sont versionnés et restent locaux.

```bash
r3con cache status
r3con cache status --json-output
r3con cache verify
r3con cache clear --yes
```

`cache clear` supprime les résultats réutilisables, mais ne supprime pas les cibles, les rapports déjà exportés ou les workspaces analytiques. Après cette commande, le prochain scan recalculera les tâches nécessaires.

## 4. Console interactive colorée

Lancez la console avec :

```bash
r3con interactive
```

Le prompt est coloré et affiche la cible active :

```text
r3con> set target ./program
r3con(program)> show options
```

Commandes intégrées :

| Commande | Fonction |
|---|---|
| `help` | Afficher les commandes principales |
| `set target PATH` | Définir la cible courante |
| `show options` | Afficher le contexte courant |
| `theme cyber` | Changer la palette |
| `history` | Afficher l’historique de la session |
| `sessions` | Afficher les sessions enregistrées |
| `run COMMAND...` | Lancer un job externe borné |
| `jobs` | Lister les jobs de la session |
| `stop JOB_ID` | Arrêter un job |
| `clear` | Effacer l’affichage |
| `exit` | Fermer la console et nettoyer les jobs |

Les thèmes disponibles sont `matrix`, `cyber`, `amber` et `mono`. Le mode non coloré est utile pour la CI :

```bash
R3CON_NO_COLOR=1 r3con interactive
```

### Jobs externes dans la console

```text
r3con> run file ./program
r3con> run strings -n 8 ./program
r3con> run readelf -h ./program
r3con> jobs
r3con> stop 657b499d64f242c3
```

Les jobs sont lancés avec un environnement réduit. Pour les outils locaux, le réseau est bloqué par défaut et le job peut continuer même si le noyau ou le conteneur interdit `unshare -n`. Utilise `--strict-network` si le job doit être refusé lorsque l’isolation réseau Linux complète n’est pas disponible. Un terminal shell libre n’est pas créé par `run`.

Les métadonnées des jobs terminés sont conservées localement sous `~/.r3con/jobs/` afin de permettre la traçabilité après fermeture de la commande :

```bash
r3con runtime jobs
r3con runtime jobs --json-output
r3con runtime show JOB_ID
r3con runtime clean --yes
```

Cette persistance concerne l’historique et les sorties bornées. Elle ne transforme pas un job batch en terminal interactif et ne permet pas de reprendre un processus après redémarrage.

## 5. Code source et audit SAST

Utilisez le domaine code source pour rechercher les risques de mémoire, d’injection, de secrets, de cryptographie, de concurrence et de configuration.

```bash
r3con audit file ./src/parser.c --report
r3con audit dir ./src --recursive --report
r3con scan ./src --profile auto --explain-plan
```

Pour une revue progressive, commencez par un fichier représentatif, vérifiez les findings, puis lancez l’analyse récursive. Les parseurs AST améliorent la précision pour C/C++ lorsque `tree-sitter` et `tree-sitter-c` sont installés. Sans ces dépendances, r3con peut utiliser un fallback textuel, qui doit être traité comme moins précis.

Avant de transmettre un finding à une équipe de développement, vérifiez le fichier, la ligne, le contexte et la recommandation. Un motif détecté dans un commentaire ou un code mort peut être un faux positif.

## 6. Binaires et reverse engineering

### Tri initial

```bash
r3con disasm file ./program --arch auto
r3con disasm strings ./program --min-len 6
r3con tools status
```

### Analyse structurée

```bash
r3con scan ./program --profile auto --explain-plan
r3con disasm imports ./program --vuln-check
r3con r2 ./program
r3con gdb ./program
```

Utilisez `r2` ou `gdb` uniquement lorsque l’outil est installé et que le binaire appartient au périmètre autorisé. Les commandes de débogage peuvent exécuter du code contenu dans la cible. Pour un binaire non fiable, préférez un environnement de laboratoire séparé.

### Différentiel

```bash
r3con compare ./program-old ./program-new --kind binary --format md --output binary-diff.md
```

Un différentiel sert à identifier les fonctions, protections, imports et strings modifiés. Il ne prouve pas à lui seul qu’une modification est vulnérable.

## 7. APK et applications mobiles

```bash
r3con apk analyze ./application.apk --report
r3con apk manifest ./AndroidManifest.xml
r3con apk permissions ./application.apk
```

Commencez par le manifeste, les permissions, les URLs, les secrets et les composants exportés. Ajoutez `jadx`, `apktool`, `aapt` et `apksigner` lorsque la décompilation, les ressources, la signature ou le DEX doivent être examinés.

Conservez l’APK original, son hash et la version des outils dans le dossier de campagne. Ne publiez pas de secrets ou de certificats extraits dans un rapport public.

## 8. Firmware et IoT

```bash
r3con firmware analyze ./firmware.bin --report
r3con firmware extract ./firmware.bin --output ./extracted
r3con firmware strings ./firmware.bin --min-len 6
r3con firmware entropy ./firmware.bin
```

Utilisez `binwalk` pour l’extraction lorsqu’il est disponible. L’extraction doit être réalisée dans un répertoire de travail dédié, car elle peut produire beaucoup de fichiers. Après extraction, recherchez les identifiants, clés, scripts de démarrage, services réseau et versions de composants.

L’analyse firmware est principalement statique. L’émulation ou le démarrage d’une image nécessite une infrastructure séparée et ne doit pas être improvisé dans le processus principal de r3con.

## 9. Réseau et PCAP

```bash
r3con network analyze ./capture.pcap
r3con network flow ./capture.pcap
r3con network dns ./capture.pcap
r3con network threat ./capture.pcap
r3con network tools ./capture.pcap
```

Utilisez `tshark` pour les champs de protocole et `zeek` pour les journaux hors ligne lorsque ces outils sont disponibles. Pour une capture live :

```bash
r3con network live eth0 --duration 60
```

La capture live peut nécessiter des privilèges et doit être limitée à une interface et une durée approuvées. Une capture réseau peut contenir des secrets, des tokens ou des données personnelles. Stockez-la dans un emplacement privé et définissez une durée de conservation.

## 10. Malware et échantillons suspects

```bash
r3con malware analyze ./sample --profile full
r3con malware pe ./sample
r3con malware elf ./sample
r3con malware ioc ./sample
r3con malware anti ./sample
r3con dynamic sandbox ./sample
```

Le runner sandboxé fonctionne d’abord en mode plan. Aucun processus n’est lancé tant que `--execute` n’est pas fourni. Le réseau est coupé par défaut et l’exécution peut être refusée lorsque l’isolation réseau n’est pas disponible.

```bash
r3con dynamic sandbox ./sample --plan
r3con dynamic sandbox ./sample --execute --timeout 10 --mem-mb 256
```

N’activez `--allow-network` que dans un laboratoire contrôlé disposant d’une surveillance et d’une autorisation explicites. Les résultats comportementaux sont bornés par les limites du runner et ne constituent pas une preuve d’absence de comportement.

## 11. Web et projets applicatifs

```bash
r3con web --help
r3con audit dir ./web-app --recursive --report
r3con scan ./web-app --profile auto
```

L’analyse locale couvre notamment les injections, secrets, configurations et patterns de code. L’intégration d’outils comme Nuclei doit être limitée à des cibles autorisées. Ne lancez pas de scan distant contre un domaine tiers sans mandat documenté.

## 12. Supply chain, cloud et conteneurs

```bash
r3con supply-chain scan ./project \
  --sbom cyclonedx \
  --dependencies \
  --secrets \
  --report supply-chain.json
```

Pour Docker, Compose, Kubernetes et Terraform, analysez d’abord les fichiers de configuration et les manifests. Conservez l’SBOM avec le commit et l’environnement ayant produit le rapport. Une dépendance détectée dans un lockfile doit être vérifiée contre le graphe réellement utilisé et non seulement contre son nom.

## 13. Fuzzing et exploitation contrôlée

Le fuzzing et les commandes d’exploitation sont réservés aux laboratoires autorisés.

```bash
r3con fuzzing plan campaign-name --timeout-ms 1000 --memory-mb 256 --max-runtime 60
r3con fuzzing export-findings campaign-name
r3con exploit --help
```

Commencez par un plan. Définissez une limite de temps, une limite mémoire, une limite de fichiers et un dossier de sortie. Les crashs doivent être triés, dédupliqués et minimisés sans modifier la cible originale.

Les fonctions ROP, heap et templates de PoC produisent des éléments d’étude. Elles ne doivent pas être interprétées comme une autorisation d’exploitation contre un système réel.

## 14. Rapports, reprise et comparaison

Un rapport doit être conservé avec la cible, son hash, la version de r3con, les versions des outils et les paramètres importants.

```bash
r3con scan ./program --profile full --report ./reports/program.json
r3con scan ./program --resume ./reports/program-run
r3con reports compare ./reports/old.json ./reports/new.json --format md
r3con explain FINDING_ID --report ./reports/program.json
r3con summarize ./reports/program.json
r3con ask ./reports/program.json "Quels risques sont corroborés par plusieurs outils ?"
```

`--resume` réutilise uniquement les tâches terminées et identifiables. Après modification de la cible, du profil ou des versions d’outils, une nouvelle analyse complète est généralement préférable.

## 15. Résultats et qualité d’interprétation

| Élément | Question à poser |
|---|---|
| Sévérité | Quel est l’impact potentiel ? |
| Exploitabilité | Existe-t-il un chemin démontré ou seulement théorique ? |
| Corroboration | Plusieurs outils observent-ils le même fait ? |
| Provenance | Quel analyseur a produit le finding ? |
| Fallback | Une dépendance manquait-elle ? |
| Localisation | Le fichier, la fonction ou l’offset sont-ils vérifiables ? |
| Action | Quelle correction ou vérification est recommandée ? |

Un rapport de qualité distingue les observations, les hypothèses, les findings confirmés et les faux positifs. Les sorties IA sont des commentaires auxiliaires et ne remplacent pas les preuves produites par les analyseurs.

## 16. Données locales et confidentialité

Les rapports, caches, sessions et bases locales se trouvent généralement sous `~/.r3con/`. Les rapports peuvent contenir du code source, des secrets, des URLs internes et des données personnelles. Protégez les permissions du répertoire et définissez une politique de conservation.

Les variables d’environnement sont adaptées aux clés API :

```bash
export OPENAI_API_KEY='...'
```

Ne mettez jamais une clé dans `config.yaml`, dans une commande enregistrée ou dans un commit Git.

## 17. Dépannage

| Symptôme | Vérification |
|---|---|
| Outil externe absent | `r3con tools doctor --json-output` |
| Résultat `unsupported` | Installer l’outil ou utiliser le fallback indiqué |
| Runner refusé | Vérifier `unshare -n`, ou utiliser un laboratoire explicitement autorisé |
| Timeout | Réduire la cible ou augmenter la limite de manière documentée |
| Rapport incomplet | Examiner les statuts par tâche et relancer avec `--resume` |
| Couleurs absentes | Vérifier `R3CON_NO_COLOR`, `--no-color` et le terminal |
| Job bloqué | Utiliser `jobs`, puis `stop JOB_ID` |
| Erreur d’installation | Créer un nouvel environnement virtuel et consulter `python --version` |

## 18. Références complémentaires

Le [modèle de fonctionnement](OPERATING_MODEL_v7.4.md) définit les concepts et les états. Le [manuel technique](MANUEL_TECHNIQUE_v7.2.md) décrit l’architecture historique et les modules internes. La [politique de sécurité](../SECURITY_AUDIT.md) présente les limites et les contrôles. Le [changelog](../CHANGELOG.md) liste les changements de version.

## Références

[1]: https://github.com/nsaagent120-droid/r3con "Dépôt officiel r3con"
[2]: https://docs.python.org/3/library/subprocess.html "Documentation Python subprocess"
[3]: https://docs.python.org/3/library/venv.html "Documentation Python venv"
[4]: https://click.palletsprojects.com/ "Documentation Click"
[5]: https://rich.readthedocs.io/ "Documentation Rich"
