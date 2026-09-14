# Modèle de fonctionnement r3con 7.4.0

## Objet du document

Ce document définit les concepts, les responsabilités et les limites de r3con 7.4.0. Il sert de référence avant l’ajout de nouvelles commandes ou d’une interface graphique. Une fonctionnalité qui ne respecte pas ce modèle doit être explicitement documentée comme une exception.

## 1. Positionnement

r3con est un orchestrateur local d’analyse de sécurité. Il coordonne des analyseurs internes, des outils externes optionnels et des sorties structurées. Il ne transforme pas automatiquement une indication en preuve et il ne remplace pas la validation humaine.

> **Règle générale :** r3con analyse des données fournies par l’opérateur et signale des observations, hypothèses et risques. L’opérateur reste responsable de l’autorisation, du périmètre et de l’interprétation.

Le fonctionnement par défaut est **offline-first**. Une intégration distante ou un fournisseur IA doit être explicitement activé et doit apparaître dans les métadonnées du résultat.

## 2. Concepts fondamentaux

| Concept | Définition | Durée de vie | Exemple |
|---|---|---|---|
| **Cible** | Fichier, répertoire, PCAP, APK, firmware, rapport ou projet soumis à l’analyse | Une commande ou un run | `./firmware.bin` |
| **Run** | Exécution complète d’un pipeline d’analyse sur une ou plusieurs cibles | Jusqu’à la fin, avec reprise possible | `r3con scan ./program` |
| **Workspace analytique** | Espace logique contenant cibles, résultats, notes et artefacts d’un sujet | Persistant sous `~/.r3con/` | `r3con workspace create firmware-lab` |
| **Workspace d’exécution** | Répertoire privé temporaire utilisé par un processus externe | Jusqu’au nettoyage du job | `/tmp/r3con-workspaces/job-...` |
| **Job** | Processus externe lancé avec des limites et un identifiant | Jusqu’à sa fin ou son arrêt | `657b499d64f242c3` |
| **Session** | Historique r3con conservant une sortie ou une interaction | Persistant selon la configuration | Session interactive ou rapport |
| **Profil** | Ensemble de capacités et de limites adaptées à un domaine | Défini par la commande ou la configuration | `auto`, `full`, `firmware` |
| **Adapter** | Code r3con qui traduit une capacité interne vers un outil externe | Fourni par le dépôt | Adaptateur `tshark`, `r2` ou `binwalk` |
| **Fallback** | Analyse de remplacement utilisée lorsque l’outil spécialisé est absent | Présent dans le résultat | Parser interne au lieu de `radare2` |
| **Finding** | Observation normalisée produite par une analyse | Persistant dans le rapport | Finding de sévérité `HIGH` |

## 3. Les trois modes d’exécution

### 3.1 Analyse orchestrée

Le mode orchestré est destiné aux audits reproductibles. r3con sélectionne des tâches, vérifie les outils disponibles, exécute les analyseurs, normalise les résultats et produit un rapport.

Commande de référence :

```bash
r3con scan TARGET --profile auto --explain-plan
```

Le mode `--plan-only` ou `--dry-run` doit être utilisé avant une campagne importante. Il montre les tâches prévues sans lancer les processus d’analyse.

### 3.2 Job externe contrôlé

Le job contrôlé est destiné à une commande ponctuelle ou parallèle. Il utilise `ExecutionWorkspace`, un répertoire privé, un environnement réduit et des limites de durée, de sortie et de processus.

Commande de référence :

```bash
r3con runtime run --timeout 120 outil --option valeur TARGET
```

Les arguments sont transmis sans shell implicite. Les opérateurs qui ont besoin d’un pipeline shell doivent le construire explicitement dans un environnement de laboratoire, et non contourner les contrôles de r3con.

Le réseau est désactivé ou refusé par défaut selon la capacité d’isolation de l’environnement. `--allow-network` constitue une exception de laboratoire et doit être justifiée dans le périmètre de l’audit.

### 3.3 Terminal interactif

Le terminal interactif `r3con interactive` est une interface de commande persistante. Il conserve un contexte de cible, un historique et des jobs externes associés à la session.

Commandes principales :

```text
r3con> set target ./sample.bin
r3con> run strings ./sample.bin
r3con> jobs
r3con> stop JOB_ID
r3con> show options
r3con> exit
```

Le terminal interactif actuel gère des jobs batch. Un terminal PTY temps réel sera une extension distincte. Il ne doit pas être confondu avec `runtime run`, qui capture la sortie et rend le contrôle à la console.

## 4. États et transitions

### 4.1 État d’un run analytique

Un run peut être `planned`, `running`, `ok`, `partial`, `unsupported`, `error`, `timeout` ou `cancelled`. Le statut global ne doit pas masquer les statuts individuels des tâches.

### 4.2 État d’un job externe

| État | Signification | Action opérateur |
|---|---|---|
| `running` | Le processus ou un enfant est encore actif | Observer avec `jobs` ou arrêter avec `stop` |
| `ok` | Le processus a retourné le code 0 | Examiner stdout, stderr et artefacts |
| `failed` | Le processus a retourné un code non nul | Vérifier l’outil, la cible et les permissions |
| `timeout` | La limite murale a été dépassée | Réduire le périmètre ou augmenter explicitement la limite |
| `unsupported` | L’outil requis n’est pas disponible | Installer l’outil ou utiliser le fallback |
| `cancelled` | L’opérateur a demandé l’arrêt | Conserver le résultat partiel pour traçabilité |

## 5. Politique de sécurité

r3con applique les principes suivants :

1. Une cible doit être autorisée par l’opérateur.
2. Un outil externe absent ne doit pas être remplacé silencieusement par une commande non déclarée.
3. Une commande externe doit être représentée en arguments séparés et non par concaténation non contrôlée.
4. Les secrets ne doivent jamais être copiés dans le dépôt, les rapports publics ou l’historique du terminal.
5. Les exécutables non fiables doivent être analysés dans un environnement isolé.
6. Le réseau doit rester désactivé pour les analyses locales qui n’en ont pas besoin.
7. Les résultats heuristiques, signatures, CVE et règles YARA doivent être validés par un analyste.
8. Les capacités d’exploitation et de fuzzing doivent rester limitées à des cibles de laboratoire autorisées.

## 6. Contrat des résultats

Chaque résultat doit idéalement préciser :

- la version de r3con ;
- la cible et son empreinte lorsque cela est possible ;
- le profil utilisé ;
- les outils réellement disponibles ;
- les fallbacks employés ;
- les limites appliquées ;
- le statut de chaque tâche ;
- les findings et leur provenance ;
- les incertitudes et les éléments nécessitant une revue humaine.

Un finding de sévérité `CRITICAL` ou `HIGH` n’est pas automatiquement une preuve d’exploitation. La confiance, la corroboration et l’exploitabilité doivent être examinées séparément.

## 7. Décisions d’architecture pour la suite

Les futures interfaces doivent réutiliser les services existants plutôt que lancer directement des sous-processus depuis l’interface utilisateur. Le chemin recommandé est :

```text
CLI ou interface web
        |
        v
Service de planification
        |
        v
ExecutionWorkspace / adaptateur déclaré
        |
        v
Job borné et journalisé
        |
        v
Résultat normalisé + artefacts
```

Un terminal PTY devra ajouter une séparation de permissions, un plafond de ressources, un mécanisme d’arrêt de groupe et une politique explicite de persistance. Il ne doit pas donner au terminal les privilèges du processus principal.

## Références

[1]: https://github.com/nsaagent120-droid/r3con "Dépôt officiel r3con"
[2]: https://click.palletsprojects.com/ "Documentation Click"
[3]: https://docs.python.org/3/library/subprocess.html "Documentation Python subprocess"
[4]: https://docs.python.org/3/library/resource.html "Documentation Python resource"
