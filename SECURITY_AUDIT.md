# Audit de sécurité v5.0.1

## Résumé

L’audit local de la release v5.0.0 n’a révélé aucune alerte Bandit de haute sévérité et aucune vulnérabilité connue dans les dépendances analysées par pip-audit. Les corrections v5.0.1 traitent les alertes moyennes confirmées ou documentent les faux positifs contrôlés.

## Corrections

- Les sondes IA locales n’acceptent que des URL HTTP loopback (`localhost`, `127.0.0.1`, `::1`).
- La mise à jour SQL conserve une liste blanche de colonnes et des valeurs paramétrées.
- Les scripts GDB générés sont privés (`0600`) au lieu d’être exécutables par tous.
- Les campagnes AFL utilisent un répertoire temporaire privé créé par `tempfile` lorsqu’aucun dossier n’est fourni.
- Les chemins `/tmp`, `/proc` et `/var/run` du module firmware sont des motifs recherchés dans l’image analysée, pas des fichiers temporaires utilisés par r3con.
- Les appels OSV et NVD sont limités à des endpoints HTTPS codés et contrôlés.

## Limites

Les alertes Bandit de faible sévérité liées à l’usage légitime de sous-processus restent visibles en audit, car r3con exécute des outils locaux optionnels avec des listes d’arguments et des timeouts. Les résultats d’analyse de sécurité doivent toujours être validés dans le contexte de la cible.

---

# Addendum v7.3 — Modèle de sécurité des nouvelles fonctions

## Runner dynamique isolé (`modules/dynamic/sandboxed_runner.py`)

- Aucune exécution automatique : la CLI `r3con dynamic sandbox` affiche un **plan**
  par défaut ; l'exécution réelle exige `--execute`.
- Réseau désactivé par défaut, avec isolation réelle (`unshare -n`) testée avant
  l'exécution. Si le noyau/hôte ne permet pas cette isolation, l'exécution est
  **refusée** (status `network_isolation_unavailable`) sauf si l'opérateur pose
  explicitement `--lenient-network` — le refus n'est jamais silencieux.
- Répertoire de travail temporaire privé (`0700`, `tempfile`),variables d'environnement non propagées
  (liste blanche PATH/LANG/LC_ALL/TERM + HOME/TMPDIR redirigés), limites RLIMIT
  (CPU, mémoire, nombre de processus, taille de fichier), timeout mural avec
  suppression de l'arbre de processus, captures tronquées (1 Mo).
- Les crashs observés deviennent des findings `observation`/`exploitability:
  unknown` : un crash n'est jamais présenté comme une exploitabilité prouvée.
- Ce module ne lance que le binaire local fourni par l'opérateur. Aucune action
  offensive distante, même en option.

## Supply chain (`modules/supply_chain/`)

- Analyse strictement locale : lecture des manifestes/lockfiles du projet, aucune
  requête réseau, aucun import de client HTTP dans le module ; `--offline` n'est
  donc pas un mode dégradé mais le comportement par défaut.
- La base d'avis par défaut est un jeu d'amorces intégré (exemples vérifiables).
  Pour une couverture réelle, fournir `--policy` (JSON/YAML local, par exemple un
  export OSV/VEX hors ligne). Les correspondances de versions sont heuristiques :
  les findings sont marqués `hypothesis` avec confiance bornée et doivent être
  confirmés contre une source d'avis à jour.
- Les findings « secrets » réutilisent le scanner local ; aucun contenu de secret
  complet n'est écrit dans les rapports (extraits bornés par le scanner).

## Explication et IA (`core/explainer.py`)

- `explain`/`summarize`/`ask` ne lisent QUE le rapport fourni : aucune ré-analyse
  de fichiers arbitraires, aucun réseau.
- Chaque réponse comporte `citations` (preuves du rapport) et `uncertainty`
  (statut, confiance, fallback, corroboration, exploitabilité). Une hypothèse
  n'est jamais mise en avant comme une confirmation.
- `--ai` est une couche optionnelle de commentaire ; sans fournisseur configuré,
  la commande réussit et indique le motif. Le texte IA est étiqueté « ne
  constitue pas une preuve ». Aucun contenu de cible n'est envoyé — seuls les
  champs déjà présents dans le rapport.

## Différentiel, cache et reprise

- `compare`/`reports compare` travaillent sur des fichiers locaux et n'écrivent
  que dans les chemins explicitement demandés ; aucune transmission.
- Le cache de tâches (`TaskCache`) est un stockage disque local versionné ; il
  ne peut contenir que des résultats d'analyse (max 2 Mo/entrée), jamais de
  contenu fichier arbitraire ; la clé dépend du hash de cible, du profil, de la
  configuration et des versions d'outils.
- La reprise (`--resume`) relit les artefacts JSON du run antérieur ; un
  artefact corrompu ou illisible est ignoré, pas exécuté à l'aveugle.

## Limites restantes (honnêtes)

- La détection de vulnérabilités supply-chain sans base d'avis fraîche est
  partielle par conception (mode hors ligne).
- Les limites mémoire RLIMIT (`RLIMIT_AS`) sont approximatives pour les runtime
  qui réservent beaucoup de mémoire virtuelle (recommander `--mem-mb` large ou
  un conteneur pour ces cas).
- `strace` n'est pas disponible partout : la capture de syscalls reste
  optionnelle et signalée comme fallback.
- Les heuristiques de détection de types de cible peuvent se tromper sur des
  images rares ; le plan explicable permet à l'analyste de vérifier avant
  exécution (`--plan-only`).
