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
