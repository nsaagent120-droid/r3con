# r3con 4.3.0 — Architecture d’intégration

## Objectif

r3con orchestre des outils spécialisés locaux. Il ne cherche pas à remplacer Ghidra, radare2, Semgrep, YARA, Binwalk, MobSF, GDB ou angr. Chaque outil est branché par un adaptateur indépendant et ses résultats restent identifiés par leur provenance.

## Commandes

```bash
r3con plugins list
r3con plugins run ./cible.bin
r3con plugins run ./cible.bin --plugin file --plugin strings --output ./runs
```

Aucun plugin n’installe automatiquement une dépendance. Un outil absent est retourné avec le statut `skipped`. Les commandes sont exécutées avec une liste d’arguments sans shell implicite, et un délai maximal est appliqué.

## Contrat de résultat

Le module `core.plugin_system` fournit `PluginSpec`, `CommandPlugin`, `PluginRegistry` et `Finding`. Un adaptateur doit déclarer son exécutable, ses capacités, son éventuel accès réseau et produire une sortie avec statut, code retour, sortie brute et provenance.

Le fichier JSON sauvegardé dans `r3con-runs/` permet de reproduire l’analyse et de rattacher les observations à l’outil exact. Les résultats externes, heuristiques ou générés par IA doivent conserver leur statut `needs-review` tant qu’un chercheur ne les a pas confirmés.

## Ajouter un adaptateur

```python
from core.plugin_system import CommandPlugin, PluginSpec

plugin = CommandPlugin(
    PluginSpec("mon-outil", "Analyse locale", "mon-outil", ["custom"], network=False),
    lambda target: ["mon-outil", "--json", target],
)
```

L’adaptateur ne doit jamais accepter une commande arbitraire construite depuis une chaîne utilisateur. Il doit utiliser une liste d’arguments fixe et valider la cible comme fichier local.
