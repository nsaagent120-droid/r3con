# r3con v5.0.2

## Interface CLI

- Palette sémantique harmonisée pour les thèmes `cyber`, `matrix`, `amber` et `mono`.
- Utilisation cohérente des styles pour les titres, bordures, messages, statuts et findings.
- Ajout de `--no-color` et de `R3CON_NO_COLOR=1` pour les logs, CI et terminaux accessibles.
- Fallback automatique vers le thème `cyber` en cas de thème inconnu.
- Désactivation automatique des animations hors terminal interactif, en CI ou avec `R3CON_NO_ANIMATION=1`.
- Ajout de tests de régression pour les thèmes et le mode monochrome.
