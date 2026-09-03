# Roadmap r3con

## Objectif de la v5.0.0

Stabiliser le contrat de résultats, fiabiliser les plugins locaux et garantir une exécution reproductible et testée. Cette version privilégie la qualité des fonctions existantes plutôt que l’ajout de nouvelles intégrations.

## Périmètre gelé

Aucune nouvelle intégration ne doit être ajoutée avant la clôture des phases 0 à 3 : CI, contrat `Finding`, pluginisation des outils historiques, puis normalisation/déduplication/corrélation.

Les extensions réseau/sandbox, Frida, QEMU, angr, libclang, MobSF, AFL++ et Semgrep restent hors périmètre fonctionnel prioritaire de ce cycle. Elles pourront être réévaluées après stabilisation.

## Phases

| Phase | Résultat attendu |
|---|---|
| 0 | CI, dépendances cohérentes et contrôles qualité automatiques. |
| 1 | Un seul contrat `Finding` versionné et testé. |
| 2 | r2/Rizin, Binwalk, Ghidra et GDB exposés comme plugins optionnels. |
| 3 | Findings normalisés, dédupliqués et corrélés par preuves indépendantes. |
| 4 | Fixtures et tests des chemins d’erreur, limites et outils absents. |
| 5 | Documentation, changelog, build propre et tag `v5.0.0`. |

Toute modification qui élargit le périmètre doit être documentée séparément et approuvée avant intégration.
