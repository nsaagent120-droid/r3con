# Changelog r3con

## 5.0.0 — Stabilisation du contrat et des plugins

### Ajouts

- Ajout d’un contrat `Finding` v2.0 canonique avec identifiant stable, cible, outil, confiance, statut, evidence, timestamp et provenance.
- Ajout de normalisation, déduplication et corrélation des observations issues de plusieurs outils.
- Enregistrement des adaptateurs Radare2/Rizin, Ghidra, Binwalk et GDB dans le registre de plugins.
- Ajout d’une CI GitHub Actions exécutant compilation, Pytest, Pyflakes et Bandit.
- Ajout de `ROADMAP.md` pour geler le périmètre de stabilisation.

### Correctifs et optimisations

- Correction des six avertissements Pyflakes existants.
- Empreinte MD5 explicitement limitée à la compatibilité et marquée non cryptographique.
- Validation des colonnes autorisées dans les mises à jour SQL.
- Conservation de la compatibilité avec l’alias historique `finding["type"]`.
- Déduplication effectuée en une passe avec corroboration indépendante et confiance bornée.

### Vérification

- 15 tests réussis, 1 test ignoré dans l’environnement local.
- Compilation Python complète réussie.

### Durcissement final

- Ajout de tests pour les outils absents, les timeouts, les adaptateurs reverse indisponibles et les fichiers dépassant la limite configurée.
- La suite finale compte 20 tests réussis et 1 test ignoré dans l’environnement local.
- La couverture mesurée sur `core`, `modules.audit` et `modules.integration` est de 32 % ; aucun seuil artificiel de 100 % n’est imposé aux modules dépendant d’outils externes.
- Les alertes Bandit de haute sévérité sont nulles. Les alertes moyennes restantes sont documentées comme revue de sécurité non bloquante pour les appels réseau contrôlés, les sous-processus optionnels et les chemins temporaires.
