# TEMPLATE — Writeup CVE (analyse de vulnérabilité)

> Copie vers `site/docs/articles/AAAA-MM-JJ-cve-XXXX-XXXX.md`.
> ⚖️ **Charte** : CVE publiée ET corrigée uniquement · PoC pédagogique minimal · labs isolés · chercheurs d'origine crédités.

---

title: "CVE-XXXX-XXXX — <nom commun> : <résumé en 10 mots>"
series: "CVE Analysis"
date: AAAA-MM-JJ
severity: CVSS X.X
type: élévation de privilèges | RCE | divulgation | DoS | contournement
component: <composant, ex. noyau Linux/mm>
tags: [cve, kernel, ...]

---

> ⚖️ *Cet article analyse une vulnérabilité publique et corrigée, à des fins pédagogiques.
> Toute reproduction doit se faire dans un environnement de test isolé vous appartenant.*

## Carte d'identité

| Champ | Valeur |
|---|---|
| CVE | CVE-XXXX-XXXX |
| Nom usuel | (ex. Dirty COW, Heartbleed...) |
| CVSS | X.X — vecteur : `AV:...` |
| Type | race condition / UAF / overflow / ... |
| Composant | fichier/répertoire du projet |
| Versions affectées | de ... à ... |
| Corrigé le | AAAA-MM-JJ (version X) |
| Commit du fix | hash + lien |
| Découverte | par qui, comment (recherche / in the wild / fuzzing) |

## TL;DR

*3 puces : la faille en une phrase, l'impact, qui doit s'en soucier.*

## Contexte

*L'écosystème, le composant, pourquoi ce code existe. C'est ici qu'on met le lecteur « à niveau ».*

## Root cause (le cœur de l'article)

*Explication technique progressive. Un schéma aide énormément ici (chronologie du bug, états mémoire).*

## Conditions d'exploitation

- Prérequis (privilèges, configuration, architecture)
- Ce qui rend l'exploitation difficile/facile
- Facteurs d'atténuation naturels

## Reproduction pédagogique (lab isolé)

*Version minimale et commentée. Objectif : faire comprendre, pas armer.*

```c
// PoC minimal, très commenté
```

```text
$ ./poc
sortie observée...
```

## Le correctif (patch review)

```diff
--- a/fichier.c
+++ b/fichier.c
@@ ...
-    ligne supprimée
+    ligne ajoutée
```

**Ce que le patch change :** ... **Ce qu'il ne change pas / effets de bord :** ...

## Mitigations & détection

- Corriger (version) / backport / config de contournement
- Comment détecter l'exploitation (logs, IDS, indicateurs)

## Les leçons

- Pour les développeurs : ...
- Pour les defenders : ...
- Pour moi : ce que ce bug m'a appris

## Références

- Advisory officiel / NVD
- Commit du fix
- Writeup du chercheur d'origine
- Articles d'analyse tiers (bien faits)

---

*Corrigé le AAAA-MM-JJ. Une imprécision ? [Écris-moi](../a-propos.md).*
