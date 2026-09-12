# TEMPLATE — Article Kernel & OS

> Copie ce fichier vers `site/docs/articles/AAAA-MM-JJ-titre.md` et remplis chaque section.
> Règle d'or : **rien n'est affirmé sans avoir été testé dans le lab.**

---

title: "<Titre court et précis>"
series: "Kernel & OS"
part: 1                # numéro dans la série (0 = standalone)
date: AAAA-MM-JJ
reading_time: ~X min
level: débutant | intermédiaire | avancé
tags: [linux, kernel, ...]

---

## TL;DR

*3 à 5 puces : ce que le lecteur saura faire à la fin. Pas de mystère.*

## Pourquoi ce sujet

*Le problème concret que ça résout (ou la question qui m'a amené là). 5 lignes max.*

## Prérequis & lab

*Environnement utilisé + comment le reproduire :*

```bash
# environnement reproductible (version kernel, VM/QEMU, paquets...)
uname -r
```

## Les concepts (l'explication)

*Ta pédagogie : analogies, schémas, définitions. Un concept = une idée = un paragraphe.*

- Terme 1 : ...
- Terme 2 : ...

## Dans le code / sous le capot

*La partie « je montre les tripes » : structures du noyau, extraits de code commentés.*

```c
/* extrait commenté — cite la version exacte du kernel / fichier */
```

## Démo pas-à-pas (le lab)

*Commandes + sorties réelles (tronquées si besoin) + interprétation de chaque résultat.*

```bash
$ commande --exemple
sortie...
```

**Lecture de la sortie :** ...

## Les pièges classiques

- Piège 1 : ...
- Piège 2 : ...

## Pour aller plus loin

- Source officielle (docs kernel.org, commit git, LWN...)
- Livre/talk
- L'article suivant de la série : [lien]

---

*Corrigé le AAAA-MM-JJ. Une erreur ? Une question ? [Contacte-moi](../a-propos.md).*
