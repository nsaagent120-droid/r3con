---
title: À propos
description: Qui écrit le Carnet Système, avec quelle méthode et quelle éthique.
icon: material/account-circle
---

# 👋 À propos

## Moi

Ingénieur passionné par le **bas niveau** : systèmes d'exploitation, embarqué, et sécurité.
Le Carnet Système est mon carnet de recherche public — j'y documente ce que j'étudie,
en français, avec la ferme intention que chaque affirmation soit vérifiable.

- 💼 LinkedIn : [linkedin.com/in/&lt;ton-pseudo&gt;](https://www.linkedin.com/in/<ton-pseudo>/)
- 💻 GitHub : [github.com/&lt;ton-pseudo&gt;](https://github.com/<ton-pseudo>)
- ✉️ `<ton.email@exemple.com>`

## Mon lab

| Outil | Usage |
|---|---|
| QEMU (x86_64, ARM64) | kernels custom, boot chain, debug GDB |
| Raspberry Pi / STM32 / ESP32 | cibles réelles : drivers, bus, RTOS |
| VM isolées | labs CVE (jamais de test sur des systèmes de prod) |
| Ghidra, binwalk, Frida | analyse binaire & firmware |
| Wireshark, mosquitto | capture et manipulation des protocoles IoT |

## Méthode éditoriale

1. **Tester d'abord** : je n'écris que ce que j'ai exécuté et observé.
2. **Citer** : versions exactes, commits, specs, advisories officiels.
3. **Corriger en public** : une erreur signalée est corrigée avec une note de changement en bas de l'article.

## Éthique

- Les analyses de vulnérabilités portent sur des CVE **publiées et corrigées**.
- Les PoC présentés sont **pédagogiques** : minimisés, commentés, pas exploitables tels quels.
- Tous les tests se font sur **mon matériel et mes VM isolées**.
- Si je découvre un jour une faille : **responsible disclosure** d'abord, article après le correctif.

## Réutilisation

- Textes : licence [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.fr)
- Code d'exemple : MIT (sauf indication contraire dans le repo)
