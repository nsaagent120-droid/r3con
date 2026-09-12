# TEMPLATE — Embarqué & Firmware / Driver

> Copie vers `site/docs/articles/AAAA-MM-JJ-titre.md`.
> Spécificité : **matériel et versions exacts** en tête, sinon l'article n'est pas reproductible.

---

title: "<Titre>"
series: "Embarqué & Firmware"
date: AAAA-MM-JJ
target: "Raspberry Pi 4 / STM32F4 / ESP32 / QEMU virt ARM64"
level: ...
tags: [embarque, firmware, arm, ...]

---

## TL;DR

*Ce que le lecteur saura reproduire à la fin.*

## Matériel & environnement

| Élément | Version/réf |
|---|---|
| Cible | ex. QEMU 8.x `virt` ARM64 / RPi 4B 4Go |
| Toolchain | `aarch64-none-elf-gcc 13.x` / `arm-none-eabi-...` |
| Hôte de dev | Linux distro + version |
| Sources | liens (U-Boot X, kernel Y, Zephyr Z) |

## Vue d'ensemble (le schéma mental)

*Où ce morceau se situe dans la chaîne : boot ? driver ? protocole ? Un schéma ASCII vaut de l'or :*

```text
ROM → SPL → U-Boot → noyau → rootfs
         ↑ on est ici
```

## Théorie express

*Ce qu'il faut comprendre avant de brancher quoi que ce soit.*

## Mise en pratique pas-à-pas

```bash
# 1. ...
# 2. ...
```

*Interprétation : chaque commande, pourquoi elle est là, ce qu'on doit observer
(sortie série, LED, trace GDB...).*

## Le code décortiqué

```c
/* driver/exemple.c — commenté ligne par ligne */
```

*Points clés : cycle de vie (probe/remove), registres, interruptions, DMA, sémantique sleep/atomic...*

## Debug & pièges rencontrés

| Symptôme | Cause | Solution |
|---|---|---|
| `...` | `...` | `...` |

## Téléchargements / repo

*Repo du lab (code complet), binaires, captures.*

## Pour aller plus loin

- Docs officielles (datasheet, TRM, docs.kernel.org)
- Article suivant de la série

---

*Une erreur ? Une carte à suggérer ? [Contacte-moi](../a-propos.md).*
