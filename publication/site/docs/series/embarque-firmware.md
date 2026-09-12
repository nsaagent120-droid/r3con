---
title: "Série — Embarqué & Firmware"
description: "Boot, device tree, drivers, RTOS, extraction de firmware : du SoC au service."
icon: material/memory
---

# 🔧 Série Embarqué & Firmware

> Du silicium au service : comment un objet devient une machine. Boot chain, device tree,
> drivers de périphériques, RTOS, et l'art d'analyser un firmware binaire.

## Articles publiés

| # | Article | Statut |
|---|---|---|
| — | *premier article à venir* | 🚧 |

## Au programme (backlog)

- La chaîne de boot d'un SoC ARM : ROM → SPL → U-Boot → kernel (démo QEMU)
- Le device tree expliqué par l'exemple
- Écrire un driver Linux pour un capteur I2C
- GPIO, SPI, I2C : les trois bus à connaître (avec un Raspberry Pi)
- Yocto vs Buildroot : construire sa distro embarquée
- Zephyr & FreeRTOS : premier RTOS pas-à-pas
- Extraire et analyser un firmware (binwalk, UART, SPI)
- Secure boot & OTA : chaîner la confiance
- ELF sous la loupe : sections, symboles, entropie
- JTAG/SWD : déboguer au niveau matériel

## Prérequis pour suivre

- Notions de C et de ligne de commande Linux
- Matériel conseillé (mais QEMU suffit pour beaucoup d'articles) : Raspberry Pi, STM32 (Blue Pill/Nucleo), ESP32, adaptateur USB-UART
