---
title: "Série — Kernel & OS"
description: "Ordonnanceur, syscalls, mémoire, drivers, Android, iOS : le noyau sans détour."
icon: material/chip
---

# 🧠 Série Kernel & OS

> Comment un système d'exploitation fonctionne **vraiment** : du syscall jusqu'à l'ordonnancement,
> de la mémoire virtuelle aux drivers. Linux d'abord, puis Windows, Android et XNU/iOS.

## Articles publiés

| # | Article | Statut |
|---|---|---|
| 1 | [L'ordonnanceur Linux, partie 1 : CFS sans douleur](../articles/2026-09-12-ordonnanceur-linux-cfs.md) | ✅ |

## Au programme (backlog)

- Le voyage d'un syscall : de `write()` à l'espace noyau
- Mémoire virtuelle : `mmap`, page fault, page cache, OOM killer
- cgroups & namespaces : le socle des conteneurs
- Écrire un driver caractère (LKM) de zéro
- eBPF : tracer le noyau en direct
- RCU et la concurrence dans le noyau
- Débugger un kernel panic : kgdb, `crash`, oops decoding
- Windows : IRQL, WDM/WDF et ce qui change vs Linux
- Android : Binder, HAL et l'architecture AOSP
- XNU/iOS : le kernel d'Apple en survol structuré

## Prérequis pour suivre

- Bases C (pointeurs, structures)
- Un Linux (VM suffisante) et l'envie de casser des choses en règle
- Pour certains articles : QEMU
