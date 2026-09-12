---
title: "L'ordonnanceur Linux, partie 1 : CFS sans douleur"
description: "Comprendre le Completely Fair Scheduler : vruntime, arbre rouge-noir, nice, classes temps réel — avec démos."
series: "Kernel & OS"
part: 1
date: 2026-09-12
reading_time: "~12 min"
level: intermédiaire
tags: [linux, kernel, scheduler, cfs]
---

## TL;DR

- CFS (Completely Fair Scheduler) ordonnance les tâches « normales » en visant une **équité proportionnelle** aux poids (`nice`), pas un simple tour de rôle.
- L'arme centrale : le **`vruntime`** (temps CPU virtuel, pondéré) et un **arbre rouge-noir** toujours trié — la prochaine tâche est toujours le nœud le plus à gauche.
- Au-dessus de CFS : les classes temps réel (`SCHED_FIFO`, `SCHED_RR`) et `SCHED_DEADLINE` passent **toujours** avant.
- À la fin, tu sauras *observer* l'ordonnanceur sur ta machine et prédire qui prend le CPU et pourquoi.

## Pourquoi ce sujet

Qui obtient le CPU, quand, et pendant combien de temps — c'est LA question de l'ordonnanceur. Sur un système embarqué ou un serveur, mal configurer les priorités, c'est des latences qui explosent, des watchdogs qui mordent, des capteurs qui perdent des échantillons. Et depuis le kernel **6.6**, CFS a été remplacé par **EEVDF** dans le noyau principal : impossible de bien comprendre EEVDF sans avoir compris CFS (c'est le sujet de la partie 2).

## Prérequis & lab

Tout se fait sur une machine Linux classique (VM suffisante), kernel ≥ 5.x :

```bash
$ uname -r
6.1.0-13-amd64
$ sudo apt install linux-perf procps   # outils d'observation
```

## Les concepts

### 1. L'idée : un « CPU idéal parfaitement équitable »

Imagine *N* tâches sur un CPU qui les exécuterait toutes **simultanément**, chacune à 1/N (pondéré par la priorité). CFS modélise ce CPU parfait et essaie de s'en approcher. La question devient : *quelle tâche est la plus « en retard » sur son dû ?* → c'est elle qui tourne.

### 2. `vruntime` : le temps pondéré

Chaque tâche accumule un **temps virtuel** (`vruntime`, champ de `struct sched_entity`) : le temps réel CPU qu'elle a consommé, **divisé par son poids** (le poids vient du `nice`) :

```text
vruntime += Δt réel × (poids par défaut / poids de la tâche)
```

- `nice 0` = poids neutre (1024) → `vruntime` avance comme le temps réel.
- `nice 5` = poids plus faible (~335) → son `vruntime` avance ~3× plus vite → elle est « punie ».
- `nice -5` = poids plus fort (~3121) → son `vruntime` avance ~3× moins vite → privilégiée.

Le facteur entre deux `nice` consécutifs est ~**1,25** (choix empirique : +1 nice ≈ +10 % de CPU relatif).

### 3. L'arbre rouge-noir : le plus en retard toujours à gauche

Les tâches prêtes (`runqueue` de chaque CPU) sont dans un arbre rouge-noir indexé par `vruntime`. Choisir la prochaine tâche = prendre le **nœud le plus à gauche** (`rb_leftmost`) — un O(1) grâce à un cache du leftmost. Insérer sa tâche après exécution = O(log n). Élégant et efficace.

### 4. `sched_latency` et la granularité

CFS ne change pas de tâche toutes les 10 ms « comme ça » : il vise à ce que toutes les tâches prêtes tournent au moins une fois par fenêtre de **`sched_latency`** (~6 ms par défaut, en fait `sysctl_sched_latency`, ajusté au nombre de tâches). Mais changer de contexte coûte cher : chaque tranche respecte une **granularité minimale** (`sysctl_sched_min_granularity`, ~0,75 ms) pour éviter le « thrashing » de commutations.

### 5. Les classes : qui passe avant qui

Chaque CPU a une runqueue avec une **hiérarchie de classes** — du plus prioritaire au dernier :

```text
stop  →  deadline (SCHED_DEADLINE)  →  rt (FIFO / RR)  →  fair (CFS/EEVDF)  →  idle
```

Une classe n'est consultée que si celle du dessus n'a rien à offrir. Deux tâches CFS se partagent le CPU en équité ; une tâche temps réel, elles, prennent tout (d'où les précautions `rt_throttled`, sujet d'un futur article).

## Dans le code

Extrait simplifié du cœur du picking (kernel 5.x, `kernel/sched/fair.c`) :

```c
/* kernel/sched/fair.c — simplifié */
static struct sched_entity *
pick_next_entity(struct cfs_rq *cfs_rq)
{
    struct sched_entity *left = __pick_first_entity(cfs_rq); /* leftmost du RB-tree */
    /* ... vérifications de granularité/wakeup ... */
    return left;   /* le plus en retard tourne */
}
```

Et la mise à jour du temps virtuel (`update_curr`) :

```c
/* delta_exec = temps réel consommé depuis la dernière mise à jour */
curr->vruntime += calc_delta_fair(delta_exec, curr);
```

`calc_delta_fair` fait exactement la pondération « diviser par le poids » décrite plus haut.

## Démo pas-à-pas

### A. Voir l'équité pondérée

Deux processus qui bouffent du CPU, l'un `nice 0`, l'autre `nice 10` :

```bash
$ nice -n 0  bash -c 'while :; do :; done' & pid1=$!
$ nice -n 10 bash -c 'while :; do :; done' & pid2=$!
$ sleep 5; top -b -n1 -p $pid1,$pid2 | tail -2
  PID USER      PR  NI    VIRT    RES  %CPU
 1234 moi       20   0    ...         89.7
 1235 moi       30  10    ...         10.3
```

**Lecture :** ~90 % / ~10 %. Or le facteur 1,25 par palier, sur 10 paliers, donne un ratio ~×8,2 — c'est exactement ce qu'on observe. L'équité proportionnelle en action.

### B. Observer le `vruntime`

```bash
$ cat /proc/$pid2/sched | egrep 'vruntime|prio'
se.vruntime                   :    482113.471920
prio                          :        110        # nice 10 → prio 110 (nice 0 → 120)
```

Le champ `se.vruntime` de `/proc/<pid>/sched` (kernel debug-friendly) montre le compteur virtuel de l'entité. Compare-le entre les deux processus : le puni avance plus vite.

### C. Les temps réels passent devant

```bash
$ chrt -f 50 bash -c 'while :; do :; done' &   # SCHED_FIFO prio 50
$ # le système reste réactif ? seulement grâce au throttling RT (95 % par défaut),
$ # sinon les tâches CFS n'auraient plus jamais le CPU.
```

**Piège classique :** un processus `SCHED_FIFO` qui boucle peut **geler** tous les cœurs. Le paramètre `kernel.sched_rt_runtime_us` (-1 = désactivé !) limite par défaut les RT à 950 ms par seconde.

## Les pièges classiques

- Croire que `nice` sert à « rendre réactif » : `nice` ne change **que** le poids CFS. Pour la latence, c'est le domaine des classes RT/deadline.
- Croire que l'ordonnanceur « alloue des % » : CFS ne planifie pas des quotas, il choisit le plus en retard à chaque commutation. Les quotas, c'est cgroup CPU (autre mécanisme).
- Oublier que chaque CPU a SA runqueue : les équilibres entre cœurs (load balancing) compliquent les mesures mono-cœur vs multi-cœurs.

## Pour aller plus loin

- [Docs noyau : sched-stats, sched-deadline](https://www.kernel.org/doc/html/latest/scheduler/index.html)
- *Systems Performance* (B. Gregg), chapitre scheduler
- L'article suivant de la série : *Le voyage d'un syscall* (à venir)

---

*Corrigé le 12 septembre 2026. Une erreur ? [Écris-moi](../a-propos.md).*
