---
title: Carnet Système — embarqué, kernel, CVE & IoT
description: Recherche en public sur les systèmes embarqués, les noyaux, les CVE et les protocoles IoT.
hide:
  - navigation
---

<div class="hero" align="center">

# 🔬 Carnet Système

**Je documente mes recherches sur les systèmes embarqués, les noyaux, les CVE et les protocoles IoT.**
*Un article par semaine, en français, tout testé dans mon lab avant publication.*

![Bannière](assets/banniere.png)

[**Commencer par la série Kernel**](series/kernel-os.md){ .md-button .md-button--primary }
[**Découvrir mon lab**](a-propos.md){ .md-button }

</div>

---

## 📚 Les 4 séries

<div class="grid cards" markdown>

- :material-chip:{ .lg .middle } **Kernel & OS**

    ---

    Ordonnanceur, syscalls, mémoire, drivers Linux & Windows, Android (Binder/HAL), XNU/iOS, eBPF, debugging kernel.

    [:arrow-right: Lire la série](series/kernel-os.md)

- :memory:{ .lg .middle } **Embarqué & Firmware**

    ---

    Chaîne de boot, device tree, drivers GPIO/I2C/SPI, RTOS, extraction de firmware, secure boot.

    [:arrow-right: Lire la série](series/embarque-firmware.md)

- :material-bug:{ .lg .middle } **CVE Analysis**

    ---

    Anatomie de vulnérabilités publiées et corrigées : root cause → exploitabilité → patch → leçons.

    [:arrow-right: Lire la série](series/cve-analysis.md)

- :material-access-point-network:{ .lg .middle } **Protocoles IoT**

    ---

    MQTT, CoAP, Zigbee, BLE, LoRaWAN, Matter : format des trames, mécanismes, sécurité, labs capturés.

    [:arrow-right: Lire la série](series/protocoles-iot.md)

</div>

---

## 🆕 Derniers articles

| Date | Article | Série |
|---|---|---|
| 12 sept. 2026 | [Dirty COW (CVE-2016-5195) : anatomie d'une course de 9 ans](articles/2026-09-12-dirty-cow-cve-2016-5195.md) | CVE Analysis |
| 12 sept. 2026 | [L'ordonnanceur Linux, partie 1 : CFS sans douleur](articles/2026-09-12-ordonnanceur-linux-cfs.md) | Kernel & OS |
| 12 sept. 2026 | [MQTT pour l'embarqué : le protocole qui fait parler les objets](articles/2026-09-12-mqtt-pour-embarque.md) | Protocoles IoT |

---

## 🧪 Ma méthode en trois règles

1. **Tester avant d'écrire** : chaque commande de mes articles a été exécutée dans mon lab (QEMU, Raspberry Pi, VM isolées).
2. **Citer ses sources** : commits, advisories, specs officielles — toujours.
3. **Publier imparfait mais régulier** : 1 article/semaine. La régularité bat la perfection.

??? note "Réutiliser mes contenus"

    Les articles sont sous licence **CC BY-SA 4.0** : tu peux les partager et les adapter,
    à condition de me créditer et de repartager à l'identique. Le code d'exemple : MIT.
