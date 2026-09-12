---
title: "Série — Protocoles IoT"
description: "MQTT, CoAP, Zigbee, BLE, LoRaWAN, Matter : trames, mécanismes et sécurité."
icon: material/access-point-network
---

# 📡 Série Protocoles IoT

> Les langages que parlent les objets connectés. Pour chaque protocole : sa place dans la pile,
> le **format des trames sur le fil**, les mécanismes clés, la sécurité — et un lab capturé.

## Articles publiés

| # | Article | Statut |
|---|---|---|
| 1 | [MQTT pour l'embarqué : le protocole qui fait parler les objets](../articles/2026-09-12-mqtt-pour-embarque.md) | ✅ |

## Au programme (backlog)

- CoAP vs MQTT : quand choisir quoi (captures Wireshark)
- BLE/GATT : profils, services, caractéristiques — et outils BlueZ
- Zigbee : le maillage 802.15.4, la formation de réseau, la sécurité
- LoRaWAN : classes A/B/C, activation OTAA/ABP, limites du duty cycle
- Matter/Thread : la nouvelle stack unifiée
- MQTT 5.0 : ce que 3.1.1 ne savait pas faire
- DTLS et le provisionnement des clés en IoT
- MQTT-SN : MQTT sans TCP pour les nœuds contraints

## Prérequis pour suivre

- Bases réseau (TCP/UDP, ports, TLS)
- Outils : Wireshark, mosquitto-clients, un dongle BLE/Zigbee si on veut toucher au radio
