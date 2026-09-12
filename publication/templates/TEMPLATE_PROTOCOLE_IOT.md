# TEMPLATE — Protocole IoT

> Copie vers `site/docs/articles/AAAA-MM-JJ-titre.md`.
> Angle imposé : **format des trames + sécurité + lab capturé**, pas juste la théorie.

---

title: "<PROTOCOLE> pour l'embarqué : <angle>"
series: "Protocoles IoT"
date: AAAA-MM-JJ
level: ...
tags: [iot, protocole, ...]

---

## TL;DR

*À quoi sert ce protocole, quand l'utiliser, quand l'éviter.*

## Sa place dans la pile

```text
Application  ← CE PROTOCOLE
Transport    (TCP / UDP)
Réseau       (IPv4/6, 6LoWPAN...)
Liaison      (Wi-Fi, 802.15.4, BLE...)
```

*Contraintes visées : latence, débit, empreinte mémoire, batterie, fiabilité.*

## Modèle de communication

*Pub/sub ? client/serveur ? requête/réponse ? Qui parle à qui. Schéma.*

## Format des messages (sur le fil)

*Détaille binaire/structure réelle — c'est ça qui différencie ton article d'un tuto de base :*

```text
octets :  0        1        2        3
      +--------+--------+--------+...
      | champ  | type   | long.  |  payload...
```

| Champ | Taille | Rôle |
|---|---|---|
| ... | ... | ... |

## Les mécanismes clés

- Mécanisme 1 (ex. QoS, sessions, découvertes...) : comment ça marche VRAIMENT
- Mécanisme 2 : ...
- Différences entre versions du protocole si pertinent

## Sécurité

| Menace | Contre-mesure dans le protocole | Ce qu'il reste à faire côté dev |
|---|---|---|
| écoute | TLS/DTLS | gestion des certificats |
| usurpation | auth | stockage des secrets |
| injection | ... | validation côté broker/serveur |

**Les erreurs qu'on voit sur le terrain :** brokers ouverts, TLS désactivé « pour tester » resté en prod, topics prévisibles, secrets en dur...

## Lab : observer et manipuler

```bash
# installation
# capture (tcpdump/Wireshark — filtre...)
# publier/souscrire/injecter une trame
```

*Capture annotée + ce qu'on y voit octet par octet.*

## Comparaison rapide

| | <PROTOCOLE> | Alternative A | Alternative B |
|---|---|---|---|
| Transport | | | |
| Empreinte | | | |
| QoS/fiabilité | | | |
| Écosystème | | | |

## Implémentations de référence

- Clients embarqués : ...
- Brokers/serveurs : ...
- Outils de test : ...

## Pour aller plus loin

- Spec officielle (RFC/standard)
- Article suivant de la série

---

*Une question ? Une capture à partager ? [Contacte-moi](../a-propos.md).*
