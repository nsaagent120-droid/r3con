# 🎯 Plan de carrière — « Carnet Système »

> Document de stratégie personnelle. Objectif : devenir **référence francophone en systèmes embarqués / kernel / sécurité**, et transformer la publication régulière en opportunités professionnelles.

---

## 1. Vision (pourquoi)

1. **Forcer la maîtrise** : on ne maîtrise vraiment que ce qu'on sait expliquer (effet Feynman).
2. **Preuve de compétence** : un corpus public, régulier et technique vaut plus qu'un CV pour les recruteurs de métiers système/sécurité.
3. **Réseau** : chaque article est une porte d'entrée (commentaires, corrections, collaborations).

## 2. Les 4 séries (la « liste très longue », structurée)

| # | Série | Sous-thèmes (backlog) |
|---|---|---|
| 1 | 🧠 **Kernel & OS** | syscalls & glibc · CFS → EEVDF · gestion mémoire (mmap, page cache, OOM) · cgroups & namespaces · eBPF · drivers Linux (LKM, char/block) · Windows kernel (IRQL, WDM/WDF) · Android (Binder, HAL, AOSP build) · XNU/iOS · verrous & RCU · oops/panic/debugging (kgdb, crash) |
| 2 | 🔧 **Embarqué & Firmware** | chaîne de boot (ROM → SPL → U-Boot → kernel) · device tree · Yocto & Buildroot · RTOS (Zephyr, FreeRTOS) · extraction firmware (binwalk, UART/JTAG/SPI) · drivers GPIO/I2C/SPI · OTA & secure boot · analyse binaire (ELF, entropie) · anti-GLivet début |
| 3 | 🕵️ **CVE Analysis** | un writeup = carte d'identité + root cause + conditions + lab + patch diff + leçons. Cibles : kernel Linux, Android, firmware IoT, librairies C (memcorrupt), désérialisation, use-after-free, races |
| 4 | 📡 **Protocoles IoT** | MQTT · MQTT-SN · CoAP · AMQP · Zigbee · BLE (GATT) · LoRaWAN · Matter/Thread · NB-IoT · sécurité : TLS/DTLS, mTLS, provisionnement, attaques classiques |

## 3. Cadence hebdomadaire (le contrat que je me fixe)

- **1 article complet / semaine** (~1500–2500 mots) — jour fixe, ex. jeudi soir.
- **+ 1 mini-fiche optionnelle** (500 mots, format [fiche de lecture](templates/TEMPLATE_FICHE_LECTURE.md)) si la semaine est légère.
- **Règle anti-abandon** : un article « bon » publié vaut mieux qu'un article « parfait » jamais fini. Timebox rédaction : **3 h max** après le lab.
- **Règle qualité** : rien n'est publié sans avoir été **testé dans le lab** (commandes exécutées, captures, résultats).

### Rotation conseillée sur 4 semaines
`Kernel` → `CVE` → `Embarqué` → `IoT` → (recommence)
*(Ça évite de s'enliser dans une seule série et ça couvre tout le profil.)*

## 4. Pipeline éditorial (le rituel)

```
IDÉE → LAB → BROUILLON → REVUE → PUBLICATION → ANNONCE
```

| Étape | Ce qu'on fait | Temps cible |
|---|---|---|
| **Idée** | piocher dans le backlog de série, écrire le titre + le TL;DR promis | 15 min |
| **Lab** | reproduire/tester : VM, QEMU, carte, capture réseau, PoC éducatif | 1–3 h |
| **Brouillon** | remplir le template, ajouter code/captures/schémas | 2–3 h |
| **Revue** | relire à voix haute, vérifier chaque commande, corriger les affirmations non sourcées | 30 min |
| **Publication** | commit + push (déploiement auto) + mise à jour série/profil | 15 min |
| **Annonce** | post LinkedIn/X : 2 lignes de hook + lien | 15 min |

## 5. Plan sur 12 semaines (premier trimestre)

| Sem. | Série | Sujet |
|---|---|---|
| 1 | CVE | ✅ Dirty COW (CVE-2016-5195) — *déjà rédigé* |
| 1 | Kernel | ✅ Ordonnanceur Linux pt.1 : CFS — *déjà rédigé* |
| 1 | IoT | ✅ MQTT pour l'embarqué — *déjà rédigé* |
| 2 | Embarqué | La chaîne de boot d'un SoC ARM (ROM → U-Boot → kernel), démo QEMU |
| 3 | Kernel | Le voyage d'un syscall : de `write()` à l'espace noyau |
| 4 | CVE | CVE « facile » récent sur firmware IoT + fiche méthode |
| 5 | IoT | CoAP vs MQTT : quand choisir quoi (avec captures Wireshark) |
| 6 | Embarqué | Le device tree expliqué à coups d'exemples |
| 7 | Kernel | Écrire un driver caractère (LKM) de zéro |
| 8 | CVE | Use-after-free dans le noyau : mécanique + 1 cas réel |
| 9 | IoT | BLE/GATT : structure, outils (BlueZ), pièges de sécurité |
| 10 | Embarqué | Extraire et analyser un firmware (binwalk + UART) |
| 11 | Kernel | eBPF : tracer le noyau en direct |
| 12 | Bilan | Rétrospective + roadmap T2 (d'après les retours) |

## 6. Jalons & indicateurs (mesurer sans s'observer chaque jour)

| Horizon | Jalon |
|---|---|
| 30 jours | Site en ligne + 4–6 articles + profil GitHub finalisé |
| 90 jours | 12+ articles, 4 séries vivantes, premiers commentaires/échanges |
| 6 mois | 25+ articles, 1 article « phare » long format (ex. : analyser un firmware complet de A à Z) |
| 12 mois | Référence identifiable du domaine FR, liens dans le CV/LinkedIn, conférences/MEETUP ou CTF |

**KPI utiles** : régularité (articles/mois tenus), temps de rédaction moyen, sources d'erreur corrigées par les lecteurs,DM LinkedIn entrants. **KPI inutiles à court terme** : étoiles, vues.

## 7. Charte éthique (non négociable)

1. Uniquement des CVE **publiées, corrigées** (patch disponible) — pas de 0-day, pas de divulgation prématurée.
2. PoC **pédagogiques** : minimal, commenté, jamais un exploit clé en main ; mention légale en tête d'article.
3. Jamais de cible réelle : labs isolés (VM, QEMU, matériel à soi).
4. Créditer les chercheurs d'origine et citer les sources officielles (advisories, commits, NVD).
5. Responsable disclosure si je découvre quelque chose : rapport au fournisseur d'abord, article après le fix.

## 8. Où prendre les sujets (veille)

- **Kernel** : LWN.net, kernel.org (git log de stable), Phoronix
- **CVE** : NVD, exploit-db, Google Project Zero blog, GR Security archives publiques, advisories constructeurs (Android Security Bulletin, MSRC, Apple)
- **Embarqué/IoT** : Hackaday, Zeal's/« Firmware Security » notes, les conf EMF/CCC, GitHub trending embarqué
- **Communauté** : r/kernel, r/ReverseEngineering, r/embedded, Discord/Matrix OSDI
