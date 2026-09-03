# r3con v4.3.0 — Architecture en Couches

## Concept

```
┌─────────────────────────────────────────────────────────────┐
│  Couche 4 : AI Enhancement          (OPTIONNEL)             │
│  Cloud APIs ou IA locale ou Multi-AI                        │
│  → Pseudo-code, analyses sémantiques, hypothèses 0day       │
│                                                             │
│  Config: export TOGETHER_API_KEY=... (ou autre provider)    │
│          ou: ollama serve (IA locale gratuite)              │
└─────────────────────────────────────────────────────────────┘
                          ↑ enrichit
┌─────────────────────────────────────────────────────────────┐
│  Couche 3 : Intelligence            (OPTIONNEL)             │
│  Expert System + Knowledge Base + CVSS Scoring              │
│  → CWE/CVSS, scénarios d'attaque, recommandations           │
│                                                             │
│  Config: export R3CON_EXPERT_MODE=true                      │
└─────────────────────────────────────────────────────────────┘
                          ↑ enrichit
┌─────────────────────────────────────────────────────────────┐
│  Couche 2 : Analysis Core           (TOUJOURS ACTIF)        │
│  Audit, Heap, Crypto, Kernel, APK, Firmware, Taint         │
│  → L'outil est déjà COMPLET et PUISSANT ici                 │
│                                                             │
│  Config: rien — fonctionne automatiquement                  │
└─────────────────────────────────────────────────────────────┘
                          ↑ base
┌─────────────────────────────────────────────────────────────┐
│  Couche 1 : Foundation              (TOUJOURS ACTIF)        │
│  CLI, DB SQLite, Rapports, Sessions, Dashboard              │
│  → Infrastructure permanente                                │
│                                                             │
│  Config: rien — toujours là                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Ce que fait chaque couche

### Couche 1 — Foundation (toujours)
- ✓ CLI hacker-style (Click + Rich)
- ✓ Base de données SQLite (~/.r3con/analysis.db)
- ✓ Historique des analyses
- ✓ Générateur de rapports (MD/HTML/JSON)
- ✓ Dashboard web (Flask)
- ✓ Détection automatique des outils disponibles
- ✓ Hash de fichiers, infos système

### Couche 2 — Analysis Core (toujours)
- ✓ Audit statique (C/C++/Python/Java/Go/Rust)
- ✓ Heap analysis (UAF, double-free, overflow)
- ✓ Crypto analysis (MD5, RC4, timing side-channel)
- ✓ Kernel analysis (race, privesc, IOCTL)
- ✓ Taint analysis (source → sink tracking)
- ✓ Hypothesis engine (sans IA)
- ✓ CVE matching (base locale)
- ✓ APK analysis (manifest, Smali, strings)
- ✓ Firmware analysis (entropy, strings, backdoors)
- ✓ Exploit chain builder

### Couche 3 — Intelligence (optionnel)
- ✓ CWE enrichment pour chaque finding
- ✓ CVSS 3.1 scoring automatique
- ✓ Expert rules (100+ règles de déduction)
- ✓ Scénarios d'attaque construits par règles
- ✓ Priority matrix (P0/P1/P2/P3)
- ✓ Fix recommendations précises
- ✓ Techniques d'exploitation par type
- ✓ Executive summary sans IA
- ✓ Attack steps generation

### Couche 4 — AI Enhancement (optionnel)
- ✓ Pseudo-code génération (ASM → C)
- ✓ Analyses sémantiques profondes
- ✓ Hypothèses 0day avancées
- ✓ Shell interactif IA
- ✓ Support 6 providers cloud
- ✓ Support IA locale (Ollama, LM Studio, vLLM)
- ✓ Multi-AI consensus

---

## Configuration rapide

### Option 1 : Zéro configuration (couches 1-2)
```bash
# Rien à faire — fonctionne immédiatement
r3con audit file ./code.c
r3con apk analyze ./app.apk
r3con firmware analyze ./firmware.bin
```

### Option 2 : + Expert System (couches 1-2-3)
```bash
export R3CON_EXPERT_MODE=true
r3con audit file ./code.c
# → +CWE, +CVSS, +scénarios d'attaque, +priority matrix
```

### Option 3 : + IA locale (couches 1-2-3-4)
```bash
export R3CON_EXPERT_MODE=true
# Lancer Ollama
ollama pull llama2
ollama serve
# r3con détecte automatiquement
r3con audit file ./code.c
# → +pseudo-code, +analyses sémantiques
```

### Option 4 : + IA cloud (couches 1-2-3-4)
```bash
export R3CON_EXPERT_MODE=true
export TOGETHER_API_KEY=...  # Nemotron FREE
r3con audit file ./code.c
# → Maximum d'analyse
```

### Option 5 : Multi-AI (couches 1-2-3-4 multi)
```bash
export R3CON_EXPERT_MODE=true
export R3CON_MULTI_AI=true
# Lancer plusieurs serveurs AI locaux
r3con audit file ./code.c
# → Consensus de plusieurs modèles IA
```

---

## Résultats selon les couches actives

### Couches 1-2 seulement
```
[CRITICAL] Buffer overflow à L42 (strcpy sans bornes)
[HIGH]     Integer overflow à L15 (malloc avec taille non vérifiée)
[MEDIUM]   Hardcoded key à L8
Risk score: 72/100
Exploit chains: 3
```

### Couches 1-2-3 (Expert Mode)
```
[CRITICAL] Buffer overflow à L42
  CWE-121 | CVSS: 9.8 | AV:N/AC:L/PR:N/UI:N
  Priority: P0 — Fix now
  Attack: Classic stack smashing → overwrite return address
  Fix: Use strncpy(dest, src, sizeof(dest)-1)

[HIGH] Integer overflow à L15
  CWE-190 | CVSS: 8.1 | AV:N/AC:L/PR:N/UI:N
  Priority: P1 — Fix this sprint
  Attack: Trigger undersized allocation → heap overflow

Expert Deductions:
  ✓ BOF with user input → RCE (confidence: 92%)
  ✓ INT_OF → Heap corruption (confidence: 88%)

Executive Summary:
  CRITICAL RISK: 1 critical vulnerability (Buffer Overflow).
  Potential for Remote Code Execution confirmed by expert rules.
  Risk rating: HIGH (72/100). Immediate remediation required.
```

### Couches 1-2-3-4 (avec IA)
```
[CRITICAL] Buffer overflow à L42
  ... (tout ce qui précède)

AI Analysis:
  The strcpy() at line 42 copies user-controlled data from argv[1]
  into a 64-byte stack buffer. An attacker can supply 72+ bytes to
  overwrite the saved return address. On Linux x86_64 without PIE:
  1. Find ROP gadgets with `ropper`
  2. Build chain: pop rdi; ret → /bin/sh → system()
  3. Calculate offset: python3 -c "print('A'*72 + <ret_addr>)"

Pseudo-code:
  void vulnerable_function(char* user_input) {
    char buffer[64];
    // [VULN] No bounds check — use strncpy(buffer, user_input, 63)
    strcpy(buffer, user_input);
    printf("Processed: %s\n", buffer);
  }
```

---

## Détection automatique au démarrage

r3con affiche les couches actives à chaque démarrage :

```
  r3con v4.3.0 — Layer Status
  ────────────────────────────────────────
  ✓  Layer 1: Foundation          Always on
  ✓  Layer 2: Analysis Core       Built-in patterns
  ✓  Layer 3: Intelligence        R3CON_EXPERT_MODE=true
  ✓  Layer 4: AI Enhancement      Nemotron / nvidia/nemotron-3-super-120b-a12b:free
  ────────────────────────────────────────
```

ou sans configuration :

```
  r3con v4.3.0 — Layer Status
  ────────────────────────────────────────
  ✓  Layer 1: Foundation          Always on
  ✓  Layer 2: Analysis Core       Built-in patterns
  ○  Layer 3: Intelligence        Set R3CON_EXPERT_MODE=true to enable
  ○  Layer 4: AI Enhancement      No AI configured (optional)
  ────────────────────────────────────────
```

L'outil fonctionne dans les deux cas. Les couches 3-4 rendent juste l'analyse plus riche.
