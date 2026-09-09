# r3con v4.3.0 — Démarrage rapide

## Installation (2 minutes)

```bash
# Depuis une copie locale du projet
cd r3con_v4.3.0
pip install click rich
```

## Utilisation immédiate (sans rien configurer)

```bash
# Auditer du code source
r3con audit file ./code.c

# Analyser un APK Android
r3con apk analyze ./app.apk

# Analyser un firmware IoT
r3con firmware analyze ./firmware.bin

# Analyser un binaire
r3con disasm file ./binary

# Recherche 0day
r3con research hypothesis ./target.c
```

## Activer l'Expert System (sans IA)

```bash
export R3CON_EXPERT_MODE=true
r3con audit file ./code.c
# → +CVSS, +CWE, +scénarios d'attaque, +priority matrix
```

## Activer une IA (optionnel)

```bash
# Option A : IA locale gratuite
ollama pull llama2 && ollama serve

# Option B : Nemotron gratuit (cloud)
export TOGETHER_API_KEY=...

# Option C : DeepSeek bon marché
export DEEPSEEK_API_KEY=sk-...

# Option D : Gemini gratuit
export GEMINI_API_KEY=...

# Option E : Groq gratuit + rapide
export GROQ_API_KEY=gsk-...
```

## Toutes les options actives

```bash
export R3CON_EXPERT_MODE=true
export TOGETHER_API_KEY=...
r3con audit file ./code.c
# → Analyse maximale
```

## Lancer le dashboard web

```bash
pip install flask
python -m modules.web.dashboard
# → http://localhost:5000
```

## Lancer les tests

```bash
python -m pytest -q
# 31 passed, 2 skipped dans l’environnement de référence
```

## Aide

```bash
r3con --help
r3con audit --help
r3con apk --help
r3con firmware --help
r3con research --help
```

## Documentation complète

- `README.md` — Vue d’ensemble et installation
- `docs/USER_GUIDE.md` — Utilisation détaillée par domaine
- `docs/MANUEL_TECHNIQUE_v7.2.md` — Architecture et modules
- `docs/STABLE_RELEASE.md` — Validation et maintenance de la release stable
