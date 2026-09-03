# r3con — Configuration des providers IA

> L'IA est 100% optionnelle. r3con fonctionne sans.

---

## Comparaison rapide

| Mode | Configuration | Modèle par défaut | Usage |
|------|---------------|-------------------|-------|
| **Offline** | Aucune clé | Règles locales | Analyse déterministe sans réseau |
| **Proxy intégré** | `OPENAI_API_BASE` + `OPENAI_API_KEY` | `gpt-5-mini` | Analyse IA structurée et console conversationnelle |
| **Ollama/local** | Serveur local compatible | Selon serveur | IA locale, sans clé externe |
| **Providers directs** | Clé dédiée | Selon provider | Anthropic, DeepSeek, Gemini, Groq ou Together |

---

## 1. Ollama (local — gratuit — recommandé si vous avez de la RAM)

```bash
# Installation
curl https://ollama.ai/install.sh | sh   # Linux
brew install ollama                       # macOS

# Télécharger un modèle
ollama pull llama2        # 4 GB — bon équilibre
ollama pull mistral       # 4 GB — meilleure qualité
ollama pull neural-chat   # 4 GB — optimisé sécurité
ollama pull codellama     # 4 GB — orienté code

# Lancer le serveur
ollama serve
# → http://localhost:11434

# r3con détecte automatiquement
r3con audit file ./code.c --ai
```

Vérifier que ça marche :
```bash
curl http://localhost:11434/api/tags
```

---

## 2. NVIDIA Nemotron via Together AI (cloud — gratuit)

Modèle de 120 milliards de paramètres. Gratuit illimité.

```bash
pip install together
```

1. S'inscrire sur https://api.together.ai/
2. Copier la clé API

```bash
export TOGETHER_API_KEY=your_key_here
r3con audit file ./code.c --ai
```

---

## 3. DeepSeek (cloud — très bon marché)

```bash
pip install openai
```

1. S'inscrire sur https://platform.deepseek.com/
2. Copier la clé API

```bash
export DEEPSEEK_API_KEY=sk-your_key_here
r3con audit file ./code.c --ai
```

Coût : ~$0.14 par million de tokens. Crédit gratuit à l'inscription.

---

## 4. Google Gemini (cloud — gratuit avec limites)

```bash
pip install google-generativeai
```

1. Aller sur https://aistudio.google.com/
2. Cliquer "Get API key"

```bash
export GEMINI_API_KEY=your_key_here
r3con audit file ./code.c --ai
```

Limite gratuite : 15 requêtes/minute.

---

## 5. Groq (cloud — gratuit — très rapide)

```bash
pip install openai   # Groq utilise le SDK OpenAI
```

1. S'inscrire sur https://console.groq.com/
2. Copier la clé API

```bash
export GROQ_API_KEY=gsk-your_key_here
r3con audit file ./code.c --ai
```

---

## 6. Anthropic Claude (cloud — payant — meilleure qualité)

```bash
pip install anthropic
```

1. S'inscrire sur https://console.anthropic.com/
2. Ajouter un moyen de paiement
3. Copier la clé API

```bash
export ANTHROPIC_API_KEY=sk-ant-your_key_here
r3con audit file ./code.c --ai
```

Coût : $0.80 par million de tokens (entrée).

---

## Détection automatique

Le moteur principal utilise le proxy OpenAI-compatible lorsqu’il trouve `OPENAI_API_BASE` et `OPENAI_API_KEY`; sinon il cherche les providers directs, puis tombe en mode offline. La sélection peut être forcée avec `R3CON_AI_PROVIDER`.

```bash
# Proxy intégré / serveur OpenAI-compatible
export OPENAI_API_BASE="https://proxy.example/v1"
export OPENAI_API_KEY="..."
export R3CON_AI_MODEL="gpt-5-mini"
export R3CON_AI_REASONING="low"       # minimal|low|medium|high pour GPT-5

# Forcer un mode local sans réseau
export R3CON_AI_OFFLINE=1

# Forcer le provider
export R3CON_AI_PROVIDER=openai         # alias de openai_compatible
# valeurs: offline, openai, openai_compatible, anthropic, deepseek, gemini, groq, together
```

## Sorties structurées et limites

Pour `audit file --ai`, le proxy reçoit un schéma JSON strict avec les champs `severity`, `type`, `line`, `description` et `recommendation`. Cela réduit les erreurs de parsing; le fallback conserve une entrée informative si le serveur refuse le schéma ou renvoie une réponse invalide. Les modèles GPT-5 utilisent `max_completion_tokens` et, par défaut, un raisonnement `low`; ce réglage est configurable par `R3CON_AI_REASONING`.

```bash
r3con --version
r3con audit file ./code.c --ai
r3con interactive
```

L’IA ne remplace pas la vérification par r2, GDB/pwndbg, Ghidra ou les analyseurs réseau. Les hypothèses, CVE possibles et primitives d’exploitation doivent être confirmées dans un laboratoire autorisé.

## Forcer un provider spécifique

Pour forcer un provider, définissez **uniquement** sa variable :

```bash
# Forcer DeepSeek
unset ANTHROPIC_API_KEY GEMINI_API_KEY GROQ_API_KEY TOGETHER_API_KEY
export DEEPSEEK_API_KEY=sk-...
```

## Custom URL (serveur perso)

```bash
export LOCAL_AI_URL=http://192.168.1.100:11434
r3con audit file ./code.c --ai
```
