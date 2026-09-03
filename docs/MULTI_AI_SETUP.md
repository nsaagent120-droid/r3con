# r3con — Multi-AI local

Utiliser plusieurs modèles IA locaux en parallèle, sans aucune clé API.

---

## Concept

```
r3con analyse le code
       ↓
   Résultats
       ↓
   Envoi parallèle
  ┌────┬────┬────┐
  ↓    ↓    ↓    ↓
llama2 mistral neural-chat custom
  ↓    ↓    ↓    ↓
  └────┴────┴────┘
       ↓
  Consensus (70%+ accord)
  Différences uniques par modèle
  Rapport agrégé
```

---

## Installation

```bash
# Installer Ollama
curl https://ollama.ai/install.sh | sh

# Télécharger plusieurs modèles
ollama pull llama2
ollama pull mistral
ollama pull neural-chat

# Lancer
ollama serve
```

---

## Configuration

```bash
# Activer Multi-AI
export R3CON_MULTI_AI=true

# Optionnel : URL custom
export LOCAL_AI_URL=http://localhost:11434

# Lancer
r3con audit file ./code.c --ai
```

---

## Utilisation Python

```python
from core.multi_ai_manager import MultiAIManager

manager = MultiAIManager()

# Voir les serveurs disponibles
manager.print_summary()

# Envoyer analyse à tous
responses = manager.send_to_all(
    prompt="Vulnerabilities in this code: strcpy(buf, input)...",
    system_prompt="Security expert. Be technical and concise.",
    max_tokens=1024
)

# Consensus
result = manager.aggregate_responses(responses)
print("Consensus:", result['consensus'])
print("Total responses:", result['total_responses'])

# Comparer directement
manager.compare_analysis("Found buffer overflow at line 42...")
```

---

## Serveurs supportés

| Serveur | Port | Type | Installation |
|---------|------|------|-------------|
| Ollama | 11434 | Natif | https://ollama.ai |
| LM Studio | 1234 | OpenAI-compatible | https://lmstudio.ai |
| vLLM | 8000 | OpenAI-compatible | `pip install vllm` |
| LocalAI | 8080 | OpenAI-compatible | https://localai.io |
| Text Gen WebUI | 5000 | Custom | https://github.com/oobabooga |

---

## Ajouter un serveur custom

```python
manager = MultiAIManager()
manager.add_custom_server(
    name="my_server",
    url="http://192.168.1.100:8000",
    server_type="openai_compatible",
    models=["my-model"]
)
```
