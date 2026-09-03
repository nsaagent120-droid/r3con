# r3con — Fonctionnalités avancées

## Expert System (Couche 3)

Activer : `export R3CON_EXPERT_MODE=true`

### Ce qui est ajouté automatiquement sur chaque finding

```python
{
    "type": "Buffer Overflow",
    "severity": "CRITICAL",
    "line": 42,
    "description": "strcpy without bounds check",

    # Ajouté par la Couche 3
    "cwe":        "CWE-121",
    "cvss":       9.8,
    "cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "priority":   "P0 — Fix now",
    "fix":        "Use strncpy(dest, src, sizeof(dest)-1). Enable -fstack-protector-all.",
    "attack_vector": "Network",
    "complexity": "Low",
}
```

### Expert Rules (100+ règles)

Exemples de règles :

| Condition | Conclusion | Confiance |
|-----------|------------|-----------|
| Buffer Overflow + user_input | RCE possible | 92% |
| Use-After-Free | Heap exploitation | 85% |
| Integer Overflow | Heap corruption | 88% |
| Hardcoded Credential | Auth bypass | 100% |
| Command Injection | Full RCE | 98% |
| TOCTOU | Privilege escalation | 70% |
| Kernel vuln | Local privesc | 90% |

### Attack Scenarios

Chaque scénario contient des étapes concrètes :

```
Scenario: BOF with user input → RCE
Confidence: 92%
Steps:
  1. Identify entry point linked to: Buffer Overflow
  2. Trigger vulnerability: craft malicious input to reach vulnerable code
  3. Overwrite control-flow structure (return address / vtable / function pointer)
  4. Redirect execution to shellcode or ROP chain
  5. Execute arbitrary code with process privileges
```

### Priority Matrix

Tous les findings sont triés par urgence :

```
P0 — Fix now        (CVSS >= 9.0)
P1 — Fix this sprint (CVSS >= 7.0)
P2 — Fix next sprint (CVSS >= 4.0)
P3 — Backlog        (CVSS < 4.0)
```

### Risk Rating

Score global 0-100 :

```
CRITICAL  : 80-100
HIGH      : 60-79
MEDIUM    : 40-59
LOW       : 20-39
MINIMAL   : 0-19
```

---

## Taint Analysis

Suit le flux de données depuis les sources contrôlées par l'attaquant jusqu'aux opérations dangereuses.

### Sources détectées

- `argv[]` — arguments ligne de commande
- `stdin` / `fgets` / `scanf` — entrée standard
- `recv` / `read` — réseau/fichier
- `getenv` — variables d'environnement
- `copy_from_user` — espace utilisateur (kernel)

### Sinks dangereux

- `strcpy` / `memcpy` — écriture mémoire
- `system` / `exec*` / `popen` — exécution de commandes
- `printf` — format string
- `malloc(user_size)` — allocation contrôlée
- `rawQuery` / SQL — injection SQL

### Exemple de flow détecté

```
Source: argv[1] @ line 5
   ↓
  [strcpy without bounds check @ line 8]
   ↓
Sink: Buffer write @ line 8
  Vulnerability: BOF
  Exploitable: YES
  Confidence: 90%
```

---

## SQLite Database

Toutes les analyses sont sauvegardées dans `~/.r3con/analysis.db`.

### Structure

```sql
-- Analyses
analysis (id, target, analysis_type, status, total_findings,
          critical_count, high_count, exploit_chains, created_at)

-- Findings
findings (id, analysis_id, severity, type, file, line,
          description, recommendation, cwe, cve, created_at)

-- Chaînes d'exploitation
exploit_chains (id, analysis_id, chain_name, description,
                steps, impact, confidence, finding_ids, created_at)

-- Taint flows
taint_flows (id, analysis_id, source_file, source_line,
             sink_file, sink_line, path, vulnerability_type, exploitable)
```

### Utilisation Python

```python
from modules.db.database import AnalysisDB

db = AnalysisDB()

# Récupérer une analyse
analysis = db.get_analysis("20260515_101800_7f77c3")

# Récupérer les findings
findings = db.get_findings("20260515_101800_7f77c3")

# Statistiques
stats = db.get_stats("20260515_101800_7f77c3")
print(stats)
# {
#   "total_findings": 8,
#   "severity_counts": {"CRITICAL": 2, "HIGH": 4, "MEDIUM": 2},
#   "exploit_chains": 3,
#   "taint_flows": 5,
#   "exploitable_flows": 3
# }
```

---

## Orchestrateur Python (r3con_core.py)

Pour intégrer r3con dans vos propres scripts.

```python
import os
from r3con_core import R3con

# Activer Expert System
os.environ['R3CON_EXPERT_MODE'] = 'true'

# Initialiser (affiche les couches actives)
r = R3con()

# Analyser du code source
with open('./target.c') as f:
    code = f.read()

result = r.analyze_source(code, lang='c', filename='target.c')

# Findings avec CVSS + CWE
for f in result['findings']:
    print(f"[{f['severity']}] {f['type']} L{f['line']}")
    print(f"  CWE: {f['cwe']} | CVSS: {f['cvss']}")
    print(f"  Fix: {f['fix']}")
    print(f"  Priority: {f['priority']}")

# Expert deductions
for ded in result['expert_deductions']:
    print(f"Rule: {ded['rule']} (confidence: {ded['confidence']})")
    print(f"  → {', '.join(ded['conclusions'])}")

# Risk rating
rr = result['risk_rating']
print(f"\nRisk: {rr['rating']} ({rr['score']}/100)")

# Attack scenarios
for scenario in result['attack_scenarios']:
    print(f"\nScenario: {scenario['name']}")
    for step in scenario['steps']:
        print(f"  {step}")

# Générer rapport
report_path = r.generate_report(result['analysis_id'])
print(f"\nReport: {report_path}")

# Analyser un APK
result_apk = r.analyze_apk('./app.apk')

# Analyser un firmware
result_fw = r.analyze_firmware('./firmware.bin')

# Status de l'installation
status = r.status()
print(f"Layers active: {status['layers']}")
print(f"AI provider: {status['ai_provider']}")
```

---

## Dashboard Web

```bash
pip install flask
python -m modules.web.dashboard

# Ouvrir http://localhost:5000
```

Affiche :
- Vue d'ensemble de l'analyse
- Répartition par sévérité (Critical/High/Medium/Low)
- Chaînes d'exploitation avec confiance et difficulté
- Findings détaillés
- Taint flows
- Statistiques en temps réel (refresh toutes les 30s)

---

## Multi-AI Manager

Envoyer les analyses à plusieurs modèles IA locaux simultanément.

```python
from core.multi_ai_manager import MultiAIManager

# Auto-découverte des serveurs disponibles
manager = MultiAIManager()
manager.print_summary()

# Envoyer à tous en parallèle
responses = manager.send_to_all(
    prompt="Analyze this vulnerability...",
    system_prompt="You are a security expert."
)

# Agréger les réponses
result = manager.aggregate_responses(responses)
print(f"Consensus: {result['consensus']}")
```

Serveurs supportés :
- Ollama (port 11434)
- LM Studio (port 1234)
- vLLM (port 8000)
- LocalAI (port 8080)
- Text Generation WebUI (port 5000)
- Serveurs custom

---

## Plugins (extensible)

Créer un plugin dans `plugins/` :

```python
class MonPlugin:
    name        = "mon_plugin"
    description = "Analyse personnalisée"
    version     = "1.0.0"

    def analyze(self, code: str, ai_engine=None) -> list:
        findings = []
        # Votre logique ici
        if "dangerous_pattern" in code:
            findings.append({
                "severity":       "HIGH",
                "type":           "Mon Type",
                "line":           1,
                "description":    "Pattern dangereux détecté",
                "recommendation": "Corriger le pattern"
            })
        return findings
```
