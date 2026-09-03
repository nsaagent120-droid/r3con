"""
r3con - Couche 4 : AI Enhancement
Enrichissement IA — cloud ou local.
100% optionnel. L'outil fonctionne sans cette couche.
"""

import os
import json
from typing import Optional, Dict


class AIEnhancement:
    """
    Couche 4 — Enrichissement IA optionnel.
    Détecte automatiquement le provider disponible.
    Dégrade gracieusement si aucun disponible.
    """

    def __init__(self):
        self.provider = self._detect()
        self.client   = None
        self.model    = None
        self._setup()

    def _detect(self) -> str:
        """Détecte le provider disponible dans l'ordre de priorité."""
        # Local AI d'abord (gratuit, offline)
        if os.environ.get("LOCAL_AI_URL"):
            return "local"
        if self._check_local_server("http://localhost:11434"):
            return "local_ollama"
        if self._check_local_server("http://localhost:1234"):
            return "local_lmstudio"
        if self._check_local_server("http://localhost:8000"):
            return "local_vllm"

        # Multi-AI local (plusieurs serveurs)
        if os.environ.get("R3CON_MULTI_AI"):
            return "multi_ai"

        # Cloud APIs
        if os.environ.get("ANTHROPIC_API_KEY"):  return "anthropic"
        if os.environ.get("DEEPSEEK_API_KEY"):   return "deepseek"
        if os.environ.get("GEMINI_API_KEY"):      return "gemini"
        if os.environ.get("GROQ_API_KEY"):        return "groq"
        if os.environ.get("TOGETHER_API_KEY"):    return "together"

        return "none"

    def _check_local_server(self, url: str) -> bool:
        try:
            import urllib.request
            urllib.request.urlopen(url + "/api/tags", timeout=1)
            return True
        except Exception:
            try:
                urllib.request.urlopen(url + "/v1/models", timeout=1)
                return True
            except Exception:
                return False

    def _setup(self):
        """Initialise le client selon le provider détecté."""
        try:
            if self.provider in ("local", "local_ollama", "local_lmstudio", "local_vllm"):
                from core.local_ai_client import LocalAIFactory
                url = os.environ.get("LOCAL_AI_URL", {
                    "local_ollama":   "http://localhost:11434",
                    "local_lmstudio": "http://localhost:1234",
                    "local_vllm":     "http://localhost:8000",
                }.get(self.provider, "http://localhost:11434"))
                self.client = LocalAIFactory.create(url=url)
                if self.client:
                    self.model = self.client.model

            elif self.provider == "multi_ai":
                from core.multi_ai_manager import MultiAIManager
                self.client = MultiAIManager()
                self.model  = "multi-ai-consensus"

            elif self.provider == "anthropic":
                import anthropic
                self.client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
                self.model  = "claude-opus-4-5"

            elif self.provider in ("deepseek", "groq", "together"):
                from openai import OpenAI
                configs = {
                    "deepseek": ("https://api.deepseek.com",                "deepseek-chat",                   "DEEPSEEK_API_KEY"),
                    "groq":     ("https://api.groq.com/openai/v1",          "mixtral-8x7b-32768",              "GROQ_API_KEY"),
                    "together": ("https://api.together.xyz/v1",             "nvidia/nemotron-3-super-120b-a12b:free","TOGETHER_API_KEY"),
                }
                base_url, model, key_env = configs[self.provider]
                self.client = OpenAI(api_key=os.environ[key_env], base_url=base_url)
                self.model  = model

            elif self.provider == "gemini":
                import google.generativeai as genai
                genai.configure(api_key=os.environ["GEMINI_API_KEY"])
                self.client = genai.GenerativeModel("gemini-1.5-flash")
                self.model  = "gemini-1.5-flash"

        except Exception:
            self.provider = "none"
            self.client   = None

    @property
    def available(self) -> bool:
        return self.provider != "none" and self.client is not None

    def enhance(self, layer2_result: Dict, layer3_result: Optional[Dict] = None) -> Dict:
        """
        Enrichit le résultat des couches 2/3 avec de l'IA.
        Si pas d'IA disponible, retourne le résultat tel quel.
        """
        if not self.available:
            return layer2_result

        base = layer3_result or layer2_result

        # Préparer le contexte pour l'IA
        context = self._build_context(base)

        enhancements = {}

        # Générer pseudo-code si binaire analysé
        if base.get("asm"):
            enhancements["pseudocode"] = self._call(
                f"Convert this assembly to commented C pseudo-code:\n\n{base['asm'][:4000]}")

        # Analyse approfondie des chaînes d'exploitation
        if base.get("exploit_chains"):
            chains_text = json.dumps(base["exploit_chains"][:3], indent=2)
            enhancements["chain_analysis"] = self._call(
                f"Analyze these exploitation chains and provide detailed attack scenarios:\n{chains_text}")

        # Deep analysis du code
        if base.get("findings"):
            enhancements["ai_deep_analysis"] = self._call(
                f"Security researcher analysis. Given these findings:\n{context}\n\n"
                f"Provide: 1) Hidden vuln chains 2) Blind spots 3) Exploitation priority")

        # 0day hypotheses
        if base.get("hypotheses"):
            enhancements["0day_hypotheses"] = self._call(
                f"Based on attack surface:\n{json.dumps(base['hypotheses'], indent=2)[:3000]}\n\n"
                f"Formulate 3 specific 0day hypotheses with exploitation paths.")

        return {**base, "ai_enhancements": enhancements,
                "ai_provider": self.provider, "ai_model": self.model}

    def _build_context(self, result: Dict) -> str:
        """Construire le contexte pour l'IA à partir des résultats."""
        findings = result.get("findings", [])
        lines    = []
        for f in findings[:20]:
            sev  = f.get("severity", "?")
            ftype = f.get("type", "?")
            line = f.get("line", "?")
            desc = f.get("description", "")[:80]
            lines.append(f"[{sev}] {ftype} @ L{line}: {desc}")
        return "\n".join(lines)

    def _call(self, prompt: str, max_tokens: int = 2048) -> str:
        """Appel IA avec gestion d'erreur."""
        SYSTEM = ("Expert security researcher. Be precise, technical. "
                  "Focus on exploitability and actionable insights.")
        try:
            if self.provider in ("local", "local_ollama", "local_lmstudio", "local_vllm"):
                return self.client.generate(prompt, SYSTEM, max_tokens) or ""

            elif self.provider == "multi_ai":
                responses = self.client.send_to_all(prompt, SYSTEM, max_tokens)
                agg       = self.client.aggregate_responses(responses)
                return agg.get("summary", "")

            elif self.provider == "anthropic":
                r = self.client.messages.create(
                    model=self.model, max_tokens=max_tokens, system=SYSTEM,
                    messages=[{"role":"user","content":prompt}])
                return r.content[0].text

            elif self.provider in ("deepseek","groq","together"):
                r = self.client.chat.completions.create(
                    model=self.model, max_tokens=max_tokens,
                    messages=[{"role":"system","content":SYSTEM},
                               {"role":"user","content":prompt}])
                return r.choices[0].message.content

            elif self.provider == "gemini":
                r = self.client.generate_content(f"{SYSTEM}\n\n{prompt}")
                return r.text

        except Exception as e:
            return f"[AI Error: {e}]"

        return ""
