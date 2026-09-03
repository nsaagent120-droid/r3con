"""
r3con - Local AI Client
Communicate with local AI models (Ollama, LM Studio, vLLM, etc.)
without requiring API keys or external services.
"""

import requests
import json
from typing import Optional, List, Dict


class LocalAIClient:
    """Client for communicating with local AI models."""

    def __init__(self, base_url: str = "http://localhost:11434", 
                 model: str = "llama2", 
                 timeout: int = 300):
        """
        Initialize local AI client.
        
        Args:
            base_url: URL of local AI server (Ollama, LM Studio, vLLM, etc.)
            model: Model name to use
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = timeout
        self.available = self._check_connection()

    def _check_connection(self) -> bool:
        """Check if local AI server is available."""
        try:
            # Validate URL has valid port
            import urllib.parse
            parsed = urllib.parse.urlparse(self.base_url)
            if parsed.port and (parsed.port < 1 or parsed.port > 65535):
                return False

            # Try Ollama API
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                return True

            # Try OpenAI-compatible API
            response = requests.get(
                f"{self.base_url}/v1/models",
                timeout=5
            )
            return response.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, system_prompt: str = "", 
                 max_tokens: int = 2048, temperature: float = 0.7) -> Optional[str]:
        """
        Generate response from local AI model.
        
        Args:
            prompt: User prompt
            system_prompt: System instruction
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0-1)
            
        Returns:
            Generated text or None if failed
        """
        if not self.available:
            return None

        try:
            # Try Ollama API (most common)
            return self._ollama_generate(prompt, system_prompt, max_tokens, temperature)
        except Exception:
            try:
                # Try OpenAI-compatible API (LM Studio, vLLM, LocalAI)
                return self._openai_compatible_generate(prompt, system_prompt, max_tokens, temperature)
            except Exception as e:
                print(f"[LocalAI Error] {e}")
                return None

    def _ollama_generate(self, prompt: str, system_prompt: str, 
                        max_tokens: int, temperature: float) -> str:
        """Generate using Ollama API."""
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": full_prompt,
                "temperature": temperature,
                "num_predict": max_tokens,
                "stream": False
            },
            timeout=self.timeout
        )
        
        if response.status_code == 200:
            return response.json().get("response", "")
        raise Exception(f"Ollama API error: {response.status_code}")

    def _openai_compatible_generate(self, prompt: str, system_prompt: str,
                                    max_tokens: int, temperature: float) -> str:
        """Generate using OpenAI-compatible API (LM Studio, vLLM, LocalAI)."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        response = requests.post(
            f"{self.base_url}/v1/chat/completions",
            json={
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            },
            timeout=self.timeout
        )
        
        if response.status_code == 200:
            data = response.json()
            if "choices" in data and len(data["choices"]) > 0:
                return data["choices"][0]["message"]["content"]
        raise Exception(f"OpenAI API error: {response.status_code}")

    def chat(self, history: List[Dict], system_prompt: str = "",
             max_tokens: int = 2048) -> Optional[str]:
        """
        Continue a conversation with the local AI model.
        
        Args:
            history: List of {"role": "user"/"assistant", "content": "..."} dicts
            system_prompt: System instruction
            max_tokens: Maximum tokens
            
        Returns:
            Generated response or None
        """
        if not self.available:
            return None

        try:
            return self._openai_compatible_chat(history, system_prompt, max_tokens)
        except Exception:
            try:
                # Fallback: convert to single prompt for Ollama
                conversation = "\n".join([
                    f"{msg['role'].upper()}: {msg['content']}"
                    for msg in history
                ])
                return self._ollama_generate(
                    conversation, system_prompt, max_tokens, 0.7
                )
            except Exception as e:
                print(f"[LocalAI Error] {e}")
                return None

    def _openai_compatible_chat(self, history: List[Dict], 
                                system_prompt: str, max_tokens: int) -> str:
        """Chat using OpenAI-compatible API."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.extend(history)
        
        response = requests.post(
            f"{self.base_url}/v1/chat/completions",
            json={
                "model": self.model,
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": max_tokens
            },
            timeout=self.timeout
        )
        
        if response.status_code == 200:
            data = response.json()
            if "choices" in data and len(data["choices"]) > 0:
                return data["choices"][0]["message"]["content"]
        raise Exception(f"OpenAI API error: {response.status_code}")

    def list_models(self) -> List[str]:
        """List available models on the server."""
        try:
            # Try Ollama
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get("models", [])
                return [m["name"] for m in models]
            
            # Try OpenAI-compatible
            response = requests.get(f"{self.base_url}/v1/models", timeout=5)
            if response.status_code == 200:
                models = response.json().get("data", [])
                return [m["id"] for m in models]
        except Exception:
            pass
        
        return []

    def stream_generate(self, prompt: str, system_prompt: str = "",
                       max_tokens: int = 2048, temperature: float = 0.7):
        """
        Stream response from local AI model (yields chunks).
        
        Args:
            prompt: User prompt
            system_prompt: System instruction
            max_tokens: Maximum tokens
            temperature: Sampling temperature
            
        Yields:
            Text chunks as they arrive
        """
        if not self.available:
            return

        try:
            full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "temperature": temperature,
                    "num_predict": max_tokens,
                    "stream": True
                },
                stream=True,
                timeout=self.timeout
            )
            
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        if "response" in data:
                            yield data["response"]
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"[LocalAI Stream Error] {e}")


class LocalAIFactory:
    """Factory for creating appropriate local AI client."""

    @staticmethod
    def create(url: Optional[str] = None, model: Optional[str] = None) -> Optional[LocalAIClient]:
        """
        Create a local AI client, auto-detecting server type and model.
        
        Args:
            url: Custom server URL (default: http://localhost:11434)
            model: Custom model name (auto-detected if not provided)
            
        Returns:
            LocalAIClient or None if no server found
        """
        import os
        
        # Check environment variable
        if not url:
            url = os.environ.get("LOCAL_AI_URL", "http://localhost:11434")
        
        client = LocalAIClient(base_url=url, model=model or "llama2")
        
        if not client.available:
            # Try other common ports
            common_urls = [
                "http://localhost:8000",  # vLLM
                "http://localhost:1234",  # LM Studio
                "http://localhost:8080",  # LocalAI
                "http://127.0.0.1:11434", # Ollama alt
            ]
            
            for alt_url in common_urls:
                client = LocalAIClient(base_url=alt_url, model=model or "llama2")
                if client.available:
                    return client
            
            return None
        
        # Auto-detect and set best available model if not specified
        if not model:
            models = client.list_models()
            if models:
                # Prefer certain models
                preferences = ["neural-chat", "mistral", "llama2", "orca"]
                for pref in preferences:
                    for m in models:
                        if pref.lower() in m.lower():
                            client.model = m
                            return client
                # Use first available
                client.model = models[0]
        
        return client
