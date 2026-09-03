"""
r3con - Multi-AI Manager
Communicate with multiple local AI models simultaneously without any API keys.
Send analysis results to multiple AI backends and aggregate responses.
"""

import requests
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor


class MultiAIManager:
    """Manage multiple local AI models and aggregate their responses."""

    # Common local AI server configurations
    COMMON_SERVERS = {
        "ollama": {
            "url": "http://localhost:11434",
            "api_endpoint": "/api/generate",
            "type": "ollama",
            "port": 11434,
            "default_models": ["llama2", "mistral", "neural-chat"]
        },
        "lm_studio": {
            "url": "http://localhost:1234",
            "api_endpoint": "/v1/chat/completions",
            "type": "openai_compatible",
            "port": 1234,
            "default_models": ["local-model"]
        },
        "vllm": {
            "url": "http://localhost:8000",
            "api_endpoint": "/v1/chat/completions",
            "type": "openai_compatible",
            "port": 8000,
            "default_models": ["model"]
        },
        "localai": {
            "url": "http://localhost:8080",
            "api_endpoint": "/v1/chat/completions",
            "type": "openai_compatible",
            "port": 8080,
            "default_models": ["gpt-3.5-turbo"]
        },
        "text_generation_webui": {
            "url": "http://localhost:5000",
            "api_endpoint": "/api/v1/chat",
            "type": "webui",
            "port": 5000,
            "default_models": ["model"]
        }
    }

    def __init__(self, max_workers: int = 5):
        """
        Initialize Multi-AI Manager.
        
        Args:
            max_workers: Maximum concurrent AI queries
        """
        self.max_workers = max_workers
        self.available_servers = []
        self.ai_instances = {}
        self._discover_servers()

    def _discover_servers(self):
        """Auto-discover available local AI servers."""
        print("[*] Discovering local AI servers...")
        
        for server_name, config in self.COMMON_SERVERS.items():
            if self._check_server(config["url"]):
                print(f"  ✓ Found {server_name} at {config['url']}")
                self.available_servers.append({
                    "name": server_name,
                    "url": config["url"],
                    "type": config["type"],
                    "models": []
                })
                
                # Get available models
                models = self._get_models(config["url"], config["type"])
                if models:
                    self.available_servers[-1]["models"] = models

    def _check_server(self, url: str, timeout: int = 2) -> bool:
        """Check if a server is running and responsive."""
        try:
            response = requests.get(
                f"{url}/api/tags",  # Try Ollama
                timeout=timeout
            )
            if response.status_code == 200:
                return True
            
            # Try OpenAI-compatible
            response = requests.get(
                f"{url}/v1/models",
                timeout=timeout
            )
            return response.status_code == 200
        except (requests.ConnectionError, requests.Timeout):
            return False

    def _get_models(self, url: str, server_type: str) -> List[str]:
        """Get available models from a server."""
        try:
            if server_type == "ollama":
                response = requests.get(f"{url}/api/tags", timeout=5)
                if response.status_code == 200:
                    models = response.json().get("models", [])
                    return [m["name"] for m in models]
            
            elif server_type in ("openai_compatible", "webui"):
                response = requests.get(f"{url}/v1/models", timeout=5)
                if response.status_code == 200:
                    models = response.json().get("data", [])
                    return [m["id"] for m in models]
        except Exception:
            pass
        
        return []

    def add_custom_server(self, name: str, url: str, server_type: str, models: List[str] = None):
        """Add a custom local AI server."""
        if self._check_server(url):
            server = {
                "name": name,
                "url": url,
                "type": server_type,
                "models": models or []
            }
            self.available_servers.append(server)
            print(f"[+] Added server: {name} ({url})")
            return True
        else:
            print(f"[-] Could not reach {name} at {url}")
            return False

    def send_to_all(self, prompt: str, system_prompt: str = "", 
                    max_tokens: int = 2048) -> Dict[str, str]:
        """
        Send prompt to all available AI servers and aggregate responses.
        
        Args:
            prompt: The analysis to send
            system_prompt: System instruction
            max_tokens: Max tokens per response
            
        Returns:
            Dict with responses from each server/model
        """
        if not self.available_servers:
            print("[-] No local AI servers found!")
            return {}

        print(f"\n[*] Sending analysis to {len(self.available_servers)} AI servers...")
        print("[*] Processing in parallel...\n")

        responses = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            # Submit tasks for each server/model combination
            for server in self.available_servers:
                models = server["models"] or ["default"]
                
                for model in models[:2]:  # Limit to 2 models per server
                    task_id = f"{server['name']}::{model}"
                    future = executor.submit(
                        self._query_single,
                        server["url"],
                        server["type"],
                        model,
                        prompt,
                        system_prompt,
                        max_tokens
                    )
                    futures[task_id] = future
            
            # Collect results as they complete
            for task_id, future in futures.items():
                try:
                    server_name, model = task_id.split("::")
                    result = future.result(timeout=120)  # 2 minute timeout per query
                    responses[task_id] = result
                    print(f"  ✓ {server_name} ({model}): {len(result)} chars")
                except Exception as e:
                    responses[task_id] = f"[Error] {str(e)}"
                    print(f"  ✗ {task_id}: Failed")

        return responses

    def _query_single(self, url: str, server_type: str, model: str,
                     prompt: str, system_prompt: str, max_tokens: int) -> str:
        """Query a single AI server."""
        try:
            if server_type == "ollama":
                return self._query_ollama(url, model, prompt, system_prompt, max_tokens)
            elif server_type == "openai_compatible":
                return self._query_openai_compatible(url, model, prompt, system_prompt, max_tokens)
            elif server_type == "webui":
                return self._query_webui(url, model, prompt, system_prompt, max_tokens)
        except Exception as e:
            return f"[Query Error] {str(e)}"

    def _query_ollama(self, url: str, model: str, prompt: str,
                     system_prompt: str, max_tokens: int) -> str:
        """Query Ollama API."""
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        
        response = requests.post(
            f"{url}/api/generate",
            json={
                "model": model,
                "prompt": full_prompt,
                "temperature": 0.7,
                "num_predict": max_tokens,
                "stream": False
            },
            timeout=300
        )
        
        if response.status_code == 200:
            return response.json().get("response", "")
        raise Exception(f"HTTP {response.status_code}")

    def _query_openai_compatible(self, url: str, model: str, prompt: str,
                                 system_prompt: str, max_tokens: int) -> str:
        """Query OpenAI-compatible API (LM Studio, vLLM, LocalAI)."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        response = requests.post(
            f"{url}/v1/chat/completions",
            json={
                "model": model,
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": max_tokens
            },
            timeout=300
        )
        
        if response.status_code == 200:
            data = response.json()
            if "choices" in data and len(data["choices"]) > 0:
                return data["choices"][0]["message"]["content"]
        raise Exception(f"HTTP {response.status_code}")

    def _query_webui(self, url: str, model: str, prompt: str,
                    system_prompt: str, max_tokens: int) -> str:
        """Query Text Generation WebUI API."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        response = requests.post(
            f"{url}/api/v1/chat",
            json={
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": max_tokens
            },
            timeout=300
        )
        
        if response.status_code == 200:
            data = response.json()
            if "choices" in data and len(data["choices"]) > 0:
                return data["choices"][0]["message"]["content"]
        raise Exception(f"HTTP {response.status_code}")

    def aggregate_responses(self, responses: Dict[str, str]) -> Dict:
        """
        Aggregate responses from multiple AIs.
        
        Args:
            responses: Dict of responses from each AI
            
        Returns:
            Aggregated analysis with consensus and differences
        """
        if not responses:
            return {"error": "No responses"}

        # Analyze agreement/disagreement
        consensus = self._find_consensus(responses)
        differences = self._find_differences(responses)

        return {
            "total_responses": len(responses),
            "all_responses": responses,
            "consensus": consensus,
            "disagreements": differences,
            "summary": self._generate_summary(responses)
        }

    def _find_consensus(self, responses: Dict[str, str]) -> List[str]:
        """Find common findings across multiple AIs."""
        # Simple consensus: find common keywords/patterns
        consensus_keywords = []
        
        if len(responses) < 2:
            return []

        # Extract key vulnerability types mentioned
        vuln_types = ["buffer overflow", "use-after-free", "integer overflow",
                      "race condition", "sql injection", "command injection",
                      "weak crypto", "hardcoded", "unsafe", "vulnerable"]

        response_texts = list(responses.values())
        
        for vuln in vuln_types:
            mentions = sum(1 for r in response_texts if vuln.lower() in r.lower())
            if mentions >= len(response_texts) * 0.7:  # 70% agreement
                consensus_keywords.append(vuln)

        return consensus_keywords

    def _find_differences(self, responses: Dict[str, str]) -> Dict[str, List[str]]:
        """Find unique findings from each AI."""
        differences = {}
        
        for ai_name, response in responses.items():
            # Extract unique findings not mentioned by others
            unique = []
            for word in response.split():
                count = sum(1 for r in responses.values() if word in r.lower())
                if count == 1:  # Unique to this AI
                    unique.append(word)
            
            if unique:
                differences[ai_name] = unique[:10]  # Top 10 unique words

        return differences

    def _generate_summary(self, responses: Dict[str, str]) -> str:
        """Generate summary from multiple AI responses."""
        summary_parts = []
        
        for ai_name, response in responses.items():
            # Take first sentence from each response
            first_sentence = response.split('.')[0] + '.'
            summary_parts.append(f"[{ai_name}] {first_sentence}")

        return "\n".join(summary_parts[:3])  # Top 3

    def compare_analysis(self, analysis: str, system_prompt: str = "") -> Dict:
        """
        Run analysis through all AIs and compare results.
        
        Args:
            analysis: Analysis results to send to AIs
            system_prompt: System instruction
            
        Returns:
            Comparison of AI responses
        """
        print(f"\n{'='*60}")
        print("MULTI-AI ANALYSIS COMPARISON")
        print(f"{'='*60}\n")
        
        # Send to all AIs
        responses = self.send_to_all(analysis, system_prompt)
        
        # Aggregate results
        aggregated = self.aggregate_responses(responses)

        # Print results
        print(f"\n{'='*60}")
        print("CONSENSUS FINDINGS (mentioned by 70%+ of AIs):")
        print(f"{'='*60}\n")
        
        if aggregated["consensus"]:
            for finding in aggregated["consensus"]:
                print(f"  ✓ {finding}")
        else:
            print("  [No strong consensus]")

        print(f"\n{'='*60}")
        print("UNIQUE FINDINGS BY AI:")
        print(f"{'='*60}\n")
        
        for ai_name, unique_words in aggregated["disagreements"].items():
            if unique_words:
                print(f"  [{ai_name}] {', '.join(unique_words[:5])}")

        return aggregated

    def print_summary(self):
        """Print available servers summary."""
        print(f"\n{'='*60}")
        print("AVAILABLE LOCAL AI SERVERS")
        print(f"{'='*60}\n")
        
        if not self.available_servers:
            print("[-] No local AI servers detected!")
            print("\nTo set up local AI:")
            print("\n1. OLLAMA (Recommended):")
            print("   brew install ollama")
            print("   ollama pull llama2")
            print("   ollama serve\n")
            print("2. LM STUDIO:")
            print("   Download from lmstudio.ai")
            print("   Start server on port 1234\n")
            print("3. vLLM:")
            print("   pip install vllm")
            print("   python -m vllm.entrypoints.openai.api_server\n")
            return

        for server in self.available_servers:
            print(f"[+] {server['name'].upper()}")
            print(f"    URL: {server['url']}")
            print(f"    Type: {server['type']}")
            if server['models']:
                print(f"    Models: {', '.join(server['models'][:3])}")
            print()
