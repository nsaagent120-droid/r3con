"""
r3con - AI Engine
Multi-provider support: Anthropic Claude, DeepSeek, Google Gemini, Groq
Plus complete offline fallback mode.
"""

import os
import json
import re
from typing import Optional

# Try importing all providers
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    from together import Together
    TOGETHER_AVAILABLE = True
except ImportError:
    TOGETHER_AVAILABLE = False

SYSTEM_PROMPT = """You are an expert security researcher specializing in:
- Binary analysis: ELF, PE, Mach-O, APK, firmware images
- Assembly (x86/x64, ARM, MIPS, RISC-V) reverse engineering
- Memory corruption: heap/stack overflows, UAF, type confusion, off-by-one
- Kernel security: race conditions, privilege escalation, driver bugs
- Cryptography: side-channels, weak implementations, padding oracles
- Protocol analysis: TLS, SSH, SMB, custom protocols
- Android APK: Dalvik/ART bytecode, Java decompilation, manifest analysis
- Firmware: RTOS patterns, hardcoded credentials, unsafe update mechanisms
- 0day research methodology, CVE analysis, patch diffing, bug bounty

Always respond in the same language as the user.
Be precise, technical, and structured. Format findings with severity levels.
This tool is used exclusively for authorized security research and bug bounty."""


class AIEngine:
    def __init__(self):
        self.api_key  = None
        self.provider = self._detect_provider()
        self.client   = None
        self.model    = None
        self.offline  = True
        self._setup()

    def _detect_provider(self) -> str:
        """Detect the provider, honoring explicit user configuration first."""
        forced = os.environ.get("R3CON_AI_PROVIDER", "").strip().lower()
        if forced in {"offline", "openai", "openai_compatible", "anthropic", "deepseek", "gemini", "groq", "together"}:
            return "openai_compatible" if forced == "openai" else forced
        if os.environ.get("R3CON_AI_OFFLINE", "").lower() in {"1", "true", "yes", "on"}:
            return "offline"
        # A proxy OpenAI-compatible n'est activé que par choix explicite.
        # Cela évite qu'un environnement hérité (CI, sandbox, IDE) ne rende
        # les commandes locales bloquantes ou non déterministes.
        if os.environ.get("OPENAI_API_BASE") and os.environ.get("OPENAI_API_KEY"):
            if os.environ.get("R3CON_AI_PROVIDER", "").strip().lower() in {"openai", "openai_compatible"}:
                return "openai_compatible"
        # Direct external providers.
        if os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        if os.environ.get("DEEPSEEK_API_KEY"):
            return "deepseek"
        if os.environ.get("GEMINI_API_KEY"):
            return "gemini"
        if os.environ.get("GROQ_API_KEY"):
            return "groq"
        if os.environ.get("TOGETHER_API_KEY"):
            return "together"
        return "offline"

    def _setup(self):
        """Initialize the selected provider."""
        if self.provider == "openai_compatible":
            if OPENAI_AVAILABLE:
                self.api_key = os.environ.get("OPENAI_API_KEY")
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url=os.environ.get("OPENAI_API_BASE"),
                    timeout=20.0,
                )
                self.model = os.environ.get("R3CON_AI_MODEL", "gpt-5-mini")
                self.offline = False

        elif self.provider == "anthropic":
            if ANTHROPIC_AVAILABLE:
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")
                self.client  = anthropic.Anthropic(api_key=self.api_key)
                self.model   = os.environ.get("R3CON_AI_MODEL", "claude-opus-5")
                self.offline = False
        
        elif self.provider == "deepseek":
            if OPENAI_AVAILABLE:
                self.api_key = os.environ.get("DEEPSEEK_API_KEY")
                self.client  = OpenAI(
                    api_key=self.api_key,
                    base_url="https://api.deepseek.com",
                    timeout=20.0,
                )
                self.model   = os.environ.get("R3CON_AI_MODEL", "deepseek-chat")
                self.offline = False
        
        elif self.provider == "gemini":
            if GEMINI_AVAILABLE:
                self.api_key = os.environ.get("GEMINI_API_KEY")
                genai.configure(api_key=self.api_key)
                self.model   = os.environ.get("R3CON_AI_MODEL", "gemini-2.5-flash")
                self.offline = False
        
        elif self.provider == "groq":
            if OPENAI_AVAILABLE:
                self.api_key = os.environ.get("GROQ_API_KEY")
                self.client  = OpenAI(
                    api_key=self.api_key,
                    base_url="https://api.groq.com/openai/v1",
                    timeout=20.0,
                )
                # mixtral-8x7b-32768 was decommissioned by Groq; llama-3.3-70b-versatile
                # is the current general-purpose default. Override via R3CON_AI_MODEL.
                self.model   = os.environ.get("R3CON_AI_MODEL", "llama-3.3-70b-versatile")
                self.offline = False
        
        elif self.provider == "together":
            if TOGETHER_AVAILABLE:
                self.api_key = os.environ.get("TOGETHER_API_KEY")
                self.client  = Together(api_key=self.api_key)
                self.model   = os.environ.get("R3CON_AI_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
                self.offline = False

    def is_online(self) -> bool:
        return not self.offline

    def _call(self, prompt: str, max_tokens: int = 2048, response_format: Optional[dict] = None) -> str:
        if self.offline or not self.client and self.provider not in ("gemini","together"):
            return self._offline_analysis(prompt)
        
        try:
            if self.provider == "openai_compatible":
                kwargs = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                }
                if self.model.startswith("gpt-5"):
                    kwargs["max_completion_tokens"] = max_tokens
                    effort = os.environ.get("R3CON_AI_REASONING", "low").lower()
                    if effort in {"minimal", "low", "medium", "high"}:
                        kwargs["extra_body"] = {"reasoning": {"effort": effort}}
                else:
                    kwargs["max_tokens"] = max_tokens
                if response_format:
                    kwargs["response_format"] = response_format
                response = self.client.chat.completions.create(**kwargs)
                return response.choices[0].message.content or ""

            elif self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            
            elif self.provider == "deepseek":
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ]
                )
                return response.choices[0].message.content
            
            elif self.provider == "gemini":
                model = genai.GenerativeModel(self.model)
                response = model.generate_content(
                    f"{SYSTEM_PROMPT}\n\nUser query:\n{prompt}"
                )
                return response.text
            
            elif self.provider == "groq":
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ]
                )
                return response.choices[0].message.content
            
            elif self.provider == "together":
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ]
                )
                return response.choices[0].message.content
        
        except Exception as e:
            return f"[AI Error] {e}\n\nFalling back to offline mode."

    def chat(self, history: list) -> str:
        if self.offline:
            last = history[-1]["content"] if history else ""
            return self._offline_chat(last)
        
        try:
            if self.provider == "openai_compatible":
                kwargs = {
                    "model": self.model,
                    "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + history,
                }
                if self.model.startswith("gpt-5"):
                    kwargs["max_completion_tokens"] = 2048
                    effort = os.environ.get("R3CON_AI_REASONING", "low").lower()
                    if effort in {"minimal", "low", "medium", "high"}:
                        kwargs["extra_body"] = {"reasoning": {"effort": effort}}
                else:
                    kwargs["max_tokens"] = 2048
                response = self.client.chat.completions.create(**kwargs)
                return response.choices[0].message.content or ""

            elif self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=2048,
                    system=SYSTEM_PROMPT,
                    messages=history
                )
                return response.content[0].text
            
            elif self.provider in ("deepseek","groq","together"):
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=2048,
                    messages=[{"role": "system", "content": SYSTEM_PROMPT}] + history
                )
                return response.choices[0].message.content
            
            elif self.provider == "gemini":
                model = genai.GenerativeModel(self.model)
                conv_text = SYSTEM_PROMPT + "\n\n"
                for msg in history:
                    conv_text += f"{msg['role'].upper()}: {msg['content']}\n\n"
                response = model.generate_content(conv_text)
                return response.text
        
        except Exception as e:
            return f"[AI Error] {e}"

    # ── Core analysis methods ──────────────────────────────────

    def asm_to_pseudocode(self, asm: str, arch: str = "x86_64", lang: str = "C") -> str:
        return self._call(
            f"Architecture: {arch}\nConvert this assembly to clear commented {lang} pseudo-code. "
            f"Identify suspicious patterns (vulns, anti-debug, shellcode).\n\n"
            f"```asm\n{asm[:6000]}\n```", max_tokens=3000)

    def audit_code(self, code: str, lang: str = "c", focus: str = "all", depth: str = "deep") -> list:
        prompt = (
            f"Perform a {depth} security audit of this {lang} code. Focus: {focus}.\n"
            f"Respond ONLY with valid JSON array. Each object: "
            f"severity(CRITICAL/HIGH/MED/LOW/INFO), type, line(int or null), description, recommendation.\n\n"
            f"```{lang}\n{code[:8000]}\n```"
        )
        finding_schema = {
            "type": "json_schema",
            "json_schema": {
                "name": "security_findings",
                "strict": True,
                "schema": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MED", "LOW", "INFO"]},
                            "type": {"type": "string"},
                            "line": {"type": ["integer", "null"]},
                            "description": {"type": "string"},
                            "recommendation": {"type": "string"},
                        },
                        "required": ["severity", "type", "line", "description", "recommendation"],
                        "additionalProperties": False,
                    },
                },
            },
        }
        result = self._call(
            prompt,
            max_tokens=3000,
            response_format=finding_schema if self.provider == "openai_compatible" else None,
        )
        try:
            clean = re.sub(r"```json|```", "", result).strip()
            return json.loads(clean)
        except Exception:
            return [{"severity":"INFO","type":"AI Analysis","line":None,
                     "description": result[:500],"recommendation":""}]

    def analyze_strings(self, strings: list) -> str:
        return self._call(
            "Analyze these binary strings. Identify hardcoded creds, C2 indicators, "
            "crypto constants, suspicious paths/commands.\n\n"
            + "\n".join(strings[:200]))

    def heap_exploitation_analysis(self, code: str, allocator: str = "glibc") -> str:
        return self._call(
            f"Analyze this code for heap exploitation primitives ({allocator}). "
            f"Identify UAF, double-free, overflow, tcache poisoning, type confusion. "
            f"Describe exploitation primitives enabled.\n\n```c\n{code[:6000]}\n```",
            max_tokens=3000)

    def crypto_analysis(self, code: str) -> str:
        return self._call(
            f"Deep cryptographic audit. Check: non-constant-time comparisons, "
            f"weak keys/IVs/nonces, ECB mode, CBC padding oracle, nonce reuse, "
            f"weak PRNG, broken hashes, missing KDF, unauthenticated encryption.\n\n"
            f"```\n{code[:6000]}\n```", max_tokens=2500)

    def kernel_analysis(self, code: str, ktype: str = "auto") -> str:
        return self._call(
            f"Kernel {ktype} security analysis. Focus: race conditions, "
            f"missing copy_from_user, integer overflow before kmalloc, "
            f"NULL deref privesc, uninitialized data leaks, signal handlers, "
            f"Spectre gadgets, IOCTL validation.\n\n```c\n{code[:6000]}\n```",
            max_tokens=3000)

    def toctou_analysis(self, code: str) -> str:
        return self._call(
            f"Find all TOCTOU vulnerabilities. For each: CHECK op, USE op, "
            f"race window, exploitation scenario, fix.\n\n```\n{code[:6000]}\n```",
            max_tokens=2500)

    def protocol_analysis(self, code: str, protocol: str = "auto") -> str:
        return self._call(
            f"Analyze this {protocol} protocol implementation. Focus: state machine bugs, "
            f"parser differentials, length validation, integer overflow in length fields, "
            f"deserialization, replay attacks, downgrade vectors.\n\n"
            f"```\n{code[:6000]}\n```", max_tokens=2500)

    def generate_hypotheses(self, content: str, context: Optional[str] = None,
                             depth: str = "deep") -> str:
        ctx = f"Context: {context}" if context else ""
        return self._call(
            f"Authorized security research. {ctx}\n"
            f"Formulate specific 0day vulnerability hypotheses. For each:\n"
            f"1. HYPOTHESIS: vulnerability class\n"
            f"2. TRIGGER PATH: exact code path\n"
            f"3. ATTACKER CONTROL: what input is controlled\n"
            f"4. IMPACT: code exec / info leak / DoS / privesc\n"
            f"5. CONFIDENCE: High/Med/Low + reasoning\n"
            f"6. NEXT STEP: PoC approach / fuzzing strategy\n\n"
            f"```\n{content[:8000]}\n```", max_tokens=4000)

    def cve_match(self, code: str, patterns: list = None, limit: int = 10) -> str:
        return self._call(
            f"Match code patterns to known CVEs. For each match: "
            f"CVE ID, similarity reason, affected component, exploitation likelihood. "
            f"Limit {limit} most relevant.\n\n```\n{code[:6000]}\n```",
            max_tokens=2500)

    def find_variant(self, code: str, cve_info: dict) -> Optional[str]:
        result = self._call(
            f"CVE: {cve_info.get('id','?')}\n"
            f"Description: {cve_info.get('description','')}\n"
            f"Does this code contain a variant? If YES explain exactly. "
            f"If NO respond 'NO_MATCH'.\n\n```\n{code[:4000]}\n```",
            max_tokens=1000)
        return None if "NO_MATCH" in result else result

    def patch_diff_analysis(self, added: list, removed: list,
                             before: str, after: str) -> str:
        return self._call(
            f"Binary patch diff analysis.\nAdded functions: {added[:20]}\n"
            f"Removed functions: {removed[:20]}\n"
            f"What vulnerability class was patched? Root cause? "
            f"Exploitation primitive before patch? Possible CVE?",
            max_tokens=2000)

    def apk_analysis(self, manifest: str, smali: str = "",
                      strings: list = None) -> str:
        return self._call(
            f"Android APK security analysis.\n\n"
            f"AndroidManifest.xml:\n```xml\n{manifest[:3000]}\n```\n\n"
            f"Smali/bytecode sample:\n```\n{smali[:3000]}\n```\n\n"
            f"Interesting strings: {(strings or [])[:50]}\n\n"
            f"Check: exported components, dangerous permissions, hardcoded secrets, "
            f"insecure storage, weak crypto, tapjacking, intent injection, "
            f"insecure IPC, debug flags, backup enabled.",
            max_tokens=3000)

    def firmware_analysis(self, file_list: list, strings: list,
                           entropy_map: dict, context: str = "") -> str:
        return self._call(
            f"Firmware security analysis. {context}\n\n"
            f"Files found: {file_list[:80]}\n\n"
            f"High-entropy regions (possible encrypted/compressed): {entropy_map}\n\n"
            f"Interesting strings: {strings[:100]}\n\n"
            f"Check: hardcoded credentials, telnet/SSH backdoors, "
            f"unsafe update mechanisms (no signature check), "
            f"debug interfaces (UART/JTAG strings), "
            f"outdated libraries with known CVEs, "
            f"world-writable scripts, RTOS task overflow patterns.",
            max_tokens=3000)

    def fuzz_hints(self, code: str, function: str = None, fmt: str = "manual") -> str:
        return self._call(
            f"Generate fuzzing strategy for this code "
            f"{'focusing on ' + function if function else ''}.\n"
            f"Output format: {fmt}.\n\n"
            f"Provide:\n"
            f"1. Input format analysis (fields, lengths, types)\n"
            f"2. Boundary values to test\n"
            f"3. Mutation strategies\n"
            f"4. Most promising code paths to hit\n"
            f"5. {'AFL++ harness skeleton' if fmt == 'afl' else 'libFuzzer harness skeleton' if fmt == 'libfuzzer' else 'Manual test cases'}\n\n"
            f"```\n{code[:6000]}\n```", max_tokens=3000)

    def emulation_analysis(self, trace: list) -> str:
        return self._call(
            f"Analyze this CPU emulation trace for security issues. "
            f"Identify: suspicious memory accesses, potential exploitable conditions, "
            f"interesting code paths, anomalies.\n\nTrace:\n{json.dumps(trace[-50:], indent=2)}",
            max_tokens=2000)

    def frida_analysis(self, events: list) -> str:
        return self._call(
            f"Analyze these Frida runtime hook events for security issues. "
            f"Identify: dangerous call patterns, UAF indicators, "
            f"interesting data flows, potential vulnerabilities.\n\n"
            f"Events: {json.dumps(events[:100], indent=2)}",
            max_tokens=2000)

    # ── Offline fallback ──────────────────────────────────────

    def _offline_analysis(self, prompt: str) -> str:
        """Rule-based offline analysis when no API is available."""
        p = prompt.lower()
        if "asm" in p or "assembly" in p:
            return self._offline_asm_hints(prompt)
        elif "heap" in p or "malloc" in p:
            return self._offline_heap_hints()
        elif "crypto" in p or "cipher" in p:
            return self._offline_crypto_hints()
        elif "kernel" in p or "kmalloc" in p:
            return self._offline_kernel_hints()
        elif "apk" in p or "android" in p:
            return self._offline_apk_hints()
        elif "firmware" in p or "rtos" in p:
            return self._offline_firmware_hints()
        elif "fuzz" in p:
            return self._offline_fuzz_hints()
        elif "hypothesis" in p or "0day" in p:
            return self._offline_hypothesis_hints()
        else:
            return self._offline_generic()

    def _offline_chat(self, msg: str) -> str:
        return (
            "[OFFLINE MODE — No AI API key detected]\n\n"
            "r3con is running in offline mode. Static analysis modules are fully functional.\n\n"
            "To enable AI analysis, set one of:\n"
            "  export ANTHROPIC_API_KEY=sk-ant-...\n"
            "  export DEEPSEEK_API_KEY=sk-...\n"
            "  export GEMINI_API_KEY=...\n"
            "  export GROQ_API_KEY=gsk-...\n\n"
            "Available offline:\n"
            "  ✓ disasm file/strings/imports\n"
            "  ✓ audit file/dir (static patterns)\n"
            "  ✓ advanced heap/crypto/kernel\n"
            "  ✓ research cve-match (local DB)\n"
            "  ✓ apk manifest/permissions\n"
            "  ✓ firmware extract/strings/entropy\n\n"
            "Requires API key:\n"
            "  ✗ AI pseudo-code generation\n"
            "  ✗ AI hypothesis engine\n"
            "  ✗ Interactive AI shell"
        )

    def _offline_asm_hints(self, prompt: str) -> str:
        return (
            "[OFFLINE] Assembly Analysis — Rule-based hints\n\n"
            "Pattern checks applied:\n"
            "• call gets / strcpy / sprintf → potential stack overflow\n"
            "• sub rsp, N without bounds → check stack frame size\n"
            "• jmp rax/rcx → potential ROP gadget\n"
            "• int 0x80 / syscall → system call interface\n"
            "• rep stosb/movsb → bulk memory operations\n"
            "• xor reg,reg → register clear (common in shellcode)\n\n"
            "For full pseudo-code generation, set an AI API key."
        )

    def _offline_heap_hints(self) -> str:
        return ("[OFFLINE] Heap Analysis\n\n"
                "Checked: double free, UAF, heap overflow, tcache patterns.\n"
                "Set an API key for exploitation primitive analysis.")

    def _offline_crypto_hints(self) -> str:
        return ("[OFFLINE] Crypto Analysis\n\n"
                "Checked: MD5/SHA1/DES/RC4, ECB mode, timing side-channels, weak PRNG.\n"
                "Set an API key for deep analysis.")

    def _offline_kernel_hints(self) -> str:
        return ("[OFFLINE] Kernel Analysis\n\n"
                "Checked: integer overflow, boundary issues, race conditions, privesc patterns.\n"
                "Set an API key for full analysis.")

    def _offline_apk_hints(self) -> str:
        return ("[OFFLINE] APK Analysis\n\n"
                "Checked: permissions, debuggable, exported components, hardcoded strings.\n"
                "Set an API key for semantic analysis.")

    def _offline_firmware_hints(self) -> str:
        return ("[OFFLINE] Firmware Analysis\n\n"
                "Checked: entropie, magic bytes, hardcoded creds, debug strings.\n"
                "Set an API key for full semantic analysis.")

    def _offline_fuzz_hints(self) -> str:
        return ("[OFFLINE] Fuzzing Hints\n\n"
                "Generic strategy: test boundaries, empty inputs, format strings, integer overflow.\n"
                "Set an API key for targeted AI-guided fuzzing.")

    def _offline_hypothesis_hints(self) -> str:
        return ("[OFFLINE] Hypothesis Engine\n\n"
                "Manual research: map entry points, trace to dangerous sinks, find validation gaps.\n"
                "Set an API key for AI hypothesis generation.")

    def _offline_generic(self) -> str:
        return (
            "[OFFLINE MODE]\n\n"
            "Set one of these to enable AI:\n"
            "  export ANTHROPIC_API_KEY=sk-ant-...\n"
            "  export DEEPSEEK_API_KEY=sk-...\n"
            "  export GEMINI_API_KEY=...\n"
            "  export GROQ_API_KEY=gsk-..."
        )
