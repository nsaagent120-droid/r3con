"""
r3con v5.0.3 - Professional Config Manager
Powerful, layered configuration: defaults < YAML < env < CLI
Supports profiles, validation, dot-notation, and per-tool config
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import json

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

DEFAULT_CONFIG = {
    "version": "5.0.3",
    "profile": "auto",  # auto, quick, deep, full, binary, firmware, apk, network, source, custom

    "analysis": {
        "default_depth": "deep",
        "default_focus": "all",
        "max_file_size_mb": 500,
        "max_binary_size_mb": 500,
        "max_firmware_size_mb": 1024,
        "max_pcap_size_mb": 500,
        "parallel": True,
        "max_workers": 4,
        "timeout": 120,
        "save_to_db": True,
        "cache_enabled": True,
        "cache_ttl_days": 7,
        "cache_max_entries": 5000,
        "artifact_retention_days": 7,
    },

    "limits": {
        "max_strings": 10000,
        "max_functions": 2000,
        "max_imports": 5000,
        "max_findings": 10000,
        "max_matches": 1000,
        "max_depth": 20,
        "max_chain_length": 50,
        "max_output_mb": 10,
        "max_log_mb": 5,
    },

    "disasm": {
        "default_arch": "auto",
        "default_output": "pseudocode",
        "engine": "auto",  # auto, capstone, r2, rizin, ghidra
        "max_instructions": 5000,
        "show_bytes": False,
        "syntax": "intel",
    },

    "binary": {
        "checksec": True,
        "rop_gadgets": True,
        "strings": True,
        "imports": True,
        "exports": True,
        "sections": True,
        "protections": True,
        "detect_packer": True,
        "detect_crypto": True,
        "entropy_analysis": True,
    },

    "firmware": {
        "entropy_block_size": 4096,
        "entropy_threshold": 7.0,
        "min_string_length": 6,
        "extract": False,
        "extract_output": "./fw_extracted",
        "detect_backdoors": True,
        "detect_creds": True,
        "detect_keys": True,
        "max_strings": 10000,
    },

    "apk": {
        "decompile": False,
        "dex_analysis": True,
        "manifest_analysis": True,
        "permission_analysis": True,
        "url_extraction": True,
        "secret_detection": True,
        "native_lib_analysis": True,
    },

    "network": {
        "max_packets": 100000,
        "max_flows": 1000,
        "detect_cleartext": True,
        "detect_legacy": True,
        "extract_iocs": True,
        "dns_analysis": True,
        "http_analysis": True,
        "tls_analysis": True,
        "live_capture": {
            "default_interface": "any",
            "default_duration": 30,
            "default_max_packets": 10000,
            "require_root": True,
        }
    },

    "audit": {
        "languages": ["c", "cpp", "python", "java", "go", "rust", "js", "php"],
        "checks": {
            "memory": True,
            "crypto": True,
            "race": True,
            "kernel": True,
            "injection": True,
            "xss": True,
            "sqli": True,
            "hardcoded_secrets": True,
            "weak_crypto": True,
            "insecure_random": True,
        },
        "severity_filter": "low",  # info, low, medium, high, critical
        "confidence_filter": 0.0,
    },

    "external_tools": {
        "auto_detect": True,
        "prefer": {
            "disasm": "capstone",  # capstone, r2, rizin, ghidra
            "decompiler": "r2",  # r2, ghidra, angr
            "firmware": "binwalk",  # binwalk, firmwalker
            "apk": "internal",  # internal, jadx, apktool
            "network": "internal",  # internal, tshark, zeek
            "dynamic": "gdb",  # gdb, qemu, frida
        },
        "timeout": {
            "default": 60,
            "ghidra": 180,
            "angr": 120,
            "jadx": 60,
            "binwalk": 120,
        },
        "enabled": {
            # Binary analysis
            "r2": True,
            "rizin": True,
            "ghidra": False,  # opt-in, heavy
            "angr": False,
            "checksec": True,
            "ropper": True,
            "one_gadget": True,
            "objdump": True,
            "readelf": True,
            "nm": True,
            "strings": True,
            "file": True,
            "strace": False,
            "ltrace": False,
            # Firmware
            "binwalk": True,
            "firmwalker": False,
            "sasquatch": False,
            # APK
            "jadx": False,
            "apktool": False,
            "dex2jar": False,
            # Network
            "tshark": True,
            "zeek": True,
            "tcpdump": True,
            # Dynamic
            "gdb": True,
            "pwndbg": True,
            "gef": True,
            "qemu": False,
            "frida": False,
            "valgrind": False,
            # Fuzzing
            "afl": False,
            "honggfuzz": False,
            # Misc
            "yara": True,
            "clamav": False,
        },
        "paths": {
            # Custom paths, env var overrides: R3CON_TOOL_<NAME>
            # e.g. R3CON_TOOL_GHIDRA=/opt/ghidra/support/analyzeHeadless
        }
    },

    "reporting": {
        "format": "md",
        "output_dir": "~/.r3con/reports",
        "include_code_snippets": True,
        "include_cvss": True,
        "include_cwe": True,
        "include_fix": True,
        "include_evidence": True,
        "sarif": {
            "enabled": False,
            "output": None,
        },
        "html": {
            "theme": "dark",
            "include_graph": True,
        }
    },

    "ai": {
        "enabled": "auto",  # auto, true, false
        "provider": "auto",  # auto, local, openai, anthropic, together, deepseek, gemini, groq
        "local_url": "http://localhost:11434",
        "local_model": "auto",
        "max_tokens": 4096,
        "timeout": 120,
        "multi_ai": False,
        "consensus_threshold": 0.7,
    },

    "expert_mode": {
        "enabled": False,
        "cvss_scoring": True,
        "attack_scenarios": True,
        "priority_matrix": True,
        "executive_summary": True,
        "exploitation_techniques": True,
    },

    "dashboard": {
        "enabled": False,
        "port": 5000,
        "host": "127.0.0.1",
        "auto_refresh": 30,
        "auth": False,
    },

    "profiles": {
        "quick": {
            "description": "Fast scan, minimal tools",
            "analysis": {"max_workers": 2, "timeout": 30},
            "limits": {"max_strings": 1000, "max_findings": 100},
            "external_tools": {"enabled": {"ghidra": False, "angr": False, "qemu": False}},
        },
        "deep": {
            "description": "Thorough analysis, balanced",
            "analysis": {"max_workers": 4, "timeout": 120},
            "external_tools": {"prefer": {"disasm": "r2"}},
        },
        "full": {
            "description": "Maximum capabilities, all tools",
            "analysis": {"max_workers": 6, "timeout": 300, "max_file_size_mb": 1024},
            "limits": {"max_strings": 50000, "max_findings": 50000},
            "external_tools": {"enabled": {"ghidra": True, "angr": True, "jadx": True, "binwalk": True}},
            "binary": {"rop_gadgets": True, "detect_packer": True},
            "firmware": {"extract": True},
        },
        "binary": {
            "description": "Binary-focused",
            "external_tools": {"prefer": {"disasm": "r2", "decompiler": "ghidra"}},
            "binary": {"checksec": True, "rop_gadgets": True},
        },
        "firmware": {
            "description": "Firmware-focused, extraction enabled",
            "firmware": {"extract": True, "detect_backdoors": True},
            "external_tools": {"enabled": {"binwalk": True, "firmwalker": True}},
        },
        "apk": {
            "description": "APK-focused",
            "apk": {"decompile": True, "dex_analysis": True},
            "external_tools": {"enabled": {"jadx": True, "apktool": True}},
        },
        "network": {
            "description": "PCAP analysis with external decoders",
            "network": {"max_packets": 500000},
            "external_tools": {"enabled": {"tshark": True, "zeek": True}},
        },
        "bugbounty": {
            "description": "Bug bounty oriented, secrets + vulns",
            "audit": {"checks": {"hardcoded_secrets": True, "injection": True, "xss": True, "sqli": True}},
            "reporting": {"include_evidence": True},
        },
    },

    "logging": {
        "level": "info",  # debug, info, warning, error
        "file": None,  # ~/.r3con/r3con.log
        "json": False,
    },
}


class ConfigManager:
    """Powerful layered config manager."""

    def __init__(self, config_path: Optional[str] = None, profile: Optional[str] = None):
        self.config_path = self._find_config(config_path)
        self.profile_name = profile or os.environ.get("R3CON_PROFILE", "auto")
        self.config = self._load()

    def _find_config(self, explicit: Optional[str]) -> Optional[Path]:
        candidates = []
        if explicit:
            candidates.append(Path(explicit))
        if os.environ.get("R3CON_CONFIG"):
            candidates.append(Path(os.environ["R3CON_CONFIG"]))
        candidates.extend([
            Path.cwd() / "config.yaml",
            Path.cwd() / "r3con.yaml",
            Path.cwd() / ".r3con.yaml",
            Path.home() / ".r3con" / "config.yaml",
            Path.home() / ".config" / "r3con" / "config.yaml",
            Path("/etc/r3con/config.yaml"),
            Path(__file__).parent.parent / "config.yaml",
        ])
        for p in candidates:
            try:
                if p.is_file() and p.stat().st_size < 1024*1024:  # 1MB max
                    return p
            except (OSError, RuntimeError):
                continue
        return None

    def _load(self) -> Dict[str, Any]:
        # Start with defaults
        config = self._deep_copy(DEFAULT_CONFIG)

        # Layer 1: YAML file
        if self.config_path and self.config_path.is_file():
            try:
                if YAML_AVAILABLE:
                    with open(self.config_path, 'r', encoding='utf-8') as f:
                        yaml_data = yaml.safe_load(f) or {}
                    config = self._deep_merge(config, yaml_data)
                else:
                    # Fallback to JSON if YAML not available
                    with open(self.config_path, 'r', encoding='utf-8') as f:
                        try:
                            json_data = json.loads(f.read())
                            config = self._deep_merge(config, json_data)
                        except json.JSONDecodeError:
                            pass
            except (OSError, ValueError, yaml.YAMLError):
                pass

        # Layer 2: Environment variables R3CON_*
        config = self._apply_env_overrides(config)

        # Layer 3: Profile
        if self.profile_name and self.profile_name != "auto":
            profile_cfg = config.get("profiles", {}).get(self.profile_name)
            if profile_cfg:
                config = self._deep_merge(config, profile_cfg)

        # Validation
        self._validate(config)

        return config

    def _apply_env_overrides(self, config: Dict) -> Dict:
        """Apply R3CON_* env vars. E.g. R3CON_ANALYSIS_TIMEOUT=300"""
        for key, value in os.environ.items():
            if not key.startswith("R3CON_"):
                continue
            # Skip known non-config envs
            if key in ("R3CON_CONFIG", "R3CON_PROFILE", "R3CON_THEME", "R3CON_NO_COLOR", "R3CON_NO_ANIMATION"):
                continue
            # Parse: R3CON_ANALYSIS_TIMEOUT -> analysis.timeout
            path = key[6:].lower().split("_")
            if len(path) < 2:
                continue

            # Special handling for tool paths: R3CON_TOOL_GHIDRA
            if path[0] == "tool" and len(path) >= 2:
                tool_name = "_".join(path[1:]).lower()
                if "external_tools" not in config:
                    config["external_tools"] = {}
                if "paths" not in config["external_tools"]:
                    config["external_tools"]["paths"] = {}
                config["external_tools"]["paths"][tool_name] = value
                continue

            # Convert value
            converted = self._convert_env_value(value)

            # Navigate and set
            current = config
            for part in path[:-1]:
                if part not in current or not isinstance(current[part], dict):
                    current[part] = {}
                current = current[part]
            current[path[-1]] = converted

        # Direct overrides for common cases
        env_map = {
            "R3CON_TIMEOUT": ("analysis", "timeout"),
            "R3CON_MAX_WORKERS": ("analysis", "max_workers"),
            "R3CON_CACHE_DIR": ("analysis", "cache_dir"),
            "R3CON_EXPERT_MODE": ("expert_mode", "enabled"),
            "R3CON_MULTI_AI": ("ai", "multi_ai"),
        }
        for env_key, (section, opt) in env_map.items():
            if env_key in os.environ:
                if section not in config:
                    config[section] = {}
                config[section][opt] = self._convert_env_value(os.environ[env_key])

        return config

    def _convert_env_value(self, value: str) -> Any:
        """Convert env string to appropriate type."""
        lower = value.lower()
        if lower in ("true", "yes", "1", "on"):
            return True
        if lower in ("false", "no", "0", "off"):
            return False
        # Try int
        try:
            if "." not in value:
                return int(value)
        except ValueError:
            pass
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        return value

    def _validate(self, config: Dict):
        """Validate critical values."""
        # Clamp analysis values
        analysis = config.get("analysis", {})
        analysis["timeout"] = max(1, min(int(analysis.get("timeout", 120)), 3600))
        analysis["max_workers"] = max(1, min(int(analysis.get("max_workers", 4)), 16))
        analysis["max_file_size_mb"] = max(1, min(int(analysis.get("max_file_size_mb", 500)), 4096))

        # Clamp limits
        limits = config.get("limits", {})
        limits["max_strings"] = max(100, min(int(limits.get("max_strings", 10000)), 100000))
        limits["max_findings"] = max(100, min(int(limits.get("max_findings", 10000)), 100000))

        # Validate profile
        if config.get("profile") not in ("auto", "quick", "deep", "full", "binary", "firmware", "apk", "network", "source", "custom", "bugbounty"):
            config["profile"] = "auto"

    def get(self, key: str, default: Any = None) -> Any:
        """Get value with dot notation: 'analysis.timeout'"""
        parts = key.split(".")
        current = self.config
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                return default
            current = current[part]
        return current

    def get_int(self, key: str, default: int = 0) -> int:
        val = self.get(key, default)
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        val = self.get(key, default)
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.lower() in ("true", "yes", "1", "on")
        return bool(val)

    def get_list(self, key: str, default: Optional[List] = None) -> List:
        val = self.get(key, default or [])
        if isinstance(val, list):
            return val
        return default or []

    def is_tool_enabled(self, tool: str) -> bool:
        """Check if external tool is enabled."""
        return self.get_bool(f"external_tools.enabled.{tool}", False)

    def get_tool_timeout(self, tool: str) -> int:
        """Get tool-specific timeout."""
        return self.get_int(f"external_tools.timeout.{tool}", self.get_int("external_tools.timeout.default", 60))

    def get_tool_path(self, tool: str) -> Optional[str]:
        """Get custom tool path from config or env."""
        # Env override already applied to external_tools.paths
        return self.get(f"external_tools.paths.{tool}")

    def get_preferred(self, category: str) -> str:
        """Get preferred tool for category: disasm, decompiler, etc."""
        return self.get(f"external_tools.prefer.{category}", "auto")

    def to_dict(self) -> Dict[str, Any]:
        return self._deep_copy(self.config)

    def save(self, path: Optional[str] = None):
        """Save current config to YAML."""
        target = Path(path) if path else (Path.home() / ".r3con" / "config.yaml")
        target.parent.mkdir(parents=True, exist_ok=True)
        if YAML_AVAILABLE:
            with open(target, 'w', encoding='utf-8') as f:
                yaml.safe_dump(self.config, f, default_flow_style=False, sort_keys=False)
        else:
            with open(target, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> Dict:
        """Deep merge override into base."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigManager._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    @staticmethod
    def _deep_copy(d: Dict) -> Dict:
        """Deep copy via json."""
        try:
            return json.loads(json.dumps(d))
        except (TypeError, ValueError):
            # Fallback shallow
            return {k: (v.copy() if isinstance(v, dict) else v) for k, v in d.items()}

    def __repr__(self):
        return f"<ConfigManager profile={self.profile_name} path={self.config_path}>"


# Global singleton for convenience
_global_config: Optional[ConfigManager] = None

def get_config(config_path: Optional[str] = None, profile: Optional[str] = None, force_reload: bool = False) -> ConfigManager:
    global _global_config
    if _global_config is None or force_reload or config_path or profile:
        _global_config = ConfigManager(config_path=config_path, profile=profile)
    return _global_config

def get(key: str, default: Any = None) -> Any:
    return get_config().get(key, default)
