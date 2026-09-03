"""
r3con - Firmware Analyzer
Firmware image analysis: extraction, entropy, strings, vulnerability patterns.
Authorized security research only.
"""

import re
import os
import math
import struct
import subprocess
from pathlib import Path
from typing import List, Dict


# Known firmware magic bytes
MAGIC_SIGNATURES = {
    b'\x1f\x8b':           "gzip compressed",
    b'BZh':                "bzip2 compressed",
    b'\xfd7zXZ\x00':      "xz compressed",
    b'LZMA':               "LZMA compressed",
    b'\x27\x05\x19\x56':  "U-Boot image",
    b'hsqs':               "SquashFS (little-endian)",
    b'sqsh':               "SquashFS (big-endian)",
    b'\x85\x19\x01\xe0':  "JFFS2 filesystem",
    b'\x19\x85':           "JFFS2 (big-endian)",
    b'PK\x03\x04':        "ZIP archive",
    b'\x7fELF':           "ELF binary",
    b'MZ':                 "PE binary (Windows/UEFI)",
    b'\xeb\x3c\x90':      "FAT filesystem",
    b'\xeb\x58\x90':      "FAT32 filesystem",
    b'\x53\xef':           "EXT2/3/4 filesystem (at offset 0x438)",
    b'ANDROID!':           "Android boot image",
    b'\x41\x4e\x44\x52':  "Android sparse image",
}

# Dangerous patterns in firmware strings
FIRMWARE_VULN_PATTERNS = [
    (r'(?i)(password|passwd)\s*[=:]\s*\S+',
     "CRITICAL", "Hardcoded Credential",
     "Hardcoded password found in firmware"),
    (r'(?i)(admin|root|user)\s*[=:]\s*(admin|root|1234|password|default|toor)',
     "CRITICAL", "Default Credential",
     "Default credential pair found — common backdoor"),
    (r'(?i)(telnetd|telnet\s+-l)',
     "HIGH", "Telnet Service",
     "Telnet daemon string — cleartext remote access, no encryption"),
    (r'(?i)(gdbserver|gdb\s+--remote)',
     "HIGH", "Debug Server",
     "GDB server string — debug interface potentially exposed"),
    (r'(?i)/dev/ttyS[0-9]|uart[0-9]|console=ttyS',
     "MED", "UART Console",
     "UART serial console string — potential debug access point"),
    (r'(?i)(jtag|boundary.scan|openocd)',
     "MED", "JTAG Interface",
     "JTAG debugging string — hardware debug interface present"),
    (r'(?i)(dropbear|openssh|sshd)',
     "INFO", "SSH Service",
     "SSH daemon — verify key-based auth, no password login"),
    (r'(?i)(wget|curl)\s+http://',
     "HIGH", "Insecure Update",
     "Firmware update over HTTP — no transport security, MitM possible"),
    (r'(?i)(no.verify|skip.verify|insecure|--no-check-certificate)',
     "CRITICAL", "Verification Disabled",
     "Signature/certificate verification disabled — firmware tampering possible"),
    (r'(?i)(busybox|ash|dash|bash|sh)\s*-[ci]',
     "MED", "Shell Invocation",
     "Shell invocation string — verify no user-controlled input reaches here"),
    (r'(?i)(chmod\s+777|chmod\s+a\+[rwx])',
     "HIGH", "World-Writable Permission",
     "World-writable chmod — security misconfiguration"),
    (r'(?i)(/etc/shadow|/etc/passwd)\s*world',
     "CRITICAL", "Password File Exposure",
     "Password file with world access"),
    (r'(?i)CVE-[0-9]{4}-[0-9]+',
     "HIGH", "Known CVE Reference",
     "CVE identifier found in strings — may indicate vulnerable component"),
    (r'(?i)(openssl|libssl)\s+[01]\.[0-9]',
     "HIGH", "Old OpenSSL Version",
     "Old OpenSSL version string — likely has known CVEs"),
    (r'(?i)linux\s+[23]\.[0-9]|kernel\s+[23]\.[0-9]',
     "HIGH", "Old Kernel Version",
     "Old Linux kernel version — multiple known vulnerabilities"),
    (r'(?i)(udhcpc|dnsmasq|hostapd)\s+[0-9]\.[0-9]',
     "MED", "Service Version String",
     "Network service version — check against CVE database"),
]

INTERESTING_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/etc/init.d/", "/etc/rc.d/", "/etc/crontab",
    "/tmp/", "/var/run/", "/proc/",
    "/usr/sbin/telnetd", "/usr/bin/gdbserver",
    "/bin/sh", "/bin/bash", "/bin/busybox",
    "update.sh", "upgrade.sh", "factory_reset",
]


class FirmwareAnalyzer:
    def __init__(self, firmware_path: str):
        self.path       = firmware_path
        self.size       = 0
        self.data       = b""
        self.strings    = []
        self.regions    = []
        self._loaded    = False

    def load(self) -> bool:
        try:
            self.data  = Path(self.path).read_bytes()
            self.size  = len(self.data)
            self._loaded = True
            return True
        except Exception:
            return False

    # ── Identification ────────────────────────────────────────

    def identify(self) -> Dict:
        """Identify firmware type and embedded components."""
        result = {
            "size":       self.size,
            "size_human": self._human_size(self.size),
            "components": [],
            "arch_hints": [],
        }
        if not self._loaded:
            return result

        # Scan for magic bytes
        for magic, desc in MAGIC_SIGNATURES.items():
            offset = self.data.find(magic)
            if offset >= 0:
                result["components"].append({
                    "offset": offset,
                    "hex":    hex(offset),
                    "type":   desc,
                })

        result["component_counts"] = {}
        for component in result["components"]:
            kind = component["type"]
            result["component_counts"][kind] = result["component_counts"].get(kind, 0) + 1
        result["filesystem_hints"] = [c for c in result["components"] if "filesystem" in c["type"].lower() or "squash" in c["type"].lower() or "jffs" in c["type"].lower() or "ext" in c["type"].lower()]
        result["service_hints"] = sorted({name for name in ("telnetd", "gdbserver", "dropbear", "sshd", "dnsmasq", "hostapd", "busybox") if name in self.data.decode("latin-1", errors="ignore").lower()})

        # Architecture hints from ELF headers
        elf_offsets = [i for i in range(len(self.data)-4)
                       if self.data[i:i+4] == b'\x7fELF']
        for off in elf_offsets[:5]:
            if off + 19 < len(self.data):
                ei_class  = self.data[off+4]
                ei_data   = self.data[off+5]
                e_machine = struct.unpack_from("<H" if ei_data==1 else ">H",
                                               self.data, off+18)[0]
                arch_map  = {3:"x86", 62:"x86_64", 40:"ARM",
                             183:"ARM64", 8:"MIPS", 243:"RISC-V"}
                arch      = arch_map.get(e_machine, f"unknown({e_machine})")
                bits      = "64-bit" if ei_class == 2 else "32-bit"
                endian    = "little-endian" if ei_data == 1 else "big-endian"
                result["arch_hints"].append(
                    f"ELF at 0x{off:x}: {arch} {bits} {endian}")

        return result

    # ── Entropy analysis ──────────────────────────────────────

    def entropy_map(self, block_size: int = 4096) -> List[Dict]:
        """Compute entropy per block to find encrypted/compressed regions."""
        regions = []
        for offset in range(0, self.size, block_size):
            block   = self.data[offset:offset+block_size]
            entropy = self._entropy(block)
            regions.append({
                "offset":  offset,
                "hex":     hex(offset),
                "size":    len(block),
                "entropy": round(entropy, 3),
                "type":    self._entropy_class(entropy),
            })
        return regions

    def high_entropy_regions(self, threshold: float = 7.0) -> List[Dict]:
        """Return only high-entropy (encrypted/compressed) regions."""
        return [r for r in self.entropy_map() if r["entropy"] >= threshold]

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq  = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        total = len(data)
        return -sum((c/total) * math.log2(c/total) for c in freq.values())

    def _entropy_class(self, e: float) -> str:
        if e >= 7.5: return "encrypted/compressed"
        if e >= 6.5: return "high entropy"
        if e >= 4.0: return "normal"
        return "low entropy (text/padding)"

    # ── String extraction ─────────────────────────────────────

    def extract_strings(self, min_len: int = 6) -> List[Dict]:
        """Extract printable strings with offsets and categories."""
        regex   = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')
        results = []
        for m in regex.finditer(self.data):
            s   = m.group().decode("ascii", errors="ignore")
            cat = self._categorize_string(s)
            results.append({
                "offset":   m.start(),
                "hex":      hex(m.start()),
                "value":    s,
                "category": cat,
            })
        self.strings = results
        return results

    def _categorize_string(self, s: str) -> str:
        if re.search(r'(?i)(password|passwd|secret|key|token)', s): return "credential"
        if re.search(r'(?i)\b(?:admin|root|user)\s*[:=]\s*(?:admin|root|1234|password|default|toor)\b', s): return "credential"
        if re.search(r'https?://', s):                               return "url"
        if re.search(r'^(/[a-z][a-z0-9/_.-]{3,})$', s):            return "path"
        if re.search(r'(?i)(error|fail|warn|debug|info)\b', s):     return "log"
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s): return "ip_addr"
        if re.search(r'(?i)(telnet|ssh|uart|jtag|gdb)', s):         return "debug"
        if re.search(r'CVE-[0-9]{4}-[0-9]+', s):                   return "cve_ref"
        return ""

    # ── Vulnerability scan ────────────────────────────────────

    def scan_vulns(self) -> List[Dict]:
        """Scan extracted strings for vulnerability patterns."""
        findings = []
        if not self.strings:
            self.extract_strings()

        for s_entry in self.strings:
            s   = s_entry["value"]
            off = s_entry["hex"]
            for pat, sev, vtype, desc in FIRMWARE_VULN_PATTERNS:
                if re.search(pat, s):
                    findings.append({
                        "severity":       sev,
                        "type":           vtype,
                        "offset":         off,
                        "line":           None,
                        "description":    f"{desc}: '{s[:60]}'",
                        "recommendation": desc.split("—")[-1].strip()
                                          if "—" in desc else "Investigate this string"
                    })
                    break

        return findings

    # ── Path analysis ─────────────────────────────────────────

    def find_interesting_paths(self) -> List[Dict]:
        """Find interesting filesystem paths in the firmware."""
        results = []
        if not self.strings:
            self.extract_strings()

        for s_entry in self.strings:
            s = s_entry["value"]
            for path in INTERESTING_PATHS:
                if path.lower() in s.lower():
                    results.append({
                        "offset": s_entry["hex"],
                        "path":   s,
                        "match":  path,
                    })
        return results

    # ── Extraction ────────────────────────────────────────────

    def extract_filesystem(self, output_dir: str) -> Dict:
        """Try to extract filesystem using binwalk or dd."""
        result = {"success": False, "method": None, "output": output_dir, "error": None}
        os.makedirs(output_dir, exist_ok=True)

        # Try binwalk
        try:
            proc = subprocess.run(
                ["binwalk", "--extract", "--directory", output_dir, self.path],
                capture_output=True, text=True, timeout=120
            )
            result["method"] = "binwalk"
            result["returncode"] = proc.returncode
            result["stdout"] = (proc.stdout or "")[-20000:]
            result["stderr"] = (proc.stderr or "")[-20000:]
            result["success"] = proc.returncode == 0
            if not result["success"]:
                result["error"] = "binwalk_failed"
            return result
        except FileNotFoundError:
            pass
        except Exception as e:
            result["error"] = str(e)

        # Try dd extraction based on identified components
        result["method"] = "manual"
        result["error"]  = (
            "binwalk not found. Install it: pip install binwalk\n"
            "Or: sudo apt install binwalk\n\n"
            "Manual extraction hint: use 'dd if=firmware.bin bs=1 skip=<offset>' "
            "for each identified component."
        )
        return result

    # ── Utilities ─────────────────────────────────────────────

    def _human_size(self, size: int) -> str:
        for unit in ["B","KB","MB","GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def get_summary(self) -> Dict:
        """Get a summary suitable for AI analysis."""
        id_info  = self.identify()
        strings  = self.extract_strings()[:200]

        cred_strings  = [s["value"] for s in strings if s["category"] == "credential"]
        url_strings   = [s["value"] for s in strings if s["category"] == "url"]
        debug_strings = [s["value"] for s in strings if s["category"] == "debug"]
        path_strings  = [s["value"] for s in strings if s["category"] == "path"]

        entropy_map   = self.entropy_map()
        high_entropy  = [r for r in entropy_map if r["entropy"] >= 7.0]

        return {
            "file_list":    id_info.get("components", []),
            "arch_hints":   id_info.get("arch_hints", []),
            "strings": {
                "credentials": cred_strings[:20],
                "urls":        url_strings[:20],
                "debug":       debug_strings[:20],
                "paths":       path_strings[:30],
            },
            "entropy_map":  {
                "high_entropy_regions": len(high_entropy),
                "samples": high_entropy[:5],
            },
            "size":         self._human_size(self.size),
        }
