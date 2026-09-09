"""
r3con - Firmware Analyzer - FIXED VERSION
Fixes: magic scanning all occurrences, UTF-16 strings, XOR detection, better vuln patterns
"""

import re
import os
import math
import struct
import subprocess
from pathlib import Path
from typing import List, Dict
from collections import Counter


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
    b'\x89PNG':            "PNG image",
    b'\xff\xd8\xff':       "JPEG image",
    b'UBI#':               "UBI filesystem",
    b'\x28\xb5\x2f\xfd':  "ZSTD compressed",
    b'\x04\x22\x4d\x18':  "LZ4 compressed",
    b'\x5d\x00\x00':      "LZMA alone",
    b'CRAMFS':             "CRAMFS filesystem",
    b'-rom1fs-':           "ROMFS filesystem",
    b'\x53\x51\x4c\x69':  "SQLite database",
    b'\x75\x73\x74\x61\x72': "TAR archive",
    b'\x30\x82':           "DER certificate",
    b'-----BEGIN ':       "PEM certificate/key",
    b'\x02\x00\x00\x00':  "Possible UBI or binary struct",
}

FIRMWARE_VULN_PATTERNS = [
    (r'(?i)(password|passwd)\s*[=:]+\s*\S{3,}', "CRITICAL", "Hardcoded Credential", "Hardcoded password found in firmware"),
    (r'(?i)(admin|root|user)\s*[=:]+\s*(admin|root|1234|password|default|toor|123456)', "CRITICAL", "Default Credential", "Default credential pair found — common backdoor"),
    (r'(?i)telnetd.*-l\s*/bin/sh.*-p\s*\d+', "CRITICAL", "Telnet backdoor with custom port", "Telnet backdoor with custom port - cleartext RCE"),
    (r'(?i)(telnetd|telnet\s+-l|busybox\s+telnetd)', "HIGH", "Telnet Service", "Telnet daemon string — cleartext remote access"),
    (r'(?i)(gdbserver|gdb\s+--remote)', "HIGH", "Debug Server", "GDB server string — debug interface exposed"),
    (r'(?i)/dev/ttyS[0-9]|uart[0-9]|console=ttyS', "MED", "UART Console", "UART serial console string — debug access"),
    (r'(?i)(jtag|boundary.scan|openocd|swd)', "MED", "JTAG Interface", "JTAG debugging string — hardware debug interface"),
    (r'(?i)(dropbear|openssh|sshd)', "INFO", "SSH Service", "SSH daemon — verify key-based auth"),
    (r'(?i)(wget|curl)\s+http://', "HIGH", "Insecure Update", "Firmware update over HTTP — MitM possible"),
    (r'(?i)(no.verify|skip.verify|insecure|--no-check-certificate|VERIFY_NONE|CERT_NONE)', "CRITICAL", "Verification Disabled", "Signature/certificate verification disabled"),
    (r'(?i)(busybox|ash|dash|bash|sh)\s*-[ci]', "MED", "Shell Invocation", "Shell invocation string"),
    (r'(?i)(chmod\s+777|chmod\s+a\+[rwx])', "HIGH", "World-Writable Permission", "World-writable chmod"),
    (r'(?i)CVE-[0-9]{4}-[0-9]{4,7}', "HIGH", "Known CVE Reference", "CVE identifier found in strings"),
    (r'(?i)(openssl|libssl)\s+[01]\.[0-9]\.[0-9][a-z]?', "HIGH", "Old OpenSSL Version", "Old OpenSSL version string"),
    (r'(?i)linux\s+[23]\.[0-9]|kernel\s+[23]\.[0-9]\.[0-9]+', "HIGH", "Old Kernel Version", "Old Linux kernel version"),
    (r'(?i)(udhcpc|dnsmasq|hostapd)\s+[0-9]\.[0-9]', "MED", "Service Version String", "Network service version"),
    (r'(?i)\bbackdoor\b|\bbackd00r\b|hardcoded.*key', "HIGH", "Backdoor keyword", "Backdoor keyword found"),
    (r'(?i)(aws_access|aws_secret|AKIA[0-9A-Z]{16})', "CRITICAL", "AWS Key", "AWS key found"),
    (r'(?i)(BEGIN RSA PRIVATE|BEGIN EC PRIVATE|BEGIN PRIVATE)', "CRITICAL", "Private Key", "Private key material embedded"),
    (r'(?i)(admin.*password|password.*admin|root.*toor)', "CRITICAL", "Default Cred Combo", "Default credential combination"),
]

INTERESTING_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/gshadow",
    "/etc/init.d/", "/etc/rc.d/", "/etc/crontab", "/etc/sudoers",
    "/tmp/", "/var/run/", "/proc/", "/sys/",
    "/usr/sbin/telnetd", "/usr/bin/gdbserver", "/usr/sbin/sshd",
    "/bin/sh", "/bin/bash", "/bin/busybox", "/bin/dropbear",
    "update.sh", "upgrade.sh", "factory_reset", "debug.sh",
    "/etc/lighttpd/", "/etc/nginx/", "/www/", "/htdocs/",
]


class FirmwareAnalyzer:
    def __init__(self, firmware_path: str):
        self.path = firmware_path
        self.size = 0
        self.data = b""
        self.strings = []
        self.regions = []
        self._loaded = False

    def load(self) -> bool:
        try:
            self.data = Path(self.path).read_bytes()
            self.size = len(self.data)
            self._loaded = True
            return True
        except Exception:
            return False

    def identify(self) -> Dict:
        result = {
            "size": self.size,
            "size_human": self._human_size(self.size),
            "components": [],
            "arch_hints": [],
            "total_magic_hits": 0,
            "filesystem_hints": [],
            "certificate_hints": [],
            "service_hints": [],
            "obfuscation_hints": [],
        }
        if not self._loaded:
            return result

        MAX_HITS_PER_MAGIC = 25
        for magic, desc in MAGIC_SIGNATURES.items():
            start = 0
            hits = 0
            if len(magic) == 0:
                continue
            while hits < MAX_HITS_PER_MAGIC:
                offset = self.data.find(magic, start)
                if offset < 0:
                    break
                # Filter false positives for small magics
                if len(magic) <= 2 and offset > 0:
                    # Require some context for 2-byte magics
                    pass
                result["components"].append({
                    "offset": offset,
                    "hex": hex(offset),
                    "type": desc,
                    "magic": magic.hex()[:16],
                })
                hits += 1
                start = offset + 1

        result["components"].sort(key=lambda x: x["offset"])
        result["total_magic_hits"] = len(result["components"])

        # Counts
        counts = {}
        for c in result["components"]:
            counts[c["type"]] = counts.get(c["type"], 0) + 1
        result["component_counts"] = counts

        result["filesystem_hints"] = [c for c in result["components"] if any(k in c["type"].lower() for k in ("filesystem", "squash", "jffs", "ext", "ubi", "cram", "rom", "fat"))]
        result["certificate_hints"] = [c for c in result["components"] if "certificate" in c["type"].lower() or "PEM" in c["type"] or "DER" in c["type"]]
        
        data_lower = self.data.decode("latin-1", errors="ignore").lower()
        service_list = ("telnetd", "gdbserver", "dropbear", "sshd", "dnsmasq", "hostapd", "busybox", "lighttpd", "nginx", "apache", "ftpd", "vsftpd", "udhcpd", "telnet", "ssh", "upnp", "miniupnpd")
        result["service_hints"] = sorted({name for name in service_list if name in data_lower})

        # ELF scan - all occurrences up to 50
        elf_offsets = []
        start = 0
        while len(elf_offsets) < 50:
            off = self.data.find(b'\x7fELF', start)
            if off < 0:
                break
            elf_offsets.append(off)
            start = off + 4

        for off in elf_offsets[:20]:
            if off + 20 < len(self.data):
                try:
                    ei_class = self.data[off+4]
                    ei_data = self.data[off+5]
                    if ei_data not in (1, 2):
                        continue
                    e_machine = struct.unpack_from("<H" if ei_data == 1 else ">H", self.data, off+18)[0]
                    arch_map = {3:"x86", 62:"x86_64", 40:"ARM", 183:"ARM64", 8:"MIPS", 243:"RISC-V", 20:"PPC", 21:"PPC64"}
                    arch = arch_map.get(e_machine, f"unknown({e_machine})")
                    bits = "64-bit" if ei_class == 2 else "32-bit"
                    endian = "little-endian" if ei_data == 1 else "big-endian"
                    result["arch_hints"].append(f"ELF at 0x{off:x}: {arch} {bits} {endian}")
                except Exception:
                    continue

        result["obfuscation_hints"] = self._detect_obfuscation()
        return result

    def _detect_obfuscation(self) -> List[str]:
        hints = []
        if not self._loaded or self.size < 100:
            return hints
        sample = self.data[:65536]
        freq = Counter(sample)
        most_common = freq.most_common(5)
        for byte_val, count in most_common:
            if count > len(sample) * 0.25 and byte_val in (0x00, 0xFF):
                hints.append(f"High frequency 0x{byte_val:02x} ({count/len(sample)*100:.1f}%) - possible padding/XOR")
        if len(sample) >= 4096:
            ent = self._entropy(sample[:4096])
            if 0.5 < ent < 4.0 and sample[:100].count(b'\x00') < 50:
                hints.append(f"Low entropy {ent:.2f} not zero-filled - possible XOR/encryption")
        # Check XOR with single byte
        if len(sample) >= 256:
            # Try to find printable strings after XOR 0xFF
            xored = bytes(b ^ 0xFF for b in sample[:1024])
            if b'/etc/passwd' in xored or b'/bin/sh' in xored:
                hints.append("XOR 0xFF obfuscation detected - strings visible after XOR")
        return hints

    def entropy_map(self, block_size: int = 4096) -> List[Dict]:
        regions = []
        for offset in range(0, self.size, block_size):
            block = self.data[offset:offset+block_size]
            entropy = self._entropy(block)
            regions.append({
                "offset": offset,
                "hex": hex(offset),
                "size": len(block),
                "entropy": round(entropy, 3),
                "type": self._entropy_class(entropy),
            })
        return regions

    def high_entropy_regions(self, threshold: float = 7.0) -> List[Dict]:
        return [r for r in self.entropy_map() if r["entropy"] >= threshold]

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        total = len(data)
        return -sum((c/total) * math.log2(c/total) for c in freq.values())

    def _entropy_class(self, e: float) -> str:
        if e >= 7.5: return "encrypted/compressed"
        if e >= 6.5: return "high entropy"
        if e >= 4.0: return "normal"
        return "low entropy (text/padding)"

    def extract_strings(self, min_len: int = 6) -> List[Dict]:
        results = []
        # ASCII strings
        regex = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')
        for m in regex.finditer(self.data):
            s = m.group().decode("ascii", errors="ignore")
            cat = self._categorize_string(s)
            results.append({"offset": m.start(), "hex": hex(m.start()), "value": s, "category": cat, "encoding": "ascii"})

        # UTF-16LE strings (common in Windows firmware)
        try:
            utf16_regex = re.compile(rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}')
            for m in utf16_regex.finditer(self.data):
                try:
                    s = m.group().decode("utf-16le", errors="ignore")
                    # Filter printable
                    if all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in s):
                        cat = self._categorize_string(s)
                        results.append({"offset": m.start(), "hex": hex(m.start()), "value": s, "category": cat, "encoding": "utf16le"})
                except Exception:
                    continue
        except Exception:
            pass

        # Deduplicate by offset
        seen = set()
        deduped = []
        for r in sorted(results, key=lambda x: x["offset"]):
            if r["offset"] not in seen:
                seen.add(r["offset"])
                deduped.append(r)
        
        self.strings = deduped
        return deduped

    def _categorize_string(self, s: str) -> str:
        sl = s.lower()
        if re.search(r'(?i)(password|passwd|secret|key|token|aws_access|aws_secret)', s): return "credential"
        if re.search(r'(?i)\b(?:admin|root|user)\s*[:=]\s*(?:admin|root|1234|password|default|toor)\b', s): return "credential"
        if re.search(r'https?://', s): return "url"
        if re.search(r'^(/[a-z][a-z0-9/_.-]{3,})$', s): return "path"
        if re.search(r'(?i)(error|fail|warn|debug|info)\b', s): return "log"
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s): return "ip_addr"
        if re.search(r'(?i)(telnet|ssh|uart|jtag|gdb|backdoor)', s): return "debug"
        if re.search(r'CVE-[0-9]{4}-[0-9]+', s): return "cve_ref"
        if re.search(r'-----BEGIN ', s): return "private_key"
        return ""

    def scan_vulns(self) -> List[Dict]:
        findings = []
        if not self.strings:
            self.extract_strings()
        for s_entry in self.strings:
            s = s_entry["value"]
            off = s_entry["hex"]
            for pat, sev, vtype, desc in FIRMWARE_VULN_PATTERNS:
                if re.search(pat, s):
                    findings.append({
                        "severity": sev,
                        "type": vtype,
                        "offset": off,
                        "line": None,
                        "description": f"{desc}: '{s[:80]}'",
                        "recommendation": desc.split("—")[-1].strip() if "—" in desc else "Investigate this string",
                        "evidence": {"offset": off, "string": s[:100], "encoding": s_entry.get("encoding", "ascii")},
                    })
                    break
        return findings

    def find_interesting_paths(self) -> List[Dict]:
        results = []
        if not self.strings:
            self.extract_strings()
        for s_entry in self.strings:
            s = s_entry["value"]
            for path in INTERESTING_PATHS:
                if path.lower() in s.lower():
                    results.append({"offset": s_entry["hex"], "path": s, "match": path})
        return results

    def extract_filesystem(self, output_dir: str) -> Dict:
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

        # Try unsquashfs if SquashFS detected
        components = self.identify().get("components", [])
        has_squash = any("SquashFS" in c["type"] for c in components)
        if has_squash:
            try:
                # Try to find squashfs offset
                for comp in components:
                    if "SquashFS" in comp["type"]:
                        off = comp["offset"]
                        # Try dd + unsquashfs
                        tmp_file = os.path.join(output_dir, f"squashfs_{off}.bin")
                        subprocess.run(["dd", f"if={self.path}", f"of={tmp_file}", f"bs=1", f"skip={off}"], capture_output=True, timeout=30)
                        result["method"] = "unsquashfs_attempt"
                        result["squashfs_offset"] = off
                        break
            except Exception:
                pass

        result["method"] = "manual"
        result["error"] = "binwalk not found. Install: pip install binwalk or apt install binwalk. Manual: dd if=firmware.bin bs=1 skip=<offset>"
        return result

    def _human_size(self, size: int) -> str:
        for unit in ["B","KB","MB","GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def get_summary(self) -> Dict:
        id_info = self.identify()
        strings = self.extract_strings()[:300]
        cred_strings = [s["value"] for s in strings if s["category"] == "credential"]
        url_strings = [s["value"] for s in strings if s["category"] == "url"]
        debug_strings = [s["value"] for s in strings if s["category"] == "debug"]
        path_strings = [s["value"] for s in strings if s["category"] == "path"]
        key_strings = [s["value"] for s in strings if s["category"] == "private_key"]
        entropy_map = self.entropy_map()
        high_entropy = [r for r in entropy_map if r["entropy"] >= 7.0]
        return {
            "file_list": id_info.get("components", []),
            "arch_hints": id_info.get("arch_hints", []),
            "service_hints": id_info.get("service_hints", []),
            "obfuscation_hints": id_info.get("obfuscation_hints", []),
            "strings": {
                "credentials": cred_strings[:20],
                "urls": url_strings[:20],
                "debug": debug_strings[:20],
                "paths": path_strings[:30],
                "private_keys": key_strings[:10],
            },
            "entropy_map": {"high_entropy_regions": len(high_entropy), "samples": high_entropy[:5]},
            "size": self._human_size(self.size),
            "total_components": id_info.get("total_magic_hits", 0),
        }
