"""
r3con v6.2 - Network External Tools Integration PRO
Wrappers pour tshark, tcpdump, suricata, zeek, nmap, etc.
"""
from __future__ import annotations
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

MAX_PCAP_SIZE = 500 * 1024 * 1024
MAX_OUTPUT = 8_000_000

def _validate_pcap(path: str) -> bool:
    if not path or len(path) > 1024 or "\x00" in path:
        return False
    p = Path(path)
    try:
        return p.exists() and p.is_file() and 0 < p.stat().st_size <= MAX_PCAP_SIZE
    except Exception:
        return False

def _run(cmd: List[str], timeout: int = 60) -> Optional[str]:
    if not cmd or len(cmd) > 30:
        return None
    for arg in cmd:
        if not isinstance(arg, str) or len(arg) > 1024 or "\x00" in arg:
            return None
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=min(timeout, 300))
        output = result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else ""
        if not output and result.stderr.strip():
            output = result.stderr.strip()
        if len(output) > MAX_OUTPUT:
            output = output[:MAX_OUTPUT]
        return output if output else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, ValueError):
        return None

def tool_exists(name: str) -> bool:
    if not name or len(name) > 64 or "\x00" in name:
        return False
    if any(c in name for c in ";|&`$()><\n\r/"):
        return False
    try:
        subprocess.run([name, '--version'], capture_output=True, timeout=3)
        return True
    except Exception:
        return False

def detect_network_tools() -> Dict[str, Any]:
    tools = {
        "tshark": shutil.which("tshark") is not None,
        "tcpdump": shutil.which("tcpdump") is not None,
        "dumpcap": shutil.which("dumpcap") is not None,
        "zeek": shutil.which("zeek") is not None,
        "suricata": shutil.which("suricata") is not None,
        "nmap": shutil.which("nmap") is not None,
        "wireshark": shutil.which("wireshark") is not None,
        "tcmp": shutil.which("tcmp") is not None,
        "ngrep": shutil.which("ngrep") is not None,
        "netsniff-ng": shutil.which("netsniff-ng") is not None,
        "p0f": shutil.which("p0f") is not None,
    }
    # Also check python libs
    try:
        import scapy
        tools["scapy"] = True
    except ImportError:
        tools["scapy"] = False

    try:
        import dpkt
        tools["dpkt"] = True
    except ImportError:
        tools["dpkt"] = False

    return tools

class TSharkWrapper:
    """TShark wrapper PRO - deep packet inspection."""

    def __init__(self, pcap_path: str, timeout: int = 120):
        self.pcap = Path(pcap_path)
        self.timeout = max(1, min(timeout, 300))
        self.bin = shutil.which("tshark")

    def status(self) -> Dict[str, Any]:
        return {"available": self.bin is not None, "binary": self.bin}

    def analyze(self) -> Dict[str, Any]:
        if not self.bin:
            return {"status": "unsupported", "tool": "tshark", "install": "apt install tshark"}
        if not _validate_pcap(str(self.pcap)):
            return {"status": "invalid", "error": "invalid_pcap"}

        # Get protocol hierarchy
        out = _run([self.bin, "-n", "-r", str(self.pcap), "-q", "-z", "io,phs"], timeout=self.timeout)
        hierarchy = out[:5000] if out else ""

        # Get conversations
        out2 = _run([self.bin, "-n", "-r", str(self.pcap), "-q", "-z", "conv,ip"], timeout=self.timeout)
        conversations = out2[:5000] if out2 else ""

        # Get endpoints
        out3 = _run([self.bin, "-n", "-r", str(self.pcap), "-q", "-z", "endpoints,ip"], timeout=self.timeout)
        endpoints = out3[:5000] if out3 else ""

        return {
            "status": "ok",
            "tool": "tshark",
            "hierarchy": hierarchy,
            "conversations": conversations,
            "endpoints": endpoints,
        }

    def extract_fields(self, fields: List[str]) -> Dict[str, Any]:
        """Extract specific fields."""
        if not self.bin:
            return {"status": "unsupported", "tool": "tshark"}
        if not _validate_pcap(str(self.pcap)):
            return {"status": "invalid", "error": "invalid_pcap"}

        # Validate fields
        safe_fields = []
        safe_pattern = re.compile(r'^[a-zA-Z0-9._\-]+$')
        for f in fields[:64]:
            if f and len(f) <= 100 and "\x00" not in f and safe_pattern.match(f):
                if not any(c in f for c in ";|&`$()><\n\r\"'"):
                    safe_fields.append(f)

        if not safe_fields:
            return {"status": "invalid", "error": "no_safe_fields"}

        cmd = [self.bin, "-n", "-r", str(self.pcap), "-T", "json"]
        for field in safe_fields:
            cmd.extend(["-e", field])

        out = _run(cmd, timeout=self.timeout)
        if out:
            try:
                records = json.loads(out)
                if isinstance(records, list) and len(records) > 10000:
                    records = records[:10000]
                return {"status": "ok", "tool": "tshark", "records": records, "count": len(records)}
            except json.JSONDecodeError:
                return {"status": "partial", "tool": "tshark", "raw": out[:10000]}

        return {"status": "error", "tool": "tshark"}

    def extract_http(self) -> Dict[str, Any]:
        """Extract HTTP objects."""
        if not self.bin:
            return {"status": "unsupported", "tool": "tshark"}
        if not _validate_pcap(str(self.pcap)):
            return {"status": "invalid", "error": "invalid_pcap"}

        cmd = [self.bin, "-n", "-r", str(self.pcap), "-Y", "http", "-T", "fields",
               "-e", "http.host", "-e", "http.request.method", "-e", "http.request.uri",
               "-e", "http.user_agent", "-e", "http.response.code"]
        out = _run(cmd, timeout=self.timeout)
        if out:
            lines = out.splitlines()[:1000]
            requests = []
            for line in lines:
                parts = line.split("\t")
                if len(parts) >= 3:
                    requests.append({
                        "host": parts[0] if len(parts) > 0 else "",
                        "method": parts[1] if len(parts) > 1 else "",
                        "uri": parts[2] if len(parts) > 2 else "",
                        "user_agent": parts[3] if len(parts) > 3 else "",
                        "status": parts[4] if len(parts) > 4 else "",
                    })
            return {"status": "ok", "tool": "tshark_http", "requests": requests, "count": len(requests)}

        return {"status": "error", "tool": "tshark_http"}

    def extract_dns(self) -> Dict[str, Any]:
        """Extract DNS queries."""
        if not self.bin:
            return {"status": "unsupported", "tool": "tshark"}
        if not _validate_pcap(str(self.pcap)):
            return {"status": "invalid", "error": "invalid_pcap"}

        cmd = [self.bin, "-n", "-r", str(self.pcap), "-Y", "dns", "-T", "fields",
               "-e", "dns.qry.name", "-e", "dns.qry.type", "-e", "dns.resp.name"]
        out = _run(cmd, timeout=self.timeout)
        if out:
            queries = []
            for line in out.splitlines()[:5000]:
                parts = line.split("\t")
                if parts and parts[0]:
                    queries.append(parts[0])

            unique = sorted(set(queries))
            return {"status": "ok", "tool": "tshark_dns", "queries": unique[:1000], "count": len(unique), "total": len(queries)}

        return {"status": "error", "tool": "tshark_dns"}

class SuricataWrapper:
    """Suricata IDS wrapper."""

    def __init__(self, pcap_path: str, timeout: int = 120):
        self.pcap = Path(pcap_path)
        self.timeout = max(1, min(timeout, 300))
        self.bin = shutil.which("suricata")

    def analyze(self) -> Dict[str, Any]:
        if not self.bin:
            return {"status": "unsupported", "tool": "suricata", "install": "apt install suricata"}
        if not _validate_pcap(str(self.pcap)):
            return {"status": "invalid", "error": "invalid_pcap"}

        with tempfile.TemporaryDirectory(prefix="r3con-suricata-") as outdir:
            cmd = [self.bin, "-r", str(self.pcap), "-l", outdir]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "tool": "suricata"}
            except Exception as e:
                return {"status": "error", "tool": "suricata", "error": str(e)[:500]}

            logs = {}
            try:
                for path in Path(outdir).glob("*.json"):
                    try:
                        if path.stat().st_size > MAX_OUTPUT:
                            continue
                        content = path.read_text(errors="ignore")[:MAX_OUTPUT]
                        # Parse eve.json
                        if path.name == "eve.json":
                            events = []
                            for line in content.splitlines()[:10000]:
                                try:
                                    events.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
                            logs["eve"] = events[:1000]
                            logs["eve_count"] = len(events)
                            # Extract alerts
                            alerts = [e for e in events if e.get("event_type") == "alert"]
                            logs["alerts"] = alerts[:100]
                            logs["alert_count"] = len(alerts)
                        else:
                            logs[path.name] = content[:10000]
                    except Exception:
                        continue
            except Exception:
                pass

            return {
                "status": "ok" if proc.returncode == 0 else "partial",
                "tool": "suricata",
                "logs": logs,
                "returncode": proc.returncode,
                "stderr": proc.stderr[:2000] if proc.stderr else "",
            }

class ZeekWrapper:
    """Zeek wrapper."""

    def __init__(self, pcap_path: str, timeout: int = 120):
        self.pcap = Path(pcap_path)
        self.timeout = max(1, min(timeout, 300))
        self.bin = shutil.which("zeek")

    def analyze(self) -> Dict[str, Any]:
        if not self.bin:
            return {"status": "unsupported", "tool": "zeek", "install": "apt install zeek"}
        if not _validate_pcap(str(self.pcap)):
            return {"status": "invalid", "error": "invalid_pcap"}

        with tempfile.TemporaryDirectory(prefix="r3con-zeek-") as outdir:
            cmd = [self.bin, "-C", "-r", str(self.pcap)]
            try:
                proc = subprocess.run(cmd, cwd=outdir, capture_output=True, text=True, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "tool": "zeek"}
            except Exception as e:
                return {"status": "error", "tool": "zeek", "error": str(e)[:500]}

            logs = {}
            try:
                for path in Path(outdir).glob("*.log"):
                    try:
                        if not path.is_file() or path.stat().st_size > MAX_OUTPUT:
                            continue
                        content = path.read_text(errors="ignore")[:MAX_OUTPUT]
                        logs[path.name] = content[:10000]
                        if len(logs) >= 20:
                            break
                    except Exception:
                        continue
            except Exception:
                pass

            return {
                "status": "ok" if proc.returncode == 0 else "partial",
                "tool": "zeek",
                "logs": logs,
                "log_count": len(logs),
                "returncode": proc.returncode,
            }

class NmapWrapper:
    """Nmap wrapper for live network analysis."""

    def __init__(self, target: str, timeout: int = 60):
        self.target = target
        self.timeout = max(1, min(timeout, 300))
        self.bin = shutil.which("nmap")

    def scan(self, args: List[str] = None) -> Dict[str, Any]:
        if not self.bin:
            return {"status": "unsupported", "tool": "nmap", "install": "apt install nmap"}

        # Validate target - must be IP or hostname, no injection
        if not self.target or len(self.target) > 256 or "\x00" in self.target:
            return {"status": "invalid", "error": "invalid_target"}
        if any(c in self.target for c in ";|&`$()><\n\r\"'"):
            return {"status": "invalid", "error": "invalid_chars_in_target"}

        # Safe args
        safe_args = args or ["-sV", "-F"]  # Fast scan
        # Validate args
        allowed_flags = {"-sV", "-sS", "-sT", "-F", "-O", "-A", "-p", "--top-ports", "-Pn", "-n"}
        filtered_args = []
        for arg in safe_args[:20]:
            if arg in allowed_flags or re.match(r'^-p[\d,\-]+$', arg) or re.match(r'^\d+$', arg) or re.match(r'^--top-ports$', arg):
                filtered_args.append(arg)

        cmd = [self.bin] + filtered_args + [self.target]
        out = _run(cmd, timeout=self.timeout)
        if out:
            return {"status": "ok", "tool": "nmap", "output": out[:10000], "command": " ".join(cmd)}

        return {"status": "error", "tool": "nmap"}

class NetworkToolsManager:
    """Manager for all network tools."""

    def __init__(self, pcap_path: str = None):
        self.pcap_path = pcap_path

    def detect_all(self) -> Dict[str, bool]:
        return detect_network_tools()

    def analyze_all(self) -> Dict[str, Any]:
        if not self.pcap_path or not _validate_pcap(self.pcap_path):
            return {"status": "error", "error": "invalid_pcap_path"}

        results = {}

        # tshark
        try:
            tshark = TSharkWrapper(self.pcap_path)
            results["tshark"] = tshark.analyze()
            results["tshark_http"] = tshark.extract_http()
            results["tshark_dns"] = tshark.extract_dns()
        except Exception as e:
            results["tshark"] = {"status": "error", "error": str(e)[:500]}

        # suricata
        try:
            results["suricata"] = SuricataWrapper(self.pcap_path).analyze()
        except Exception as e:
            results["suricata"] = {"status": "error", "error": str(e)[:500]}

        # zeek
        try:
            results["zeek"] = ZeekWrapper(self.pcap_path).analyze()
        except Exception as e:
            results["zeek"] = {"status": "error", "error": str(e)[:500]}

        return results
