"""Network group - passive analysis."""
from __future__ import annotations
from pathlib import Path
import json
import click
from rich.panel import Panel
from rich.table import Table
from rich import box
from .helpers import console, section, info, warn, hpanel, spinner
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from modules.network.protocol_analyzer import ProtocolAnalyzer
from modules.network.external_analyzers import ExternalNetworkAnalyzer
from modules.network.live_capture import LiveCaptureAnalyzer

@click.group()
def network():
    """Passive offline/live network and protocol analysis; no scanning or injection."""

@network.command("live")
@click.option("--interface", "interface_name", default="any", show_default=True, help="Local capture interface")
@click.option("--duration", default=30, show_default=True, type=click.IntRange(1, 3600), help="Max duration seconds")
@click.option("--max-packets", default=10000, show_default=True, type=click.IntRange(1, 1000000))
@click.option("--filter", "display_filter", default=None, help="Optional TShark display filter")
@click.option("--json-output", "json_output", type=click.Path(dir_okay=False), help="Write JSON")
def network_live(interface_name, duration, max_packets, display_filter, json_output):
    analyzer = LiveCaptureAnalyzer(interface=interface_name, duration=duration, max_packets=max_packets, display_filter=display_filter)
    result = analyzer.capture()
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if json_output:
        Path(json_output).write_text(payload, encoding="utf-8")
        console.print(f"Report written: {json_output}")
    else:
        if result.get("status") == "error":
            raise click.ClickException(result.get("error", "live capture failed"))
        section("LIVE PASSIVE NETWORK ANALYSIS")
        info(f"Interface: {result.get('interface')} | Duration: {result.get('duration_actual', 0)} s")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
        t.add_column(style="dim cyan", width=18)
        t.add_column(style="bold white")
        t.add_row("Packets", str(result.get("packets", 0)))
        t.add_row("Bytes", str(result.get("bytes", 0)))
        t.add_row("Protocols", ", ".join(f"{k}: {v}" for k, v in result.get("protocols", {}).items()) or "none")
        iocs = result.get("iocs", {})
        t.add_row("DNS / HTTP / TLS", f"{len(iocs.get('dns', []))} / {len(iocs.get('http_hosts', []))} / {len(iocs.get('tls_sni', []))}")
        t.add_row("Flows", str(len(result.get("flows", []))))
        console.print(Panel(t, title="[bold]Live Capture Summary[/]", border_style="green"))
        if result.get("stderr"):
            warn("TShark reported a partial capture; inspect the JSON report for details.")
        if result.get("iocs"):
            hpanel(json.dumps(result["iocs"], ensure_ascii=False, indent=2), "Observed Network IOCs", "info")

@network.command("analyze")
@click.argument("pcap_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--max-packets", default=100000, show_default=True, type=click.IntRange(1, 1000000))
@click.option("--max-mb", default=256, show_default=True, type=click.IntRange(1, 4096))
@click.option("--json-output", "json_output", is_flag=True, help="Print JSON")
@click.option("--engine", type=click.Choice(["internal", "tshark", "zeek", "all"]), default="internal", show_default=True)
def network_analyze(pcap_path, max_packets, max_mb, json_output, engine):
    result = ProtocolAnalyzer(pcap_path, max_packets=max_packets, max_bytes=max_mb * 1024 * 1024).analyze()
    external = ExternalNetworkAnalyzer(pcap_path)
    if engine in ("tshark", "all"):
        result["tshark"] = external.tshark_fields(["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "dns.qry.name", "http.host"])
    if engine in ("zeek", "all"):
        result["zeek"] = external.zeek_offline()
    if engine == "tshark":
        result = result["tshark"]
    elif engine == "zeek":
        result = result["zeek"]
    if json_output:
        click.echo(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0 if result.get("status") in ("ok", "partial") else 3)
    section("PASSIVE NETWORK ANALYSIS")
    info(f"Target: {pcap_path}")
    if result.get("status") != "ok":
        raise click.ClickException(result.get("error", "network analysis failed"))
    from .helpers import show_findings
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    t.add_column(style="dim cyan", width=18)
    t.add_column(style="bold white")
    t.add_row("Packets", str(result["packets_read"]))
    t.add_row("Link type", str(result["linktype"]))
    t.add_row("Protocols", ", ".join(f"{k}: {v}" for k, v in result["protocols"].items()) or "none")
    ioc_count = sum(len(values) for values in result.get("iocs", {}).values())
    t.add_row("Findings", str(len(result["findings"])))
    t.add_row("IOCs", str(ioc_count))
    console.print(Panel(t, title="[bold]Capture Summary[/]", border_style="dim cyan"))
    show_findings(result["findings"])
    if result.get("packets_truncated"):
        warn("Packet limit reached; result is partial.")
