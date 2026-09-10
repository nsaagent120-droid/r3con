"""Triage de fuzzing sans dépendance externe : corpus, clusters de crashs,
statistiques et export vers le contrat Finding r3con.

Conçu pour AFL++/honggfuzz/libFuzzer (arborescences ``crashes/``,
``queue/``, ``fuzzer_stats``) mais fonctionne aussi sur des dossiers
artisanaux. Toute opération est locale et NON destructive : la minimisation
écrit dans un dossier séparé, elle ne supprime jamais le corpus d'origine.
"""
from __future__ import annotations

import hashlib
import re
import signal as _signal
from pathlib import Path
from typing import Any

from core.result_schema import normalize_findings

CRASHY_SIGNALS = {
    "SIGSEGV": ("HIGH", "Segmentation fault"),
    "SIGABRT": ("HIGH", "Abort (assertion/corruption détectée par l'allocateur)"),
    "SIGBUS": ("HIGH", "Bus error"),
    "SIGILL": ("HIGH", "Illegal instruction"),
    "SIGFPE": ("MEDIUM", "Floating point exception"),
    "SIGXCPU": ("MEDIUM", "CPU time limit exceeded"),
    "timeout": ("MEDIUM", "Hang / dépassement de timeout"),
}


def content_signature(data: bytes, head: int = 512) -> str:
    """Signature de contenu : hash des premiers octets significatifs + taille."""
    digest = hashlib.sha256(data[:head]).hexdigest()[:16]
    return f"{digest}:{len(data)}"


def crash_signal_hint(name: str, data: bytes) -> str:
    """Déduit un signal depuis le nom de fichier AFL (crash,sig06,…) ou binaire."""
    m = re.search(r"(?:sig|SIG)[-_:]?\s?(\d{1,3})", name, re.I)
    if m:
        try:
            return _signal.Signals(int(m.group(1))).name
        except ValueError:
            return f"SIG{int(m.group(1))}"
    lowered = name.lower()
    for token, sig in (("segv", "SIGSEGV"), ("abrt", "SIGABRT"), ("bus", "SIGBUS"),
                       ("ill", "SIGILL"), ("fpe", "SIGFPE"), ("timeout", "timeout"),
                       ("hang", "timeout")):
        if token in lowered:
            return sig
    return "unknown"


def cluster_crashes(crashes_dir: str | Path) -> list[dict[str, Any]]:
    """Regroupe les crashs par signature (nom + contenu) — un cluster = un bug."""
    root = Path(crashes_dir)
    clusters: dict[str, dict[str, Any]] = {}
    if not root.is_dir():
        return []
    for entry in sorted(root.iterdir()):
        if not entry.is_file() or entry.name.startswith("."):
            continue
        try:
            data = entry.read_bytes()
        except OSError:
            continue
        signal = crash_signal_hint(entry.name, data)
        signature = f"{signal}|{content_signature(data)}"
        cluster = clusters.setdefault(signature, {
            "cluster_id": signature[:12],
            "signal": signal,
            "occurrences": 0,
            "files": [],
            "total_bytes": 0,
        })
        cluster["occurrences"] += 1
        cluster["total_bytes"] += len(data)
        cluster["files"].append({"path": str(entry), "size": len(data),
                                 "sha256_16": hashlib.sha256(data).hexdigest()[:16]})
    out = []
    for cluster in clusters.values():
        sev, why = CRASHY_SIGNALS.get(cluster["signal"], ("MEDIUM", "Crash non classé"))
        cluster["severity"] = sev
        cluster["signal_description"] = why
        cluster["files"] = cluster["files"][:50]
        out.append(cluster)
    return sorted(out, key=lambda c: (-c["occurrences"], c["cluster_id"]))


def minimize_corpus(source_dir: str | Path, dest_dir: str | Path | None = None,
                    max_files: int = 500) -> dict[str, Any]:
    """Corpus minimal déterministe : unicité par hash, tri par taille.

    Écrit dans ``dest_dir`` (défaut : ``<source>.min``) — le corpus d'origine
    n'est jamais modifié.
    """
    src = Path(source_dir)
    if not src.is_dir():
        return {"status": "invalid", "error": "corpus_dir_missing", "source": str(src)}
    dest = Path(dest_dir) if dest_dir else src.with_name(src.name + ".min")
    dest.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    kept, skipped = [], 0
    candidates = []
    for entry in src.rglob("*"):
        if entry.is_file() and not entry.name.startswith("."):
            try:
                size = entry.stat().st_size
            except OSError:
                continue
            candidates.append((size, entry))
    for size, entry in sorted(candidates):
        try:
            digest = hashlib.sha256(entry.read_bytes()).hexdigest()
        except OSError:
            continue
        if digest in seen:
            skipped += 1
            continue
        seen.add(digest)
        if len(kept) >= max_files:
            skipped += 1
            continue
        target = dest / f"{digest[:12]}_{entry.name}"[:120]
        try:
            target.write_bytes(entry.read_bytes())
            kept.append({"file": str(target), "sha256_12": digest[:12], "size": size})
        except OSError:
            skipped += 1
    return {"status": "ok", "source": str(src), "output": str(dest),
            "original_count": len(candidates), "unique_kept": len(kept),
            "skipped": skipped, "files": kept}


def parse_fuzzer_stats(aflo_out: str | Path) -> dict[str, Any]:
    """Lit ``fuzzer_stats`` (AFL++) et les compteurs de dossiers adjacents."""
    root = Path(aflo_out)
    stats: dict[str, Any] = {"output_dir": str(root)}
    for candidate in (root / "fuzzer_stats", root / "main" / "fuzzer_stats"):
        if candidate.is_file():
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^([\w ]+?)\s*:\s*(.+)$", line.strip())
                if m:
                    key = m.group(1).strip().replace(" ", "_").lower()
                    value: Any = m.group(2).strip()
                    if re.fullmatch(r"\d+(\.\d+)?", str(value)):
                        value = float(value) if "." in str(value) else int(value)
                    stats[key] = value
            stats["found_in"] = str(candidate)
            break
    for sub in ("crashes", "hangs", "queue", "fuzz/pow_queue"):
        d = root / sub.split("/")[0] if "/" not in sub else root
        d = root / sub
        if sub == "fuzz/pow_queue":
            continue
        if d.is_dir():
            stats.setdefault(sub, len([x for x in d.iterdir() if x.is_file()]))
    stats.setdefault("execs_done", 0)
    stats.setdefault("execs_per_sec", 0)
    stats["has_crashes"] = bool(stats.get("crashes") or stats.get("unique_crashes"))
    return stats


def detect_resume(output_dir: str | Path) -> dict[str, Any]:
    """Peut-on reprendre ? AFL conserve l'état dans l'arborescence de sortie."""
    root = Path(output_dir)
    candidates = [root / "fuzzer_stats", root / "main" / "fuzzer_stats"]
    for candidate in candidates:
        if candidate.is_file():
            return {"resumable": True, "state_file": str(candidate),
                    "note": "relancer afl-fuzz avec le même -o reprend automatiquement le corpus/queue"}
    return {"resumable": False, "note": "aucun fuzzer_stats trouvé : première exécution attendue"}


def crashes_to_findings(clusters: list[dict[str, Any]], target: str, *, tool: str = "afl++",
                        campaign: str = "") -> list[dict[str, Any]]:
    """Convertit des clusters de crashs en findings du contrat r3con."""
    findings = []
    for cluster in clusters:
        signal = cluster.get("signal", "unknown")
        findings.append({
            "finding_type": "fuzzing-crash",
            "severity": cluster.get("severity", "MEDIUM"),
            "confidence": min(0.95, 0.55 + 0.05 * cluster.get("occurrences", 1)),
            "status": "observation",
            "exploitability": "unknown",
            "target": target,
            "tool": tool,
            "description": f"Crash '{signal}' atteint par {tool} : {cluster.get('signal_description', '')} "
                           f"({cluster.get('occurrences', 1)} occurrence(s) groupée(s))",
            "recommendation": "Minimiser le cas (afl-cmin/twopi), rejouer sous gdb/ASAN, puis "
                              "évaluer l'exploitabilité AVANT de qualifier le finding.",
            "evidence": {"cluster_id": cluster.get("cluster_id"), "files": cluster.get("files", [])[:10],
                         "total_bytes": cluster.get("total_bytes")},
            "location": {"file": (cluster.get("files") or [{}])[0].get("path")},
            "tags": ["fuzzing", "crash", signal.lower()],
            "provenance": {"campaign": campaign, "clustering": "content-signature"},
        })
    return normalize_findings(findings, target=target, tool=tool, tool_version="unknown")
