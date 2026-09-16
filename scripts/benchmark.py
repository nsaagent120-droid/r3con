#!/usr/bin/env python3
"""Benchmark local reproductible des chemins principaux de r3con.

Le script crée un corpus temporaire déterministe, exécute l'orchestrateur
plusieurs fois et écrit des métriques JSON. Il ne lit aucune donnée utilisateur
et ne lance aucun outil réseau.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

from core.__version__ import __version__
from modules.orchestration.orchestrator import Orchestrator


def build_fixture(root: Path, files: int) -> list[Path]:
    source = root / "fixture"
    source.mkdir()
    template = """def transform(value):\n    if value:\n        return value.strip()\n    return ''\n\n"""
    for index in range(files):
        (source / f"module_{index:03d}.py").write_text(template * (1 + index % 3), encoding="utf-8")
    return sorted(source.glob("*.py"))


def run_once(targets: list[Path], workers: int, use_cache: bool) -> dict:
    tracemalloc.start()
    started = time.perf_counter()
    results = [Orchestrator(
        str(target), profile="source", timeout=120, max_mb=32,
        max_workers=workers, cache=use_cache,
    ).run() for target in targets]
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "status": "ok" if all(result.get("status") not in {"error", "invalid"} for result in results) else "partial",
        "duration_ms": elapsed_ms,
        "peak_tracemalloc_mb": round(peak / 1024 / 1024, 3),
        "findings": sum(len(result.get("findings", [])) for result in results),
        "cache_stats": {"runs": len(results), "statuses": [result.get("status") for result in results]},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=20)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--workers", type=int, default=min(os.cpu_count() or 2, 4))
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    if not 1 <= args.files <= 500 or not 1 <= args.runs <= 20 or not 1 <= args.workers <= 16:
        parser.error("files/runs/workers hors limites")

    with tempfile.TemporaryDirectory(prefix="r3con-benchmark-") as directory:
        targets = build_fixture(Path(directory), args.files)
        samples = [run_once(targets, args.workers, not args.no_cache) for _ in range(args.runs)]
    payload = {
        "schema": "r3con-benchmark-1",
        "r3con_version": __version__,
        "python": os.sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "parameters": {"files": args.files, "runs": args.runs, "workers": args.workers, "cache": not args.no_cache},
        "samples": samples,
        "summary": {
            "duration_ms_median": round(statistics.median(s["duration_ms"] for s in samples), 2),
            "duration_ms_min": min(s["duration_ms"] for s in samples),
            "duration_ms_max": max(s["duration_ms"] for s in samples),
            "peak_memory_mb_max": max(s["peak_tracemalloc_mb"] for s in samples),
        },
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
