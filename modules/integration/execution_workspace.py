"""Workspaces d'exécution bornés pour outils externes.

Le module fournit un backend réutilisable par la CLI ou une future interface web.
Il ne lance jamais de shell implicite : les commandes sont des listes argv.
Chaque workspace possède un répertoire privé, un environnement réduit, des
limites de durée/sortie/processus et un arrêt de groupe de processus.

Ce socle est volontairement non interactif (jobs batch). Un terminal PTY pourra
être ajouté séparément sans mélanger ses permissions avec celles des jobs.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MAX_COMMAND_ARGS = 64
MAX_ARG_LENGTH = 4096
DEFAULT_CAPTURE_BYTES = 1024 * 1024
JOB_STORE_DIR = Path.home() / ".r3con" / "jobs"


@dataclass(frozen=True)
class WorkspaceLimits:
    """Limites applicables à un job et à son workspace."""

    wall_timeout_s: int = 300
    max_output_bytes: int = DEFAULT_CAPTURE_BYTES
    max_processes: int = 32
    allow_network: bool = False
    strict_network: bool = True
    env_whitelist: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TERM")

    def __post_init__(self) -> None:
        if not 1 <= int(self.wall_timeout_s) <= 24 * 3600:
            raise ValueError("wall_timeout_s doit être compris entre 1 et 86400")
        if not 4096 <= int(self.max_output_bytes) <= 50 * 1024 * 1024:
            raise ValueError("max_output_bytes doit être compris entre 4096 et 50MiB")
        if not 1 <= int(self.max_processes) <= 512:
            raise ValueError("max_processes doit être compris entre 1 et 512")


@dataclass
class WorkspaceJob:
    id: str
    argv: list[str]
    cwd: Path
    process: subprocess.Popen[bytes]
    started_at: float
    limits: WorkspaceLimits
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    timed_out: bool = False
    truncated: bool = False
    returncode: int | None = None
    _collector: threading.Thread | None = field(default=None, repr=False)

    @property
    def status(self) -> str:
        if self.returncode is not None:
            return "timeout" if self.timed_out else ("ok" if self.returncode == 0 else "failed")
        return "running"

    def result(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "argv": self.argv,
            "cwd": str(self.cwd),
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "duration_s": round(max(0.0, time.monotonic() - self.started_at), 3),
            "stdout": bytes(self.stdout).decode("utf-8", errors="replace"),
            "stderr": bytes(self.stderr).decode("utf-8", errors="replace"),
        }


class ExecutionWorkspace:
    """Gestionnaire de workspaces locaux pour exécutions contrôlées."""

    def __init__(self, root: str | Path | None = None, *, limits: WorkspaceLimits | None = None,
                 persist: bool = True):
        self.root = Path(root) if root else Path(tempfile.gettempdir()) / "r3con-workspaces"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.limits = limits or WorkspaceLimits()
        self.jobs: dict[str, WorkspaceJob] = {}
        self._lock = threading.RLock()
        self.persist = persist
        if self.persist:
            JOB_STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(JOB_STORE_DIR, 0o700)

    def _persist(self, job: WorkspaceJob) -> None:
        if not self.persist:
            return
        payload = job.result()
        payload["limits"] = {
            "wall_timeout_s": job.limits.wall_timeout_s,
            "max_output_bytes": job.limits.max_output_bytes,
            "max_processes": job.limits.max_processes,
            "allow_network": job.limits.allow_network,
            "strict_network": job.limits.strict_network,
        }
        path = JOB_STORE_DIR / f"{job.id}.json"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, path)
        except (OSError, TypeError, ValueError):
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def list_persisted() -> list[dict[str, Any]]:
        if not JOB_STORE_DIR.exists():
            return []
        rows = []
        for path in sorted(JOB_STORE_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                rows.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return rows

    @staticmethod
    def get_persisted(job_id: str) -> dict[str, Any] | None:
        path = JOB_STORE_DIR / f"{job_id}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    @staticmethod
    def clean_persisted() -> int:
        removed = 0
        if JOB_STORE_DIR.exists():
            for path in JOB_STORE_DIR.glob("*.json"):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    pass
        return removed

    @staticmethod
    def _validate_argv(argv: list[str]) -> list[str]:
        if not isinstance(argv, list) or not argv or len(argv) > MAX_COMMAND_ARGS:
            raise ValueError("argv doit contenir de 1 à 64 arguments")
        clean: list[str] = []
        for arg in argv:
            if not isinstance(arg, str) or not arg or len(arg) > MAX_ARG_LENGTH or "\x00" in arg:
                raise ValueError("argument de commande invalide")
            clean.append(arg)
        return clean

    def _environment(self, cwd: Path, extra_env: dict[str, str] | None) -> dict[str, str]:
        env = {key: os.environ[key] for key in self.limits.env_whitelist if key in os.environ}
        env.update({"HOME": str(cwd), "TMPDIR": str(cwd), "TMP": str(cwd), "TEMP": str(cwd)})
        if not self.limits.allow_network:
            env.update({"http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9", "no_proxy": ""})
        if extra_env:
            for key, value in extra_env.items():
                if key not in self.limits.env_whitelist:
                    raise ValueError(f"variable d'environnement non autorisée: {key}")
                if "\x00" in key or "\x00" in value:
                    raise ValueError("variable d'environnement invalide")
            env.update(extra_env)
        return env

    def _prefix(self) -> list[str]:
        if self.limits.allow_network:
            return []
        unshare = shutil.which("unshare")
        if not unshare:
            if self.limits.strict_network:
                raise RuntimeError("isolation réseau indisponible: unshare absent")
            return []
        probe = subprocess.run([unshare, "-n", "--", "true"], capture_output=True, timeout=5)
        if probe.returncode != 0:
            if self.limits.strict_network:
                raise RuntimeError("isolation réseau indisponible dans cet environnement")
            return []
        return [unshare, "-n", "--"]

    def start(self, argv: list[str], *, extra_env: dict[str, str] | None = None) -> str:
        """Démarre un job batch et retourne son identifiant."""
        clean_argv = self._validate_argv(argv)
        cwd = Path(tempfile.mkdtemp(prefix="job-", dir=self.root))
        os.chmod(cwd, 0o700)
        try:
            full_argv = self._prefix() + clean_argv
            proc = subprocess.Popen(
                full_argv,
                cwd=cwd,
                env=self._environment(cwd, extra_env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except Exception:
            shutil.rmtree(cwd, ignore_errors=True)
            raise
        job_id = uuid.uuid4().hex[:16]
        job = WorkspaceJob(job_id, clean_argv, cwd, proc, time.monotonic(), self.limits)
        with self._lock:
            self.jobs[job_id] = job
        self._persist(job)
        job._collector = threading.Thread(target=self._collect, args=(job,), daemon=True)
        job._collector.start()
        return job_id

    def _collect(self, job: WorkspaceJob) -> None:
        try:
            out, err = job.process.communicate(timeout=job.limits.wall_timeout_s)
        except subprocess.TimeoutExpired as exc:
            job.timed_out = True
            try:
                os.killpg(os.getpgid(job.process.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                job.process.kill()
            out, err = job.process.communicate()
            _ = exc
        limit = job.limits.max_output_bytes
        if len(out) > limit or len(err) > limit:
            job.truncated = True
        job.stdout.extend(out[:limit])
        job.stderr.extend(err[:limit])
        job.returncode = job.process.returncode
        self._persist(job)

    def status(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self.jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        return job.result()

    def stop(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self.jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        if job.process.poll() is None:
            try:
                os.killpg(os.getpgid(job.process.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                job.process.terminate()
            try:
                job.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(job.process.pid), signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    job.process.kill()
        if job._collector:
            job._collector.join(timeout=5)
        return job.result()

    def cleanup(self, job_id: str) -> None:
        with self._lock:
            job = self.jobs.pop(job_id, None)
        if not job:
            return
        if job.process.poll() is None:
            self.stop(job_id)
        shutil.rmtree(job.cwd, ignore_errors=True)

    def close(self) -> None:
        for job_id in list(self.jobs):
            self.cleanup(job_id)

    def __enter__(self) -> "ExecutionWorkspace":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


__all__ = ["ExecutionWorkspace", "WorkspaceJob", "WorkspaceLimits"]
