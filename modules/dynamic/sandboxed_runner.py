"""Runner dynamique local isolé pour l'analyse comportementale contrôlée.

Garanties du modèle (documentées dans SECURITY_AUDIT.md) :

- exécution JAMAIS automatique : ``execute()`` est explicite, le mode par
  défaut des commandes CLI est ``plan`` (simulation, aucun processus lancé) ;
- réseau désactivé par défaut : isolation via ``unshare -n`` quand le noyau
  le permet ; sinon l'exécution est REFUSÉE (mode strict) avec message
  explicite, jamais silencieusement autorisée ;
- répertoire temporaire privé 0700 créé par ``tempfile`` ;
- limites de ressources réelles (RLIMIT) : CPU, mémoire, fichiers,
  nombre de processus enfants ; timeout mural avec arbre de processus tué ;
- capture bornée au périmètre : stdout/stderr tronqués, fichiers créés dans
  le répertoire de travail, signaux de crash ; rien n'est envoyé ailleurs.

Ce module n'exploite jamais une cible distante : il ne lance que le binaire
local fourni par l'utilisateur, dans le bac à sable décrit ci-dessus.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.result_schema import Status, make_result, normalize_findings

MAX_CAPTURE_BYTES = 1024 * 1024
MAX_TRACKED_FILES = 200
CRASH_SIGNALS = {signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS, signal.SIGILL,
                 signal.SIGFPE, getattr(signal, "SIGSYS", signal.SIGXCPU)}


@dataclass
class SandboxLimits:
    cpu_seconds: int = 5
    memory_mb: int = 256
    wall_timeout_s: int = 10
    max_processes: int = 32
    max_file_mb: int = 8
    allow_network: bool = False
    strict_network: bool = True
    strace: bool = False
    env_whitelist: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TERM")
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.cpu_seconds = max(1, int(self.cpu_seconds))
        self.memory_mb = max(16, int(self.memory_mb))
        self.wall_timeout_s = max(1, int(self.wall_timeout_s))
        self.max_processes = max(1, int(self.max_processes))
        self.max_file_mb = max(1, int(self.max_file_mb))


def _try_import_resource() -> Any:
    try:
        import resource
        return resource
    except ImportError:  # pragma: no cover - absent sur Windows
        return None


class SandboxedRunner:
    """Exécute une cible locale dans un bac à sable borné et observable."""

    def __init__(self, target: str | Path, args: list[str] | None = None, *,
                 stdin_data: bytes | None = None, input_file: str | Path | None = None,
                 limits: SandboxLimits | None = None, workdir_parent: str | Path | None = None):
        self.target = Path(target)
        self.args = [str(a) for a in (args or [])]
        self.stdin_data = stdin_data
        self.input_file = Path(input_file) if input_file else None
        self.limits = limits or SandboxLimits()
        self.workdir_parent = Path(workdir_parent) if workdir_parent else None

    # ── capacité d'isolation réseau ───────────────────────────────

    @staticmethod
    def network_isolation_available() -> tuple[bool, str]:
        """Teste réellement ``unshare -n`` (les conteneurs le bloquent souvent)."""
        unshare = shutil.which("unshare")
        if not unshare:
            return False, "binaire 'unshare' absent"
        try:
            proc = subprocess.run([unshare, "-n", "--", "true"], capture_output=True,
                                  timeout=5, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"échec du test unshare : {type(exc).__name__}"
        if proc.returncode == 0:
            return True, "unshare -n opérationnel"
        return False, f"unshare -n refusé par le noyau (rc={proc.returncode})"

    # ── planification (simulation) ────────────────────────────────

    def plan(self) -> dict[str, Any]:
        """Décrit l'exécution SANSC LA LANCER — mode par défaut de la CLI."""
        resource = _try_import_resource()
        net_ok, net_detail = self.network_isolation_available()
        wrapper: list[str] = []
        network = "autorisé (--allow-network)" if self.limits.allow_network else "désactivé"
        warnings: list[str] = []
        if not self.limits.allow_network:
            if net_ok:
                wrapper = [shutil.which("unshare") or "unshare", "-n", "--"]
            else:
                network = "non isolable"
                if self.limits.strict_network:
                    warnings.append(f"Réseau non isolable ({net_detail}) et mode strict : "
                                    "l'exécution sera REFUSÉE ; relancez avec --allow-network en "
                                    "laboratoire de confiance ou installez user-namespace/unshare.")
                else:
                    warnings.append(f"Réseau non isolable ({net_detail}) ; exécution avec réseau "
                                     "disponible — responsabilité de l'opérateur.")
        argv = [*wrapper, str(self.target), *self.args]
        return make_result(
            Status.OK, mode="plan", executed=False,
            target=str(self.target),
            target_exists=self.target.is_file(),
            argv=argv,
            cwd="<répertoire temporaire privé 0700>",
            env_whitelist=list(self.limits.env_whitelist) + ["HOME=<sbox>"],
            network=network,
            resource_limits={
                "cpu_seconds": self.limits.cpu_seconds,
                "memory_mb": self.limits.memory_mb,
                "wall_timeout_s": self.limits.wall_timeout_s,
                "max_child_processes": self.limits.max_processes,
                "max_file_mb": self.limits.max_file_mb,
                "enforced_via_rlimits": resource is not None,
            },
            strace=bool(self.limits.strace and shutil.which("strace")),
            capture=["stdout(1Mo max)", "stderr(1Mo max)", "fichiers créés dans le workdir",
                     "signaux", "code de sortie"],
            warnings=warnings,
        )

    # ── exécution ─────────────────────────────────────────────────

    def _snapshot(self, directory: Path) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        try:
            entries = list(directory.rglob("*"))
        except OSError:
            return out
        for entry in entries[:MAX_TRACKED_FILES]:
            try:
                if entry.is_file():
                    stat = entry.stat()
                    digest = ""
                    if stat.st_size <= 1024 * 1024:
                        digest = hashlib.sha256(entry.read_bytes()).hexdigest()[:16]
                    out[str(entry.relative_to(directory))] = {"size": stat.st_size, "sha256_16": digest}
            except OSError:
                continue
        return out

    def execute(self) -> dict[str, Any]:
        """Lance réellement la cible dans le bac à sable (appel explicite)."""
        if not self.target.is_file():
            return make_result(Status.INVALID, mode="executed", error="target_not_found",
                               target=str(self.target))

        plan = self.plan()
        net_ok, net_detail = self.network_isolation_available()
        if not self.limits.allow_network and not net_ok and self.limits.strict_network:
            return make_result(Status.INVALID, mode="executed", error="network_isolation_unavailable",
                               detail=net_detail,
                               hint="utilisez --allow-network uniquement en laboratoire contrôlé, "
                                    "ou installez un noyau autorisant unshare -n")

        resource = _try_import_resource()
        workdir = Path(tempfile.mkdtemp(prefix="r3con-sbx-", dir=str(self.workdir_parent)
                                        if self.workdir_parent else None))
        os.chmod(workdir, 0o700)
        findings: list[dict] = []
        warnings = list(plan.get("warnings") or [])

        stdin = subprocess.DEVNULL
        if self.input_file:
            try:
                stdin = open(self.input_file, "rb")  # noqa: SIM115 - fermé ci-dessous
            except OSError as exc:
                return make_result(Status.INVALID, mode="executed", error=f"input_file: {exc}"[:300])
        elif self.stdin_data is not None:
            stdin = subprocess.PIPE

        limits = self.limits

        def _apply_rlimits() -> None:
            if resource is None:
                return
            resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds + 1))
            mem = limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes))
            fsize = limits.max_file_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))

        env = {k: os.environ[k] for k in limits.env_whitelist if k in os.environ}
        env.update({"HOME": str(workdir), "TMPDIR": str(workdir),
                    "TMP": str(workdir), "TEMP": str(workdir)})
        if not limits.allow_network:
            # Filet de sécurité en plus de unshare : aucun proxy résolvable.
            env.update({"http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
                        "no_proxy": ""})

        prefix = [shutil.which("unshare"), "-n", "--"] if (not limits.allow_network and net_ok) else []
        strace_log: Path | None = None
        if limits.strace and shutil.which("strace"):
            strace_log = workdir / "r3con-strace.log"
            prefix = prefix + [shutil.which("strace"), "-f", "-qq", "-tt", "-o", str(strace_log)]
        elif limits.strace:
            warnings.append("strace demandé mais absent : capture syscalls ignorée (fallback)")

        argv = prefix + [str(self.target), *self.args]
        before = self._snapshot(workdir)
        timed_out = False
        stdout = stderr = b""
        returncode: int | None = None
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv construit depuis des chemins validés
                argv, cwd=str(workdir), stdin=stdin, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, preexec_fn=_apply_rlimits,
                start_new_session=True,
            )
            try:
                out_b, err_b = proc.communicate(input=self.stdin_data, timeout=limits.wall_timeout_s)
                stdout, stderr, returncode = out_b[:MAX_CAPTURE_BYTES], err_b[:MAX_CAPTURE_BYTES], proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()
                out_b, err_b = proc.communicate(timeout=5)
                stdout, stderr = out_b[:MAX_CAPTURE_BYTES], err_b[:MAX_CAPTURE_BYTES]
        except OSError as exc:
            return make_result(Status.ERROR, mode="executed", engine="sandboxed-runner",
                               error=f"launch_failed: {exc}"[:300], workdir=str(workdir))
        finally:
            if hasattr(stdin, "close"):
                stdin.close()

        after = self._snapshot(workdir)
        created = {k: v for k, v in after.items() if k not in before or before[k] != v}
        created.pop("r3con-strace.log", None)
        crash_signal = None
        if returncode is not None and returncode < 0:
            try:
                crash_signal = signal.Signals(-returncode).name
            except ValueError:
                crash_signal = f"SIG{-returncode}"

        syscall_summary = None
        network_hints: list[str] = []
        if strace_log is not None and strace_log.is_file():
            try:
                log = strace_log.read_text(errors="replace")[:2 * 1024 * 1024]
                counts: dict[str, int] = {}
                for m in re.finditer(r"^\[(?:pid \d+) \] (\w+)\(", log, re.M):
                    counts[m.group(1)] = counts.get(m.group(1), 0) + 1
                syscall_summary = dict(sorted(counts.items(), key=lambda kv: -kv[1])[:25])
                network_hints = [x for x in re.findall(r"connect\(([^\n]{0,120})", log)
                                 if "AF_INET" in x][:20]
            except OSError:
                warnings.append("log strace illisible")

        if crash_signal:
            findings.append({
                "finding_type": "runtime-crash",
                "severity": "HIGH" if crash_signal in {s.name for s in CRASH_SIGNALS} else "MEDIUM",
                "confidence": 0.9, "status": "observation", "exploitability": "unknown",
                "tool": "r3con-sandbox", "tool_version": "1.0",
                "target": str(self.target),
                "description": f"Crash du processus local sous exécution isolée : signal {crash_signal}",
                "recommendation": "Reproduire sous gdb/ASAN avant toute conclusion ; ne jamais conclure à "
                                  "une exploitabilité depuis un seul crash.",
                "evidence": {"signal": crash_signal, "stderr_tail": stderr.decode("utf-8", "replace")[-400:]},
                "tags": ["dynamic", "sandbox"],
                "provenance": {"mode": "executed", "isolation": plan["network"]},
            })
        if timed_out:
            findings.append({
                "finding_type": "runtime-timeout", "severity": "INFO", "confidence": 0.95,
                "status": "observation", "tool": "r3con-sandbox", "tool_version": "1.0",
                "target": str(self.target),
                "description": f"Exécution interrompue après {limits.wall_timeout_s}s (arbre de processus tué)",
                "evidence": {"wall_timeout_s": limits.wall_timeout_s},
                "tags": ["dynamic", "sandbox"],
            })

        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except OSError:
            warnings.append(f"workdir temporaire non nettoyé : {workdir} (mode 0700 conservé)")

        status = Status.TIMEOUT if timed_out else Status.OK
        return make_result(
            status, mode="executed", engine="sandboxed-runner", target=str(self.target),
            returncode=returncode, crash_signal=crash_signal, timed_out=timed_out,
            network_isolation=plan["network"], rlimits_enforced=resource is not None,
            stdout_tail=stdout.decode("utf-8", "replace")[-2000:],
            stderr_tail=stderr.decode("utf-8", "replace")[-2000:],
            files_created=created, syscall_summary=syscall_summary,
            network_hints=network_hints, warnings=warnings,
            findings=normalize_findings(findings, target=str(self.target), tool="r3con-sandbox",
                                        tool_version="1.0"),
        )
