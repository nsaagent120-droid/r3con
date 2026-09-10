"""Détection unifiée des types de cible (offline, stdlib uniquement).

Source unique de vérité pour classer une cible avant orchestration :
ELF, PE, Mach-O, APK, firmware, PCAP, code source, archive et conteneur.
La détection renvoie des ``indicators`` explicables affichés par
``r3con scan --explain-plan`` et jamais aucune donnée n'est envoyée
ailleurs que sur le disque local.
"""
from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Kinds historiques conservés pour la sélection de profil de l'orchestrateur.
KIND_BINARY = "binary"
KIND_FIRMWARE = "firmware"
KIND_APK = "apk"
KIND_NETWORK = "network"
KIND_SOURCE = "source"
KIND_ARCHIVE = "archive"
KIND_CONTAINER = "container"
KIND_DIRECTORY = "directory"
KIND_UNKNOWN = "unknown"

ELF_MACHINES = {
    3: "x86", 8: "powerpc", 20: "arm", 21: "arm64 (reserved)", 40: "arm64",
    62: "x86-64", 183: "RISC-V", 243: "RISC-V",
}

SOURCE_SUFFIXES = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".py", ".go", ".rs",
                   ".java", ".kt", ".js", ".ts", ".php", ".rb", ".sh", ".pl", ".cs",
                   ".swift", ".lua", ".asm", ".s", ".yaml", ".yml", ".toml", ".ini"}

ARCHIVE_MAGICS = {
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ\x00": "xz",
    b"\x04\x22\x4d\x18": "lz4",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"PK\x05\x06": "zip-empty",
    b"Rar!\x1a\x07": "rar",
    b"\x5d\x00\x00": "lzma",
}

FIRMWARE_MAGICS = {
    b"hsqs": "squashfs",
    b"hsqsv4": "squashfs",
    b"UBI#": "ubi",
    b"\x85\x19\x03\x20": "jffs2",
    b"\x20\x03\x19\x85": "jffs2",
    b"\x27\x05\x19\x56": "u-boot-legacy",
    b"-rom1fs-": "romfs",
    b"\x45\x3d\x28\xcd": "cramfs-be",
    b"\xcd\x28\x3d\x45": "cramfs-le",
    b"HDR0": "broadcom-trx",
    b"070701": "cpio-newc",
    b"070702": "cpio-newc",
    b"\xe2\xe1\xf5\xdf": "erofs",
}

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "pcap-be",
    b"\xa1\xb2\xc3\xd4": "pcap-le",
    b"\x4d\x3c\xb2\xa1": "pcap-ns-be",
    b"\xa1\xb2\x3c\x4d": "pcap-ns-le",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}

HEAD_SIZE = 64 * 1024


@dataclass
class TargetType:
    """Classification explicable d'une cible."""

    kind: str = KIND_UNKNOWN
    types: list[str] = field(default_factory=list)
    confidence: float = 0.0
    indicators: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "types": list(self.types), "confidence": self.confidence,
                "indicators": list(self.indicators), "details": dict(self.details), "path": self.path}


def _zip_classify(path: Path, head: bytes) -> TargetType:
    result = TargetType(kind=KIND_ARCHIVE, types=["zip", "archive"], confidence=0.6,
                        indicators=["signature ZIP (PK\\x03\\x04)"], path=str(path))
    names: set[str] = set()
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except (OSError, zipfile.BadZipFile):
        result.confidence = 0.3
        result.indicators.append("contenu ZIP illisible ou tronqué")
        if b"AndroidManifest" in head or b"classes.dex" in head:
            result.kind = KIND_APK
            result.types = ["apk"]
            result.confidence = 0.5
            result.indicators.append("empreintes AndroidManifest/classes.dex dans l'en-tête")
        return result

    if {"AndroidManifest.xml", "classes.dex"} & names:
        result.kind = KIND_APK
        result.types = ["apk", "android"]
        result.confidence = 0.95
        result.indicators.append(f"entrées Android dans l'archive : {sorted(x for x in names if x.endswith(('.xml', '.dex')) or x == 'AndroidManifest.xml')[:3]}")
        if any(n.startswith("lib/") and n.endswith(".so") for n in names):
            result.types.append("native-libs")
            result.details["native_libs"] = sum(1 for n in names if n.startswith("lib/") and n.endswith(".so"))
    elif "manifest.json" in names or "repositories" in names:
        layer_like = any(n.endswith(".tar") or n.endswith("/layer.tar") or n.startswith("blobs/sha256/") for n in names)
        if layer_like or "repositories" in names:
            result.kind = KIND_CONTAINER
            result.types = ["container-image", "docker-archive"]
            result.confidence = 0.9
            result.indicators.append("archive d'image de conteneur (manifest.json/layers)")
    elif {"oci-layout"} & names:
        result.kind = KIND_CONTAINER
        result.types = ["container-image", "oci-layout"]
        result.confidence = 0.9
        result.indicators.append("OCI image layout (oci-layout)")
    else:
        result.confidence = 0.7
        result.indicators.append(f"archive ZIP de {len(names)} entrées sans signature applicative")
    result.details["entries_sample"] = sorted(names)[:12]
    return result


def _tar_classify(path: Path, head: bytes) -> TargetType:
    result = TargetType(kind=KIND_ARCHIVE, types=["tar", "archive"], confidence=0.75,
                        indicators=["en-tête USTAR à l'offset 257"], path=str(path))
    try:
        import tarfile
        with tarfile.open(path, "r:*") as tf:
            names = tf.getnames()[:4000]
        lowered = {n.rsplit("/", 1)[-1] for n in names}
        if {"manifest.json", "repositories", "oci-layout"} & lowered:
            result.kind = KIND_CONTAINER
            result.types = ["container-image", "oci-layout" if "oci-layout" in lowered else "docker-archive"]
            result.confidence = 0.85
            result.indicators.append("entrées manifest.json/oci-layout dans le TAR → image de conteneur")
        if any(n.startswith("squashfs-root") or n.endswith(".trx") for n in names):
            result.kind = KIND_FIRMWARE
            result.confidence = 0.7
            result.indicators.append("structure de firmware extraite dans l'archive")
        result.details["entries_sample"] = names[:12]
    except Exception as exc:  # noqa: BLE001 - tarfile raises broad errors on damaged archives
        result.confidence = 0.4
        result.indicators.append(f"lecture TAR partielle : {type(exc).__name__}")
    return result


def _looks_textual(head: bytes) -> bool:
    if not head:
        return False
    sample = head[:4096]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return len(sample) > 0 and printable / len(sample) > 0.85


def detect_target(path: str | Path, *, head_bytes: bytes | None = None) -> TargetType:
    """Classifier une cible locale, sans accès réseau ni outil externe."""
    p = Path(path)
    if p.is_dir():
        return TargetType(kind=KIND_DIRECTORY, types=["directory"], confidence=0.99,
                          indicators=["le chemin est un répertoire"], path=str(p))

    head = head_bytes if head_bytes is not None else _read_head(p)
    result = TargetType(path=str(p), indicators=[])
    if not head:
        result.kind, result.confidence = KIND_UNKNOWN, 0.0
        result.indicators.append("fichier vide ou illisible")
        return result
    result.details["size"] = p.stat().st_size if p.exists() else len(head)

    # ELF
    if head.startswith(b"\x7fELF"):
        klass = head[4] if len(head) > 4 else 0
        endian = head[5] if len(head) > 5 else 0
        etype = int.from_bytes(head[16:18], "little" if endian == 1 else "big") if len(head) >= 18 else 0
        machine_id = int.from_bytes(head[18:20], "little" if endian == 1 else "big") if len(head) >= 20 else 0
        if klass in (1, 2) and endian in (1, 2):
            result.types = ["elf", "elf64" if klass == 2 else "elf32"]
            result.details.update({"elf_class": klass, "elf_endian": "little" if endian == 1 else "big",
                                   "elf_type": etype, "elf_machine": machine_id,
                                   "elf_machine_name": ELF_MACHINES.get(machine_id, "unknown")})
            if etype in (2, 3):  # EXEC, DYN (shared/pie)
                result.kind = KIND_BINARY
                result.confidence = 0.97 if etype == 2 else 0.9
                result.indicators.append(f"en-tête ELF valide, type {'EXEC' if etype == 2 else 'DYN'}, machine {result.details['elf_machine_name']}")
            else:
                result.kind = KIND_FIRMWARE
                result.confidence = 0.6
                result.indicators.append(f"signature ELF avec type d'objet inattendu ({etype}) → suspect firmware")
            return _finish(result, head)
        else:
            result.kind = KIND_FIRMWARE
            result.confidence = 0.5
            result.types = ["elf-like"]
            result.indicators.append(
                "signature ELF mais classe/endien invalides → image brute contenant un en-tête ELF"
            )
            return _finish(result, head)

    # PE (MZ + PE\0\0)
    if head.startswith(b"MZ"):
        if b"PE\x00\x00" in head[:4096]:
            result.kind = KIND_BINARY
            result.types = ["pe", "portable-executable"]
            result.confidence = 0.95
            result.indicators.append("en-tête DOS MZ + signature PE")
            if head[2:4] == b"\x90\x00":
                result.details["msdos_stub"] = True
            # .NET / dotnet heuristics
            if b"mscoree.dll" in head[:8192]:
                result.types.append("dotnet")
                result.indicators.append("import mscoree.dll détecté")
        else:
            result.kind = KIND_FIRMWARE
            result.types = ["mz-like"]
            result.confidence = 0.35
            result.indicators.append("signature MZ sans table PE → image brute")
        return _finish(result, head)

    # Mach-O (32/64, little/big endian + fat binaries)
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xff\xed\xfa\xce"):
        result.kind = KIND_BINARY
        result.types = ["mach-o"]
        result.confidence = 0.95
        result.indicators.append("magic Mach-O")
        return _finish(result, head)
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        narchs = int.from_bytes(head[4:8], "big" if head[0] == 0xCA else "little")
        if 1 <= narchs <= 36:
            result.kind = KIND_BINARY
            result.types = ["mach-o", "universal"]
            result.confidence = 0.8
            result.indicators.append(f"Mach-O universel avec {narchs} architecture(s)")
            result.details["narchs"] = narchs
            return _finish(result, head)

    # DEX
    if head.startswith(b"dex\n"):
        result.kind = KIND_APK
        result.types = ["dex", "android"]
        result.confidence = 0.9
        result.indicators.append("fichier DEX Android isolé")
        return _finish(result, head)

    # PCAP / PCAPNG
    if head[:4] in PCAP_MAGICS:
        result.kind = KIND_NETWORK
        result.types = ["pcap", "pcapng" if PCAP_MAGICS[head[:4]] == "pcapng" else "libpcap"]
        result.confidence = 0.97
        result.indicators.append(f"magic capture {PCAP_MAGICS[head[:4]]}")
        return _finish(result, head)

    # Archives
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x07\x08"):
        return _zip_classify(p, head)
    if len(head) > 262 and head[257:262] == b"ustar":
        return _tar_classify(p, head)
    for magic, name in ARCHIVE_MAGICS.items():
        if head.startswith(magic):
            result.kind = KIND_ARCHIVE
            result.types = [name, "archive"]
            result.confidence = 0.85
            result.indicators.append(f"archive {name}")
            return _finish(result, head)

    # Signatures firmware connues
    for magic, name in FIRMWARE_MAGICS.items():
        if head.startswith(magic) or (len(magic) == 4 and magic in head[:512]):
            result.kind = KIND_FIRMWARE
            result.types = [name, "firmware-image"]
            result.confidence = 0.85 if head.startswith(magic) else 0.55
            result.indicators.append(f"signature firmware {name}")
            return _finish(result, head)
    if len(head) > 64 * 1024 and b"hsqs" in head[-8192:]:
        result.kind = KIND_FIRMWARE
        result.types = ["squashfs", "firmware-image"]
        result.confidence = 0.8
        result.indicators.append("magic squashfs en fin d'image")
        return _finish(result, head)
    if b"\x7fELF" in head[64:]:
        result.kind = KIND_FIRMWARE
        result.types = ["elf-embedded"]
        result.confidence = 0.7
        result.indicators.append("binaire ELF embarqué détecté hors en-tête")
        return _finish(result, head)

    # Code source
    suffix = p.suffix.lower()
    if suffix in SOURCE_SUFFIXES and _looks_textual(head):
        result.kind = KIND_SOURCE
        result.types = ["source", suffix.lstrip(".")]
        result.confidence = 0.95
        result.indicators.append(f"extension source {suffix} + contenu texte")
        return _finish(result, head)
    if head.startswith(b"#!") and b"\n" in head[:256]:
        shebang = head[: head.index(b"\n")].decode("utf-8", "replace")
        result.kind = KIND_SOURCE
        result.types = ["script", "source"]
        result.confidence = 0.9
        result.indicators.append(f"shebang {shebang[:64]}")
        return _finish(result, head)

    # Binaire non signé / heuristique texte
    if _looks_textual(head):
        result.kind = KIND_SOURCE
        result.types = ["text"]
        result.confidence = 0.45
        result.indicators.append("contenu majoritairement texte sans extension connue")
        return _finish(result, head)

    size = result.details.get("size", len(head))
    result.kind = KIND_FIRMWARE if size > 1024 * 1024 else KIND_BINARY
    result.confidence = 0.4
    result.indicators.append(f"aucune signature reconnue ; heuristique de taille ({size} octets)")
    return _finish(result, head)


def _read_head(p: Path) -> bytes:
    try:
        with p.open("rb") as fh:
            return fh.read(HEAD_SIZE)
    except OSError:
        return b""


def _finish(result: TargetType, head: bytes) -> TargetType:
    result.details.setdefault("head_preview", head[:16].hex())
    if "size" not in result.details:
        try:
            result.details["size"] = Path(result.path).stat().st_size
        except OSError:
            result.details["size"] = len(head)
    return result


def human_description(target: TargetType) -> str:
    """Résumé d'une ligne pour l'affichage ``--explain-plan``."""
    pct = int(round(target.confidence * 100))
    return (f"{target.kind} ({', '.join(target.types) or 'n/a'}) — confiance {pct}% ; "
            + ("; ".join(target.indicators) if target.indicators else "aucun indicateur"))
