"""Génération de SBOM hors ligne : CycloneDX 1.5 JSON et SPDX 2.3 JSON.

Les deux formats sont produits avec la seule bibliothèque standard. Les
identifiants d'intégrité sont déterministes (uuid5/Namespace à partir du
répertoire analysé) afin que deux SBOM d'une même cible non modifiée soient
comparables en revue ; l'horodatage reste réel, sauf en mode
``deterministic`` pour les besoins de la CI.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from core.__version__ import __version__ as R3CON_VERSION

CYCLONEDX_SPEC = "1.5"
SPDX_VERSION = "SPDX-2.3"
UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/nsaagent120-droid/r3con")


def _timestamp(deterministic: bool) -> str:
    if deterministic:
        return "1970-01-01T00:00:00Z"
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sanitize(component: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(component.get("name", "unknown"))[:200],
        "version": str(component.get("version", "unknown"))[:100],
        "ecosystem": str(component.get("ecosystem", "generic"))[:60],
        "purl": str(component.get("purl", ""))[:400],
        "scope": str(component.get("scope", "runtime")),
        "source": str(component.get("source", "manifest")),
        "manifest": str(component.get("manifest", ""))[:300],
    }


def build_cyclonedx(components: list[dict], target: str, *, deterministic: bool = False,
                    tool_fingerprint: str = "") -> dict[str, Any]:
    entries = []
    seen: set[str] = set()
    for raw in components:
        comp = _sanitize(raw)
        ref = f"{comp['ecosystem']}/{comp['name']}@{comp['version']}"
        if ref in seen:
            continue
        seen.add(ref)
        entries.append({
            "type": "library" if comp["ecosystem"] not in {"docker", "k8s", "terraform"} else "platform",
            "name": comp["name"],
            "version": comp["version"],
            "purl": comp["purl"] or f"pkg:generic/{comp['name']}@{comp['version']}",
            "bom-ref": ref,
            "scope": "required" if comp["scope"] == "runtime" else "optional",
            "properties": [
                {"name": "r3con:source", "value": comp["source"]},
                {"name": "r3con:manifest", "value": comp["manifest"]},
                {"name": "r3con:ecosystem", "value": comp["ecosystem"]},
            ],
        })
    serial = uuid.uuid5(UUID_NS, f"sbom|{target}|{len(entries)}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(deterministic),
            "tools": [{"vendor": "r3con", "name": "r3con-supply-chain", "version": R3CON_VERSION}],
            "component": {"type": "application", "name": target, "bom-ref": "r3con:target"},
        },
        "components": entries,
        "externalReferences": [{
            "type": "build-system",
            "url": "https://github.com/nsaagent120-droid/r3con",
            "comment": "Généré localement par r3con (aucune donnée transmise).",
        }],
    }


def build_spdx(components: list[dict], target: str, *, deterministic: bool = False,
               tool_fingerprint: str = "") -> dict[str, Any]:
    packages, relationships = [], []
    seen: set[str] = set()
    first_id: str | None = None
    counter = -1
    for raw in components:
        comp = _sanitize(raw)
        ref = f"{comp['ecosystem']}/{comp['name']}@{comp['version']}"
        if ref in seen:
            continue
        seen.add(ref)
        counter += 1
        spdx_id = f"SPDXRef-r3con-component-{counter}"
        first_id = first_id or spdx_id
        packages.append({
            "SPDXID": spdx_id,
            "name": comp["name"],
            "versionInfo": comp["version"],
            "downloadLocation": comp["purl"] or "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": comp["purl"] or f"pkg:generic/{comp['name']}",
            }],
            "primaryPackagePurpose": "LIBRARY",
            "annotations": [{
                "annotator": f"Tool: r3con-{R3CON_VERSION}",
                "annotationType": "OTHER",
                "comment": f"ecosystem={comp['ecosystem']};source={comp['source']};manifest={comp['manifest']}",
            }],
        })
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": spdx_id,
        })
    doc_ns = f"https://r3con.local/sbom/{uuid.uuid5(UUID_NS, f'spdx|{target}|{len(packages)}')}"
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"r3con-sbom-{uuid.uuid5(UUID_NS, target)}",
        "documentNamespace": doc_ns,
        "creationInfo": {
            "created": _timestamp(deterministic),
            "creators": [f"Tool: r3con-{R3CON_VERSION}"],
            "licenseListVersion": "3.22",
        },
        "packages": packages,
        "relationships": ([{"spdxElementId": "SPDXRef-DOCUMENT",
                            "relationshipType": "DESCRIBES",
                            "relatedSpdxElement": first_id}]
                          if first_id else []) + relationships,
    }
