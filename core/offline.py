"""Kill-switch hors ligne global pour r3con.

Priorité :
1. variable d'environnement ``R3CON_OFFLINE`` (valeurs vraies : 1/true/yes/on) ;
2. clé de configuration ``analysis.offline``.

Utilisé par les appelants distants (VirusTotal, MalwareBazaar, NVD, enrichissement
supply chain) pour refuser TOUTE requête sortante — y compris l'envoi d'un simple
hash de fichier — sans attendre que chaque module implémente son propre drapeau.
"""
from __future__ import annotations

import os
from typing import Any

_TRUTHY = {"1", "true", "yes", "on", "force"}


def is_offline() -> bool:
    """Vrai si l'environnement ou la configuration impose le mode hors ligne."""
    value = os.environ.get("R3CON_OFFLINE", "").strip().lower()
    if value:
        return value in _TRUTHY
    try:
        from core.config_manager import get_config
        return bool(get_config().get_bool("analysis.offline", False))
    except Exception:
        return False


def offline_payload(source: str) -> dict[str, Any]:
    """Résultat normalisé 'skipped' pour une source distante désactivée."""
    return {
        "status": "skipped",
        "source": source,
        "reason": "offline_mode",
        "hint": "requêtes distantes désactivées (R3CON_OFFLINE ou analysis.offline)",
    }
