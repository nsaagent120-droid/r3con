"""Analyse de chaîne d'approvisionnement logicielle — 100 % locale.

Aucune donnée du projet n'est envoyée à un service distant par défaut :
la détection de vulnérabilités s'appuie sur une politique locale optionnelle
(fichier JSON/YAML fourni par l'utilisateur) et sur un jeu d'amorces
intégré. Les SBOM (CycloneDX, SPDX) sont construits hors ligne.

Support progressif : Python, npm, Java/Kotlin (Maven/Gradle), Go, Rust,
Docker, Kubernetes, Terraform.
"""
from .scanner import SupplyChainScanner, discover_manifests

__all__ = ["SupplyChainScanner", "discover_manifests"]
