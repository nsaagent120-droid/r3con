"""Reporting modules v7.0 PRO."""
from .enhanced_reporting import EnhancedReporting
from .bugbounty_report import BugBountyReportGenerator
from .sarif_export import SARIFExporter
from .jira_exporter import JIRAExporter, DefectDojoExporter, GitHubIssuesExporter, MITRENavigatorExporter

# Backward compat alias
BugBountyReport = BugBountyReportGenerator

__all__ = [
    "EnhancedReporting",
    "BugBountyReportGenerator",
    "BugBountyReport",
    "SARIFExporter",
    "JIRAExporter",
    "DefectDojoExporter",
    "GitHubIssuesExporter",
    "MITRENavigatorExporter",
]
