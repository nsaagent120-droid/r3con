"""
r3con - CI/CD Integration
Génère automatiquement les configurations CI/CD pour
intégrer r3con dans GitHub Actions, GitLab CI, etc.
"""

from pathlib import Path
from typing import Dict


GITHUB_ACTIONS_TEMPLATE = """name: r3con Security Analysis

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    name: r3con Security Scan

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Install r3con
      run: |
        pip install click rich capstone lief
        # Optional: pip install together  # For AI analysis

    - name: Run r3con analysis
      run: |
        python -m r3con_ci --target . --format sarif --output results.sarif
      env:
        R3CON_EXPERT_MODE: true
        # TOGETHER_API_KEY: ${{ secrets.TOGETHER_API_KEY }}  # Optional AI

    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: results.sarif

    - name: Comment PR with findings
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const sarif = JSON.parse(fs.readFileSync('results.sarif', 'utf8'));
          const results = sarif.runs[0].results || [];
          const critical = results.filter(r => r.level === 'error').length;
          if (critical > 0) {
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## r3con Security Scan\\n\\n🔴 **${critical} critical/high findings detected.**\\n\\nPlease review the Security tab for details.`
            });
          }
"""

GITLAB_CI_TEMPLATE = """# r3con Security Analysis - GitLab CI

stages:
  - security

r3con-scan:
  stage: security
  image: python:3.10-slim
  
  before_script:
    - pip install click rich capstone lief
  
  script:
    - export R3CON_EXPERT_MODE=true
    - python -m r3con_ci --target . --format sarif --output gl-sast-report.sarif
    - python -m r3con_ci --target . --format json  --output gl-sast-report.json
  
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.sarif
      - gl-sast-report.json
    when: always
    expire_in: 30 days
  
  allow_failure: true
  
  variables:
    R3CON_EXPERT_MODE: "true"
    # TOGETHER_API_KEY: $TOGETHER_API_KEY  # Optional
"""

PRE_COMMIT_TEMPLATE = """# .pre-commit-config.yaml
# r3con pre-commit hook

repos:
  - repo: local
    hooks:
      - id: r3con-security-scan
        name: r3con Security Scan
        entry: python -m r3con_ci --target
        language: python
        types: [python, c, cpp]
        args: [--format, text, --fail-on, HIGH]
        additional_dependencies: [click, rich]
"""

MAKEFILE_TEMPLATE = """# r3con Makefile targets

.PHONY: security security-full security-deps security-ci

# Quick scan (offline, fast)
security:
\t@echo "Running r3con quick scan..."
\tR3CON_EXPERT_MODE=true python -m r3con_ci --target . --format text

# Full scan with all modules
security-full:
\t@echo "Running r3con full scan..."
\tR3CON_EXPERT_MODE=true python -m r3con_ci --target . --format all --output reports/

# Dependency scan only
security-deps:
\t@echo "Scanning dependencies..."
\tpython -m r3con_ci --target . --scan deps --format text

# CI mode (fail on critical)
security-ci:
\t@echo "Running r3con CI scan..."
\tR3CON_EXPERT_MODE=true python -m r3con_ci --target . --format sarif --output security.sarif --fail-on CRITICAL
"""


class CICDIntegration:
    """Generate CI/CD configuration files for r3con."""

    def generate_github_actions(self, output_dir: str = '.github/workflows') -> str:
        """Generate GitHub Actions workflow file."""
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        out  = path / 'r3con-security.yml'
        out.write_text(GITHUB_ACTIONS_TEMPLATE)
        return str(out)

    def generate_gitlab_ci(self, output_path: str = '.gitlab-ci-security.yml') -> str:
        """Generate GitLab CI configuration."""
        path = Path(output_path)
        path.write_text(GITLAB_CI_TEMPLATE)
        return str(path)

    def generate_pre_commit(self, output_path: str = '.pre-commit-config.yaml') -> str:
        """Generate pre-commit hook configuration."""
        path = Path(output_path)
        path.write_text(PRE_COMMIT_TEMPLATE)
        return str(path)

    def generate_makefile_targets(self, output_path: str = 'Makefile.security') -> str:
        """Generate Makefile security targets."""
        path = Path(output_path)
        path.write_text(MAKEFILE_TEMPLATE)
        return str(path)

    def generate_all(self, project_dir: str = '.') -> Dict:
        """Generate all CI/CD configuration files."""
        base    = Path(project_dir)
        outputs = {}

        outputs['github_actions'] = self.generate_github_actions(
            str(base / '.github' / 'workflows'))
        outputs['gitlab_ci']      = self.generate_gitlab_ci(
            str(base / '.gitlab-ci-security.yml'))
        outputs['pre_commit']     = self.generate_pre_commit(
            str(base / '.pre-commit-config-security.yaml'))
        outputs['makefile']       = self.generate_makefile_targets(
            str(base / 'Makefile.security'))

        return outputs
