# Quickstart r3con 7.3.0

## 1. Install (2 min)

```bash
git clone https://github.com/nsaagent120-droid/r3con.git
cd r3con
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
r3con --help
```

## 2. Premier scan explicable

```bash
# Binaire
r3con scan ./program --profile auto --explain-plan
r3con scan ./program --profile binary --json-output report.json

# Source
r3con audit file ./src/main.c --report
r3con audit dir ./src --recursive

# APK / Firmware
r3con apk analyze ./app.apk --report
r3con firmware analyze ./fw.bin --report

# Réseau / Malware
r3con network analyze ./capture.pcap --json
r3con malware analyze ./sample --profile full
```

## 3. Comprendre le rapport

```bash
r3con summarize report.json
r3con explain FINDING_ID --report report.json
r3con ask report.json "Quels risques sont corroborés par plusieurs outils ?"
```

## 4. Différentiel et supply-chain

```bash
# Diff binaires / APK / rapports
r3con compare ./old.bin ./new.bin --format md --output diff.md
r3con reports compare old.json new.json --format md

# Supply-chain offline
r3con supply-chain scan ./project --sbom cyclonedx --dependencies --secrets
```

## 5. Outils et offline

```bash
r3con tools status
r3con tools doctor --json-output

# Forcer offline (aucune requête distante)
R3CON_OFFLINE=1 r3con scan ./target --offline
```

## 6. Sandbox et fuzzing (labo uniquement)

```bash
# Sandbox : plan par défaut, pas d'exécution
r3con dynamic sandbox ./binary --timeout-ms 5000
# Exécution isolée (réseau coupé, RLIMIT)
r3con dynamic sandbox ./binary --execute --memory-mb 256

# Fuzzing : plan + export findings
r3con fuzzing plan mycamp --timeout-ms 1000 --memory-mb 256
r3con fuzzing export-findings mycamp
```

## 7. CI

```yaml
# examples/github-actions/r3con-scan.yml
- run: pip install -e .
- run: r3con scan ./src --profile source --fail-on high --json-output report.json
- uses: actions/upload-artifact@v4
  with:
    path: report.json
```

## 8. Aide

```bash
r3con --help
r3con scan --help
r3con supply-chain scan --help
r3con dynamic sandbox --help
```

Docs complètes : `README.md`, `docs/USER_GUIDE.md`, `docs/STABLE_RELEASE.md`, `docs/ARCHITECTURE.md`.
