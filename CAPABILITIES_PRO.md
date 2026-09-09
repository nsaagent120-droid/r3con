# r3con v5.1.0 PRO - Titan - Capacités Étendues

> **35+ outils externes intégrés, config puissante, chaînage automatique, profils**

## 🚀 Nouveautés v5.1.0 PRO

### 1. Configuration Puissante (core/config_manager.py)

**Système en couches :** `defaults < YAML < env vars < CLI overrides`

- **YAML** : `config.yaml`, `~/.r3con/config.yaml`, `/etc/r3con/config.yaml`, `$R3CON_CONFIG`
- **ENV** : Toutes les options via `R3CON_*` (ex: `R3CON_ANALYSIS_TIMEOUT=300`, `R3CON_TOOL_GHIDRA=/opt/...`)
- **Profils** : 10 profils prédéfinis + custom
- **Validation** : Clamp automatique, type conversion

```bash
r3con config show
r3con config show --profile full
r3con config profiles
r3con config init --output ~/.r3con/config.yaml --profile full
r3con config env  # liste toutes les env vars

# Env overrides
export R3CON_PROFILE=full
export R3CON_ANALYSIS_TIMEOUT=300
export R3CON_TOOL_GHIDRA=/opt/ghidra/support/analyzeHeadless
export R3CON_EXTERNAL_TOOLS_ENABLED_GHIDRA=true
```

**Profils PRO :**

| Profil | Description | Workers | Timeout | Outils |
|--------|-------------|---------|---------|--------|
| `quick` | Rapide, léger | 2 | 30s | minimal |
| `deep` | Équilibré (défaut) | 4 | 120s | r2, checksec, ropper |
| `full` | Max, tous outils | 6 | 300s | ghidra, angr, jadx, binwalk... |
| `binary` | Focus binaire | 4 | 120s | checksec, ropper, one_gadget, r2 |
| `firmware` | Focus firmware | 4 | 120s | binwalk, firmwalker, extraction |
| `apk` | Focus APK | 4 | 120s | jadx, apktool |
| `network` | Focus PCAP | 4 | 120s | tshark, zeek |
| `bugbounty` | Secrets + vulns | 4 | 120s | secrets, injection |
| `exploit` | ROP + exploit | 4 | 120s | ropper, one_gadget, pwndbg |
| `stealth` | Furtif, offline | 2 | 60s | aucun réseau |

### 2. Intégration 35+ Outils Externes

**ToolManager PRO** détecte automatiquement, gère les capacités, et propose un plan d'installation.

**Binaire (12) :**
- `r2`/`radare2` - disasm + decompile
- `rizin` - moderne
- `ghidra` - decompilation lourde (opt-in)
- `checksec` - protections (canary, NX, PIE, RELRO)
- `ropper` - ROP/JOP gadgets
- `one_gadget` - one gadget RCE
- `objdump` - binutils disasm
- `readelf` - ELF headers
- `nm` - symboles
- `strings` - extraction
- `file` - magic detection
- `angr` - symbolic execution (python lib)

**Firmware (5) :**
- `binwalk` - extraction
- `firmwalker` - secrets
- `sasquatch` - squashfs
- `ubi_reader` - UBI
- `jefferson` - JFFS2

**APK (5) :**
- `jadx` - DEX→Java
- `apktool` - manifest + smali
- `dex2jar` - DEX→JAR
- `apksigner` - signatures
- `zipalign` - alignment

**Réseau (5) :**
- `tshark` - PCAP decode
- `zeek` - logs
- `tcpdump` - capture
- `wireshark` - GUI
- `capinfos` - PCAP info

**Dynamique (8) :**
- `gdb` - debugger
- `pwndbg` - GDB plugin
- `gef` - GDB Enhanced
- `qemu` - emulation
- `frida` - instrumentation
- `strace` - syscall trace
- `ltrace` - library trace
- `valgrind` - memcheck

**Fuzzing (3) + Misc (4) :**
- `afl++`, `honggfuzz`, `radamsa`
- `yara`, `clamav`, `ssdeep`

```bash
# Status
r3con tools status
r3con tools summary
r3con tools check r2
r3con tools check ghidra

# Plan d'installation (jamais auto-install)
r3con tools plan
r3con tools plan r2 ghidra jadx binwalk

# Chaînage automatique PRO
r3con tools enhanced ./binary --profile binary
r3con tools enhanced ./firmware.bin --profile firmware --json-output
```

### 3. Adapters Avancés (advanced_adapters.py)

Chaque outil a son adapter avec :
- Validation path + taille (500MB max)
- Timeout configurable
- Limites output (10MB)
- Parsing structuré
- Fallback

**Exemples :**
- `ChecksecAdapter` : parse protections
- `RopperAdapter` : cherche gadgets `pop rdi`
- `OneGadgetAdapter` : one gadget RCE
- `ObjdumpAdapter` : disasm intel
- `ReadelfAdapter` : headers + sections
- `BinwalkAdapter` : extraction + entropy
- `JadxAdapter` : java files
- `AngrAdapter` : symbolic execution avec `find/avoid`
- `EnhancedToolChain` : chaîne 10+ outils

### 4. Orchestrateur PRO (enhanced_orchestrator.py)

**Capacités x10 :**

- Utilise `ConfigManager` → toutes limites configurables
- Détection cible améliorée (ELF embedded, APK signature, printable ratio, firmware indicators)
- Plan basé sur profil + outils disponibles + config
- Chaînage automatique si `external_tools.chaining.enabled=true`
- Cache version-aware (config hash + tool versions + TTL 7j)
- Parallélisation configurable (1-16 workers)
- Artifacts + tool summary

```bash
# Classic (v5.0)
r3con analyze ./binary --profile binary

# PRO (v5.1) - avec config puissante
r3con analyze-pro ./binary --profile full --with-ghidra --with-angr --chain
r3con analyze-pro ./binary --profile exploit --json-output report.json
r3con analyze-pro ./firmware.bin --profile firmware --config ~/.r3con/config.yaml
r3con analyze-pro ./app.apk --profile apk --with-jadx

# Env overrides
R3CON_PROFILE=full R3CON_ANALYSIS_TIMEOUT=300 r3con analyze-pro ./binary
R3CON_TOOL_GHIDRA=/opt/ghidra/support/analyzeHeadless r3con analyze-pro ./binary --with-ghidra
```

### 5. Limites Extensibles

Toutes les limites sont maintenant configurables via YAML/env :

```yaml
limits:
  max_strings: 50000
  max_functions: 5000
  max_findings: 50000
  max_rop_gadgets: 1000
  max_output_mb: 50

analysis:
  max_file_size_mb: 1024
  max_workers: 8
  timeout: 300

external_tools:
  timeout:
    ghidra: 300
    angr: 180
```

```bash
export R3CON_LIMITS_MAX_FINDINGS=50000
export R3CON_ANALYSIS_MAX_FILE_SIZE_MB=1024
export R3CON_EXTERNAL_TOOLS_TIMEOUT_GHIDRA=300
```

## 📦 Installation PRO

```bash
# Minimal
pip install r3con

# PRO full (35+ tools support)
pip install "r3con[full]"

# Avec outils système
sudo apt-get install binutils checksec binwalk tshark zeek gdb strace ltrace file
pip install ropper angr yara-python jadx  # etc.

# Vérifier
r3con tools summary
r3con config show --profile full
```

## 🎯 Exemples d'usage PRO

```bash
# Binaire avec chaîne complète
r3con analyze-pro ./vuln_binary --profile full --with-ghidra --chain
# → checksec + strings + readelf + objdump + ropper + one_gadget + r2 + ghidra + angr

# Firmware avec extraction
r3con analyze-pro ./router.bin --profile firmware --config config.pro.yaml
# → binwalk extract + strings + entropy + secrets + backdoors

# APK avec decompilation
r3con analyze-pro ./app.apk --profile apk --with-jadx
# → apktool + jadx + strings + manifest + permissions

# Bug bounty - secrets + vulns
r3con analyze-pro ./target --profile bugbounty --workers 8 --timeout 300

# Exploit dev
r3con analyze-pro ./binary --profile exploit --chain
r3con tools enhanced ./binary --profile binary --json-output

# Stealth (offline, pas de réseau)
r3con analyze-pro ./binary --profile stealth
```

## 🔧 Config PRO complète

Voir `config.pro.yaml` (300+ lignes) pour toutes les options :

- 10 profils
- 35+ outils avec timeouts custom
- Limites extensibles
- Chaining config
- Reporting (md/html/json/sarif)
- AI + expert mode
- Dashboard + logging + performance + security

Copier vers `~/.r3con/config.yaml` et éditer.

## 📊 Comparaison v5.0 vs v5.1 PRO

| Feature | v5.0.3 | v5.1.0 PRO |
|---------|--------|------------|
| Outils externes | 7 | 35+ |
| Config | basique | puissante (YAML+env+profils) |
| Profils | 6 | 10 + custom |
| Limites | hardcodées | configurables |
| Chaînage | non | oui, auto |
| Adapters | 2 | 15+ |
| Orchestrateur | basique | enhanced + cache version-aware |
| CLI | 20 commandes | 30+ commandes |

## 🚀 Prochaines étapes (v5.2)

- [ ] Ghidra headless complet avec scripts custom
- [ ] angr explorations avancées (taint, vuln detection)
- [ ] QEMU emulation + syscall tracing
- [ ] Frida hooking automatique
- [ ] AFL++ fuzzing intégré
- [ ] Dashboard web PRO avec graphes
- [ ] SBOM + signature
