# Capabilities r3con 7.3.0 — Matrice complète

## Résumé

- **47+ capabilities**, 27 groupes CLI, 50+ commandes, 35+ outils externes détectés, 10 profils.
- **95% offline** par défaut, 100% offline avec `R3CON_OFFLINE=1`.
- **Rapide** : <1s pour ELF 150KB en profil quick, pipeline parallèle par niveaux.
- **1 outil pour tout** : remplace 15+ outils spécialisés en triage.

## Matrice par domaine

| Domaine | Fonctionnalités offline | Outils externes optionnels | Note offline | Note avec outils |
|---|---|---|---|---|
| **Code source** | C/C++, Python, Java, Go, Rust, JS, PHP — mémoire, injection, secrets, crypto, concurrence | tree-sitter, tree-sitter-c | 8/10 | 9/10 |
| **Binaire** | ELF/PE/Mach-O parsing, imports, exports, protections, strings, entropie, disasm | capstone, lief, radare2/rizin, ghidra | 7/10 | 9/10 |
| **APK** | Manifest, permissions, URLs, secrets, DEX, libs natives | jadx, apktool | 8/10 | 9/10 |
| **Firmware** | Entropie, strings, extraction, backdoor indicators | binwalk | 7/10 | 8.5/10 |
| **Malware** | PE/ELF, IOC, behavior, anti-analyse, unpacking, classifier (8 moteurs) | yara-python, capa | 8/10 | 9/10 |
| **Réseau** | PCAP/pcapng, flux, DNS, HTTP, TLS, threat, beaconing, DGA, JA3 | scapy, tshark, tcpdump, zeek | 7.5/10 | 9/10 |
| **Web** | SAST 6 cats (SQLi, XSS, SSTI, LFI, RCE, auth) + DAST | nuclei | 9/10 SAST | 9/10 avec nuclei |
| **Cloud** | Dockerfile, Compose, K8s, Terraform — 23 règles | checkov (optionnel) | 9.5/10 | 9.5/10 |
| **Container** | Image tar, layers, secrets, CVE heuristique | trivy, grype | 9/10 secrets, 7/10 CVE | 9/10 |
| **Secrets** | 20 patterns (AWS, GCP, GitHub, etc.) + high entropy | - | 10/10 | 10/10 |
| **Supply-chain** | 7 écosystèmes, lockfiles, transitifs, SBOM CycloneDX/SPDX, policy offline | - (100% offline) | 8/10 sans base fraîche | 9/10 avec policy |
| **Diff** | Binaires, APK, firmware, source, rapports — protections, fonctions, perms, strings, findings | - | 10/10 | 10/10 |
| **Sandbox** | Plan sans exécution, --execute → isolé réseau coupé, RLIMIT, crash→findings | unshare, strace | 10/10 | 10/10 |
| **Fuzzing** | Plan avec limites, triage clustering, minimisation non destructive, export findings | afl++, honggfuzz, radamsa | 8/10 | 9/10 |
| **Symbolic** | AST + validation, reachability unknown sans z3, heuristique | z3-solver, angr | 5/10 | 9/10 |
| **IA/RAG** | RAG v2 local, embeddings TF-IDF, agent OODA, multi-AI manager | openai, together, ollama local | 8/10 TF-IDF | 9.5/10 transformers |
| **Reporting** | MD, HTML, PDF fallback, SARIF, JIRA, DefectDojo, GitHub, MITRE | jinja2, weasyprint, markdown | 9.5/10 | 10/10 |
| **Exploitation** | ROP gadgets, primitives heap, templates PoC bof/rop/format/heap | capstone | 8/10 | 9/10 |
| **Dashboard** | Static v1 + WebSocket real-time v2 (14 tabs) | flask, flask-socketio | 7/10 | 9/10 |
| **Workspace** | Fédérés cloisonnés + fédération + partage + graph + notes + tmux legacy | tmux | 10/10 | 10/10 |

## Outils externes — 35+ détectés

**Catégories** : disasm, binary, firmware, network, web, cloud, secrets.

Exemples : `capstone`, `lief`, `radare2`, `rizin`, `ghidra`, `binwalk`, `tshark`, `tcpdump`, `nuclei`, `jadx`, `apktool`, `yara`, `capa`, `strace`, `afl-fuzz`, `honggfuzz`, `radamsa`, `checksec`, `ropper`, `one_gadget`, `nm`, `readelf`, `objdump`, `strings`, `file`, `upx`, `exiftool`, `nmap`, etc.

- `r3con tools status` : liste disponibilité.
- `r3con tools doctor` : versions + libs optionnelles + conseils install.
- `r3con tools check <tool>` : détail 1 outil.
- Tâches sans outil et sans repli → `unsupported/tool_unavailable` AVANT exécution, n'empêche pas `ok` global.

## Profils (10)

| Profil | Usage | Tâches typiques |
|---|---|---|
| `quick` | Tri rapide <1s | identify, strings |
| `deep` | Audit standard | identify, strings, imports, protections |
| `full` | Audit complet | identify, strings, imports, protections, disasm, rop, secrets |
| `binary` | Binaire ELF/PE/Mach-O | identify, strings, imports, protections, checksec, ropper, disasm, r2 |
| `firmware` | Firmware IoT | identify, firmware_identify, firmware_strings, entropy, binwalk, secrets |
| `apk` | APK Android | identify, apk_identify, apk_strings, apk_permissions |
| `network` | PCAP | network_internal, tshark, zeek |
| `source` | Code source | source_audit |
| `bugbounty` | Bug bounty triage | identify, strings, secrets, protections |
| `exploit` | Exploit dev | identify, protections, checksec, ropper, one_gadget, r2 |
| `stealth` | Minimal discret | identify, strings, imports |
| `auto` | Détection auto via `target_types.py` | map kind → profil |

## Commandes — 50+

**Core** : `scan`, `compare`, `supply-chain`, `dynamic sandbox`, `explain`, `summarize`, `ask`, `reports compare`, `tools doctor`

**Analysis** : `analyze`, `analyze-pro`, `benchmark`, `correlate`, `diff`

**Domains** : `disasm file|strings|imports`, `audit file|dir`, `apk analyze|manifest|permissions`, `firmware analyze|extract|strings|entropy`, `malware analyze|pe|elf|ioc|behavior|classifier|unpack|anti`, `network analyze|threat|flow|dns|http|tls|live`, `web analyze|sast|dast`, `cloud analyze|docker|k8s|terraform`, `container scan|secrets|layers`, `decompile file`, `secrets scan`, `advanced heap|crypto|kernel|toctou|proto`, `research hypothesis|cve-match|variant|patch-diff|fuzz-hints`

**Ops** : `tools status|check|plan|summary|enhanced`, `config show|profiles|init|env`, `workspace create|list|show|info|add-target|fork|merge|link|share|graph|notes|tmux`, `fuzzing engines|create|corpus|stats|triage|plan|export-findings`, `agent plan|run`, `exploit rop|template`, `report gen|jira|defectdojo|mitre`, `dashboard start|test`, `ml embeddings|rag|cluster`, `r2`, `gdb`, `session`, `plugins`, `interactive`

## Comparaison vs outils spécialisés

| Outil spécialisé | Domaine | r3con offline | r3con + outils | USP r3con |
|---|---|---|---|---|
| Ghidra, IDA, Binary Ninja | Decompiler | 7/10 pseudo | 10/10 avec Ghidra | 1 outil pour tout, tri rapide |
| Cuckoo, capa, VirusTotal | Malware | 9/10 heuristic | 9/10 | 100% offline, 8 moteurs |
| Wireshark, Suricata, Zeek | Network | 7.5/10 | 9/10 | 6 analyseurs + DGA/beaconing |
| Burp Pro, Nuclei | Web | 9/10 SAST | 9/10 avec nuclei | SAST+DAST unifié |
| Checkov, Prowler | Cloud | 9.5/10 | 9.5/10 | 23 règles offline |
| Trivy, Grype | Container | 9/10 secrets | 9/10 | tar+secrets offline |
| Trufflehog, GitLeaks | Secrets | 10/10 | 10/10 | 20 patterns + entropy |
| angr, z3 | Symbolic | 5/10 | 9/10 | Fallback heuristique sans |
| ChromaDB, LangChain | ML/RAG | 8/10 TF-IDF | 9.5/10 transformers | 100% offline TF-IDF |
| DefectDojo, JIRA, MITRE | Reporting | 9.5/10 | 10/10 | 7 exporters |

**Note globale honnête** :
- Pentest rapide / audit offline / bug bounty triage / CI/CD : **9.5/10 EXCELLENT**
- Reverse profond / malware avancé / exploit dev : **7/10 BON**, compléter avec Ghidra/angr/Burp
- Remplacer 15 outils en triage : **9/10 Très bon compromis unified**

## Offline-first

- Aucun fichier, secret, donnée envoyé distant par défaut.
- `R3CON_OFFLINE=1` ou `--offline` ou `analysis.offline` = kill-switch global bloque même hash.
- `tools doctor` indique ce qui est local vs externe.
- Plan explicable (`--explain-plan`) montre outil requis, disponibilité, repli, conseil install AVANT exécution.
