#!/usr/bin/env bash
# r3con 7.2.0 - installation complète reproductible
# Usage: bash scripts/install_full.sh [options]
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${R3CON_VENV:-${PROJECT_ROOT}/.venv}"
INSTALL_SYSTEM=1
INSTALL_DOCKER=0
INSTALL_EXTRA_TOOLS=1
RUN_TESTS=1
NONINTERACTIVE=0

log() { printf '\033[1;36m[r3con]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[r3con][WARN]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[r3con][ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Installation complète de r3con 7.2.0.

Options:
  --no-system       Ne pas installer de paquets système avec apt/dnf/pacman.
  --docker          Installer Docker si possible et tenter d'activer son service.
  --no-extras       Installer uniquement les dépendances Python du projet.
  --no-tests        Ne pas exécuter la suite de tests finale.
  --yes             Mode non interactif lorsque le gestionnaire de paquets le permet.
  --venv PATH       Utiliser un autre répertoire de virtualenv.
  -h, --help        Afficher cette aide.

Exemples:
  bash scripts/install_full.sh
  bash scripts/install_full.sh --docker --yes
  bash scripts/install_full.sh --no-system --venv ~/.venvs/r3con
EOF
}

while (($#)); do
    case "$1" in
        --no-system) INSTALL_SYSTEM=0 ;;
        --docker) INSTALL_DOCKER=1 ;;
        --no-extras) INSTALL_EXTRA_TOOLS=0 ;;
        --no-tests) RUN_TESTS=0 ;;
        --yes) NONINTERACTIVE=1 ;;
        --venv) shift; [[ $# -gt 0 ]] || fail "--venv attend un chemin"; VENV_DIR="$1" ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Option inconnue: $1 (utilisez --help)" ;;
    esac
    shift
done

[[ -f "${PROJECT_ROOT}/pyproject.toml" ]] || fail "pyproject.toml introuvable: ${PROJECT_ROOT}"

if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
    [[ "$INSTALL_SYSTEM" -eq 0 ]] || fail "sudo est requis pour installer les paquets système"
fi

apt_install() {
    local packages=("$@")
    [[ "$INSTALL_SYSTEM" -eq 1 ]] || return 0
    if command -v apt-get >/dev/null 2>&1; then
        log "Installation apt: ${packages[*]}"
        $SUDO apt-get update
        DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y --no-install-recommends "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        log "Installation dnf: ${packages[*]}"
        $SUDO dnf install -y "${packages[@]}"
    elif command -v pacman >/dev/null 2>&1; then
        log "Installation pacman: ${packages[*]}"
        $SUDO pacman -Sy --needed --noconfirm "${packages[@]}"
    else
        fail "Gestionnaire de paquets non supporté. Utilisez --no-system et installez les outils manuellement."
    fi
}

optional_install() {
    local packages=("$@")
    [[ "$INSTALL_SYSTEM" -eq 1 ]] || return 0
    set +e
    apt_install "${packages[@]}"
    local rc=$?
    set -e
    ((rc == 0)) || warn "Paquets optionnels non installés: ${packages[*]}"
}

install_system_tools() {
    apt_install python3 python3-venv python3-pip python3-dev build-essential git \
        file binutils gdb strace ltrace xxd p7zip-full unzip gzip bzip2 xz-utils \
        libpcap-dev

    # Ces paquets varient fortement selon les distributions. Leur absence ne bloque pas r3con.
    optional_install tshark tcpdump yara clamav upx-ucl
    if [[ "$INSTALL_DOCKER" -eq 1 ]]; then
        optional_install docker.io docker-compose-v2
        if command -v systemctl >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
            $SUDO systemctl enable --now docker 2>/dev/null || warn "Impossible d'activer Docker automatiquement"
        fi
        if command -v docker >/dev/null 2>&1 && [[ "$(id -u)" -ne 0 ]]; then
            $SUDO usermod -aG docker "${USER:-$(id -un)}" 2>/dev/null || warn "Impossible d'ajouter l'utilisateur au groupe docker"
            warn "Reconnectez-vous pour que le groupe docker soit actif."
        fi
    fi
}

install_python_environment() {
    command -v python3 >/dev/null 2>&1 || fail "python3 est requis"
    log "Création ou réutilisation du virtualenv: ${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    python -m pip install --upgrade pip setuptools wheel
    log "Installation r3con avec tous les extras Python"
    python -m pip install -e "${PROJECT_ROOT}[full,dev]"
}

configure_local_environment() {
    mkdir -p "${HOME}/.r3con" "${HOME}/.r3con/cache" "${HOME}/.r3con/reports" \
        "${HOME}/.r3con/sessions" "${HOME}/.r3con/workspaces" "${PROJECT_ROOT}/reports"
    if [[ ! -f "${HOME}/.r3con/.env.example" ]]; then
        cat > "${HOME}/.r3con/.env.example" <<'EOF'
# Copier vers ~/.r3con/.env et remplir uniquement les variables nécessaires.
# Ne jamais commiter ce fichier avec de vraies clés.
OPENAI_API_KEY=
TOGETHER_API_KEY=
VT_API_KEY=
R3CON_NO_COLOR=0
EOF
    fi
}

print_tool_report() {
    local tools=(python3 r3con file objdump readelf strings nm gdb strace ltrace tshark tcpdump yara docker radare2 rizin jadx apktool nuclei trivy kubectl terraform)
    printf '\n\033[1;35mOutils détectés\033[0m\n'
    local tool
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '  [OK]      %s\n' "$tool"
        else
            printf '  [absent]  %s\n' "$tool"
        fi
    done
}

main() {
    cd "${PROJECT_ROOT}"
    log "Projet: ${PROJECT_ROOT}"
    [[ "$INSTALL_SYSTEM" -eq 1 ]] && install_system_tools
    install_python_environment
    configure_local_environment

    # Les outils lourds/non uniformes sont signalés, pas téléchargés de manière opaque.
    if [[ "$INSTALL_EXTRA_TOOLS" -eq 1 ]]; then
        warn "Ghidra, JADX, Nuclei, Trivy, Zeek et rizin/radare2 peuvent nécessiter une installation spécifique à votre distribution."
    fi

    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    log "Version installée: $(r3con --version 2>&1 | head -1)"
    if [[ "$RUN_TESTS" -eq 1 ]]; then
        log "Exécution des tests"
        python -m pytest -q -rs
    fi
    print_tool_report
    cat <<EOF

Installation terminée.
Activez l'environnement avec:
  source "${VENV_DIR}/bin/activate"
Documentation:
  ${PROJECT_ROOT}/README.md
  ${PROJECT_ROOT}/docs/USER_GUIDE.md
  ${PROJECT_ROOT}/docs/MANUEL_TECHNIQUE_v7.2.md
EOF
}

main "$@"
