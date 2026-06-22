#!/usr/bin/env bash
# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Installateur unique pour AnonymizerGPT :
#   - dépendances système (OCR tesseract, presse-papiers X11/Wayland, tkinter)
#   - environnement virtuel Python + dépendances pip
#
# Usage :
#   ./install.sh            # installe tout
#   ./install.sh --no-apt   # saute les paquets système (pip/venv uniquement)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"
SKIP_APT=0
for arg in "$@"; do
  case "$arg" in
    --no-apt) SKIP_APT=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Argument inconnu: $arg" >&2; exit 1 ;;
  esac
done

info()  { printf '\033[1;34m[*]\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }

# ── 1. Dépendances système (Debian / Kali / Ubuntu) ──────────────
APT_PACKAGES=(
  tesseract-ocr          # moteur OCR
  tesseract-ocr-fra      # langue française pour l'OCR
  python3-tk             # tkinter (requis par la GUI customtkinter)
  python3-venv           # création d'environnements virtuels
  xclip                  # presse-papiers image sous X11
  wl-clipboard           # presse-papiers image sous Wayland
)

if [ "$SKIP_APT" -eq 0 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    info "Installation des dépendances système via apt..."
    SUDO=""
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    $SUDO apt-get update -y
    $SUDO apt-get install -y "${APT_PACKAGES[@]}"
    ok "Dépendances système installées."
  else
    warn "apt-get introuvable. Installe manuellement : ${APT_PACKAGES[*]}"
    warn "(macOS : brew install tesseract ; relance avec --no-apt)"
  fi
else
  info "--no-apt : dépendances système ignorées."
fi

# ── 2. Vérification de Python ────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 est requis mais introuvable." >&2
  exit 1
fi
info "Python détecté : $(python3 --version)"

# ── 3. Environnement virtuel + dépendances pip ───────────────────
if [ ! -d "$VENV_DIR" ]; then
  info "Création de l'environnement virtuel ($VENV_DIR)..."
  python3 -m venv "$VENV_DIR"
fi

info "Installation des dépendances Python..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/pip" install -r requirements.txt
ok "Dépendances Python installées."

# ── 4. Récapitulatif ─────────────────────────────────────────────
cat <<EOF

$(ok "Installation terminée.")

Pour commencer :
  source $VENV_DIR/bin/activate
  python3 proxy_gui.py                       # interface graphique
  python3 demo.py --demo --verify-demo       # démo + vérification anti-régression
  echo "10.0.50.12" | python3 anonymizer_core.py --mode anonymize --project test
EOF
