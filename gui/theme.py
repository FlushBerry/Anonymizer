# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
"""Thème centralisé : palettes de couleurs, polices et apparence customtkinter.

Plusieurs thèmes complets sont disponibles (`PALETTES`). `set_theme(name)` met
à jour les couleurs du module — toute la GUI lit ses couleurs via `theme.<NOM>`,
donc un rebuild des panneaux suffit à re-thémer entièrement l'application.
La taille de police mono (zones de texte) est pilotée par `theme.MONO_SIZE`.
"""

from __future__ import annotations

import customtkinter as ctk

# ── Palettes complètes (chaque thème redéfinit toutes les couleurs) ──
PALETTES: dict[str, dict] = {
    "GitHub Dark": {
        "_mode": "dark",
        "BG": "#0d1117", "PANEL": "#161b22", "PANEL_2": "#1c2128", "ELEVATED": "#21262d",
        "BORDER": "#30363d", "ACCENT": "#2f81f7", "ACCENT_HOVER": "#1f6feb",
        "GREEN": "#3fb950", "GREEN_HOVER": "#2ea043", "RED": "#f85149", "RED_HOVER": "#da3633",
        "YELLOW": "#d29922", "PURPLE": "#bc8cff", "TEXT": "#e6edf3", "MUTED": "#8b949e",
        "HIGHLIGHT_BG": "#5a1e1e",
    },
    "Dracula": {
        "_mode": "dark",
        "BG": "#282a36", "PANEL": "#21222c", "PANEL_2": "#343746", "ELEVATED": "#44475a",
        "BORDER": "#44475a", "ACCENT": "#bd93f9", "ACCENT_HOVER": "#a679f0",
        "GREEN": "#50fa7b", "GREEN_HOVER": "#3fe06a", "RED": "#ff5555", "RED_HOVER": "#e63946",
        "YELLOW": "#f1fa8c", "PURPLE": "#ff79c6", "TEXT": "#f8f8f2", "MUTED": "#6272a4",
        "HIGHLIGHT_BG": "#6e2233",
    },
    "Nord": {
        "_mode": "dark",
        "BG": "#2e3440", "PANEL": "#3b4252", "PANEL_2": "#434c5e", "ELEVATED": "#4c566a",
        "BORDER": "#4c566a", "ACCENT": "#88c0d0", "ACCENT_HOVER": "#6ba7b8",
        "GREEN": "#a3be8c", "GREEN_HOVER": "#8fad78", "RED": "#bf616a", "RED_HOVER": "#a64f58",
        "YELLOW": "#ebcb8b", "PURPLE": "#b48ead", "TEXT": "#eceff4", "MUTED": "#7b88a1",
        "HIGHLIGHT_BG": "#5c3a40",
    },
    "Matrix": {
        "_mode": "dark",
        "BG": "#000000", "PANEL": "#0a140a", "PANEL_2": "#0f1f0f", "ELEVATED": "#143014",
        "BORDER": "#1f4a1f", "ACCENT": "#00ff66", "ACCENT_HOVER": "#00cc52",
        "GREEN": "#39ff14", "GREEN_HOVER": "#2fd60f", "RED": "#ff3131", "RED_HOVER": "#d62828",
        "YELLOW": "#c8ff00", "PURPLE": "#7fffd4", "TEXT": "#b9ffb9", "MUTED": "#4f9f4f",
        "HIGHLIGHT_BG": "#3a0f0f",
    },
    "Solarized Light": {
        "_mode": "light",
        "BG": "#fdf6e3", "PANEL": "#eee8d5", "PANEL_2": "#e4ddc8", "ELEVATED": "#d9d2bd",
        "BORDER": "#ccc4ac", "ACCENT": "#268bd2", "ACCENT_HOVER": "#1e6fa8",
        "GREEN": "#859900", "GREEN_HOVER": "#6d7d00", "RED": "#dc322f", "RED_HOVER": "#b82926",
        "YELLOW": "#b58900", "PURPLE": "#6c71c4", "TEXT": "#073642", "MUTED": "#93a1a1",
        "HIGHLIGHT_BG": "#f3c5c0",
    },
}

DEFAULT_THEME = "GitHub Dark"

# ── Polices (familles disponibles d'office sur Kali/Debian) ──────
FAMILY_UI = "DejaVu Sans"
FAMILY_MONO = "DejaVu Sans Mono"
MONO_SIZE = 12  # taille des zones de texte (requêtes / résultats), pilotée par les Paramètres

# ── Couleurs courantes (injectées par set_theme) ─────────────────
# Valeurs initiales = thème par défaut (remplies juste en dessous).
BG = PANEL = PANEL_2 = ELEVATED = BORDER = ""
ACCENT = ACCENT_HOVER = GREEN = GREEN_HOVER = RED = RED_HOVER = ""
YELLOW = PURPLE = TEXT = MUTED = HIGHLIGHT_BG = ""
_current_theme = DEFAULT_THEME


def set_theme(name: str) -> None:
    """Charge une palette dans les variables de module (puis rebuild de l'UI)."""
    global _current_theme
    palette = PALETTES.get(name, PALETTES[DEFAULT_THEME])
    _current_theme = name if name in PALETTES else DEFAULT_THEME
    globals().update({k: v for k, v in palette.items() if not k.startswith("_")})
    ctk.set_appearance_mode("light" if palette.get("_mode") == "light" else "dark")


def current_theme() -> str:
    return _current_theme


def theme_names() -> list[str]:
    return list(PALETTES)


def font_ui(size: int = 13, weight: str = "normal") -> tuple:
    return (FAMILY_UI, size, weight) if weight != "normal" else (FAMILY_UI, size)


def font_mono(size: int | None = None, weight: str = "normal") -> tuple:
    size = MONO_SIZE if size is None else size
    return (FAMILY_MONO, size, weight) if weight != "normal" else (FAMILY_MONO, size)


def apply_theme(name: str | None = None) -> None:
    """À appeler avant de construire la fenêtre."""
    set_theme(name or DEFAULT_THEME)


# Initialise les variables de module dès l'import.
set_theme(DEFAULT_THEME)
