# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bandeau supérieur « Paramètres » : titre, nom du projet courant, démo, réglages."""

from __future__ import annotations

import customtkinter as ctk

from . import theme


class TopBar(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=theme.PANEL, corner_radius=0, height=56)
        self.app = app
        self.pack_propagate(False)

        # Titre / logo
        ctk.CTkLabel(
            self, text="🕵  AnonymizerGPT", font=theme.font_ui(18, "bold"), text_color=theme.TEXT,
        ).pack(side="left", padx=(16, 24))

        # Nom du projet (toujours visible)
        self._project_var = ctk.StringVar(value="Projet : (aucun)")
        ctk.CTkLabel(
            self, textvariable=self._project_var, font=theme.font_ui(13), text_color=theme.ACCENT,
        ).pack(side="left")

        # Réglages (droite)
        ctk.CTkButton(
            self, text="⚙  Paramètres", width=120, font=theme.font_ui(13),
            fg_color=theme.ELEVATED, hover_color=theme.BORDER, text_color=theme.TEXT,
            command=app.open_settings,
        ).pack(side="right", padx=(8, 16), pady=10)

        # Lancer la démo (droite)
        ctk.CTkButton(
            self, text="▶  Lancer la démo", width=140, font=theme.font_ui(13, "bold"),
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            command=app.load_demo,
        ).pack(side="right", padx=8, pady=10)

    def set_project_name(self, name: str | None) -> None:
        self._project_var.set(f"Projet : {name}" if name else "Projet : (aucun)")
