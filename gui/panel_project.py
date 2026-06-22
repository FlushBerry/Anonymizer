# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
"""Sidebar gauche : gestion de projet + listes blacklist / whitelist."""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from . import theme
from .widgets import WordRow


class ProjectPanel(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=theme.PANEL, corner_radius=0, width=300)
        self.app = app
        self.pack_propagate(False)
        self._kind = "blacklist"
        self._word_rows: list[WordRow] = []

        self._build_project_section()
        self._build_words_section()
        self.bind("<Configure>", self._on_resize)

    # ─── Section « Gestion projet » ──────────────────────────────
    def _build_project_section(self) -> None:
        ctk.CTkLabel(
            self, text="📁  Gestion projet", font=theme.font_ui(15, "bold"), text_color=theme.TEXT,
        ).pack(anchor="w", padx=14, pady=(14, 6))

        self._dir_var = ctk.StringVar(value="")
        self._dir_label = ctk.CTkLabel(
            self, textvariable=self._dir_var, font=theme.font_ui(11), text_color=theme.MUTED,
            anchor="w", wraplength=270, justify="left",
        )
        self._dir_label.pack(anchor="w", padx=14, fill="x")

        ctk.CTkButton(
            self, text="📂  Changer de dossier…", font=theme.font_ui(12),
            fg_color=theme.ELEVATED, hover_color=theme.BORDER, text_color=theme.TEXT,
            command=self.app.change_projects_dir,
        ).pack(fill="x", padx=14, pady=(6, 8))

        listbox_frame = ctk.CTkFrame(self, fg_color=theme.PANEL_2, corner_radius=6)
        listbox_frame.pack(fill="both", expand=True, padx=14, pady=(0, 6))
        self.project_list = tk.Listbox(
            listbox_frame, activestyle="none", font=theme.font_mono(12),
            bg=theme.PANEL_2, fg=theme.TEXT, selectbackground=theme.ACCENT,
            selectforeground="#ffffff", relief="flat", borderwidth=0, highlightthickness=0,
        )
        self.project_list.pack(fill="both", expand=True, padx=6, pady=6)
        self.project_list.bind("<Double-Button-1>", lambda _e: self._load_selected())

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=(0, 10))
        ctk.CTkButton(
            btn_row, text="＋ Nouveau", font=theme.font_ui(12), width=10,
            fg_color=theme.GREEN, hover_color=theme.GREEN_HOVER,
            command=self.app.create_project_dialog,
        ).pack(side="left", expand=True, fill="x", padx=(0, 4))
        ctk.CTkButton(
            btn_row, text="📥 Charger", font=theme.font_ui(12), width=10,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            command=self._load_selected,
        ).pack(side="left", expand=True, fill="x", padx=(4, 0))

    # ─── Section blacklist / whitelist ───────────────────────────
    def _build_words_section(self) -> None:
        sep = ctk.CTkFrame(self, height=1, fg_color=theme.BORDER)
        sep.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(
            self, text="🏷  Mots gérés", font=theme.font_ui(15, "bold"), text_color=theme.TEXT,
        ).pack(anchor="w", padx=14, pady=(6, 4))

        self._segment = ctk.CTkSegmentedButton(
            self, values=["Blacklist", "Whitelist"], font=theme.font_ui(12),
            command=self._on_segment_change,
            selected_color=theme.ACCENT, selected_hover_color=theme.ACCENT_HOVER,
        )
        self._segment.set("Blacklist")
        self._segment.pack(fill="x", padx=14, pady=(0, 4))

        self._hint = ctk.CTkLabel(
            self, text="", font=theme.font_ui(11), text_color=theme.MUTED,
            anchor="w", wraplength=270, justify="left",
        )
        self._hint.pack(anchor="w", padx=14, pady=(0, 4))

        add_row = ctk.CTkFrame(self, fg_color="transparent")
        add_row.pack(fill="x", padx=14, pady=(0, 6))
        self._word_entry = ctk.CTkEntry(
            add_row, placeholder_text="mot à ajouter…", font=theme.font_mono(12),
            fg_color=theme.PANEL_2, border_color=theme.BORDER,
        )
        self._word_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._word_entry.bind("<Return>", lambda _e: self._add_word())
        ctk.CTkButton(
            add_row, text="＋", width=34, font=theme.font_ui(14, "bold"),
            fg_color=theme.ELEVATED, hover_color=theme.ACCENT,
            command=self._add_word,
        ).pack(side="right")

        ctk.CTkButton(
            self, text="📄  Importer un fichier de mots…", font=theme.font_ui(12),
            fg_color=theme.ELEVATED, hover_color=theme.BORDER, text_color=theme.TEXT,
            command=lambda: self.app.add_words_from_file(self._kind),
        ).pack(fill="x", padx=14, pady=(0, 6))

        self._words_frame = ctk.CTkScrollableFrame(
            self, fg_color=theme.PANEL, label_text="",
        )
        self._words_frame.pack(fill="both", expand=True, padx=8, pady=(0, 10))

        self._update_hint()

    # ─── Callbacks internes ──────────────────────────────────────
    def _on_segment_change(self, value: str) -> None:
        self._kind = "whitelist" if value == "Whitelist" else "blacklist"
        self._update_hint()
        self.refresh_words()

    def _update_hint(self) -> None:
        if self._kind == "blacklist":
            self._hint.configure(text="Blacklist : mots TOUJOURS anonymisés (noms de code, hostnames internes…).")
        else:
            self._hint.configure(text="Whitelist : mots JAMAIS anonymisés (laissés en clair).")

    def _add_word(self) -> None:
        word = self._word_entry.get().strip()
        if not word:
            return
        self.app.add_word(self._kind, word)
        self._word_entry.delete(0, "end")

    def _load_selected(self) -> None:
        selection = self.project_list.curselection()
        if not selection:
            return
        name = self.project_list.get(selection[0])
        self.app.load_selected_project(name)

    def _on_resize(self, event=None) -> None:
        # Le texte du panneau gauche revient à la ligne selon la largeur courante.
        wrap = max(120, self.winfo_width() - 44)
        self._dir_label.configure(wraplength=wrap)
        self._hint.configure(wraplength=wrap)
        for row in self._word_rows:
            row.set_wrap(wrap - 50)

    # ─── Rafraîchissement (appelé par App) ───────────────────────
    def set_projects_dir(self, path: str) -> None:
        self._dir_var.set(f"Dossier : {path}")

    def refresh_projects(self, projects: list[str], current: str | None = None) -> None:
        self.project_list.delete(0, "end")
        for name in projects:
            self.project_list.insert("end", name)
        if current and current in projects:
            idx = projects.index(current)
            self.project_list.selection_clear(0, "end")
            self.project_list.selection_set(idx)
            self.project_list.see(idx)

    def refresh_words(self) -> None:
        for child in self._words_frame.winfo_children():
            child.destroy()
        self._word_rows = []
        words = self.app.get_words(self._kind)
        if not words:
            ctk.CTkLabel(
                self._words_frame, text="(aucun mot)", font=theme.font_ui(11), text_color=theme.MUTED,
            ).pack(anchor="w", padx=6, pady=6)
            return
        wrap = max(120, self.winfo_width() - 44) - 50
        for word in words:
            row = WordRow(
                self._words_frame, word, wraplength=wrap,
                on_delete=lambda w: self.app.remove_word(self._kind, w),
            )
            row.pack(fill="x", pady=2, padx=2)
            self._word_rows.append(row)
