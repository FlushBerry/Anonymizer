# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
"""Composants d'interface réutilisables.

- CopyableTextbox : zone de texte avec une petite icône « copier » en haut-droite.
- HighlightView   : zone de texte (tk.Text) supportant le surlignage rouge des entités.
- WordRow         : ligne « mot + croix rouge de suppression » pour les listes black/whitelist.
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable

import customtkinter as ctk

from . import theme


class CopyableTextbox(ctk.CTkFrame):
    """CTkTextbox + bouton « copier » superposé en haut à droite."""

    def __init__(self, master, readonly: bool = False, placeholder: str = "", **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._readonly = readonly

        self.textbox = ctk.CTkTextbox(
            self,
            wrap="word",
            font=theme.font_mono(),
            fg_color=theme.PANEL_2,
            border_color=theme.BORDER,
            border_width=1,
            text_color=theme.TEXT,
        )
        self.textbox.pack(fill="both", expand=True)

        self._copy_btn = ctk.CTkButton(
            self,
            text="⧉",
            width=30,
            height=26,
            font=theme.font_ui(14),
            fg_color=theme.ELEVATED,
            hover_color=theme.ACCENT,
            text_color=theme.TEXT,
            command=self._copy_to_clipboard,
        )
        self._copy_btn.place(relx=1.0, x=-14, y=8, anchor="ne")

        self._placeholder = placeholder
        if placeholder:
            self.set_text(placeholder)
        if readonly:
            self.textbox.configure(state="disabled")

    # ── API texte ────────────────────────────────────────────────
    def get_text(self) -> str:
        return self.textbox.get("1.0", "end-1c")

    def set_text(self, text: str) -> None:
        if self._readonly:
            self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")
        self.textbox.insert("1.0", text or "")
        if self._readonly:
            self.textbox.configure(state="disabled")

    def clear(self) -> None:
        self.set_text("")

    def focus_text(self) -> None:
        self.textbox.focus_set()

    def bind_text(self, sequence: str, func) -> None:
        self.textbox.bind(sequence, func)

    # ── Copier ───────────────────────────────────────────────────
    def _copy_to_clipboard(self) -> None:
        text = self.get_text()
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception:
            return
        self._copy_btn.configure(text="✓", fg_color=theme.GREEN)
        self.after(900, lambda: self._copy_btn.configure(text="⧉", fg_color=theme.ELEVATED))


class HighlightView(ctk.CTkFrame):
    """Zone tk.Text dédiée au surlignage rouge des entités détectées."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=theme.PANEL_2, border_color=theme.BORDER, border_width=1, **kwargs)

        self.text = tk.Text(
            self,
            wrap="word",
            font=theme.font_mono(),
            bg=theme.PANEL_2,
            fg=theme.TEXT,
            insertbackground=theme.TEXT,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            padx=10,
            pady=10,
        )
        scrollbar = ctk.CTkScrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)

        self.text.tag_configure("entity", background=theme.HIGHLIGHT_BG, foreground="#ffd7d5")
        self.text.tag_configure("muted", foreground=theme.MUTED)

        self._copy_btn = ctk.CTkButton(
            self, text="⧉", width=30, height=26, font=theme.font_ui(14),
            fg_color=theme.ELEVATED, hover_color=theme.ACCENT, text_color=theme.TEXT,
            command=self._copy_to_clipboard,
        )
        self._copy_btn.place(relx=1.0, x=-26, y=8, anchor="ne")

        self.text.configure(state="disabled")

    def render(self, raw: str, spans: list[tuple[int, int]]) -> None:
        """Affiche `raw` avec les sous-chaînes `spans` (fusionnées, triées) surlignées."""
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        if not raw:
            self.text.insert("1.0", "(requête vide — anonymise d'abord une requête)", "muted")
            self.text.configure(state="disabled")
            return
        cursor = 0
        for start, end in spans:
            if cursor < start:
                self.text.insert("end", raw[cursor:start])
            self.text.insert("end", raw[start:end], "entity")
            cursor = end
        if cursor < len(raw):
            self.text.insert("end", raw[cursor:])
        self.text.configure(state="disabled")

    def _copy_to_clipboard(self) -> None:
        text = self.text.get("1.0", "end-1c")
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception:
            return
        self._copy_btn.configure(text="✓", fg_color=theme.GREEN)
        self.after(900, lambda: self._copy_btn.configure(text="⧉", fg_color=theme.ELEVATED))


class WordRow(ctk.CTkFrame):
    """Ligne d'une liste de mots : le mot + une croix rouge pour le supprimer."""

    def __init__(self, master, word: str, on_delete: Callable[[str], None], wraplength: int = 200, **kwargs):
        super().__init__(master, fg_color=theme.PANEL_2, corner_radius=6, **kwargs)
        self.word = word

        del_btn = ctk.CTkButton(
            self, text="✕", width=26, height=26, font=theme.font_ui(13, "bold"),
            fg_color="transparent", hover_color=theme.RED_HOVER, text_color=theme.RED,
            command=lambda: on_delete(word),
        )
        del_btn.pack(side="right", padx=(4, 6), pady=4)

        self.label = ctk.CTkLabel(
            self, text=word, anchor="w", justify="left", wraplength=wraplength,
            font=theme.font_mono(12), text_color=theme.TEXT,
        )
        self.label.pack(side="left", fill="x", expand=True, padx=(10, 4), pady=4)

    def set_wrap(self, wraplength: int) -> None:
        self.label.configure(wraplength=max(80, wraplength))
