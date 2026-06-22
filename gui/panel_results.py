# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
"""Panneau « Résultats » (bas-droite) : onglets anonymisée / déanonymisée /
surlignée / stats / mapping."""

from __future__ import annotations

import customtkinter as ctk

from . import theme
from .widgets import CopyableTextbox, HighlightView

TAB_ANON = "Anonymisée"
TAB_DEANON = "Dé-anonymisée"
TAB_HIGHLIGHT = "Surlignée"
TAB_STATS = "Stats"
TAB_MAPPING = "Mapping"


class ResultsPanel(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=theme.PANEL, corner_radius=0)
        self.app = app

        ctk.CTkLabel(
            self, text="📊  Résultats", font=theme.font_ui(15, "bold"), text_color=theme.TEXT,
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self.tabview = ctk.CTkTabview(
            self, fg_color=theme.PANEL_2,
            segmented_button_fg_color=theme.PANEL,
            segmented_button_selected_color=theme.ACCENT,
            segmented_button_selected_hover_color=theme.ACCENT_HOVER,
        )
        self.tabview.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        for name in (TAB_ANON, TAB_DEANON, TAB_HIGHLIGHT, TAB_STATS, TAB_MAPPING):
            self.tabview.add(name)

        self.anon_box = CopyableTextbox(self.tabview.tab(TAB_ANON), readonly=True)
        self.anon_box.pack(fill="both", expand=True)

        self.deanon_box = CopyableTextbox(self.tabview.tab(TAB_DEANON), readonly=True)
        self.deanon_box.pack(fill="both", expand=True)

        self.highlight_view = HighlightView(self.tabview.tab(TAB_HIGHLIGHT))
        self.highlight_view.pack(fill="both", expand=True)

        self.stats_box = CopyableTextbox(self.tabview.tab(TAB_STATS), readonly=True)
        self.stats_box.pack(fill="both", expand=True)

        self.mapping_box = CopyableTextbox(self.tabview.tab(TAB_MAPPING), readonly=True)
        self.mapping_box.pack(fill="both", expand=True)

    # ─── Mises à jour ────────────────────────────────────────────
    def show_anonymized(self, text: str, focus: bool = True) -> None:
        self.anon_box.set_text(text)
        if focus:
            self.tabview.set(TAB_ANON)

    def show_deanonymized(self, text: str, focus: bool = True) -> None:
        self.deanon_box.set_text(text)
        if focus:
            self.tabview.set(TAB_DEANON)

    def show_highlight(self, raw: str, spans: list[tuple[int, int]]) -> None:
        self.highlight_view.render(raw, spans)

    def show_stats(self, stats: dict) -> None:
        if not stats:
            self.stats_box.set_text("(aucune détection)")
            return
        total = sum(int(v) for v in stats.values())
        lines = [f"{'TYPE':<26} COMPTE", "-" * 40]
        for etype, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            bar = "█" * min(int(count), 24)
            lines.append(f"{etype:<26} {int(count):>3}  {bar}")
        lines += ["-" * 40, f"{'TOTAL':<26} {total:>3}"]
        self.stats_box.set_text("\n".join(lines))

    def show_mapping(self, mappings: dict, types: dict) -> None:
        if not mappings:
            self.mapping_box.set_text("(aucun mapping actif)")
            return
        # Regroupé par type d'anonymisation (domain, password_param, ip, …), trié.
        groups: dict[str, list[tuple[str, str]]] = {}
        for original, anonymized in mappings.items():
            etype = types.get(original, "?")
            groups.setdefault(etype, []).append((original, anonymized))
        lines: list[str] = []
        for etype in sorted(groups):
            entries = sorted(groups[etype], key=lambda x: x[0].lower())
            lines.append(f"━━ {etype}  ({len(entries)}) ━━")
            for original, anonymized in entries:
                lines.append(f"   {original}  →  {anonymized}")
            lines.append("")
        self.mapping_box.set_text("\n".join(lines).rstrip())

    def clear(self) -> None:
        self.anon_box.clear()
        self.deanon_box.clear()
        self.highlight_view.render("", [])
        self.stats_box.clear()
        self.mapping_box.clear()
