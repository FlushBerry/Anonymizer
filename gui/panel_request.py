# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
"""Panneau « Requêtes » (haut-droite) : onglets type Burp Repeater + barre d'actions."""

from __future__ import annotations

import tkinter as tk
from tkinter import simpledialog

import customtkinter as ctk

from . import ocr, theme
from .widgets import CopyableTextbox


class RequestPanel(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=theme.PANEL, corner_radius=0)
        self.app = app
        self._tabs: dict[str, CopyableTextbox] = {}
        self._counter = 0

        self._build_toolbar()
        # Les actions sont ancrées EN BAS (side="bottom") avant le tabview : elles
        # restent donc toujours visibles même quand on réduit fortement le panneau.
        self._build_actions()

        self.tabview = ctk.CTkTabview(
            self, fg_color=theme.PANEL_2,
            segmented_button_fg_color=theme.PANEL,
            segmented_button_selected_color=theme.ACCENT,
            segmented_button_selected_hover_color=theme.ACCENT_HOVER,
        )
        self.tabview.pack(side="top", fill="both", expand=True, padx=10, pady=(0, 6))

        self.add_request()  # première requête par défaut

    # ─── Construction ────────────────────────────────────────────
    def _build_toolbar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkLabel(
            bar, text="📨  Requêtes", font=theme.font_ui(15, "bold"), text_color=theme.TEXT,
        ).pack(side="left")
        ctk.CTkButton(
            bar, text="✕ Supprimer", width=100, font=theme.font_ui(12),
            fg_color=theme.ELEVATED, hover_color=theme.RED_HOVER, text_color=theme.RED,
            command=self.close_active,
        ).pack(side="right", padx=(6, 0))
        ctk.CTkButton(
            bar, text="＋ Nouvelle", width=100, font=theme.font_ui(12),
            fg_color=theme.GREEN, hover_color=theme.GREEN_HOVER,
            command=lambda: self.add_request(select=True),
        ).pack(side="right")

    def _build_actions(self) -> None:
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        ctk.CTkButton(
            actions, text="🔒  Anonymiser", font=theme.font_ui(13, "bold"), height=38,
            fg_color=theme.GREEN, hover_color=theme.GREEN_HOVER,
            command=self.app.action_anonymize,
        ).pack(side="left", expand=True, fill="x", padx=(0, 4))
        ctk.CTkButton(
            actions, text="🔓  Dé-anonymiser", font=theme.font_ui(13, "bold"), height=38,
            fg_color=theme.PURPLE, hover_color="#a371f7", text_color="#1a1a2e",
            command=self.app.action_deanonymize,
        ).pack(side="left", expand=True, fill="x", padx=4)
        ctk.CTkButton(
            actions, text="🖼  Import img→texte", font=theme.font_ui(13), height=38,
            fg_color=theme.ELEVATED, hover_color=theme.BORDER, text_color=theme.TEXT,
            command=self.app.action_import_image,
        ).pack(side="left", expand=True, fill="x", padx=(4, 0))

    # ─── Gestion des onglets ─────────────────────────────────────
    def add_request(self, text: str = "", select: bool = True, title: str | None = None) -> str:
        self._counter += 1
        name = title or f"Requête {self._counter}"
        while name in self._tabs:
            self._counter += 1
            name = f"Requête {self._counter}"
        tab = self.tabview.add(name)
        box = CopyableTextbox(tab)
        box.pack(fill="both", expand=True)
        if text:
            box.set_text(text)
        box.bind_text("<<Paste>>", self._on_paste)
        self._tabs[name] = box
        self._bind_tab_menus()  # clic droit (renommer / supprimer) sur chaque onglet
        if select:
            self.tabview.set(name)
        return name

    # ─── Menu clic droit : renommer / supprimer une requête ──────
    def _bind_tab_menus(self) -> None:
        """(Re)lie le clic droit sur le bouton de chaque onglet.

        On lie les widgets tk internes du CTkButton (canvas + label) avec un bind
        standard (qui *remplace*) : CTkButton.bind force add="+" et s'accumulerait
        à chaque rebind, provoquant des menus en double.
        """
        try:
            buttons = self.tabview._segmented_button._buttons_dict
        except Exception:
            return
        for name, btn in buttons.items():
            handler = lambda e, n=name: self._show_tab_menu(e, n)
            for child in btn.winfo_children():
                child.bind("<Button-3>", handler)

    def _show_tab_menu(self, event, name: str) -> None:
        if name not in self._tabs:
            return
        self.tabview.set(name)  # sélectionne l'onglet cliqué
        menu = tk.Menu(
            self, tearoff=0, bg=theme.PANEL_2, fg=theme.TEXT,
            activebackground=theme.ACCENT, activeforeground="#ffffff",
            bd=0, font=theme.font_ui(12),
        )
        menu.add_command(label="✎  Renommer…", command=lambda: self._rename_tab(name))
        menu.add_command(label="✕  Supprimer", command=self.close_active)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _rename_tab(self, name: str) -> None:
        new = simpledialog.askstring("Renommer la requête", "Nouveau nom :", initialvalue=name, parent=self)
        if not new:
            return
        new = new.strip()
        if not new or new == name:
            return
        if new in self._tabs:
            self.app.set_status(f"Le nom « {new} » existe déjà.", error=True)
            return
        try:
            self.tabview.rename(name, new)
        except Exception as exc:
            self.app.set_status(f"Renommage impossible : {exc}", error=True)
            return
        self._tabs[new] = self._tabs.pop(name)
        self._bind_tab_menus()
        self.tabview.set(new)
        self.app.autosave()  # le nouveau nom est persisté dans le projet
        self.app.set_status(f"Requête renommée : « {new} »")

    def close_active(self) -> None:
        name = self.tabview.get()
        if not name:
            return
        try:
            self.tabview.delete(name)
        except Exception:
            return
        self._tabs.pop(name, None)
        if not self._tabs:
            self.add_request()  # toujours au moins une requête

    # ─── Texte de la requête active ──────────────────────────────
    def get_active_text(self) -> str:
        box = self._active_box()
        return box.get_text() if box else ""

    def set_active_text(self, text: str) -> None:
        box = self._active_box()
        if box:
            box.set_text(text)

    def _active_box(self) -> CopyableTextbox | None:
        return self._tabs.get(self.tabview.get())

    # ─── Sauvegarde / restauration des onglets (rebuild thème) ───
    def export_tabs(self) -> dict:
        return {
            "tabs": [(name, box.get_text()) for name, box in self._tabs.items()],
            "active": self.tabview.get(),
        }

    def _clear_all(self) -> None:
        for name in list(self._tabs.keys()):
            try:
                self.tabview.delete(name)
            except Exception:
                pass
            self._tabs.pop(name, None)
        self._counter = 0

    def reset_to_empty(self) -> None:
        """Décharge toutes les requêtes et laisse une requête vierge (nouveau projet)."""
        self._clear_all()
        self.add_request()

    def import_tabs(self, state: dict | None) -> None:
        if not state or not state.get("tabs"):
            self.reset_to_empty()
            return
        self._clear_all()
        for title, text in state["tabs"]:
            self.add_request(text=text, select=False, title=title)
        active = state.get("active")
        if active in self._tabs:
            self.tabview.set(active)

    # ─── Coller une image → OCR ──────────────────────────────────
    def _on_paste(self, _event=None):
        # OCR indisponible ou pas d'image → on laisse TOUJOURS le collage texte par défaut.
        if not ocr.ocr_available() or not ocr.clipboard_has_image_hint(self):
            return None
        try:
            extracted = ocr.extract_text_from_clipboard_image()
        except Exception as exc:
            self.app.set_status(f"OCR presse-papiers : {exc}", error=True)
            return None  # ne pas bloquer le collage texte
        if extracted:
            box = self._active_box()
            if box:
                box.textbox.insert("insert", extracted)
            self.app.set_status("Image OCRisée et insérée.")
            return "break"
        return None
