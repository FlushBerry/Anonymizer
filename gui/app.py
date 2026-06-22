# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fenêtre principale d'AnonymizerGPT.

`App` possède l'instance `Anonymizer` (le moteur core) et joue le rôle de
contrôleur : les panneaux (topbar, projet, requêtes, résultats) délèguent
toutes leurs actions à des méthodes de `App`. Aucune logique d'anonymisation
n'est ré-implémentée ici — tout passe par `anonymizer_core`.

Disposition :
    ┌─────────────────────────────────────────────┐
    │ TopBar (projet · démo · paramètres)           │
    ├───────────────┬───────────────────────────────┤
    │ ProjectPanel  │ RequestPanel (onglets requêtes)│
    │ (gestion +    │───── sash ajustable ──────────│
    │  black/white) │ ResultsPanel (onglets résultats)│
    ├───────────────┴───────────────────────────────┤
    │ Barre de statut                                │
    └─────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

import customtkinter as ctk

import anonymizer_core
from anonymizer_core import Anonymizer, DEMO_QUERY, DEMO_SEEDS

from . import theme
from .panel_project import ProjectPanel
from .panel_request import RequestPanel
from .panel_results import ResultsPanel
from .topbar import TopBar

CORE_DIR = Path(anonymizer_core.__file__).resolve().parent
PROJECT_PREFIX = "anonfile_"


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        # Préférences d'interface (modifiables dans Paramètres).
        self.ui_theme: str = theme.DEFAULT_THEME
        self.mono_size: int = theme.MONO_SIZE
        self.layout: str = "vertical"  # "vertical" = requêtes/résultats haut-bas ; "horizontal" = gauche-droite
        theme.apply_theme(self.ui_theme)

        self.title("AnonymizerGPT — Pentest AI Anonymizer")
        self.geometry("1320x860")
        self.minsize(1040, 680)
        self.configure(fg_color=theme.BG)

        self.anon = Anonymizer()
        self.projects_dir: Path = CORE_DIR / "projects"
        self.current_project: str | None = None
        self._last_raw: str = ""
        self._last_anonymized: str = ""
        self._last_entities: list = []

        self._build_layout()
        self._bootstrap()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self) -> None:
        self.autosave()  # persiste les requêtes du projet courant avant de quitter
        self.destroy()

    # ─── Construction de l'interface ─────────────────────────────
    def _build_layout(self) -> None:
        self.topbar = TopBar(self, self)
        self.topbar.pack(side="top", fill="x")

        self.status = ctk.CTkLabel(
            self, text="Prêt.", anchor="w", height=26, font=theme.font_ui(12),
            fg_color=theme.PANEL, text_color=theme.MUTED,
        )
        self.status.pack(side="bottom", fill="x")

        self._body = tk.PanedWindow(
            self, orient="horizontal", bg=theme.BORDER, sashwidth=6,
            sashrelief="flat", borderwidth=0, opaqueresize=True,
        )
        self._body.pack(side="top", fill="both", expand=True)

        self.project_panel = ProjectPanel(self._body, self)
        self._body.add(self.project_panel, minsize=200, width=300, stretch="never")

        orient = "horizontal" if self.layout == "horizontal" else "vertical"
        self._right = tk.PanedWindow(
            self._body, orient=orient, bg=theme.BORDER, sashwidth=6,
            sashrelief="flat", borderwidth=0, opaqueresize=True,
        )
        self._body.add(self._right, minsize=480, stretch="always")

        self.request_panel = RequestPanel(self._right, self)
        self.results_panel = ResultsPanel(self._right, self)
        if orient == "vertical":
            # minsize requêtes = toolbar + 1 ligne + boutons d'action toujours visibles.
            self._right.add(self.request_panel, minsize=210, height=420, stretch="always")
            self._right.add(self.results_panel, minsize=180, stretch="always")
        else:
            self._right.add(self.request_panel, minsize=380, width=640, stretch="always")
            self._right.add(self.results_panel, minsize=320, stretch="always")

    def _bootstrap(self) -> None:
        self.project_panel.set_projects_dir(str(self.projects_dir))
        # Projet « default » chargé d'office pour persister black/whitelist & mappings.
        self.load_project("default", announce=False)
        self.refresh_projects()
        self.set_status("Prêt. Projet « default » chargé.")

    # ─── Barre de statut ─────────────────────────────────────────
    def set_status(self, message: str, error: bool = False) -> None:
        self.status.configure(text=message, text_color=theme.RED if error else theme.MUTED)

    # ─── Démo & paramètres (topbar) ──────────────────────────────
    def load_demo(self) -> None:
        # Bascule sur un projet dédié « demo » pour ne pas écraser le projet courant.
        self.load_project("demo", announce=False)
        self.anon.load_custom_words(DEMO_SEEDS)
        self.request_panel.add_request(text=DEMO_QUERY, select=True, title="DEMO")
        self.project_panel.refresh_words()
        self.autosave()
        self.set_status("Démo chargée (projet « demo », blacklist = graines démo). Clique « Anonymiser ».")

    LAYOUT_LABELS = {"Haut / Bas": "vertical", "Gauche / Droite": "horizontal"}

    def open_settings(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("Paramètres")
        win.geometry("460x420")
        win.configure(fg_color=theme.BG)
        win.transient(self)
        win.after(120, win.grab_set)

        ctk.CTkLabel(win, text="⚙  Paramètres", font=theme.font_ui(16, "bold")).pack(anchor="w", padx=18, pady=(16, 10))

        # Thème (change toutes les couleurs)
        ctk.CTkLabel(win, text="Thème de couleurs", font=theme.font_ui(12), text_color=theme.MUTED).pack(anchor="w", padx=18)
        theme_menu = ctk.CTkOptionMenu(
            win, values=theme.theme_names(), font=theme.font_ui(12),
            command=lambda v: self._apply_ui_settings(theme_name=v),
            fg_color=theme.ELEVATED, button_color=theme.ACCENT, button_hover_color=theme.ACCENT_HOVER,
        )
        theme_menu.set(self.ui_theme)
        theme_menu.pack(anchor="w", padx=18, pady=(4, 12))

        # Taille de police des zones de texte
        ctk.CTkLabel(win, text="Taille police (requêtes / résultats)", font=theme.font_ui(12), text_color=theme.MUTED).pack(anchor="w", padx=18)
        font_menu = ctk.CTkOptionMenu(
            win, values=["10", "11", "12", "13", "14", "16", "18", "20"], font=theme.font_ui(12),
            command=lambda v: self._apply_ui_settings(mono_size=int(v)),
            fg_color=theme.ELEVATED, button_color=theme.ACCENT, button_hover_color=theme.ACCENT_HOVER,
        )
        font_menu.set(str(self.mono_size))
        font_menu.pack(anchor="w", padx=18, pady=(4, 12))

        # Disposition requêtes / résultats (style Burp)
        ctk.CTkLabel(win, text="Disposition requêtes / résultats", font=theme.font_ui(12), text_color=theme.MUTED).pack(anchor="w", padx=18)
        inv = {v: k for k, v in self.LAYOUT_LABELS.items()}
        layout_menu = ctk.CTkOptionMenu(
            win, values=list(self.LAYOUT_LABELS), font=theme.font_ui(12),
            command=lambda v: self._apply_ui_settings(layout=self.LAYOUT_LABELS[v]),
            fg_color=theme.ELEVATED, button_color=theme.ACCENT, button_hover_color=theme.ACCENT_HOVER,
        )
        layout_menu.set(inv.get(self.layout, "Haut / Bas"))
        layout_menu.pack(anchor="w", padx=18, pady=(4, 12))

        # Dossier des projets
        ctk.CTkLabel(win, text="Dossier des projets", font=theme.font_ui(12), text_color=theme.MUTED).pack(anchor="w", padx=18)
        dir_var = ctk.StringVar(value=str(self.projects_dir))
        ctk.CTkLabel(win, textvariable=dir_var, font=theme.font_mono(11), wraplength=420, justify="left").pack(anchor="w", padx=18)
        ctk.CTkButton(
            win, text="📂 Changer…", font=theme.font_ui(12), fg_color=theme.ELEVATED, hover_color=theme.BORDER,
            command=lambda: (self.change_projects_dir(), dir_var.set(str(self.projects_dir))),
        ).pack(anchor="w", padx=18, pady=(4, 12))

        ctk.CTkLabel(
            win, text="OCR : tesseract (eng+fra). Coller une image (Ctrl+V) dans une requête lance l'OCR.",
            font=theme.font_ui(11), text_color=theme.MUTED, wraplength=420, justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 8))

    def _apply_ui_settings(self, theme_name: str | None = None, mono_size: int | None = None,
                           layout: str | None = None) -> None:
        """Applique thème / taille de police / disposition en reconstruisant l'UI."""
        if theme_name:
            self.ui_theme = theme_name
        if mono_size:
            self.mono_size = int(mono_size)
        if layout:
            self.layout = layout

        req_state = self.request_panel.export_tabs()
        self.topbar.destroy()
        self.status.destroy()
        self._body.destroy()

        theme.set_theme(self.ui_theme)
        theme.MONO_SIZE = self.mono_size
        self.configure(fg_color=theme.BG)

        self._build_layout()
        self.request_panel.import_tabs(req_state)
        self.topbar.set_project_name(self.current_project)
        self.project_panel.set_projects_dir(str(self.projects_dir))
        self.project_panel.refresh_words()
        self.refresh_projects()
        if self._last_raw:
            self.results_panel.show_anonymized(self._last_anonymized, focus=False)
            self.results_panel.show_highlight(self._last_raw, self._merge_entity_spans(self._last_raw, self._last_entities))
            self.results_panel.show_stats(self._stats_from_entities(self._last_entities))
        self.results_panel.show_mapping(self.anon.mappings, self.anon.types)
        self.set_status("Préférences d'interface appliquées.")

    def add_words_from_file(self, kind: str) -> None:
        path = filedialog.askopenfilename(
            title="Fichier de mots (un par ligne)",
            filetypes=[("Listes de mots", "*.txt *.lst *.wordlist *.dic *.csv"), ("Tous", "*.*")],
        )
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            self.set_status(f"Lecture du fichier échouée : {exc}", error=True)
            return
        words = [w.strip() for w in content.splitlines() if w.strip() and not w.lstrip().startswith("#")]
        added = 0
        for word in words:
            if kind == "whitelist":
                added += self.anon.add_whitelist_word(word)
            else:
                added += self.anon.add_blacklist_word(word)
        self.project_panel.refresh_words()
        self.autosave()
        self.set_status(f"{added} mot(s) ajouté(s) à la {kind} (sur {len(words)} lus dans le fichier).")

    # ─── Gestion projet ──────────────────────────────────────────
    def _project_name_from_file(self, path: Path) -> str:
        stem = path.stem
        return stem[len(PROJECT_PREFIX):] if stem.startswith(PROJECT_PREFIX) else stem

    def list_projects(self) -> list[str]:
        if not self.projects_dir.exists():
            return []
        names: list[str] = []
        for path in sorted(self.projects_dir.glob("*.json")):
            name = self._project_name_from_file(path)
            if name not in names:
                names.append(name)
        return names

    def refresh_projects(self) -> None:
        self.project_panel.refresh_projects(self.list_projects(), current=self.current_project)

    def change_projects_dir(self) -> None:
        chosen = filedialog.askdirectory(title="Choisir le dossier des projets", initialdir=str(self.projects_dir))
        if not chosen:
            return
        self.projects_dir = Path(chosen)
        self.project_panel.set_projects_dir(str(self.projects_dir))
        self.refresh_projects()
        self.set_status(f"Dossier projets : {self.projects_dir}")

    def create_project_dialog(self) -> None:
        name = simpledialog.askstring("Nouveau projet", "Nom du projet :", parent=self)
        if not name or not name.strip():
            return
        safe = Anonymizer.sanitize_project_name(name)
        existed = self.resolve_project_state_path_exists(safe)
        self.load_project(safe, announce=False)
        if existed:
            self.set_status(f"Projet « {safe} » existait déjà — chargé.")
        else:
            self.set_status(f"Projet « {safe} » créé (aucune requête).")

    def resolve_project_state_path_exists(self, safe_name: str) -> bool:
        path = Anonymizer.resolve_project_state_path(safe_name, projects_dir=self.projects_dir)
        legacy = Anonymizer.resolve_legacy_project_state_path(safe_name, projects_dir=self.projects_dir)
        return path.exists() or legacy.exists()

    def load_selected_project(self, name: str) -> None:
        self.load_project(name)

    def load_project(self, name: str, announce: bool = True) -> None:
        safe = Anonymizer.sanitize_project_name(name)
        # Persiste les requêtes du projet sortant avant de changer.
        if self.current_project and self.current_project != safe:
            self.autosave()
        try:
            path = self.anon.load_project_state(safe, projects_dir=self.projects_dir, create_if_missing=True)
        except Exception as exc:
            self.set_status(f"Échec chargement projet : {exc}", error=True)
            return
        self.current_project = safe
        self._after_project_change()
        self._restore_requests(path)
        if announce:
            self.set_status(f"Projet « {safe} » chargé.")

    def _after_project_change(self) -> None:
        self.topbar.set_project_name(self.current_project)
        self.project_panel.refresh_words()
        self.results_panel.clear()
        self._last_raw, self._last_anonymized, self._last_entities = "", "", []
        self.refresh_projects()

    def _restore_requests(self, path) -> None:
        """Charge les requêtes associées au projet (décharge celles du projet précédent)."""
        requests = None
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(data, dict):
                requests = data.get("requests")
        except Exception:
            requests = None
        self.request_panel.import_tabs(requests if isinstance(requests, dict) else None)

    def autosave(self) -> None:
        if not self.current_project:
            return
        try:
            self.anon.save_project_state(
                self.current_project,
                projects_dir=self.projects_dir,
                extra_payload={"requests": self.request_panel.export_tabs()},
            )
        except Exception as exc:
            self.set_status(f"Échec sauvegarde : {exc}", error=True)

    # ─── Blacklist / whitelist ───────────────────────────────────
    def get_words(self, kind: str) -> list[str]:
        if kind == "whitelist":
            return self.anon.get_whitelist_words()
        return self.anon.get_blacklist_words()

    def add_word(self, kind: str, word: str) -> None:
        if kind == "whitelist":
            self.anon.add_whitelist_word(word)
        else:
            self.anon.add_blacklist_word(word)
        self.project_panel.refresh_words()
        self.autosave()
        self.set_status(f"Mot ajouté à la {kind} : {word}")

    def remove_word(self, kind: str, word: str) -> None:
        if kind == "whitelist":
            remaining = [w for w in self.anon.get_whitelist_words() if w != word]
            self.anon.load_whitelist_words(remaining)
        else:
            remaining = [w for w in self.anon.get_blacklist_words() if w != word]
            self.anon.load_blacklist_words(remaining)
        self.project_panel.refresh_words()
        self.autosave()
        self.set_status(f"Mot retiré de la {kind} : {word}")

    # ─── Actions principales ─────────────────────────────────────
    def action_anonymize(self) -> None:
        text = self.request_panel.get_active_text()
        if not text.strip():
            self.set_status("Requête vide — rien à anonymiser.", error=True)
            return
        anonymized, entities = self.anon.anonymize(text)
        self._last_raw, self._last_entities = text, entities
        self._last_anonymized = anonymized

        self.results_panel.show_anonymized(anonymized)
        self.results_panel.show_highlight(text, self._merge_entity_spans(text, entities))
        self.results_panel.show_stats(self._stats_from_entities(entities))
        self.results_panel.show_mapping(self.anon.mappings, self.anon.types)
        self.autosave()
        self.set_status(f"Anonymisation : {len(entities)} entité(s) détectée(s).")

    def action_deanonymize(self) -> None:
        text = self.request_panel.get_active_text()
        if not text.strip():
            self.set_status("Requête vide — rien à dé-anonymiser.", error=True)
            return
        restored, subs = self.anon.deanonymize(text)
        self.results_panel.show_deanonymized(restored)
        self.set_status(f"Dé-anonymisation : {len(subs)} substitution(s) inversée(s).")

    def action_import_image(self) -> None:
        from . import ocr
        path = filedialog.askopenfilename(
            title="Choisir une image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.tif *.tiff *.webp"), ("Tous", "*.*")],
        )
        if not path:
            return
        try:
            extracted = ocr.extract_text_from_image(Path(path))
        except Exception as exc:
            messagebox.showerror("OCR", str(exc))
            self.set_status(f"OCR échoué : {exc}", error=True)
            return
        if not extracted:
            self.set_status("OCR : aucun texte détecté dans l'image.", error=True)
            return
        existing = self.request_panel.get_active_text()
        merged = (existing + "\n" + extracted) if existing.strip() else extracted
        self.request_panel.set_active_text(merged)
        self.set_status(f"Image OCRisée ({len(extracted)} caractères insérés).")

    # ─── Helpers ─────────────────────────────────────────────────
    @staticmethod
    def _stats_from_entities(entities: list) -> dict:
        stats: dict[str, int] = {}
        for entity in entities:
            stats[entity.entity_type] = stats.get(entity.entity_type, 0) + 1
        return stats

    @staticmethod
    def _merge_entity_spans(raw: str, entities: list) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        for entity in entities or []:
            try:
                start, end = int(entity.start), int(entity.end)
            except Exception:
                continue
            if 0 <= start < end <= len(raw):
                spans.append((start, end))
        spans.sort(key=lambda x: x[0])
        merged: list[tuple[int, int]] = []
        for start, end in spans:
            if not merged or start > merged[-1][1]:
                merged.append((start, end))
            else:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        return merged


def main() -> int:
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
