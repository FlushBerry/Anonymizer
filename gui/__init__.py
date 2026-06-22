# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
"""Package GUI d'AnonymizerGPT.

Découpage modulaire (chaque fichier = une responsabilité) :
    theme.py          couleurs, polices, apparence customtkinter
    widgets.py        composants réutilisables (textbox + copier, ligne-mot, vue surlignée)
    ocr.py            OCR image fichier / presse-papiers (tesseract)
    topbar.py         bandeau "Paramètres" (nom projet + démo + réglages)
    panel_project.py  sidebar gauche : gestion projet + blacklist/whitelist
    panel_request.py  onglets de requêtes (style Burp Repeater) + actions
    panel_results.py  onglets résultats (anonymisée / déanonymisée / surlignée / stats / mapping)
    app.py            fenêtre principale, possède l'Anonymizer et orchestre les panneaux

Lancement : `python3 proxy_gui.py` (lanceur léger qui appelle gui.app.main()).
"""

from .app import App, main

__all__ = ["App", "main"]
