#!/usr/bin/env python3
# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Lanceur de l'interface graphique AnonymizerGPT.

L'implémentation est dans le package `gui/` (découpé en modules : theme,
widgets, ocr, topbar, panel_project, panel_request, panel_results, app).
Ce fichier reste le point d'entrée :  python3 proxy_gui.py
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from gui.app import main as app_main
    except ImportError as exc:  # customtkinter / Pillow absents
        print(f"Dépendances GUI manquantes : {exc}", file=sys.stderr)
        print("Installe-les avec : ./install.sh  (ou pip install -r requirements.txt)", file=sys.stderr)
        return 1
    return app_main()


if __name__ == "__main__":
    raise SystemExit(main())
