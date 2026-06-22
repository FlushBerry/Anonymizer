# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
"""OCR : extraction de texte depuis une image (fichier ou presse-papiers).

Fonctions autonomes (sans dépendance à la GUI) réutilisables par tout le projet.
Backends presse-papiers essayés dans l'ordre : xclip (X11), wl-paste (Wayland),
PIL.ImageGrab. Le moteur OCR est pytesseract si disponible, sinon le binaire
`tesseract`.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import tempfile
from pathlib import Path

OCR_LANG = "eng+fra"
_IMAGE_MIMES = ("image/png", "image/jpeg", "image/bmp", "image/tiff")
_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}

_OCR_HINT = (
    "OCR indisponible : le binaire « tesseract » est introuvable.\n"
    "Installe-le via  ./install.sh  (ou  sudo apt install -y tesseract-ocr tesseract-ocr-fra)."
)


def ocr_available() -> bool:
    """True si le binaire tesseract est présent (requis même avec pytesseract)."""
    return shutil.which("tesseract") is not None


# ─── OCR moteur ──────────────────────────────────────────────────

def extract_text_from_image(image_path: Path, lang: str = OCR_LANG) -> str:
    """OCR d'un fichier image → texte. pytesseract d'abord, fallback binaire."""
    try:
        from PIL import Image
        import pytesseract
        with Image.open(image_path) as img:
            text = pytesseract.image_to_string(img, lang=lang, config="--psm 6")
        if text and text.strip():
            return text.strip()
    except Exception:
        pass

    tesseract_bin = shutil.which("tesseract")
    if not tesseract_bin:
        raise RuntimeError(_OCR_HINT)
    completed = subprocess.run(
        [tesseract_bin, str(image_path), "stdout", "-l", lang, "--psm", "6"],
        check=False, capture_output=True, text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or "Échec OCR tesseract").strip())
    return (completed.stdout or "").strip()


def extract_text_from_image_bytes(image_bytes: bytes, lang: str = OCR_LANG) -> str | None:
    """OCR de bytes image bruts → texte."""
    if not image_bytes:
        return None
    try:
        from PIL import Image
        import pytesseract
        with Image.open(io.BytesIO(image_bytes)) as img:
            text = pytesseract.image_to_string(img, lang=lang, config="--psm 6")
        if text and text.strip():
            return text.strip()
    except Exception:
        pass

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            temp_path = Path(tmp.name)
            tmp.write(image_bytes)
        return extract_text_from_image(temp_path, lang=lang)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


# ─── Lecture image presse-papiers ────────────────────────────────

def _read_clipboard_image_xclip() -> bytes | None:
    xclip = shutil.which("xclip")
    if not xclip:
        return None
    try:
        targets = subprocess.run(
            [xclip, "-selection", "clipboard", "-t", "TARGETS", "-o"],
            check=False, capture_output=True, text=True, timeout=3,
        )
        targets_text = targets.stdout or ""
    except Exception:
        return None
    for mime in _IMAGE_MIMES:
        if mime in targets_text:
            try:
                result = subprocess.run(
                    [xclip, "-selection", "clipboard", "-t", mime, "-o"],
                    check=False, capture_output=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout and len(result.stdout) > 8:
                    return result.stdout
            except Exception:
                continue
    return None


def _read_clipboard_image_wlpaste() -> bytes | None:
    wl_paste = shutil.which("wl-paste")
    if not wl_paste:
        return None
    try:
        list_types = subprocess.run(
            [wl_paste, "--list-types"],
            check=False, capture_output=True, text=True, timeout=3,
        )
        types_text = list_types.stdout or ""
    except Exception:
        return None
    for mime in _IMAGE_MIMES:
        if mime in types_text:
            try:
                result = subprocess.run(
                    [wl_paste, "--no-newline", "--type", mime],
                    check=False, capture_output=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout and len(result.stdout) > 8:
                    return result.stdout
            except Exception:
                continue
    return None


def _read_clipboard_image_pil() -> bytes | None:
    try:
        from PIL import ImageGrab
    except Exception:
        return None
    try:
        clip_data = ImageGrab.grabclipboard()
    except Exception:
        return None
    if clip_data is None:
        return None
    if hasattr(clip_data, "save"):
        buf = io.BytesIO()
        try:
            clip_data.save(buf, format="PNG")
            raw = buf.getvalue()
            if raw and len(raw) > 8:
                return raw
        except Exception:
            pass
        return None
    if isinstance(clip_data, list):
        for candidate in clip_data:
            try:
                path = Path(str(candidate))
            except Exception:
                continue
            if path.suffix.lower() in _IMAGE_SUFFIXES and path.exists():
                return path.read_bytes()
        return None
    if isinstance(clip_data, (bytes, bytearray)):
        return bytes(clip_data) if len(clip_data) > 8 else None
    return None


def read_clipboard_image_bytes() -> bytes | None:
    """Essaie tous les backends pour récupérer une image du presse-papiers."""
    for backend in (_read_clipboard_image_xclip, _read_clipboard_image_wlpaste, _read_clipboard_image_pil):
        data = backend()
        if data:
            return data
    return None


def clipboard_has_image_hint(tk_widget=None) -> bool:
    """Le presse-papiers semble-t-il contenir une image ? (vérif rapide)."""
    xclip = shutil.which("xclip")
    if xclip:
        try:
            targets = subprocess.run(
                [xclip, "-selection", "clipboard", "-t", "TARGETS", "-o"],
                check=False, capture_output=True, text=True, timeout=3,
            )
            for mime in _IMAGE_MIMES:
                if mime in (targets.stdout or ""):
                    return True
        except Exception:
            pass
    if tk_widget is not None:
        try:
            targets = tk_widget.tk.call("selection", "get", "-selection", "CLIPBOARD", "-type", "TARGETS")
            if "image/" in str(targets).lower():
                return True
        except Exception:
            pass
    return False


def extract_text_from_clipboard_image() -> str | None:
    """Pipeline complet : image presse-papiers → OCR → texte (ou None)."""
    image_bytes = read_clipboard_image_bytes()
    if not image_bytes:
        return None
    text = extract_text_from_image_bytes(image_bytes)
    return text.strip() if text and text.strip() else None
