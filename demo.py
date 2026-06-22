#!/usr/bin/env python3
# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Démo + vérification anti-régression en ligne de commande (sans GUI).

Pipeline de démonstration : anonymise une requête, simule une réponse IA
(factice), puis dé-anonymise. La commande clé est `--verify-demo`, qui vérifie
qu'aucun marqueur sensible de DEMO_QUERY ne survit à l'anonymisation : c'est le
garde-fou anti-régression à lancer après toute modification des règles.

Exemples :
    python3 demo.py --demo --pretty
    python3 demo.py --demo --verify-demo
    python3 demo.py --mode anonymize --project audit1 --input-file data.txt

Pour l'anonymisation CLI « pure », voir anonymizer_core.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from anonymizer_core import (
    Anonymizer,
    DEMO_MUST_NOT_LEAK,
    DEMO_QUERY,
    DEMO_SEEDS,
    fake_ai_response,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AnonymizerGPT - démo & vérification CLI")
    parser.add_argument("--mode", choices=["pipeline", "anonymize", "deanonymize"], default="pipeline")
    parser.add_argument("--demo", action="store_true", help="Charge la requete demo complexe")
    parser.add_argument("--input-file", type=Path, help="Lit la requete depuis un fichier")
    parser.add_argument("--output-file", type=Path, help="Ecrit la sortie dans un fichier")
    parser.add_argument("--anonymize-only", action="store_true", help="Affiche seulement le texte anonymise")
    parser.add_argument("--pretty", action="store_true", help="Sortie JSON structurée")
    parser.add_argument("--project", default="default", help="Projet (état séparé par projet)")
    parser.add_argument("--projects-dir", type=Path, help="Dossier des projets (défaut: ./projects)")
    parser.add_argument("--state-file", type=Path, help="Fichier d'état explicite (prioritaire sur --project)")
    parser.add_argument("--blacklist", help="Mots blacklist séparés par virgule")
    parser.add_argument("--whitelist", help="Mots whitelist séparés par virgule")
    parser.add_argument("--show-mappings", action="store_true", help="Affiche la table de mapping")
    parser.add_argument("--verify-demo", action="store_true", help="Verifie que les marqueurs sensibles demo sont bien anonymises")
    return parser


def read_input(args: argparse.Namespace) -> str:
    if args.demo:
        return DEMO_QUERY

    if args.input_file:
        return args.input_file.read_text(encoding="utf-8")

    data = sys.stdin.read()
    if data.strip():
        return data

    raise SystemExit("Aucune entree detectee. Utilise --demo, --input-file ou stdin.")


def write_output(args: argparse.Namespace, content: str) -> None:
    if args.output_file is None:
        print(content)
        return
    args.output_file.write_text(content, encoding="utf-8")


def split_csv_words(value: str | None) -> list[str]:
    if not value:
        return []
    return [word.strip() for word in value.split(",") if word.strip()]


def print_mappings(anon: Anonymizer) -> None:
    if not anon.mappings:
        print("(aucun mapping actif)")
        return

    print("\n=== MAPPINGS ===")
    for original, anonymized in anon.mappings.items():
        etype = anon.types.get(original, "?")
        print(f"[{etype}] {original} -> {anonymized}")


def verify_demo(anonymized: str) -> tuple[bool, list[str]]:
    leaks = [marker for marker in DEMO_MUST_NOT_LEAK if marker in anonymized]
    return (len(leaks) == 0), leaks


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    anon = Anonymizer()
    project_name = Anonymizer.sanitize_project_name(args.project)
    state_path = Anonymizer.resolve_project_state_path(
        project_name,
        projects_dir=args.projects_dir,
        explicit_state_file=args.state_file,
    )
    anon.load_project_state(project_name, projects_dir=args.projects_dir, state_file=state_path, create_if_missing=True)

    blacklist_words = split_csv_words(args.blacklist)
    if blacklist_words:
        anon.load_blacklist_words(blacklist_words)

    whitelist_words = split_csv_words(args.whitelist)
    for word in whitelist_words:
        anon.add_whitelist_word(word)

    if args.demo and not blacklist_words:
        anon.load_custom_words(DEMO_SEEDS)

    raw = read_input(args)

    if args.mode == "deanonymize":
        restored, substitutions = anon.deanonymize(raw)
        payload = {
            "mode": "deanonymize",
            "project": project_name,
            "state_file": str(state_path),
            "restored": restored,
            "substitutions": substitutions,
        }
        out = json.dumps(payload, indent=2, ensure_ascii=False) if args.pretty else restored
        write_output(args, out)
        return 0

    anonymized, entities = anon.anonymize(raw)
    anon.save_project_state(project_name, projects_dir=args.projects_dir, state_file=state_path)

    if args.mode == "anonymize":
        payload = {
            "mode": "anonymize",
            "project": project_name,
            "state_file": str(state_path),
            "anonymized": anonymized,
            "entities": [e.__dict__ for e in entities],
            "stats": anon.get_stats(),
            "blacklist_words": anon.get_blacklist_words(),
            "whitelist_words": anon.get_whitelist_words(),
        }
        out = json.dumps(payload, indent=2, ensure_ascii=False) if args.pretty else anonymized
        write_output(args, out)
        if args.show_mappings:
            print_mappings(anon)
        if args.verify_demo:
            ok, leaks = verify_demo(anonymized)
            if ok:
                print("\n[OK] Verification demo: aucune fuite brute detectee.")
                return 0
            print("\n[KO] Verification demo: fuites detectees:")
            for leak in leaks:
                print(f" - {leak}")
            return 1
        return 0

    if args.anonymize_only:
        write_output(args, anonymized)
    else:
        ai_response = fake_ai_response(anonymized)
        restored, substitutions = anon.deanonymize(ai_response)

        print("=== REQUETE ORIGINALE ===")
        print(raw)
        print("\n=== REQUETE ANONYMISÉE ===")
        print(anonymized)

        print("\n=== ENTITES DETECTEES ===")
        if not entities:
            print("Aucune entite detectee")
        else:
            by_type: dict[str, int] = {}
            for entity in entities:
                by_type[entity.entity_type] = by_type.get(entity.entity_type, 0) + 1
            for entity_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
                print(f"{entity_type}: {count}")

        print("\n=== REPONSE IA BRUTE ===")
        print(ai_response)

        print("\n=== REPONSE DE-ANONYMISÉE ===")
        print(restored)

        if substitutions:
            print("\n=== SUBSTITUTIONS INVERSEES ===")
            for substitution in substitutions:
                print(f"{substitution['anon']} -> {substitution['orig']} ({substitution['count']}x)")

    if args.show_mappings:
        print_mappings(anon)

    if args.verify_demo:
        ok, leaks = verify_demo(anonymized)
        if ok:
            print("\n[OK] Verification demo: aucune fuite brute detectee.")
            return 0
        print("\n[KO] Verification demo: fuites detectees:")
        for leak in leaks:
            print(f" - {leak}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
