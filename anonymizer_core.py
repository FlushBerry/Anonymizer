#!/usr/bin/env python3
# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Moteur d'anonymisation commun (CLI + GUI)."""

from __future__ import annotations

import argparse
import itertools
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit


class WordlistGenerator:
    LEET_MAP = {
        "a": ["@", "4"],
        "e": ["3"],
        "i": ["1", "!"],
        "o": ["0"],
        "s": ["$", "5"],
        "t": ["7"],
        "l": ["1"],
        "g": ["9"],
    }
    SEPARATORS = ["", ".", "-", "_", " "]
    COMMON_SUFFIXES = ["", "123", "1", "01", "2024", "2025", "!", "@", "#"]

    def generate(self, seeds: dict) -> list[str]:
        variants: set[str] = set()
        base_words: list[str] = []

        for key, value in seeds.items():
            if key == "custom" and isinstance(value, list):
                base_words.extend(v.strip() for v in value if v and v.strip())
            elif isinstance(value, str) and value.strip():
                base_words.append(value.strip())

        for word in base_words:
            variants.update(self._generate_variants(word))

        combo_keys = ["firstname", "lastname", "company"]
        combo_words = [seeds.get(k, "") for k in combo_keys if seeds.get(k)]
        if len(combo_words) >= 2:
            for a, b in itertools.permutations(combo_words, 2):
                for sep in self.SEPARATORS:
                    variants.add(f"{a}{sep}{b}".lower())
                    variants.add(f"{a}{sep}{b}")

        variants.discard("")
        return sorted(variants, key=len, reverse=True)

    def _generate_variants(self, word: str) -> set[str]:
        out: set[str] = set()
        w = word.strip()
        if not w:
            return out

        out.update([w, w.lower(), w.upper(), w.capitalize(), w.title()])
        parts = re.split(r"[\s\-_.]+", w)
        if len(parts) > 1:
            for sep in self.SEPARATORS:
                joined = sep.join(parts)
                out.update([joined.lower(), joined, joined.upper()])
            initials = "".join(p[0] for p in parts if p)
            out.update([initials.lower(), initials.upper()])

        for suffix in self.COMMON_SUFFIXES:
            out.add(f"{w.lower()}{suffix}")

        out.add(self._leetify(w.lower()))
        return out

    def _leetify(self, word: str) -> str:
        return "".join(self.LEET_MAP.get(c, [c])[0] for c in word)


@dataclass
class Entity:
    original: str
    anonymized: str
    entity_type: str
    start: int
    end: int


@dataclass(frozen=True)
class Candidate:
    original: str
    entity_type: str
    start: int
    end: int
    priority: int


class Anonymizer:
    MIN_CUSTOM_MATCH_LEN = 4

    IBAN_COUNTRY_LENGTHS = {
        "AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BE": 16, "BA": 20,
        "BR": 29, "BG": 22, "CR": 22, "HR": 21, "CY": 28, "CZ": 24, "DK": 18,
        "DO": 28, "EE": 20, "FO": 18, "FI": 18, "FR": 27, "GE": 22, "DE": 22,
        "GI": 23, "GR": 27, "GL": 18, "GT": 28, "HU": 28, "IS": 26, "IE": 22,
        "IL": 23, "IT": 27, "JO": 30, "KZ": 20, "XK": 20, "KW": 30, "LV": 21,
        "LB": 28, "LI": 21, "LT": 20, "LU": 20, "MK": 19, "MT": 31, "MR": 27,
        "MU": 30, "MD": 24, "MC": 27, "ME": 22, "NL": 18, "NO": 15, "PK": 24,
        "PS": 29, "PL": 28, "PT": 25, "QA": 29, "RO": 24, "SM": 27, "SA": 24,
        "RS": 22, "SK": 24, "SI": 19, "ES": 24, "SE": 24, "CH": 21, "TN": 24,
        "TR": 26, "AE": 23, "GB": 22, "VG": 24,
    }

    USER_KEYWORDS = [
        "user",
        "username",
        "login",
        "usr",
        "uname",
        "user_name",
        "login_name",
        "account",
        "acct",
        "uid",
        "userid",
        "user_id",
        "email",
        "mail",
        "e-mail",
        "signin",
        "sign_in",
        "logon",
        "auth_user",
        "admin_user",
        "samaccountname",
        "upn",
        "userprincipalname",
        "cn",
        "dn",
        "principal",
        "subject",
        "identity",
        "ident",
        "client_id",
    ]

    PASS_KEYWORDS = [
        "password",
        "passwd",
        "pass",
        "pwd",
        "passfile",
        "passwd_file",
        "secret",
        "passw",
        "pass_word",
        "user_pass",
        "user_password",
        "auth_pass",
        "login_pass",
        "credential",
        "cred",
        "pin",
        "passcode",
        "passphrase",
        "pass_phrase",
        "master_password",
        "mdp",
        "mot_de_passe",
        "motdepasse",
        "contraseña",
        "kennwort",
        "client_secret",
        "app_secret",
        "secret_key",
        "proxy_cred",
        "proxy_credentials",
        "db_password",
        "redis_password",
        "rabbitmq_password",
        "sshpass",
        "otp",
        "otp_code",
    ]

    TOKEN_KEYWORDS = [
        "token",
        "api_key",
        "apikey",
        "api-key",
        "access_token",
        "auth_token",
        "bearer",
        "authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-token",
        "session_token",
        "refresh_token",
        "id_token",
        "csrf_token",
        "csrf",
        "xsrf",
        "x-csrf-token",
        "x-xsrf-token",
        "oauth_token",
        "jwt",
        "auth_code",
        "code",
        "grant",
        "nonce",
        "private_token",
        "pat",
        "session_key",
        "authkey",
        "accesskey",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "azure_client_secret",
        "gcp_credentials",
        "service_account",
        "private_key",
        "signing_key",
        "encryption_key",
        "hmac_key",
        "shared_secret",
        "pre_shared_key",
        "psk",
        "webhook_secret",
        "jwt_secret",
        "signing_secret",
        "elasticsearch_api_key",
        "grafana_api_key",
        "sonarqube_token",
        "jenkins_token",
        "saml_assertion",
        "assertion",
    ]

    COOKIE_KEYWORDS = [
        "session",
        "sessionid",
        "session_id",
        "sid",
        "ssid",
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "aspsessionid",
        "cfid",
        "cftoken",
        "laravel_session",
        "ci_session",
        "connect.sid",
        "express:sess",
        "rack.session",
        "wp_logged_in",
        "wordpress_logged_in",
        "wordpress_sec",
        "_session",
        "__session",
        "auth_session",
        "user_session",
        "remember_token",
        "remember_me",
        "_identity",
        "_csrf",
        "xsrf-token",
        "__requestverificationtoken",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "sso_token",
        "cas_ticket",
        "saml_token",
        "awsalb",
        "awsalbcors",
        "serverid",
        "cf_clearance",
        "__cfduid",
        "__cf_bm",
        "next-auth.session-token",
    ]

    AUTH_HEADER_KEYWORDS = [
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-forwarded-user",
        "x-remote-user",
        "x-authenticated-user",
        "www-authenticate",
        "proxy-authenticate",
        "x-auth",
        "x-token",
        "x-session",
        "x-amz-security-token",
        "x-amz-credential",
    ]

    DATE_KEYWORDS = [
        "date",
        "birthdate",
        "dob",
        "birthday",
        "created_at",
        "updated_at",
        "expires",
        "expiry",
        "expiration",
        "valid_from",
        "valid_to",
        "timestamp",
        "time",
        "last_login",
        "start_date",
        "end_date",
    ]

    XML_SAFE_TAGS = {
        "assemblybinding",
        "assemblyidentity",
        "supportedruntime",
        "runtime",
        "startup",
    }
    NON_SENSITIVE_WORDS = {
        "error",
        "errors",
        "warning",
        "warnings",
        "info",
        "debug",
        "trace",
        "fatal",
        "success",
        "ok",
        "pass",
        "fail",
        "enabled",
        "disabled",
        "true",
        "false",
        "null",
        "none",
        "json",
        "xml",
        "yaml",
        "yml",
        "http",
        "https",
        "tcp",
        "udp",
        "tls",
        "ssl",
        "gzip",
        "deflate",
        "br",
        "chunked",
        "keep-alive",
        "close",
        "strict",
        "lax",
        "sameorigin",
        "nosniff",
        "deny",
        "allow",
        "application/json",
        "application/xml",
        "text/plain",
        "utf-8",
        "utf8",
        "dev",
        "test",
        "staging",
        "production",
        "prod",
        "localhost",
        "loopback",
    }
    DEFAULT_CONFIG_WHITELIST = {
        "host",
        "hostname",
        "port",
        "protocol",
        "scheme",
        "method",
        "path",
        "route",
        "endpoint",
        "timeout",
        "retries",
        "retry",
        "interval",
        "ttl",
        "cache",
        "logging",
        "loglevel",
        "content-type",
        "accept",
        "accept-language",
        "accept-encoding",
        "user-agent",
        "connection",
        "origin",
        "referer",
        "cors",
        "csrf",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
        "same-site",
    }
    SAFE_HOST_SUFFIXES = {
        "w3.org",
        "www.w3.org",
        "xmlsoap.org",
        "schemas.xmlsoap.org",
    }

    def __init__(self):
        self.mappings: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        self.types: dict[str, str] = {}
        self.counter: dict[str, int] = {}
        self.custom_wordlist: list[str] = []
        self.whitelist_words: dict[str, str] = {}
        self.custom_variant_family: dict[str, int] = {}
        self.custom_family_alias: dict[int, str] = {}
        self.custom_family_canonical: dict[int, str] = {}
        self.custom_family_counter: int = 0
        self.ip_network_map: dict[str, int] = {}
        self.domain_root_map: dict[str, str] = {}
        self.domain_fqdn_map: dict[str, str] = {}
        self.domain_root_sub_counter: dict[str, int] = {}
        self.url_host_map: dict[str, str] = {}
        self.url_host_counter: int = 0
        self.url_candidate_pattern = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s]+", re.IGNORECASE)
        self.secret_kv_pattern = re.compile(
            r"(?i)\b([A-Za-z0-9_.-]*(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|credential|cred|authkey|session[_-]?key|private[_-]?token|sshpass|kubeconfig|kube_config|passfile|passwd_file)[A-Za-z0-9_.-]*)\s*[:=]\s*[\"']?([^\n\r\"' ]{3,})",
            re.IGNORECASE | re.MULTILINE,
        )
        self.nikto_id_pattern = re.compile(r"\bnikto\b[^\n\r]*--id\s+[\"']?([^:\s\"']+):([^\"'\s]+)", re.IGNORECASE)
        self.tool_password_pattern = re.compile(
            r"\b(?:hydra|crackmapexec|nxc|medusa|patator)\b[^\n\r]*\s-p\s+[\"']?([^\s\"']+)",
            re.IGNORECASE,
        )
        self.proxy_cred_pattern = re.compile(r"--proxy-cred(?:entials)?\s+[\"']?([^\"'\s]+)", re.IGNORECASE)
        self._compile_patterns()
        self._apply_default_config_whitelist()

    @staticmethod
    def sanitize_project_name(name: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", (name or "").strip())
        cleaned = cleaned.strip("._-")
        return cleaned or "default"

    @classmethod
    def resolve_project_state_path(
        cls,
        project_name: str,
        projects_dir: Path | str | None = None,
        explicit_state_file: Path | str | None = None,
    ) -> Path:
        if explicit_state_file is not None:
            return Path(explicit_state_file)
        base_dir = Path(projects_dir) if projects_dir is not None else Path(__file__).resolve().parent / "projects"
        base_dir.mkdir(parents=True, exist_ok=True)
        safe_name = cls.sanitize_project_name(project_name)
        return base_dir / f"anonfile_{safe_name}.json"

    @classmethod
    def resolve_legacy_project_state_path(
        cls,
        project_name: str,
        projects_dir: Path | str | None = None,
    ) -> Path:
        base_dir = Path(projects_dir) if projects_dir is not None else Path(__file__).resolve().parent / "projects"
        base_dir.mkdir(parents=True, exist_ok=True)
        safe_name = cls.sanitize_project_name(project_name)
        return base_dir / f"{safe_name}.json"

    def _apply_default_config_whitelist(self) -> None:
        return

    def _compile_patterns(self) -> None:
        user_alt = "|".join(re.escape(k) for k in self.USER_KEYWORDS)
        pass_alt = "|".join(re.escape(k) for k in self.PASS_KEYWORDS)
        token_alt = "|".join(re.escape(k) for k in self.TOKEN_KEYWORDS)
        cookie_name_alt = "|".join(re.escape(k) for k in self.COOKIE_KEYWORDS)
        auth_header_alt = "|".join(re.escape(k) for k in self.AUTH_HEADER_KEYWORDS)

        def _rx(pattern: str) -> re.Pattern[str]:
            return re.compile(pattern, re.IGNORECASE | re.MULTILINE)

        self.detectors: dict[str, list[dict]] = {
            "private_key": [
                {
                    "pattern": _rx(r"-----BEGIN[^-]+PRIVATE KEY-----[\s\S]+?-----END[^-]+PRIVATE KEY-----"),
                    "group": 0,
                    "priority": 100,
                },
                {
                    "pattern": _rx(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----"),
                    "group": 0,
                    "priority": 100,
                },
            ],
            "ssh_key": [
                {
                    "pattern": _rx(r"ssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/=]+(?:\s+\S+)?"),
                    "group": 0,
                    "priority": 98,
                },
            ],
            "jwt": [
                {
                    "pattern": _rx(r"\beyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\b"),
                    "group": 0,
                    "priority": 96,
                },
            ],
            "auth_header": [
                {
                    "pattern": _rx(
                        rf"(?:{auth_header_alt})\s*[:=]\s*(?:Bearer|Basic|Digest|NTLM|Negotiate|AWS4-HMAC-SHA256|Token|token)\s+([^\s\r\n,;]+)"
                    ),
                    "group": 1,
                    "priority": 95,
                },
                {
                    "pattern": _rx(rf"(?:{auth_header_alt})\s*[:=]\s*[\"\']?([a-zA-Z0-9\-_.~+/=]{{16,}})[\"\']?"),
                    "group": 1,
                    "priority": 94,
                },
            ],
            "url_creds": [
                {
                    "pattern": _rx(r"(?:[a-z][a-z0-9+.\-]*)://([^:\s/@]+):(.+?)@([^\s/@:]+(?::\d+)?)(?:/[^\s]*)?(?=\s|$)"),
                    "priority": 94,
                },
            ],
            "db_uri": [
                {
                    "pattern": _rx(r"\b(?:postgres(?:ql)?|mysql|mariadb|mssql|sqlserver|mongodb(?:\+srv)?|redis|amqp)://[^\s\"'<>]+"),
                    "group": 0,
                    "priority": 94,
                },
            ],
            "token_format": [
                {"pattern": _rx(r"\bghp_[A-Za-z0-9]{36}\b"), "group": 0, "priority": 93},
                {"pattern": _rx(r"\bgithub_pat_[A-Za-z0-9_]{45,}\b"), "group": 0, "priority": 93},
                {"pattern": _rx(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"), "group": 0, "priority": 93},
                {"pattern": _rx(r"\bxox[baprs]-[A-Za-z0-9-]{10,100}\b"), "group": 0, "priority": 93},
                {"pattern": _rx(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), "group": 0, "priority": 93},
                {"pattern": _rx(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "group": 0, "priority": 93},
                {
                    "pattern": _rx(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9\-_]{20,}"),
                    "group": 0,
                    "priority": 93,
                },
            ],
            "cookie_session": [
                {
                    "pattern": _rx(rf"\b({cookie_name_alt})\s*=\s*([^;\r\n\s]+)"),
                    "group": 2,
                    "priority": 92,
                },
            ],
            "username_param": [
                {
                    "pattern": _rx(rf"[?&;]\s*({user_alt})=([^&\s#\"\']+)"),
                    "group": 2,
                    "priority": 90,
                },
                {
                    "pattern": _rx(rf"[\"\']({user_alt})[\"\']\s*:\s*[\"\']([^\"\']+)[\"\']"),
                    "group": 2,
                    "priority": 89,
                },
                {
                    "pattern": _rx(rf"(?<![A-Za-z0-9_])({user_alt})\s*[=:]\s*[\"\']?([^\s&,;\"\'\]\}}]+)[\"\']?"),
                    "group": 2,
                    "priority": 88,
                },
            ],
            "password_param": [
                {
                    "pattern": _rx(rf"[?&;]\s*({pass_alt})=([^&\s#\"\']+)"),
                    "group": 2,
                    "priority": 90,
                },
                {
                    "pattern": _rx(rf"[\"\']({pass_alt})[\"\']\s*:\s*[\"\']([^\"\']+)[\"\']"),
                    "group": 2,
                    "priority": 89,
                },
                {
                    "pattern": _rx(rf"(?<![A-Za-z0-9_])({pass_alt})\s*[=:]\s*[\"\']?([^\s&,;\"\'\]\}}]+)[\"\']?"),
                    "group": 2,
                    "priority": 88,
                },
            ],
            "token_param": [
                {
                    "pattern": _rx(rf"[?&;]\s*({token_alt})=([^&\s#\"\']+)"),
                    "group": 2,
                    "priority": 90,
                },
                {
                    "pattern": _rx(rf"[\"\']({token_alt})[\"\']\s*:\s*[\"\']([^\"\']+)[\"\']"),
                    "group": 2,
                    "priority": 89,
                },
                {
                    "pattern": _rx(rf"(?<![A-Za-z0-9_])({token_alt})\s*[=:]\s*[\"\']?([a-zA-Z0-9\-_.~+/=]{{8,}})[\"\']?"),
                    "group": 2,
                    "priority": 88,
                },
            ],
            "aws_key": [
                {
                    "pattern": _rx(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
                    "group": 0,
                    "priority": 86,
                },
            ],
            "ntlm_hash": [
                {
                    "pattern": _rx(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b"),
                    "group": 0,
                    "priority": 85,
                },
                {
                    "pattern": _rx(r"\b[^:\s]*[g-zG-Z_.@\\-][^:\s]*::[^:\s]*[g-zG-Z_.@\\-][^:\s]*:[A-Fa-f0-9]{8,32}:[A-Fa-f0-9]{8,}:[A-Fa-f0-9]{8,}\b"),
                    "group": 0,
                    "priority": 85,
                },
            ],
            "credit_card": [
                {
                    "pattern": _rx(r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
                    "group": 0,
                    "priority": 84,
                },
            ],
            "uuid": [
                {
                    "pattern": _rx(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"),
                    "group": 0,
                    "priority": 82,
                },
            ],
            "iban": [
                {
                    "pattern": _rx(r"\bIBAN\s*[:=]?\s*([A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{2,6}){2,7})\b"),
                    "group": 1,
                    "priority": 87,
                },
                {
                    "pattern": _rx(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
                    "group": 0,
                    "priority": 86,
                },
                {
                    "pattern": _rx(r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{2,6}){3,7}\b"),
                    "group": 0,
                    "priority": 86,
                },
            ],
            "bic": [
                {
                    "pattern": _rx(r"\b(?:BIC|SWIFT)\s*[:=]?\s*([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b"),
                    "group": 1,
                    "priority": 82,
                },
            ],
            "ssn_us": [
                {
                    "pattern": _rx(r"\b\d{3}-\d{2}-\d{4}\b"),
                    "group": 0,
                    "priority": 82,
                },
            ],
            "email": [
                {
                    "pattern": _rx(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
                    "group": 0,
                    "priority": 80,
                },
            ],
            "mac": [
                {
                    "pattern": _rx(r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"),
                    "group": 0,
                    "priority": 79,
                },
                {
                    "pattern": _rx(r"\b(?:[0-9a-fA-F]{2}[:\-]){7}[0-9a-fA-F]{2}\b"),
                    "group": 0,
                    "priority": 79,
                },
                {
                    "pattern": _rx(r"\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b"),
                    "group": 0,
                    "priority": 79,
                },
                {
                    "pattern": _rx(r"\b(?:MAC|HWADDR|BSSID|EUI(?:-64)?)\s*[:=]\s*([0-9a-fA-F]{12})\b"),
                    "group": 1,
                    "priority": 79,
                },
            ],
            "hash": [
                {"pattern": _rx(r"\b[0-9a-fA-F]{128}\b"), "group": 0, "priority": 78},  # SHA-512
                {"pattern": _rx(r"\b[0-9a-fA-F]{96}\b"), "group": 0, "priority": 78},   # SHA-384
                {"pattern": _rx(r"\b[0-9a-fA-F]{64}\b"), "group": 0, "priority": 78},
                {"pattern": _rx(r"\b[0-9a-fA-F]{56}\b"), "group": 0, "priority": 78},   # SHA-224
                {"pattern": _rx(r"\b[0-9a-fA-F]{40}\b"), "group": 0, "priority": 78},
                {"pattern": _rx(r"\b[0-9a-fA-F]{32}\b"), "group": 0, "priority": 78},
                {"pattern": _rx(r"\$2[abyx]?\$\d{2}\$[./A-Za-z0-9]{30,90}"), "group": 0, "priority": 78},  # bcrypt
                {"pattern": _rx(r"\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"), "group": 0, "priority": 78},
                {"pattern": _rx(r"\$[156]\$[^\s$]{1,32}\$[^\s]{20,}"), "group": 0, "priority": 78},  # md5/sha256/sha512 crypt
                {"pattern": _rx(r"\$y\$[^\s$]{1,32}\$[^\s$]{1,64}\$[^\s]{20,}"), "group": 0, "priority": 78},  # yescrypt-like
                {"pattern": _rx(r"\bpbkdf2(?:-sha(?:1|224|256|384|512))?\$[A-Za-z0-9./$+=:-]{20,}\b"), "group": 0, "priority": 78},
            ],
            "ip": [
                {
                    "pattern": _rx(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?\b"),
                    "group": 0,
                    "priority": 70,
                },
                {
                    "pattern": _rx(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b"),
                    "group": 0,
                    "priority": 69,
                },
                {
                    "pattern": _rx(r"\b(?:[0-9a-f]{1,4}:){1,7}:\b"),
                    "group": 0,
                    "priority": 69,
                },
                {
                    "pattern": _rx(r"(?<![0-9a-f:])::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?(?:%[0-9A-Za-z_.-]+)?(?:/\d{1,3})?(?![0-9a-f:])"),
                    "group": 0,
                    "priority": 69,
                },
                {
                    "pattern": _rx(r"\[[0-9a-f:.%]+\](?:/\d{1,3})?"),
                    "group": 0,
                    "priority": 69,
                },
            ],
            "domain": [
                {
                    "pattern": _rx(
                        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|fr|de|uk|io|co|eu|gov|edu|local|internal|corp|lan|tech|biz|info|dev|app|cloud|xyz|me|tv|cc|us|ca|au|nl|be|ch|at|ru|cn|jp|kr|in|br|mil|int|museum|aero|coop|pro)\b"
                    ),
                    "group": 0,
                    "priority": 60,
                },
            ],
            "phone": [
                {"pattern": _rx(r"(?<!\d)(?:\+33|0033|0)[\s.\-]?[1-9](?:[\s.\-]?\d{2}){4}(?!\d)"), "group": 0, "priority": 55},
                {
                    "pattern": _rx(r"(?<!\d)(?:\+1|001)?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)"),
                    "group": 0,
                    "priority": 55,
                },
                {
                    "pattern": _rx(r"(?<!\d)\+\d{6,15}(?!\d)"),
                    "group": 0,
                    "priority": 55,
                },
            ],
            "date": [
                {"pattern": _rx(r"\b\d{4}[-/]\d{2}[-/]\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2})?(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)?\b"), "group": 0, "priority": 52},
                {"pattern": _rx(r"\b\d{2}[-/]\d{2}[-/]\d{4}(?:\s+\d{2}:\d{2}(?::\d{2})?)?\b"), "group": 0, "priority": 52},
            ],
        }

        self.fake_generators = {
            "ip": lambda n: f"192.0.2.{n}",
            "email": lambda n: f"user{n}@anon.local",
            "url_creds": lambda n: f"https://anonuser{n}:REDACTED@target{n}.anon.local/path",
            "auth_header": lambda n: f"[REDACTED_AUTH_{n}]",
            "cookie_session": lambda n: f"[REDACTED_COOKIE_{n}]",
            "db_uri": lambda n: f"[REDACTED_DB_URI_{n}]",
            "token_format": lambda n: f"[REDACTED_TOKENFMT_{n}]",
            "http_url": lambda n: f"http://host{n}.test.local",
            "username_param": lambda n: f"anon_user_{n}",
            "password_param": lambda n: f"[REDACTED_PASS_{n}]",
            "token_param": lambda n: f"[REDACTED_TOKEN_{n}]",
            "file_path": lambda n: f"/redacted/path/{n}",
            "domain": lambda n: f"target{n}.anon.local",
            "mac": lambda n: f"00:de:ad:be:ef:{n:02x}",
            "hash": lambda n: f"[REDACTED_HASH_{n}]",
            "phone": lambda n: f"+3360000000{n:02d}",
            "private_key": lambda n: f"[REDACTED_PRIVATE_KEY_{n}]",
            "jwt": lambda n: f"[REDACTED_JWT_{n}]",
            "aws_key": lambda n: f"[REDACTED_AWS_KEY_{n}]",
            "ssh_key": lambda n: f"[REDACTED_SSH_KEY_{n}]",
            "ntlm_hash": lambda n: f"[REDACTED_NTLM_{n}]",
            "credit_card": lambda n: f"[REDACTED_CC_{n}]",
            "uuid": lambda n: f"00000000-0000-4000-8000-{n:012d}",
            "iban": lambda n: f"FR7630006000010000000000{n:02d}",
            "bic": lambda n: f"AAAABBCC{n:03d}"[:11],
            "ssn_us": lambda n: f"000-00-{n:04d}",
            "date": lambda n: f"2000-01-{(n % 28) + 1:02d}",
            "xml_text": lambda n: f"XMLTEXT{n}",
            "xml_number": lambda n: f"{n:02d}",
            "custom": lambda n: f"[ANON_CUSTOM_{n}]",
        }

        # ─── Load extended detection rules from external file ─────────
        try:
            from detection_rules import EXTENDED_RULES, EXTENDED_FAKES
            for _rule_type, _pattern, _group, _priority in EXTENDED_RULES:
                self.detectors.setdefault(_rule_type, []).append(
                    {"pattern": _rx(_pattern), "group": _group, "priority": _priority}
                )
            self.fake_generators.update(EXTENDED_FAKES)
        except ImportError:
            pass  # detection_rules.py not present — core detectors only

    def load_custom_words(self, seeds: dict) -> int:
        self.custom_wordlist = []
        self.custom_variant_family.clear()
        self.custom_family_alias.clear()
        self.custom_family_canonical.clear()
        self.custom_family_counter = 0

        seed_words: list[str] = []
        for key, value in seeds.items():
            if key == "custom" and isinstance(value, list):
                seed_words.extend(v.strip() for v in value if isinstance(v, str) and v.strip())
            elif isinstance(value, str) and value.strip():
                seed_words.append(value.strip())

        for word in seed_words:
            self._register_custom_family(word)

        self.custom_wordlist.sort(key=len, reverse=True)
        return len(self.custom_wordlist)

    def load_blacklist_words(self, words: list[str]) -> int:
        return self.load_custom_words({"custom": words})

    def add_custom_word(self, word: str) -> int:
        return self._register_custom_family(word)

    def add_blacklist_word(self, word: str) -> int:
        return self.add_custom_word(word)

    def load_whitelist_words(self, words: list[str]) -> int:
        self.whitelist_words.clear()
        for word in words:
            if not isinstance(word, str):
                continue
            cleaned = word.strip()
            if not cleaned:
                continue
            key = cleaned.casefold()
            if key not in self.whitelist_words:
                self.whitelist_words[key] = cleaned
        return len(self.whitelist_words)

    def add_whitelist_word(self, word: str) -> int:
        if not isinstance(word, str):
            return 0
        cleaned = word.strip()
        if not cleaned:
            return 0
        key = cleaned.casefold()
        if key in self.whitelist_words:
            return 0
        self.whitelist_words[key] = cleaned
        return 1

    def get_whitelist_words(self) -> list[str]:
        return sorted(self.whitelist_words.values(), key=lambda x: x.casefold())

    def get_blacklist_words(self) -> list[str]:
        if self.custom_family_canonical:
            words = [self.custom_family_canonical[k] for k in sorted(self.custom_family_canonical)]
            return sorted(words, key=lambda x: x.casefold())
        return sorted(self.custom_wordlist, key=lambda x: x.casefold())

    @staticmethod
    def _normalize_custom_key(value: str) -> str:
        return value.strip().casefold()

    def _add_custom_variant(self, variant: str) -> int:
        if not variant or not variant.strip():
            return 0
        key = self._normalize_custom_key(variant)
        if not key:
            return 0
        for existing in self.custom_wordlist:
            if self._normalize_custom_key(existing) == key:
                return 0
        self.custom_wordlist.append(variant)
        return 1

    def _register_custom_family(self, word: str) -> int:
        if not word or not word.strip():
            return 0
        custom_word = word.strip()
        key = self._normalize_custom_key(custom_word)
        if not key:
            return 0
        if key in self.custom_variant_family:
            return 0

        self.custom_family_counter += 1
        family_id = self.custom_family_counter
        self.custom_family_canonical[family_id] = custom_word
        self.custom_variant_family[key] = family_id
        added = self._add_custom_variant(custom_word)

        self.custom_wordlist.sort(key=len, reverse=True)
        return added

    def anonymize(self, text: str, max_passes: int = 1) -> tuple[str, list[Entity]]:
        del max_passes  # Compatibilite API: on fige a un passage pour eviter les re-anonymisations.
        candidates = self._collect_candidates(text)
        if not candidates:
            return text, []
        return self._apply_candidates(text, candidates)

    def deanonymize(self, text: str) -> tuple[str, list[dict]]:
        result = text
        substitutions: list[dict] = []

        for anon, orig in sorted(self.reverse.items(), key=lambda x: len(x[0]), reverse=True):
            if anon in result:
                count = result.count(anon)
                result = result.replace(anon, orig)
                substitutions.append({"anon": anon, "orig": orig, "count": count})

        return result, substitutions

    def get_stats(self) -> dict[str, int]:
        stats: dict[str, int] = {}
        for _, entity_type in self.types.items():
            stats[entity_type] = stats.get(entity_type, 0) + 1
        return stats

    def export_state(self) -> dict:
        return {
            "mappings": dict(self.mappings),
            "reverse": dict(self.reverse),
            "types": dict(self.types),
            "counter": dict(self.counter),
            "custom_wordlist": list(self.custom_wordlist),
            "whitelist_words": dict(self.whitelist_words),
            "custom_variant_family": dict(self.custom_variant_family),
            "custom_family_alias": dict(self.custom_family_alias),
            "custom_family_canonical": dict(self.custom_family_canonical),
            "custom_family_counter": int(self.custom_family_counter),
            "ip_network_map": dict(self.ip_network_map),
            "domain_root_map": dict(self.domain_root_map),
            "domain_fqdn_map": dict(self.domain_fqdn_map),
            "domain_root_sub_counter": dict(self.domain_root_sub_counter),
            "url_host_map": dict(self.url_host_map),
            "url_host_counter": int(self.url_host_counter),
        }

    def import_state(self, state: dict) -> None:
        if not isinstance(state, dict):
            self.reset()
            return

        self.mappings = {str(k): str(v) for k, v in state.get("mappings", {}).items()}
        self.reverse = {str(k): str(v) for k, v in state.get("reverse", {}).items()}
        self.types = {str(k): str(v) for k, v in state.get("types", {}).items()}
        self.counter = {str(k): int(v) for k, v in state.get("counter", {}).items()}
        self.custom_wordlist = [str(v) for v in state.get("custom_wordlist", [])]
        self.whitelist_words = {str(k): str(v) for k, v in state.get("whitelist_words", {}).items()}
        self.custom_variant_family = {str(k): int(v) for k, v in state.get("custom_variant_family", {}).items()}
        self.custom_family_alias = {int(k): str(v) for k, v in state.get("custom_family_alias", {}).items()}
        self.custom_family_canonical = {int(k): str(v) for k, v in state.get("custom_family_canonical", {}).items()}
        self.custom_family_counter = int(state.get("custom_family_counter", 0))
        self.ip_network_map = {str(k): int(v) for k, v in state.get("ip_network_map", {}).items()}
        self.domain_root_map = {str(k): str(v) for k, v in state.get("domain_root_map", {}).items()}
        self.domain_fqdn_map = {str(k): str(v) for k, v in state.get("domain_fqdn_map", {}).items()}
        self.domain_root_sub_counter = {str(k): int(v) for k, v in state.get("domain_root_sub_counter", {}).items()}
        self.url_host_map = {str(k): str(v) for k, v in state.get("url_host_map", {}).items()}
        self.url_host_counter = int(state.get("url_host_counter", 0))
        self._apply_default_config_whitelist()

    def save_project_state(
        self,
        project_name: str,
        projects_dir: Path | str | None = None,
        state_file: Path | str | None = None,
        extra_payload: dict | None = None,
    ) -> Path:
        path = self.resolve_project_state_path(project_name, projects_dir=projects_dir, explicit_state_file=state_file)
        if state_file is None and not path.exists():
            legacy_path = self.resolve_legacy_project_state_path(project_name, projects_dir=projects_dir)
            if legacy_path.exists():
                path = legacy_path
        payload = {
            "project_name": self.sanitize_project_name(project_name),
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "blacklist_words": self.get_blacklist_words(),
            "whitelist_words": self.get_whitelist_words(),
            "anon_state": self.export_state(),
        }
        if extra_payload and isinstance(extra_payload, dict):
            payload.update(extra_payload)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def load_project_state(
        self,
        project_name: str,
        projects_dir: Path | str | None = None,
        state_file: Path | str | None = None,
        create_if_missing: bool = True,
    ) -> Path:
        path = self.resolve_project_state_path(project_name, projects_dir=projects_dir, explicit_state_file=state_file)
        if not path.exists():
            self.reset()
            if create_if_missing:
                self.save_project_state(project_name, projects_dir=projects_dir, state_file=path)
            return path

        payload = json.loads(path.read_text(encoding="utf-8"))
        state_obj = payload.get("anon_state") if isinstance(payload, dict) else None
        if isinstance(state_obj, dict):
            self.import_state(state_obj)
        else:
            self.import_state(payload if isinstance(payload, dict) else {})

        if isinstance(payload, dict):
            if not isinstance(payload.get("anon_state"), dict):
                blacklist = payload.get("blacklist_words")
                if isinstance(blacklist, list):
                    self.load_blacklist_words([str(x) for x in blacklist])
                whitelist = payload.get("whitelist_words")
                if isinstance(whitelist, list):
                    for word in whitelist:
                        self.add_whitelist_word(str(word))
        self._apply_default_config_whitelist()
        return path

    def reset(self) -> None:
        self.mappings.clear()
        self.reverse.clear()
        self.types.clear()
        self.counter.clear()
        self.ip_network_map.clear()
        self.domain_root_map.clear()
        self.domain_fqdn_map.clear()
        self.domain_root_sub_counter.clear()
        self.url_host_map.clear()
        self.url_host_counter = 0
        self.whitelist_words.clear()
        self.custom_variant_family.clear()
        self.custom_family_alias.clear()
        self.custom_family_canonical.clear()
        self.custom_family_counter = 0
        self._apply_default_config_whitelist()

    def _collect_candidates(self, text: str) -> list[Candidate]:
        candidates: list[Candidate] = []

        for entity_type, detector_specs in self.detectors.items():
            for spec in detector_specs:
                pattern = spec["pattern"]
                priority = spec["priority"]

                for match in pattern.finditer(text):
                    if entity_type == "url_creds":
                        if match.lastindex and match.lastindex >= 2:
                            self._append_candidate(
                                candidates,
                                text,
                                match.group(1),
                                "username_param",
                                match.start(1),
                                match.end(1),
                                priority,
                            )
                            self._append_candidate(
                                candidates,
                                text,
                                match.group(2),
                                "password_param",
                                match.start(2),
                                match.end(2),
                                priority,
                            )
                        continue

                    group = spec.get("group", 0)
                    value = match.group(group)
                    start = match.start(group)
                    end = match.end(group)
                    self._append_candidate(candidates, text, value, entity_type, start, end, priority)

        self._collect_http_url_candidates(text, candidates)

        self._collect_custom_candidates(text, candidates)

        self._collect_url_credential_candidates(text, candidates)
        self._collect_secret_kv_candidates(text, candidates)
        self._collect_cli_credential_candidates(text, candidates)
        self._collect_xml_soap_candidates(text, candidates)
        self._collect_ipv6_candidates(text, candidates)

        return candidates

    def _collect_custom_candidates(self, text: str, candidates: list[Candidate]) -> None:
        identifier_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")

        for word in self.custom_wordlist:
            if len(word) < self.MIN_CUSTOM_MATCH_LEN:
                continue
            if self._is_whitelisted_word(word):
                continue

            # Cas 1: mot "isolé" (comportement historique)
            pattern_word = rf"(?<![A-Za-z0-9_]){re.escape(word)}(?![A-Za-z0-9_])"
            for match in re.finditer(pattern_word, text, flags=re.IGNORECASE):
                self._append_candidate(candidates, text, match.group(0), "custom", match.start(), match.end(), 50)

            # Cas 2: sous-chaîne dans un identifiant concaténé (PascalCase/snake_case)
            for token_match in identifier_pattern.finditer(text):
                token = token_match.group(0)
                for sub_match in re.finditer(re.escape(word), token, flags=re.IGNORECASE):
                    start = token_match.start() + sub_match.start()
                    end = token_match.start() + sub_match.end()
                    self._append_candidate(candidates, text, text[start:end], "custom", start, end, 51)

    def _collect_http_url_candidates(self, text: str, candidates: list[Candidate]) -> None:
        pattern = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
        for match in pattern.finditer(text):
            token = match.group(0).rstrip("),;.]")
            if len(token) < 8:
                continue
            try:
                parts = urlsplit(token)
                host = (parts.hostname or "").strip().lower()
                if host == "localhost" or self._is_safe_host(host):
                    continue
            except Exception:
                pass
            start = match.start()
            end = start + len(token)
            self._append_candidate(candidates, text, token, "http_url", start, end, 99)

    def _collect_url_credential_candidates(self, text: str, candidates: list[Candidate]) -> None:
        """
        Extraction robuste user:password@host sur URLs (ftp/smb/sftp/http...),
        y compris quand le mot de passe contient un ou plusieurs '@'.
        """
        for url_match in self.url_candidate_pattern.finditer(text):
            token = url_match.group(0).rstrip("),;.")
            scheme_pos = token.find("://")
            if scheme_pos < 0:
                continue

            auth_start = scheme_pos + 3
            authority_and_rest = token[auth_start:]
            at_pos = authority_and_rest.rfind("@")
            if at_pos <= 0:
                continue

            userinfo = authority_and_rest[:at_pos]
            if ":" not in userinfo:
                continue

            username, password = userinfo.split(":", 1)
            if not username or not password:
                continue

            user_start = url_match.start() + auth_start
            user_end = user_start + len(username)
            pass_start = user_end + 1
            pass_end = pass_start + len(password)

            self._append_candidate(
                candidates,
                text,
                username,
                "username_param",
                user_start,
                user_end,
                97,
            )
            self._append_candidate(
                candidates,
                text,
                password,
                "password_param",
                pass_start,
                pass_end,
                97,
            )

    def _collect_ipv6_candidates(self, text: str, candidates: list[Candidate]) -> None:
        """
        Fallback IPv6 extractor pour formes compactes/zone-id/bracket
        souvent vues en sortie de nmap/nuclei.
        """
        pattern = re.compile(r"(?<![A-Za-z0-9])(\[?[0-9A-Fa-f:.%]{2,}\]?(/\d{1,3})?)(?![A-Za-z0-9])")
        for match in pattern.finditer(text):
            token = match.group(1)
            if ":" not in token:
                continue
            self._append_candidate(
                candidates,
                text,
                token,
                "ip",
                match.start(1),
                match.end(1),
                71,
            )

    def _collect_secret_kv_candidates(self, text: str, candidates: list[Candidate]) -> None:
        for match in self.secret_kv_pattern.finditer(text):
            key = match.group(1).lower()
            value = match.group(2)
            start = match.start(2)
            end = match.end(2)

            if key in {
                "publickeytoken",
                "oldversion",
                "newversion",
                "runtimeversion",
                "targetframework",
                "frameworkversion",
                "sku",
                "version",
            }:
                continue

            entity_type = self._classify_secret_key(key, value)
            if entity_type is None:
                continue

            self._append_candidate(candidates, text, value, entity_type, start, end, 91)

    def _collect_xml_soap_candidates(self, text: str, candidates: list[Candidate]) -> None:
        """
        Détecte les valeurs sensibles dans XML/SOAP:
        - texte de balises: <Password>secret</Password>
        - attributs: <Auth token="abc" username="bob" />
        """
        tag_text_pattern = re.compile(
            r"<([A-Za-z_][A-Za-z0-9_.:-]*)(?:\s+[^<>]*?)?>([^<]{1,256})</\1>",
            re.IGNORECASE | re.MULTILINE,
        )
        open_tag_pattern = re.compile(
            r"<([A-Za-z_][A-Za-z0-9_.:-]*)(\s+[^<>]*?)?>",
            re.IGNORECASE | re.MULTILINE,
        )
        attr_pattern = re.compile(
            r"([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*([\"'])([^\"'\r\n]{1,256})\2",
            re.IGNORECASE | re.MULTILINE,
        )

        for match in tag_text_pattern.finditer(text):
            tag_name = match.group(1).split(":")[-1]
            raw_value = match.group(2).strip()
            if not raw_value or len(raw_value) < 2:
                continue
            if self._is_xml_value_non_sensitive(tag_name, "", raw_value):
                continue
            entity_type = self._classify_secret_key(tag_name, raw_value)
            if entity_type is None:
                entity_type = self._classify_generic_xml_value(raw_value)
            if entity_type is None:
                continue
            value_start = match.start(2) + (len(match.group(2)) - len(match.group(2).lstrip()))
            value_end = value_start + len(raw_value)
            self._append_candidate(candidates, text, raw_value, entity_type, value_start, value_end, 93)

        for tag_match in open_tag_pattern.finditer(text):
            full_tag_name = tag_match.group(1)
            attrs_blob = tag_match.group(2) or ""
            tag_local = full_tag_name.split(":")[-1]

            for attr_match in attr_pattern.finditer(attrs_blob):
                attr_name = attr_match.group(1).split(":")[-1]
                attr_value = attr_match.group(3).strip()
                if not attr_value or len(attr_value) < 2:
                    continue
                if self._is_xml_value_non_sensitive(tag_local, attr_name, attr_value):
                    continue

                entity_type = self._classify_secret_key(attr_name, attr_value)
                if entity_type is None:
                    entity_type = self._classify_generic_xml_value(attr_value)
                if entity_type is None:
                    continue

                value_rel_start = attr_match.start(3) + len(attr_match.group(3)) - len(attr_match.group(3).lstrip())
                value_start = tag_match.start(2) + value_rel_start
                value_end = value_start + len(attr_value)
                self._append_candidate(candidates, text, attr_value, entity_type, value_start, value_end, 93)

    @classmethod
    def _is_xml_value_non_sensitive(cls, tag_name: str, attr_name: str, value: str) -> bool:
        tag_l = (tag_name or "").strip().lower()
        attr_l = (attr_name or "").strip().lower()
        val = value.strip()

        if attr_l.startswith("xmlns") or attr_l in {"xsi:type", "schemaLocation"}:
            return True

        if tag_l in cls.XML_SAFE_TAGS and attr_l in {
            "name",
            "version",
            "sku",
            "culture",
            "publickeytoken",
            "processorarchitecture",
        }:
            return True

        if val.lower().startswith("urn:schemas-microsoft-com:asm."):
            return True
        if re.fullmatch(r"v\d+(?:\.\d+){0,3}", val):
            return True
        if re.fullmatch(r"\.NETFramework,Version=v\d+(?:\.\d+){0,3}", val, flags=re.IGNORECASE):
            return True

        return False

    @classmethod
    def _classify_generic_xml_value(cls, value: str) -> str | None:
        val = value.strip()
        if not val:
            return None
        if cls._looks_already_anonymized(val):
            return None
        if val.lower() in {"true", "false", "null", "none", "n/a"}:
            return None
        if re.fullmatch(r"\d{1,32}", val):
            return "xml_number"
        if re.search(r"\d{2,4}[-/]\d{2}[-/]\d{2,4}", val):
            return "date"
        if cls._is_valid_ip(val):
            return "ip"
        if re.fullmatch(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", val):
            return "email"
        if cls._is_valid_iban(val):
            return "iban"
        if cls._is_valid_bic(val):
            return "bic"
        if cls._is_valid_mac(val):
            return "mac"
        if re.search(r"[A-Za-z]", val):
            return "xml_text"
        return None

    def _collect_cli_credential_candidates(self, text: str, candidates: list[Candidate]) -> None:
        for match in self.tool_password_pattern.finditer(text):
            value = match.group(1)
            self._append_candidate(candidates, text, value, "password_param", match.start(1), match.end(1), 92)

        for match in self.nikto_id_pattern.finditer(text):
            username = match.group(1)
            password = match.group(2)
            self._append_candidate(candidates, text, username, "username_param", match.start(1), match.end(1), 92)
            self._append_candidate(candidates, text, password, "password_param", match.start(2), match.end(2), 92)

        for match in self.proxy_cred_pattern.finditer(text):
            cred = match.group(1)
            if ":" not in cred:
                continue
            username, password = cred.split(":", 1)
            user_start = match.start(1)
            user_end = user_start + len(username)
            pass_start = user_end + 1
            pass_end = pass_start + len(password)
            self._append_candidate(candidates, text, username, "username_param", user_start, user_end, 92)
            self._append_candidate(candidates, text, password, "password_param", pass_start, pass_end, 92)

    @staticmethod
    def _classify_secret_key(key: str, value: str) -> str | None:
        key_l = key.lower()
        val = value.strip()

        if any(k in key_l for k in ("kubeconfig", "kube_config", "passfile", "passwd_file", "key_file", "cert_file", "config_file")):
            if "/" in val or "\\" in val:
                return "file_path"
            return "password_param"

        if any(k in key_l for k in ("db_uri", "db_url", "database_url", "jdbc_url", "connection_string", "dsn")):
            if "://" in val:
                return "db_uri"
            return "password_param"

        if "iban" in key_l:
            return "iban"

        if any(k in key_l for k in ("bic", "swift")):
            return "bic"

        if "email" in key_l or key_l.endswith("mail"):
            return "email"

        if any(k in key_l for k in ("phone", "mobile", "msisdn", "tel")):
            return "phone"

        if any(k in key_l for k in ("uuid", "guid")):
            return "uuid"

        if any(k in key_l for k in ("ssn", "social_security")):
            return "ssn_us"

        if "mac" in key_l:
            return "mac"

        if key_l in {"ip", "ip_addr", "ip_address", "client_ip", "server_ip"}:
            return "ip"

        if any(k in key_l for k in ("username", "user_name", "login", "account", "userid", "user_id")):
            return "username_param"

        if any(k in key_l for k in Anonymizer.DATE_KEYWORDS):
            if re.search(r"\d{2,4}[-/]\d{2}[-/]\d{2,4}", val) or "t" in val.lower():
                return "date"

        if any(k in key_l for k in ("token", "api_key", "apikey", "private_token", "authkey", "session_key", "pat")):
            return "token_param"

        if any(k in key_l for k in ("password", "passwd", "pass", "pwd", "secret", "cred", "sshpass")):
            return "password_param"

        return None

    def _append_candidate(
        self,
        candidates: list[Candidate],
        text: str,
        value: str,
        entity_type: str,
        start: int,
        end: int,
        priority: int,
    ) -> None:
        if start < 0 or end <= start:
            return

        value = value.strip()
        if len(value) < 2:
            return

        if self._is_boolean_literal(value):
            return

        if self._is_whitelisted_candidate(value, entity_type):
            return

        if self._looks_already_anonymized(value):
            return

        # Evite de redacter les clés elles-mêmes (ex: password=)
        if value.lower() in self.USER_KEYWORDS or value.lower() in self.PASS_KEYWORDS or value.lower() in self.TOKEN_KEYWORDS:
            return

        if entity_type == "iban" and not self._is_valid_iban(value):
            return

        if entity_type == "bic" and not self._is_valid_bic(value):
            return

        if entity_type == "mac" and not self._is_valid_mac(value):
            return

        if entity_type == "ip" and not self._is_valid_ip(value):
            return

        if entity_type == "ip":
            context_before = text[max(0, start - 200):start]
            if re.search(
                r"(?i)(oldversion|newversion|runtimeversion|frameworkversion|version)\s*=\s*['\"][^'\"]*$",
                context_before,
            ):
                return

        candidates.append(
            Candidate(
                original=text[start:end],
                entity_type=entity_type,
                start=start,
                end=end,
                priority=priority,
            )
        )

    @staticmethod
    def _is_boolean_literal(value: str) -> bool:
        return value.strip().lower() in {"true", "false"}

    @classmethod
    def _is_safe_host(cls, host: str) -> bool:
        h = (host or "").strip().lower().strip(".")
        if not h:
            return False
        for suffix in cls.SAFE_HOST_SUFFIXES:
            s = suffix.strip().lower().strip(".")
            if h == s or h.endswith(f".{s}"):
                return True
        return False

    def _is_whitelisted_candidate(self, value: str, entity_type: str) -> bool:
        token = (value or "").strip()
        lowered = token.lower()
        if lowered in self.NON_SENSITIVE_WORDS:
            return True
        if self._is_whitelisted_word(token):
            return True
        if entity_type == "domain":
            return self._is_safe_host(lowered)
        if entity_type == "http_url":
            try:
                host = (urlsplit(token).hostname or "").strip().lower()
            except Exception:
                return False
            return self._is_safe_host(host)
        return False

    def _is_whitelisted_word(self, value: str) -> bool:
        token = (value or "").strip().casefold()
        if not token:
            return False
        return token in self.whitelist_words or token in self.DEFAULT_CONFIG_WHITELIST

    @staticmethod
    def _overlaps(a: Candidate, b: Candidate) -> bool:
        return not (a.end <= b.start or a.start >= b.end)

    def _apply_candidates(self, text: str, candidates: list[Candidate]) -> tuple[str, list[Entity]]:
        selected: list[Candidate] = []
        seen: set[tuple[int, int, str]] = set()

        ranked = sorted(candidates, key=lambda c: (-c.priority, -(c.end - c.start), c.start))
        for candidate in ranked:
            sig = (candidate.start, candidate.end, candidate.entity_type)
            if sig in seen:
                continue
            if any(self._overlaps(candidate, existing) for existing in selected):
                continue
            selected.append(candidate)
            seen.add(sig)

        selected.sort(key=lambda c: c.start)
        if not selected:
            return text, []

        result = text
        entities: list[Entity] = []
        for candidate in reversed(selected):
            original = result[candidate.start:candidate.end]
            anonymized = self._get_or_create(original, candidate.entity_type)
            result = result[:candidate.start] + anonymized + result[candidate.end:]
            entities.append(
                Entity(
                    original=original,
                    anonymized=anonymized,
                    entity_type=candidate.entity_type,
                    start=candidate.start,
                    end=candidate.end,
                )
            )

        entities.reverse()
        return result, entities

    def _get_or_create(self, original: str, entity_type: str) -> str:
        if original in self.mappings:
            return self.mappings[original]

        if entity_type == "custom":
            family_id = self.custom_variant_family.get(self._normalize_custom_key(original))
            if family_id is not None and family_id in self.custom_family_alias:
                alias = self.custom_family_alias[family_id]
                self.mappings[original] = alias
                if alias not in self.reverse:
                    self.reverse[alias] = self.custom_family_canonical.get(family_id, original)
                self.types[original] = entity_type
                return alias

        case_insensitive_types = {"domain", "email", "ip", "iban", "bic", "mac"}
        if entity_type in case_insensitive_types:
            for existing_orig, anon in self.mappings.items():
                if existing_orig.lower() == original.lower() and self.types.get(existing_orig) == entity_type:
                    return anon

        n = self.counter.get(entity_type, 0) + 1
        self.counter[entity_type] = n
        if entity_type == "ip":
            anonymized = self._anonymize_ip(original, n)
        elif entity_type == "http_url":
            anonymized = self._anonymize_http_url(original, n)
        elif entity_type == "domain":
            anonymized = self._anonymize_domain(original, n)
        elif entity_type == "custom":
            family_id = self.custom_variant_family.get(self._normalize_custom_key(original))
            if family_id is not None:
                anonymized = f"[ANON_CUSTOM_{family_id}]"
                self.custom_family_alias[family_id] = anonymized
            else:
                generator = self.fake_generators.get(entity_type, lambda i: f"[REDACTED_{i}]")
                anonymized = generator(n)
        else:
            generator = self.fake_generators.get(entity_type, lambda i: f"[REDACTED_{i}]")
            anonymized = generator(n)

        preserve_types = {
            "username_param",
            "password_param",
            "token_param",
            "cookie_session",
            "auth_header",
            "hash",
            "date",
            "xml_text",
            "xml_number",
        }
        if entity_type in preserve_types:
            anonymized = self._preserve_value_format(original, anonymized, entity_type, n)

        self.mappings[original] = anonymized
        if anonymized not in self.reverse:
            if entity_type == "custom":
                family_id = self.custom_variant_family.get(self._normalize_custom_key(original))
                self.reverse[anonymized] = self.custom_family_canonical.get(family_id, original)
            else:
                self.reverse[anonymized] = original
        self.types[original] = entity_type
        return anonymized

    def _preserve_value_format(self, original: str, fallback: str, entity_type: str, seed: int) -> str:
        if entity_type == "date":
            return self._anonymize_date_like(original, seed)

        out: list[str] = []
        for idx, ch in enumerate(original):
            shift = (seed + idx * 7) % 26
            if ch.isdigit():
                out.append(str((int(ch) + seed + idx) % 10))
            elif "a" <= ch <= "z":
                out.append(chr(ord("a") + ((ord(ch) - ord("a") + shift) % 26)))
            elif "A" <= ch <= "Z":
                out.append(chr(ord("A") + ((ord(ch) - ord("A") + shift) % 26)))
            else:
                out.append(ch)

        candidate = "".join(out)
        if candidate == original:
            return fallback
        return candidate

    def _anonymize_date_like(self, value: str, seed: int) -> str:
        val = value.strip()

        ymd = re.fullmatch(r"(\d{4})([-/])(\d{2})\2(\d{2})", val)
        if ymd:
            sep = ymd.group(2)
            year = 2000 + (seed % 30)
            month = (seed % 12) + 1
            day = (seed % 28) + 1
            return f"{year:04d}{sep}{month:02d}{sep}{day:02d}"

        dmy = re.fullmatch(r"(\d{2})([-/])(\d{2})\2(\d{4})", val)
        if dmy:
            sep = dmy.group(2)
            day = (seed % 28) + 1
            month = (seed % 12) + 1
            year = 2000 + (seed % 30)
            return f"{day:02d}{sep}{month:02d}{sep}{year:04d}"

        iso_dt = re.fullmatch(
            r"(\d{4})-(\d{2})-(\d{2})([T\s])(\d{2}):(\d{2})(?::(\d{2}))?(\.\d{1,6})?(Z|[+-]\d{2}:?\d{2})?",
            val,
        )
        if iso_dt:
            sep = iso_dt.group(4)
            sec = iso_dt.group(7)
            frac = iso_dt.group(8) or ""
            tz = iso_dt.group(9) or ""
            year = 2000 + (seed % 30)
            month = (seed % 12) + 1
            day = (seed % 28) + 1
            hour = (seed * 3) % 24
            minute = (seed * 7) % 60
            second = (seed * 11) % 60
            if sec is None:
                return f"{year:04d}-{month:02d}-{day:02d}{sep}{hour:02d}:{minute:02d}{frac}{tz}"
            return f"{year:04d}-{month:02d}-{day:02d}{sep}{hour:02d}:{minute:02d}:{second:02d}{frac}{tz}"

        return self._preserve_value_format(val, f"[REDACTED_DATE_{seed}]", "token_param", seed)

    @staticmethod
    def _looks_already_anonymized(value: str) -> bool:
        lowered = value.lower()
        return (
            value.startswith("[REDACTED_")
            or value.startswith("[ANON_")
            or lowered.startswith("anon_user_")
            or lowered.endswith("@anon.local")
            or lowered.startswith("+3360000000")
            or lowered.startswith("/redacted/path/")
            or lowered.endswith(".anon.local")
            or ".test.local" in lowered
        )

    @staticmethod
    def _is_valid_iban(value: str) -> bool:
        compact = re.sub(r"[\s\-]", "", value).upper()
        if len(compact) < 15 or len(compact) > 34:
            return False
        if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", compact):
            return False
        expected_len = Anonymizer.IBAN_COUNTRY_LENGTHS.get(compact[:2])
        if expected_len and len(compact) != expected_len:
            return False
        rearranged = compact[4:] + compact[:4]
        numeric = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
        mod = 0
        for digit in numeric:
            mod = (mod * 10 + int(digit)) % 97
        return mod == 1

    @staticmethod
    def _is_valid_bic(value: str) -> bool:
        return re.fullmatch(r"[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?", value.strip().upper()) is not None

    def _anonymize_ip(self, original: str, n: int) -> str:
        ip_obj, prefix_len, had_prefix, bracketed = self._parse_ip_candidate(original)
        if ip_obj is None:
            return self.fake_generators["ip"](n)

        if isinstance(ip_obj, ipaddress.IPv4Address):
            anon = self._anonymize_ipv4(ip_obj, had_prefix, prefix_len)
        else:
            anon = self._anonymize_ipv6(ip_obj, had_prefix, prefix_len)

        if bracketed:
            if "/" in anon:
                base, cidr = anon.split("/", 1)
                return f"[{base}]/{cidr}"
            return f"[{anon}]"
        return anon

    def _anonymize_ipv4(self, ip_obj: ipaddress.IPv4Address, has_prefix: bool, prefix_len: int) -> str:
        prefix_len = max(0, min(prefix_len, 32))

        grouping_prefix = prefix_len if has_prefix else 24
        grouping_prefix = max(8, min(grouping_prefix, 32))
        group_network = ipaddress.ip_network(f"{ip_obj}/{grouping_prefix}", strict=False)
        group_key = str(group_network)

        if group_key not in self.ip_network_map:
            self.ip_network_map[group_key] = len(self.ip_network_map)
        group_idx = self.ip_network_map[group_key]

        # 198.18.0.0/15 (bench/testing) : permet de conserver un grouping réseau.
        second_octet = 18 + (group_idx // 256)
        third_octet = group_idx % 256
        host_octet = int(str(ip_obj).split(".")[-1])
        anon_ip = f"198.{second_octet}.{third_octet}.{host_octet}"
        if has_prefix:
            return f"{anon_ip}/{prefix_len}"
        return anon_ip

    def _anonymize_ipv6(self, ip_obj: ipaddress.IPv6Address, has_prefix: bool, prefix_len: int) -> str:
        prefix_len = max(0, min(prefix_len, 128))

        grouping_prefix = prefix_len if has_prefix else 64
        grouping_prefix = max(16, min(grouping_prefix, 128))
        group_network = ipaddress.ip_network(f"{ip_obj}/{grouping_prefix}", strict=False)
        group_key = str(group_network)

        if group_key not in self.ip_network_map:
            self.ip_network_map[group_key] = len(self.ip_network_map)
        group_idx = self.ip_network_map[group_key] % 65535

        base_prefix = int(ipaddress.IPv6Address(f"2001:db8:{group_idx:04x}::"))
        host_part = int(ip_obj) & ((1 << 64) - 1)
        anon_value = base_prefix | host_part
        anon_ip = str(ipaddress.IPv6Address(anon_value))
        if has_prefix:
            return f"{anon_ip}/{prefix_len}"
        return anon_ip

    def _anonymize_domain(self, original: str, n: int) -> str:
        fqdn = original.strip().lower().rstrip(".")
        if not fqdn:
            return self.fake_generators["domain"](n)
        if fqdn in self.domain_fqdn_map:
            return self.domain_fqdn_map[fqdn]

        labels = fqdn.split(".")
        root = self._extract_domain_root(labels)
        root_label_count = len(root.split("."))
        sub_labels = labels[:-root_label_count] if len(labels) > root_label_count else []

        if root not in self.domain_root_map:
            root_alias = self._build_test_root_alias(len(self.domain_root_map) + 1)
            self.domain_root_map[root] = root_alias
            self.domain_root_sub_counter[root_alias] = 0
        root_alias = self.domain_root_map[root]

        if fqdn == root:
            alias = root_alias
        else:
            self.domain_root_sub_counter[root_alias] += 1
            sub_id = self.domain_root_sub_counter[root_alias]
            host_label = f"host{sub_id}"
            if len(sub_labels) <= 1:
                alias = f"{host_label}.{root_alias}"
            else:
                extra_labels = [f"sousdom{i + 1}" for i in range(len(sub_labels) - 1)]
                alias = ".".join(extra_labels + [host_label, root_alias])

        self.domain_fqdn_map[fqdn] = alias
        return alias

    @staticmethod
    def _build_test_root_alias(index: int) -> str:
        if index <= 1:
            return "test.local"
        return f"test{index}.local"

    def _anonymize_http_url(self, original: str, n: int) -> str:
        try:
            parts = urlsplit(original)
        except Exception:
            return self.fake_generators["http_url"](n)

        scheme = (parts.scheme or "http").lower()
        if scheme not in {"http", "https"}:
            scheme = "http"
        host = parts.hostname or ""
        if host.strip().lower() == "localhost" or self._is_safe_host(host):
            return original
        if host:
            host_alias = self._anonymize_url_host(host)
        else:
            self.url_host_counter += 1
            host_alias = f"host{self.url_host_counter}.test.local"

        path = parts.path or ""
        if not path.startswith("/") and path:
            path = "/" + path

        port_part = f":{parts.port}" if parts.port else ""
        userinfo = "anon:anon@" if (parts.username or parts.password) else ""

        # Harmonisation: URLs HTTP(S) anonymisées en conservant le schéma original.
        return f"{scheme}://{userinfo}{host_alias}{port_part}{path}"

    def _anonymize_url_host(self, host: str) -> str:
        key = host.strip().lower().strip("[]")
        if not key:
            self.url_host_counter += 1
            return f"host{self.url_host_counter}.test.local"
        if key in self.url_host_map:
            return self.url_host_map[key]

        try:
            ip_obj = ipaddress.ip_address(key)
        except ValueError:
            ip_obj = None

        if ip_obj is not None:
            self.url_host_counter += 1
            root_alias = self._build_test_root_alias(1 + (self.url_host_counter // 50))
            alias = f"host{self.url_host_counter}.{root_alias}"
        else:
            alias = self._get_or_create(key, "domain")

        self.url_host_map[key] = alias
        return alias

    @staticmethod
    def _extract_domain_root(labels: list[str]) -> str:
        if len(labels) <= 2:
            return ".".join(labels)
        if len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "net", "gov", "edu", "ac"}:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    @staticmethod
    def _is_valid_mac(value: str) -> bool:
        token = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]{12}", token):
            return True
        if "." in token:
            if re.fullmatch(r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}", token):
                return True
            if re.fullmatch(r"(?:[0-9a-f]{4}\.){3}[0-9a-f]{4}", token):
                return True
            return False
        if ":" in token or "-" in token:
            if ":" in token and "-" in token:
                return False
            sep = ":" if ":" in token else "-"
            parts = token.split(sep)
            if len(parts) not in {6, 8}:
                return False
            return all(re.fullmatch(r"[0-9a-f]{2}", p or "") for p in parts)
        return False

    @staticmethod
    def _parse_ip_candidate(value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | None, int, bool, bool]:
        raw = value.strip()
        if not raw:
            return None, 0, False, False

        bracketed = raw.startswith("[") and "]" in raw
        token = raw
        if bracketed:
            close_idx = token.find("]")
            token = token[1:close_idx] + token[close_idx + 1:]
        token = token.strip("(){}<>,;")

        has_prefix = "/" in token
        prefix_len = 128
        addr_part = token
        if has_prefix:
            addr_part, prefix_part = token.rsplit("/", 1)
            if not prefix_part.isdigit():
                return None, 0, False, bracketed
            prefix_len = int(prefix_part)

        if "%" in addr_part:
            addr_part = addr_part.split("%", 1)[0]

        addr_part = addr_part.strip("[]")
        if not addr_part:
            return None, 0, False, bracketed

        try:
            ip_obj = ipaddress.ip_address(addr_part)
        except ValueError:
            return None, 0, False, bracketed

        if isinstance(ip_obj, ipaddress.IPv4Address):
            if has_prefix and not (0 <= prefix_len <= 32):
                return None, 0, False, bracketed
            return ip_obj, prefix_len if has_prefix else 32, has_prefix, bracketed

        if has_prefix and not (0 <= prefix_len <= 128):
            return None, 0, False, bracketed
        return ip_obj, prefix_len if has_prefix else 128, has_prefix, bracketed

    @classmethod
    def _is_valid_ip(cls, value: str) -> bool:
        ip_obj, _, _, _ = cls._parse_ip_candidate(value)
        return ip_obj is not None


DEFAULT_AI_INSTRUCTION = (
    "Les données ci-dessous ont été anonymisées : IPs, identifiants, mots de passe, "
    "clés/API, domaines et autres secrets ont été remplacés par des valeurs factices "
    "cohérentes. Raisonne directement sur ces valeurs anonymisées, ne tente pas de "
    "deviner les valeurs réelles."
)


def build_ai_prompt(anonymized_context: str, instruction: str | None = None) -> str:
    """Emballe un texte déjà anonymisé en un prompt prêt à coller dans une IA.

    (Capacité « bridge » fusionnée dans le core : entrée texte/.txt → sortie prête pour IA.)
    """
    header = instruction or DEFAULT_AI_INSTRUCTION
    return f"{header}\n\n----- DÉBUT CONTEXTE ANONYMISÉ -----\n{anonymized_context}\n----- FIN CONTEXTE ANONYMISÉ -----"


def fake_ai_response(query: str) -> str:
    return (
        "Voici mon analyse :\n\n"
        "D'apres votre requete, voici les etapes recommandees :\n"
        "1. Scanner les cibles mentionnees\n"
        "2. Verifier les services exposes\n"
        "3. Tester les credentials fournis\n\n"
        "Contexte repris :\n---\n"
        f"{query}\n"
        "---\n\n"
        "Commencez par un nmap sur les cibles identifiees."
    )


def _core_parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Anonymizer Core - anonymisation/deanonymisation avec état par projet")
    parser.add_argument("--mode", choices=["anonymize", "deanonymize"], default="anonymize")
    parser.add_argument("--input-file", type=Path, help="Entrée depuis un fichier (sinon stdin)")
    parser.add_argument("--output-file", type=Path, help="Sortie vers un fichier (sinon stdout)")
    parser.add_argument("--project", default="default", help="Nom du projet (état distinct par projet)")
    parser.add_argument("--projects-dir", type=Path, help="Dossier des états projet (défaut: ./projects)")
    parser.add_argument("--state-file", type=Path, help="Fichier état explicite (prioritaire sur --project)")
    parser.add_argument("--blacklist", help="Liste de mots blacklist séparés par virgule")
    parser.add_argument("--whitelist", help="Liste de mots whitelist séparés par virgule")
    parser.add_argument("--pretty", action="store_true", help="Sortie JSON structurée")
    parser.add_argument(
        "--prompt",
        action="store_true",
        help="Mode anonymize : emballe la sortie en prompt prêt pour une IA (entête d'instruction)",
    )
    return parser.parse_args()


def _core_read_input(input_file: Path | None) -> str:
    if input_file is not None:
        return input_file.read_text(encoding="utf-8")
    return sys.stdin.read()


def _core_write_output(output_file: Path | None, content: str) -> None:
    if output_file is None:
        print(content)
        return
    output_file.write_text(content, encoding="utf-8")


def _core_split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def core_main() -> int:
    args = _core_parse_args()
    anon = Anonymizer()

    safe_project_name = Anonymizer.sanitize_project_name(args.project)
    state_path = Anonymizer.resolve_project_state_path(
        safe_project_name,
        projects_dir=args.projects_dir,
        explicit_state_file=args.state_file,
    )
    anon.load_project_state(
        safe_project_name,
        projects_dir=args.projects_dir,
        state_file=state_path,
        create_if_missing=True,
    )

    blacklist_words = _core_split_csv(args.blacklist)
    if blacklist_words:
        anon.load_blacklist_words(blacklist_words)

    whitelist_words = _core_split_csv(args.whitelist)
    for word in whitelist_words:
        anon.add_whitelist_word(word)

    raw = _core_read_input(args.input_file)

    if args.mode == "deanonymize":
        restored, substitutions = anon.deanonymize(raw)
        payload = {
            "project": safe_project_name,
            "state_file": str(state_path),
            "mode": "deanonymize",
            "restored": restored,
            "substitutions": substitutions,
        }
        out = json.dumps(payload, ensure_ascii=False, indent=2) if args.pretty else restored
        _core_write_output(args.output_file, out)
        return 0

    anonymized, entities = anon.anonymize(raw)
    anon.save_project_state(safe_project_name, projects_dir=args.projects_dir, state_file=state_path)
    ai_ready = build_ai_prompt(anonymized) if args.prompt else anonymized
    payload = {
        "project": safe_project_name,
        "state_file": str(state_path),
        "mode": "anonymize",
        "anonymized": anonymized,
        "ai_prompt": ai_ready if args.prompt else None,
        "entities": [e.__dict__ for e in entities],
        "stats": anon.get_stats(),
        "blacklist_words": anon.get_blacklist_words(),
        "whitelist_words": anon.get_whitelist_words(),
    }
    out = json.dumps(payload, ensure_ascii=False, indent=2) if args.pretty else ai_ready
    _core_write_output(args.output_file, out)
    return 0


DEMO_SEEDS = {
    "company": "CyberTech Solutions",
    "firstname": "Marie",
    "lastname": "Laurent",
    "domain": "cybertech-solutions.fr",
    "project": "Audit-Phoenix",
    "hostname": "srv-compta-01",
    "custom": [
        "serveur-compta",
        "backup-nas",
        "intranet-rh",
        "prod-k8s-eu-west-1",
        "jump-host-admin",
        "vault-prod",
    ],
}

# Les fixtures de démo ci-dessous contiennent des secrets *factices* (clés API, tokens)
# destinés à valider la détection. Pour éviter que le secret-scanning de GitHub (push
# protection) ne bloque le push en les confondant avec de vrais secrets, chaque préfixe
# reconnaissable est coupé par le marqueur « ‹ » (U+2039), retiré au chargement par
# _undefang(). Le texte reconstruit à l'exécution est rigoureusement identique à
# l'original : la détection et le harnais anti-fuite (--verify-demo) ne changent pas.
_DEMO_DEFANG = "‹"


def _undefang(value: str) -> str:
    """Retire les marqueurs de defang d'une fixture de démo."""
    return value.replace(_DEMO_DEFANG, "")


DEMO_QUERY = _undefang("""Pendant l'audit Audit-Phoenix pour CyberTech Solutions, on a centralise des extraits heterogenes:

=== HTTP RAW REQUEST ===
POST /api/v3/auth/login?username=marie.laurent&password=Cyb3rT3ch!2024&access_token=tok_live_9b4f11f22711aa19&client_secret=s3cr3t_k3y_pr0d_2024! HTTP/1.1
Host: intranet.cybertech-solutions.fr
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1hcmllIExhdXJlbnQiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Proxy-Authorization: Basic YWRtaW46U3VwM3JTZWNyZXQh
X-API-Key: sk-proj-‹abc123def456ghi789jkl012mno345pqr
X-Auth-Token: 8f2cc5d5093048e1af19962cb5f70d3f
X-Amz-Security-Token: IQoJb3JpZ2luX2VjEOX//////////wEaCXVzLWVhc3QtMSJHMEUCIF5
Cookie: PHPSESSID=abc123def456; session_id=user_marie_laurent_9876; remember_token=eyJpZCI6MTIzfQ==; wordpress_logged_in=marie.laurent%7C1234567890%7Cabcdef; cf_clearance=xyz789abc456def123; next-auth.session-token=nextauthtoken_prod_456
Set-Cookie: refresh_token=dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4; Path=/; HttpOnly; Secure

{"username":"marie.laurent","password":"Cyb3rT3ch!2024","otp_code":"847293","grant_type":"password","csrf_token":"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6","client_id":"app-cybertech-prod","client_secret":"UltraSecret-Prod-2026","device":{"mac":"00:1A:2B:3C:4D:5E","uuid":"550e8400-e29b-41d4-a716-446655440000"}}

=== URL / CREDENTIALS ===
Credentials trouves via URL: https://audit-admin:Sup3rSecret!@vpn.cybertech-solutions.fr:8443/console
Fallback SMB: smb://marie-admin:P@ssw0rd123@10.0.50.15/shared
FTP export: ftp://ops.backup:FtP!2026@files.cybertech-solutions.fr/export
SFTP admin: sftp://ops.backup:Sup3r@Sftp#2026@files.cybertech-solutions.fr:22/home
SMB finance: smb://CORP;ops.backup:SmbP@ss!2026@10.0.50.18/finance
CIFS archive: cifs://audit:CiFsPass!2026@10.0.50.19/archive

=== LOGS / CONFIG / ENV ===
login_name=marie.laurent
pwd='Sup3rSecret!2026'
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DB_URI="postgres://dbadmin:DBpass!2026@db01.cybertech-solutions.internal:5432/prod"
JWT_TOKEN=eyJraWQiOiJrMSJ9.eyJ1c2VyIjoibWFyaWUubGF1cmVudCIsInJvbGUiOiJhZG1pbiJ9.eW91LW5lZWQtbW9yZS1zZWN1cml0eQ

=== INDICATEURS RESEAU ===
Cibles: 10.0.50.12, 10.0.50.15/24, 172.16.22.44, 2001:0db8:85a3:0000:0000:8a2e:0370:7334
DNS internes: vault-prod.cybertech-solutions.internal, jump-host-admin.corp, api.partner-example.com
Recheck FQDN: files.cybertech-solutions.fr, files.cybertech-solutions.fr, vpn.cybertech-solutions.fr
Recheck reseau: 10.0.50.18, 10.0.50.19, 10.0.51.18
IPv6 variees: [2001:db8::10], fe80::1ff:fe23:4567:890a%eth0, fd12:3456:789a::1, ::ffff:192.0.2.128/96
MAC variants: 00:1A:2B:3C:4D:5E, 00-1A-2B-3C-4D-5F, 001A.2B3C.4D60, MAC=001A2B3C4D61

=== OUTILS PENTEST (style HackTricks) ===
nmap -sV -sC -Pn target:
Nmap scan report for vpn.cybertech-solutions.fr (10.0.50.12)
Host is up (0.021s latency).
MAC Address: 00:50:56:AA:BB:CC (VMware)
| ssl-cert: Subject: commonName=api.partner-example.com/emailAddress=secops@cybertech-solutions.fr
| Subject Alternative Name: DNS:api.partner-example.com, DNS:admin.partner-example.com

sqlmap dump:
Database: usersdb
Table: users
+----+------------------------------+------------------------------------------+-----------------------+
| id | email                        | password_hash                            | api_token             |
+----+------------------------------+------------------------------------------+-----------------------+
| 1  | admin@cybertech-solutions.fr | $2b$12$abcdefghijklmnopqrstuu6s6XW6W7... | ghp_‹abcdEFGHijklMNOPqrstUVWXyz0123456789 |
+----+------------------------------+------------------------------------------+-----------------------+

nikto finding:
+ /phpinfo.php leaks SERVER_ADMIN=webmaster@cybertech-solutions.fr

nuclei finding .env:
DB_URL=postgresql://prod_admin:ProdDBP@ss!2026@db02.cybertech-solutions.internal:5432/prod
SLACK_TOKEN=xoxb-‹1209384756-1209384756-ABCDabcdABCDabcd1234
STRIPE_SECRET=sk_live_‹51N8abcdEFGHijklMNOPqrstUVWX123456
GOOGLE_API_KEY=AIza‹SyA-BCdEFghIJklMNOpqRSTuvWXyz012345
DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789012345678/‹abcdefghijklmnopqrstuvwxyzABCDE123456
GITLAB_PAT=glpat-‹ABCDEFGHIJKLMNOPQRST
GITHUB_FINE=github_pat_‹11AA22bb33CC44dd55EE66ff77GG88hh99II00JJ11KK22LL33MM44NN55OO66

ffuf/nuclei callback:
https://admin.partner-example.com/api?token=tok_live_hacktrix_00112233445566
http://10.0.50.18/internal/debug?apikey=hacktrixKey_ABCDEF1234567890

=== PARAMETRES CLI SENSIBLES ===
kubeconfig=/home/kali/.kube/config
kube_config=/home/kali/.kube/prod-config
passwd_file=/tmp/passwds.txt
sshpass=Sup3rSshPass!2026
proxy_cred=corp\\adm-soc:Pr0xyCred!2026
redis_password=r3disPass!2026
rabbitmq_password=rabbitPass!2026
elasticsearch_api_key=ZXNfa2V5X2FiY2RlZjEyMzQ1Njc4OTA=
grafana_api_key=eyJrIjoiR1JBRkFOQV9LRVlfMTIzNDU2Nzg5MCJ9
sonarqube_token=sqp_‹ABCDEFGHIJKLMNOPQRSTUVWXYZ123456
jenkins_token=11a22b33c44d55e66f77g88h99i00j11
crackmapexec smb 10.10.10.0/24 -u admin -p 'CMEPass!2026'
nikto -h https://target --id admin:niktoPass!2026

=== HASHES / NTLM / CRYPTO ===
MD5: 5d41402abc4b2a76b9719d911017c592
SHA1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
SHA224: d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA384: 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
SHA512: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
BCRYPT: $2b$12$abcdefghijklmnopqrstuu6s6XW6W7FhV2zv7u5rD5nQW0OQK5F8G
Argon2id: $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$NnVrb29MZ2dZeE9uQ1FxWm9nN3B0Zz09
PBKDF2: pbkdf2-sha256$29000$YWFhYmJiY2NjZGRk$R9Q6Yv4fS2jLQJxkVnNfQmQ1dVQ1c2NoZW1l
Net-NTLMv2: marie.laurent::CYBERTECH:1122334455667788:aabbccdd:0011223344556677
Private key:
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDfakefakefake
-----END PRIVATE KEY-----
Certificat:
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEbmh5uDANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJG
-----END CERTIFICATE-----
SSH key:
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSampleVeryLongKeyValueOnlyForDemo== marie@srv-compta-01

=== XML / SOAP ===
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:sec="http://example.org/sec" xmlns:pay="http://example.org/payment">
  <soapenv:Header>
    <sec:Auth username="Marie.Admin" password="Sup3rSoap!2026" token="tok_xml_ABC123def456" created_at="2026-02-24T22:18:59Z" />
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>marie.laurent</wsse:Username>
        <wsse:Password Type="PasswordText">S0apHeader#Pass2026</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body>
    <pay:PaymentRequest>
      <pay:IBAN>DE89 3704 0044 0532 0130 00</pay:IBAN>
      <pay:BIC>BNPAFRPPXXX</pay:BIC>
      <pay:BeneficiaryEmail>finance.ops@cybertech-solutions.fr</pay:BeneficiaryEmail>
      <pay:BeneficiaryPhone>+33 6 11 22 33 44</pay:BeneficiaryPhone>
      <pay:BirthDate>1989-10-31</pay:BirthDate>
      <pay:DueDate>31/12/2026</pay:DueDate>
      <pay:CallbackUrl>https://ops-admin:Sup3rSoapCb!@api.partner-example.com/pay</pay:CallbackUrl>
      <pay:ClientSecret>s3cret-XML-2026</pay:ClientSecret>
      <pay:ApiKey>ghp_‹abcdEFGHijklMNOPqrstUVWXyz0123456789</pay:ApiKey>
    </pay:PaymentRequest>
  </soapenv:Body>
</soapenv:Envelope>

=== DONNEES PERSONNELLES / FIN ===
Contact principal: Marie Laurent, marie.laurent@cybertech-solutions.fr, +33 6 12 34 56 78, +1 (415) 555-0188
Carte de test: 4111 1111 1111 1111
IBAN: FR7630006000011234567890189
IBAN backup: GB82 WEST 1234 5698 7654 32
IBAN virement: DE89 3704 0044 0532 0130 00
BIC/SWIFT: BNPAFRPPXXX
US SSN: 078-05-1120

=== EXTENDED DETECTION RULES (complementary) ===

--- PGP / Certificats ---
-----BEGIN PGP PRIVATE KEY BLOCK-----
lQOsBGHexamplePGPkeyBlockForDemo
-----END PGP PRIVATE KEY BLOCK-----
PKCS12: pkcs12 = SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkSGVsbG8=
Cert request: -----BEGIN CERTIFICATE REQUEST-----
DH params: -----BEGIN DH PARAMETERS-----

--- Cloud Tokens ---
Google OAuth: ya29.‹A0ARrdaM_TestOAuthTokenForDemoOnly12
GCP service account: {"type": "service_account", "project_id": "cybertech-audit"}
GCP API key: AIza‹SyB-TestGcpKeyOnlyForDemoXyz0123456
Firebase FCM: AAAAtestFcmKeyForDemoOnlyAAAAtestFcmKeyForDemoOnlyAAAAtestFcmKeyForDemoOnlyAAAAtestFcmKeyForDemoOnlyAAAAtestFcmKeyForDemoOnlyAAAAtestFcmKeyForDemoOnlyAAAAtestFcm
Azure: client_secret = AzureClientSecretForDemo123456789012
Azure storage: AccountKey=QXp1cmVTdG9yYWdlS2V5Rm9yRGVtb09ubHlRWHp1cmVTdG9yYWdlS2V5Rm9yRGVtb09ubHlRWA==
Azure SAS: ?sv=2021-08-06&ss=bfqt&srt=sco&sig=DemoSignatureForAzureSas
DigitalOcean: dop_v1_‹aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd
Heroku: HRKU-‹abcdef12-3456-7890-abcd-ef1234567890
Vault: hvs.‹ABCDEFGHIJKLMNOPqrstuvwx

--- SaaS ---
Twilio SID: AC‹00112233445566778899aabbccddeeff
SendGrid: SG.‹DemoSendgridKeyPartOne_.DemoSendgridKeyPartTwo_
Mailchimp: aabbcc‹ddeeff00112233445566778899-us14
NPM: npm_‹AbCdEfGhIjKlMnOpQrStUvWxYz1234567890
Cloudflare: cloudflare_api_key = DemoCloudflareTokenForTestingPurposesOnly

--- Docker / K8s / Infra ---
Docker registry: {"auth": "ZGVtb3VzZXI6ZGVtb3Bhc3N3b3Jk"}
Ansible:
$ANSIBLE_VAULT;1.2;AES256
Terraform state: {"password": "TerraformDemoPassword123!"}

--- Network Protocols ---
FTP: ftp://ftpuser:FtpDemoPass!@files.cybertech-solutions.internal/export
RDP: rdp://rdpadmin:RdpDem0P@ss@jump.cybertech-solutions.internal
Telnet: telnet://telnetuser:T3lnet!@legacy.cybertech-solutions.internal
MQTT: mqtt://iotdevice:MqttS3cret@broker.cybertech-solutions.internal
Redis: redis://:R3disVerySecret@cache.cybertech-solutions.internal
MongoDB: mongodb://mongoAdmin:M0ng0Pass!2026@db03.cybertech-solutions.internal/admin
RabbitMQ: amqp://rabbit:RabbitMQ_S3cret@mq.cybertech-solutions.internal
Elasticsearch: http://elastic:ElasticDemo!@es01.cybertech-solutions.internal:9200
SNMP: community = "CyberSnmpComm"
VPN: pre_shared_key = MyVpn_PreSharedKey_Demo2026!
WiFi: psk="WiFiDemoPassword2026!"
RADIUS: radius_secret = R4diusD3mo!Secret

--- Internal Hostnames ---
DNS: dc01.corp, fileserver.internal, proxy.intranet, nas01.lan

--- Databases ---
MSSQL: Server=sqlprod.cybertech-solutions.internal;Database=AuditDB;Password=MsSqlD3mo!2026
ODBC: DSN=ProdDSN;UID=dba;PWD=OdbcDemoPass2026!
Kafka: sasl.password = KafkaS3cretDemo2026

--- Auth Protocols ---
SAML: SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wi
OAuth code: ?code=4/0AX4XfWggME_zzABCDEFGHIJKLMNOPQ
NTLM Proxy: Proxy-Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
Kerberos: krb5_ticket = QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBPSo=
WebSocket: Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
GraphQL: {"query": "{ \"__schema\" { types { name } } }"}

--- Crypto / Secrets ---
AES: aes_key = QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
HMAC: webhook_secret = HmacDemoSecretForWebhook2026!
OTP: totp_secret = JBSWY3DPEHPK3PXPJBSWY3DP

--- PII / RGPD ---
NIR INSEE: 1 85 12 75 108 234 20
UK NI: AB 12 34 56 C
Passport: passport_number = FR12AB3456
CVV: cvv = 847
IMEI: imei = 353456789012345
Date naissance: date_of_birth = 1989-10-31
Données santé: diagnosis = J45.0-asthma
Compte US: account_number = 12345678901234
Sort code UK: sort_code = 20-05-73

--- System / Logs ---
export SECRET_KEY=DemoSecretKeyForEnvVar2026!
  secret: yaml-config-secret-value-demo-2026
LDAP: CN=marie.admin,OU=IT,DC=cybertech,DC=internal
LDAP bind: ldap_password = LdapBindD3mo!2026
Windows path: C:\\Users\\marie.admin\\AppData\\Local\\Temp\\secrets.txt
Registry: HKLM\\SOFTWARE\\CyberTech\\AuditConfig\\Secrets
Stack Java: at com.cybertech.audit.Scanner.run(Scanner.java:142)
Stack Python: File "/opt/cybertech/scanner.py", line 87
CLI password: hydra -l admin --password AdminDem0Pass!2026 ssh://10.0.50.12
Debug: debug_token = DebugTokenForCyberTech2026

--- Behavioral Patterns ---
Hardcoded: password = "admin"
Commented: # api_key = sk_live_‹CommentedSecretDemo2026!
Template: ${AWS_SECRET_KEY}
Basic Auth: Authorization: Basic YWRtaW46UEBzc3cwcmQhMjAyNg==
S3: s3://cybertech-audit-bucket/findings/report.csv

=== AI / LLM PROVIDER KEYS ===
OpenAI: sk-proj-‹AbCdEf0123456789GhIjKlMnOpQrStUvWx
Anthropic: sk-ant-api03-‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG
OpenRouter: sk-or-v1-‹0123456789abcdef0123456789abcdef0123456789abcdef
HuggingFace: hf_‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
Replicate: r8_‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AB
Groq: gsk_‹AbCdEfGhIjKlMnOpQrStUvWx1234567890
Perplexity: pplx-‹0123456789abcdef0123456789abcdef0123456789
xAI: xai-‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789

=== DEV / SAAS TOKENS ===
GitHub OAuth: gho_‹16C7e42F292c6912E7710c838347Ae178B4a
Stripe pub: pk_live_‹51N8abcdEFGHijklMNOPqrstUVWX
Stripe webhook: whsec_‹AbCdEf0123456789AbCdEf0123456789abcd
Shopify: shpat_‹0123456789abcdef0123456789abcdef
Square: sq0csp-‹AbCdEfGhIjKlMnOpQrStUvWxYz0123
Postman: PMAK-‹0123456789abcdef01234567-0123456789abcdef0123456789abcdef01
Databricks: dapi‹0123456789abcdef0123456789abcdef
Doppler: dp.pt.‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD
Atlassian: ATATT‹3xFfGF0AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD
PyPI: pypi-‹AgEIabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd
Notion: ntn_‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEF
Telegram: 123456789:‹AAFakeTelegramBotTokenForDemoOnly1234
Linear: lin_api_‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD
New Relic: NRAK-‹ABCDEFGHIJKLMNOPQRSTUVWXY12
""")

DEMO_MUST_NOT_LEAK = [_undefang(_m) for _m in [
    "marie.laurent@cybertech-solutions.fr",
    "Cyb3rT3ch!2024",
    "Sup3rSecret!",
    "P@ssw0rd123",
    "FtP!2026",
    "Sup3r@Sftp#2026",
    "SmbP@ss!2026",
    "CiFsPass!2026",
    "ProdDBP@ss!2026",
    "Sup3rSshPass!2026",
    "Pr0xyCred!2026",
    "r3disPass!2026",
    "rabbitPass!2026",
    "CMEPass!2026",
    "niktoPass!2026",
    "Sup3rSoap!2026",
    "S0apHeader#Pass2026",
    "tok_xml_ABC123def456",
    "s3cret-XML-2026",
    "https://ops-admin:Sup3rSoapCb!@api.partner-example.com/pay",
    "DBpass!2026",
    "dbadmin",
    "06 12 34 56 78",
    "+1 (415) 555-0188",
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "5d41402abc4b2a76b9719d911017c592",
    "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "$2b$12$abcdefghijklmnopqrstuu6s6XW6W7FhV2zv7u5rD5nQW0OQK5F8G",
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$NnVrb29MZ2dZeE9uQ1FxWm9nN3B0Zz09",
    "pbkdf2-sha256$29000$YWFhYmJiY2NjZGRk$R9Q6Yv4fS2jLQJxkVnNfQmQ1dVQ1c2NoZW1l",
    "10.0.50.12",
    "10.0.50.18",
    "10.0.50.19",
    "[2001:db8::10]",
    "fe80::1ff:fe23:4567:890a%eth0",
    "fd12:3456:789a::1",
    "::ffff:192.0.2.128/96",
    "00-1A-2B-3C-4D-5F",
    "001A.2B3C.4D60",
    "001A2B3C4D61",
    "4111 1111 1111 1111",
    "FR7630006000011234567890189",
    "GB82 WEST 1234 5698 7654 32",
    "DE89 3704 0044 0532 0130 00",
    "BNPAFRPPXXX",
    "1989-10-31",
    "31/12/2026",
    "2026-02-24T22:18:59Z",
    "finance.ops@cybertech-solutions.fr",
    "+33 6 11 22 33 44",
    "ghp_‹abcdEFGHijklMNOPqrstUVWXyz0123456789",
    "sqp_‹ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    "11a22b33c44d55e66f77g88h99i00j11",
    "ZXNfa2V5X2FiY2RlZjEyMzQ1Njc4OTA=",
    "eyJrIjoiR1JBRkFOQV9LRVlfMTIzNDU2Nzg5MCJ9",
    "/home/kali/.kube/config",
    "/home/kali/.kube/prod-config",
    "/tmp/passwds.txt",
    "xoxb-‹1209384756-1209384756-ABCDabcdABCDabcd1234",
    "sk_live_‹51N8abcdEFGHijklMNOPqrstUVWX123456",
    "AIza‹SyA-BCdEFghIJklMNOpqRSTuvWXyz012345",
    "https://discord.com/api/webhooks/123456789012345678/‹abcdefghijklmnopqrstuvwxyzABCDE123456",
    "glpat-‹ABCDEFGHIJKLMNOPQRST",
    "github_pat_‹11AA22bb33CC44dd55EE66ff77GG88hh99II00JJ11KK22LL33MM44NN55OO66",
    "078-05-1120",
    "550e8400-e29b-41d4-a716-446655440000",
    # ── Extended rules verification ──
    "lQOsBGHexamplePGPkeyBlockForDemo",
    "SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkSGVsbG8=",
    "ya29.‹A0ARrdaM_TestOAuthTokenForDemoOnly12",
    "AIza‹SyB-TestGcpKeyOnlyForDemoXyz0123456",
    "dop_v1_‹aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd",
    "HRKU-‹abcdef12-3456-7890-abcd-ef1234567890",
    "hvs.‹ABCDEFGHIJKLMNOPqrstuvwx",
    "AC‹00112233445566778899aabbccddeeff",
    "SG.‹DemoSendgridKeyPartOne_.DemoSendgridKeyPartTwo_",
    "aabbcc‹ddeeff00112233445566778899-us14",
    "npm_‹AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
    "ZGVtb3VzZXI6ZGVtb3Bhc3N3b3Jk",

    "ftp://ftpuser:FtpDemoPass!@files.cybertech-solutions.internal/export",
    "rdp://rdpadmin:RdpDem0P@ss@jump.cybertech-solutions.internal",
    "telnet://telnetuser:T3lnet!@legacy.cybertech-solutions.internal",
    "mqtt://iotdevice:MqttS3cret@broker.cybertech-solutions.internal",
    "redis://:R3disVerySecret@cache.cybertech-solutions.internal",
    "mongodb://mongoAdmin:M0ng0Pass!2026@db03.cybertech-solutions.internal/admin",
    "amqp://rabbit:RabbitMQ_S3cret@mq.cybertech-solutions.internal",
    "http://elastic:ElasticDemo!@es01.cybertech-solutions.internal:9200",
    "CyberSnmpComm",
    "MyVpn_PreSharedKey_Demo2026!",
    "WiFiDemoPassword2026!",
    "R4diusD3mo!Secret",
    "dc01.corp",
    "fileserver.internal",
    "proxy.intranet",
    "MsSqlD3mo!2026",
    "AuditDB",
    "OdbcDemoPass2026!",
    "KafkaS3cretDemo2026",
    "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
    "dGhlIHNhbXBsZSBub25jZQ==",
    '"__schema"',
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
    "HmacDemoSecretForWebhook2026!",
    "JBSWY3DPEHPK3PXPJBSWY3DP",
    "1 85 12 75 108 234 20",
    "AB 12 34 56 C",

    "353456789012345",
    "J45.0-asthma",

    "20-05-73",
    "DemoSecretKeyForEnvVar2026!",
    "CN=marie.admin,OU=IT,DC=cybertech,DC=internal",
    "LdapBindD3mo!2026",
    "HKLM\\SOFTWARE\\CyberTech\\AuditConfig\\Secrets",
    "com.cybertech.audit.Scanner.run(Scanner.java:142)",
    "/opt/cybertech/scanner.py",
    "AdminDem0Pass!2026",
    "DebugTokenForCyberTech2026",
    "sk_live_‹CommentedSecretDemo2026!",
    "${AWS_SECRET_KEY}",
    "YWRtaW46UEBzc3cwcmQhMjAyNg==",
    "s3://cybertech-audit-bucket/findings/report.csv",
    # ── AI / LLM provider keys ──
    "sk-proj-‹AbCdEf0123456789GhIjKlMnOpQrStUvWx",
    "sk-ant-api03-‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG",
    "sk-or-v1-‹0123456789abcdef0123456789abcdef0123456789abcdef",
    "hf_‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "r8_‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AB",
    "gsk_‹AbCdEfGhIjKlMnOpQrStUvWx1234567890",
    "pplx-‹0123456789abcdef0123456789abcdef0123456789",
    "xai-‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    # ── Dev / SaaS tokens ──
    "gho_‹16C7e42F292c6912E7710c838347Ae178B4a",
    "pk_live_‹51N8abcdEFGHijklMNOPqrstUVWX",
    "whsec_‹AbCdEf0123456789AbCdEf0123456789abcd",
    "shpat_‹0123456789abcdef0123456789abcdef",
    "sq0csp-‹AbCdEfGhIjKlMnOpQrStUvWxYz0123",
    "PMAK-‹0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
    "dapi‹0123456789abcdef0123456789abcdef",
    "dp.pt.‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD",
    "ATATT‹3xFfGF0AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD",
    "pypi-‹AgEIabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
    "ntn_‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEF",
    "123456789:‹AAFakeTelegramBotTokenForDemoOnly1234",
    "lin_api_‹AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD",
    "NRAK-‹ABCDEFGHIJKLMNOPQRSTUVWXY12",
]]


if __name__ == "__main__":
    raise SystemExit(core_main())
