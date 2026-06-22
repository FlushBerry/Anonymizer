# Copyright (C) 2026 FlushBerry
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
detection_rules.py — Extended detection rules for AnonymizerGPT
═══════════════════════════════════════════════════════════════

This file defines complementary regex-based detection rules and their
associated fake-value generators.  It is imported by anonymizer_core.py
at pattern-compilation time.

To add a new rule:
  1. Append a tuple to EXTENDED_RULES:
         ("type_name", r'regex_pattern', capture_group, priority)
  2. Optionally add a matching entry in EXTENDED_FAKES:
         "type_name": lambda n: f"[REDACTED_TYPE_{n}]"
     (if omitted, the default [REDACTED_{n}] generator is used)

Priority guide (higher = matched first):
  100  Keys / certificates
  93-97  Cloud tokens, SaaS keys, AI/LLM provider keys
  89-92  Auth protocols, infra, dev/SaaS tokens
  85-88  Secrets, databases, system
  80-84  PII / RGPD
  60-79  Informational (stack traces, hostnames, LDAP)
"""

from __future__ import annotations

from typing import Callable

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Each tuple: (entity_type, regex_pattern, capture_group, priority)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXTENDED_RULES: list[tuple[str, str, int, int]] = [

    # ── Keys & Certificates ──────────────────────────────────
    ("pgp_private_key",      r'-----BEGIN PGP (?:PRIVATE|SECRET) KEY BLOCK-----[\s\S]+?-----END PGP (?:PRIVATE|SECRET) KEY BLOCK-----', 0, 100),
    ("pkcs12_base64",        r'(?:pkcs12|\.pfx|\.p12)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}', 0, 97),
    ("certificate_request",  r'-----BEGIN CERTIFICATE REQUEST-----', 0, 99),
    ("dh_parameters",        r'-----BEGIN DH PARAMETERS-----', 0, 99),

    # ── Cloud Tokens ─────────────────────────────────────────
    ("google_oauth_token",   r'\bya29\.[A-Za-z0-9_\-]{30,}', 0, 93),
    ("gcp_service_account",  r'"type"\s*:\s*"service_account"', 0, 93),
    ("gcp_api_key",          r'\bAIzaSy[A-Za-z0-9_\-]{33}\b', 0, 93),
    ("firebase_fcm_key",     r'\bAAAA[A-Za-z0-9_\-]{100,}(?![A-Za-z0-9_\-])', 0, 93),
    ("azure_client_secret",  r'client[_\-]?secret\s*[=:]\s*[A-Za-z0-9~._\-]{30,}', 0, 93),
    ("azure_storage_key",    r'AccountKey\s*=\s*[A-Za-z0-9+/]{40,}={0,2}', 0, 93),
    ("azure_sas_token",      r'\?sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&[^&\s]+(?:sig=)[^&\s]+', 0, 93),
    ("digitalocean_token",   r'\bdop_v1_[a-f0-9]{64}\b', 0, 93),
    ("heroku_api_key",       r'\bHRKU-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 0, 93),
    ("vault_token",          r'\b(?:hvs|hvb|hvr)\.[A-Za-z0-9]{24,}\b', 0, 93),

    # ── SaaS Services ────────────────────────────────────────
    ("twilio_key",           r'\b(?:AC|SK)[0-9a-f]{32}\b', 0, 93),
    ("sendgrid_key",         r'\bSG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}\b', 0, 93),
    ("mailchimp_key",        r'\b[0-9a-f]{32}-us[0-9]{1,2}\b', 0, 93),
    ("npm_token",            r'\bnpm_[A-Za-z0-9]{36}\b', 0, 93),
    ("cloudflare_key",       r'cloudflare[_\-]?(?:api[_\-]?)?(?:key|token)\s*[=:]\s*[A-Za-z0-9_\-]{35,}', 0, 93),

    # ── Docker / K8s / Infra ─────────────────────────────────
    ("docker_registry_auth", r'"auth"\s*:\s*"[A-Za-z0-9+/]{20,}={0,2}"', 0, 91),
    ("k8s_service_token",    r'(?:token|bearer)\s*[=:]\s*eyJ[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', 0, 91),
    ("ansible_vault",        r'^\$ANSIBLE_VAULT;[0-9]+\.[0-9]+;AES256', 0, 91),
    ("terraform_state_secret", r'"(?:password|secret_key|private_key|access_key)"\s*:\s*"[^"]{8,}"', 0, 90),

    # ── Network & Protocols ──────────────────────────────────
    ("ftp_creds_url",        r'\bftps?://[^:@\s]+:[^@\s]+@[^\s]+', 0, 89),
    ("rdp_creds_url",        r'\brdp://[^:@\s]+:[^@\s]+@[^\s]+', 0, 89),
    ("telnet_creds_url",     r'\btelnet://[^:@\s]+:[^@\s]+@[^\s]+', 0, 89),
    ("mqtt_creds_url",       r'\bmqtts?://[^:@\s]+:[^@\s]+@[^\s]+', 0, 89),
    ("redis_creds_url",      r'\brediss?://:[^@\s]{4,}@[^\s]+', 0, 89),
    ("mongodb_creds_url",    r'\bmongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@[^\s]+', 0, 89),
    ("rabbitmq_creds_url",   r'\bamqps?://[^:@\s]+:[^@\s]+@[^\s]+', 0, 89),
    ("elasticsearch_creds",  r'\bhttps?://[^:@\s]+:[^@\s]+@[^\s]+:(?:9200|9300)\b', 0, 88),
    ("snmp_community",       r'community\s*[=:]\s*"?(?:public|private|[A-Za-z0-9!@#$%]{6,})"?', 0, 87),
    ("vpn_psk",              r'(?:pre[_\-]?shared[_\-]?key|ipsec[_\-]?psk)\s*[=:]\s*\S{8,}', 0, 87),
    ("wifi_psk",             r'psk\s*=\s*"[^"]{8,}"', 0, 87),
    ("radius_secret",        r'(?:radius[_\-]?secret|shared[_\-]?secret)\s*[=:]\s*\S{6,}', 0, 87),
    ("hostname_internal",    r'\b[a-z0-9][a-z0-9\-]{1,30}\.(?:local|internal|corp|intranet|lan|priv|infra)\b', 0, 58),

    # ── Databases ────────────────────────────────────────────
    ("mssql_connection_string", r'(?:Server|Data Source)\s*=\s*[^;]+;[^;]*?(?:Password|PWD)\s*=\s*[^;]{4,}', 0, 88),
    ("mssql_database_name",    r'(?:Server|Data Source)\s*=\s*[^;]+;[^;]*?Database\s*=\s*([^;]{2,})', 1, 87),
    ("odbc_dsn_password",    r'DSN\s*=\s*[^;]+;[^;]*?(?:PWD|Password)\s*=\s*[^;]{4,}', 0, 88),
    ("kafka_sasl_password",  r'sasl\.(?:password|jaas\.config)\s*[=:]\s*\S{4,}', 0, 88),

    # ── Auth Protocols ───────────────────────────────────────
    ("saml_response",        r'SAMLResponse\s*=\s*[A-Za-z0-9+/]{60,}={0,2}', 0, 92),
    ("oauth_code",           r'[?&]code=[A-Za-z0-9/_\-]{20,}(?:&|$)', 0, 89),
    ("ntlm_auth_blob",       r'(?:Proxy-)?Authorization:\s*NTLM\s+TlRMTVNT[A-Za-z0-9+/]+', 0, 95),
    ("kerberos_ticket",      r'(?:krb5?[_\-]?ticket|tgt|tgs)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}', 0, 91),
    ("websocket_key",        r'Sec-WebSocket-Key\s*:\s*[A-Za-z0-9+/=]{22,}', 0, 85),
    ("graphql_introspection", r'(?:"__schema"|IntrospectionQuery)', 0, 78),

    # ── Crypto & Generic Secrets ─────────────────────────────
    ("encryption_key",       r'(?:aes[_\-]?key|encryption[_\-]?key|cipher[_\-]?key)\s*[=:]\s*([A-Za-z0-9+/]{24,}={0,2})', 1, 89),
    ("hmac_signing_secret",  r'(?:webhook[_\-]?secret|hmac[_\-]?secret|signing[_\-]?secret)\s*[=:]\s*\S{20,}', 0, 89),
    ("crypto_key_hex",       r'(?:secret|key|token|seed)\s*[=:]\s*[0-9a-fA-F]{64}\b', 0, 88),
    ("base64_secret_field",  r'(?:secret|credential|private[_\-]?key)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}', 0, 87),

    # ── PII / RGPD ───────────────────────────────────────────
    ("french_insee_nir",     r'\b[12]\s?[0-9]{2}\s?(?:0[1-9]|1[0-2]|20)\s?(?:0[1-9]|[1-8][0-9]|9[0-5]|2[AB])\s?[0-9]{3}\s?[0-9]{3}\s?[0-9]{2}\b', 0, 83),
    ("uk_ni_number",         r'\b[A-CEGHJ-PR-TW-Z]{2}\s?[0-9]{2}\s?[0-9]{2}\s?[0-9]{2}\s?[ABCD]\b', 0, 83),
    ("passport_number",      r'passport[_\-]?(?:num(?:ber)?|no)\s*[=:]\s*([A-Z0-9]{6,12})', 1, 83),
    ("cvv_cvc",              r'(?:cvv2?|cvc2?|security[_\-]?code)\s*[=:]\s*[0-9]{3,4}\b', 0, 84),
    ("imei_number",          r'imei\s*[=:]\s*[0-9]{15}\b', 0, 83),
    ("dob_birthdate",        r'(?:birth[_\-]?(?:date|day)|dob|date[_\-]?of[_\-]?birth)\s*[=:]\s*[0-9]{2,4}[\-/][0-9]{2}[\-/][0-9]{2,4}', 0, 83),
    ("health_data",          r'(?:diagnosis|icd[_\-]?10|icd[_\-]?9|patient[_\-]?id|medical[_\-]?record)\s*[=:]\s*[^\s,]{2,}', 0, 82),
    ("bank_account_us",      r'(?:account[_\-]?num(?:ber)?|routing[_\-]?num(?:ber)?)\s*[=:]\s*[0-9]{8,17}', 0, 83),
    ("uk_sort_code",         r'sort[_\-]?code\s*[=:]\s*[0-9]{2}-[0-9]{2}-[0-9]{2}', 0, 83),
    ("french_address",       r'\b[0-9]{1,4}\s+(?:(?:bis|ter|quater)\s+)?(?:rue|avenue|boulevard|impasse|chemin|all[eé]e|place)\s+[A-Za-z\u00C0-\u017F\s\-]{5,40}\s+[0-9]{5}\b', 0, 82),

    # ── System / Logs / Config ───────────────────────────────
    ("env_var_secret",       r'^(?:export\s+)?(?:API_KEY|SECRET_KEY|AWS_SECRET|PRIVATE_KEY|DB_PASSWORD|MASTER_KEY)\s*=\s*[^\s$]{6,}', 0, 85),
    ("config_secret_yaml",   r'^\s*(?:secret|credential|api[_\-]?key|private[_\-]?key|master[_\-]?key)\s*:\s*[^\s{$][^\n]{5,}', 0, 84),
    ("ldap_dn",              r'(?:CN|OU)=[^,\s]{2,}(?:,(?:CN|OU|DC)=[^,\s]{2,}){2,}', 0, 90),
    ("ldap_bind_password",   r'(?:bind[_\-]?password|bind[_\-]?passwd|ldap[_\-]?password)\s*[=:]\s*\S{4,}', 0, 85),
    ("windows_path_sensitive", r"[A-Za-z]:\\(?:Users|inetpub|AppData)\\[^\s\"']{5,}", 0, 65),
    ("registry_key",         r'HK(?:LM|CU|CR)\\(?:SOFTWARE|SYSTEM|SAM)\\[A-Za-z0-9\\_\s\-]{5,}', 0, 65),
    ("stack_trace_java",     r'at\s+[a-zA-Z0-9$.]+\([A-Za-z]+\.java:[0-9]+\)', 0, 60),
    ("stack_trace_python",   r'File "[^"]+\.py", line [0-9]+', 0, 60),
    ("cli_password_arg",     r'\s--(?:password|passwd|pass)\s*[=\s]\s*[^\s\-][^\s]{3,}', 0, 86),
    ("otp_totp_secret",      r'(?:totp|otp|2fa)[_\-]?(?:secret|seed|key)\s*[=:]\s*[A-Z2-7]{16,}', 0, 88),
    ("debug_token",          r'(?:x[_\-]?debug[_\-]?token|debug[_\-]?token)\s*[=:]\s*[A-Za-z0-9]{10,}', 0, 85),

    # ── Behavioral Patterns ──────────────────────────────────
    ("hardcoded_default_creds", r'(?:password|passwd|pass)\s*[=:]\s*"?(?:admin|root|test|guest|123456|password|changeme|default|P@ssw0rd)"?\s*$', 0, 85),
    ("commented_secret",     r'^\s*(?:#|//|/\*|<!--)\s*(?:password|secret|api[_\-]?key|token|private[_\-]?key)\s*[=:]\s*[^\s]{4,}', 0, 83),
    ("template_unresolved",  r'(?:\$\{[A-Z_]*(?:SECRET|PASSWORD|KEY|TOKEN|PRIVATE)[A-Z_]*\}|\{\{[a-z_]*(?:secret|password|key|token)[a-z_]*\}\})', 0, 80),
    ("base64_basic_auth",    r'Authorization:\s*Basic\s+([A-Za-z0-9+/]{8,}={0,2})', 1, 95),
    ("s3_bucket_url",        r'\bs3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](?:/[^\s]*)?\b', 0, 82),

    # ── AI / LLM Provider Keys ───────────────────────────────
    # (distinct prefixes; higher priority for provider-specific over generic)
    ("anthropic_api_key",    r'\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{20,}', 0, 95),
    ("openrouter_api_key",   r'\bsk-or-v1-[A-Za-z0-9]{40,}\b', 0, 95),
    ("openai_project_key",   r'\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}', 0, 94),
    ("openai_api_key",       r'\bsk-[A-Za-z0-9]{48}\b', 0, 93),
    ("huggingface_token",    r'\bhf_[A-Za-z0-9]{34,}\b', 0, 93),
    ("replicate_token",      r'\br8_[A-Za-z0-9]{37,}\b', 0, 93),
    ("groq_api_key",         r'\bgsk_[A-Za-z0-9]{20,}\b', 0, 93),
    ("perplexity_api_key",   r'\bpplx-[A-Za-z0-9]{40,}\b', 0, 93),
    ("xai_api_key",          r'\bxai-[A-Za-z0-9]{20,}\b', 0, 93),
    ("cohere_api_key",       r'(?:cohere|co)[_\-]?api[_\-]?key\s*[=:]\s*[A-Za-z0-9]{32,}', 0, 90),
    ("llm_api_key_generic",  r'(?:openai|anthropic|mistral|gemini|llm)[_\-]?api[_\-]?key\s*[=:]\s*[A-Za-z0-9_\-]{20,}', 0, 90),

    # ── Dev / SaaS Tokens (modern) ───────────────────────────
    ("slack_webhook_url",    r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', 0, 93),
    ("github_oauth_token",   r'\bgh[ousr]_[A-Za-z0-9]{36,}\b', 0, 93),
    ("stripe_pub_restricted", r'\b(?:pk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b', 0, 92),
    ("stripe_webhook_secret", r'\bwhsec_[A-Za-z0-9]{32,}\b', 0, 92),
    ("shopify_token",        r'\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b', 0, 93),
    ("square_token",         r'\b(?:sq0atp|sq0csp)-[A-Za-z0-9_\-]{22,}\b', 0, 92),
    ("square_access_token",  r'\bEAAA[A-Za-z0-9_\-]{58,}\b', 0, 92),
    ("sentry_dsn",           r'https://[0-9a-f]{32}@[A-Za-z0-9.\-]*sentry\.io/\d+', 0, 92),
    ("newrelic_key",         r'\bNRAK-[A-Z0-9]{27}\b', 0, 92),
    ("postman_api_key",      r'\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b', 0, 93),
    ("databricks_token",     r'\bdapi[a-f0-9]{32}\b', 0, 92),
    ("doppler_token",        r'\bdp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,}\b', 0, 92),
    ("atlassian_token",      r'\bATATT3[A-Za-z0-9_\-=]{20,}', 0, 92),
    ("pypi_token",           r'\bpypi-AgEI[A-Za-z0-9_\-]{40,}', 0, 93),
    ("notion_token",         r'\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b', 0, 91),
    ("dropbox_token",        r'\bsl\.[A-Za-z0-9_\-]{60,}\b', 0, 90),
    ("mapbox_token",         r'\b(?:sk|pk)\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b', 0, 93),
    ("linear_api_key",       r'\blin_api_[A-Za-z0-9]{40,}\b', 0, 92),
    ("telegram_bot_token",   r'\b\d{8,10}:[A-Za-z0-9_\-]{32,48}\b', 0, 90),
    ("algolia_admin_key",    r'algolia[_\-]?(?:admin[_\-]?)?(?:api[_\-]?)?key\s*[=:]\s*[A-Za-z0-9]{32}\b', 0, 90),
    ("datadog_api_key",      r'(?:dd|datadog)[_\-]?(?:api|app)[_\-]?key\s*[=:]\s*[0-9a-f]{32,40}\b', 0, 90),
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Fake-value generators for each extended type.
#  Signature: (n: int) -> str
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXTENDED_FAKES: dict[str, Callable[[int], str]] = {
    "pgp_private_key":       lambda n: f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n[REDACTED_PGP_KEY_{n}]\n-----END PGP PRIVATE KEY BLOCK-----",
    "pkcs12_base64":         lambda n: f"[REDACTED_PKCS12_{n}]",
    "certificate_request":   lambda n: f"[REDACTED_CSR_{n}]",
    "dh_parameters":         lambda n: f"[REDACTED_DH_PARAMS_{n}]",
    "google_oauth_token":    lambda n: f"[REDACTED_GOOG_OAUTH_{n}]",
    "gcp_service_account":   lambda n: f"[REDACTED_GCP_SA_{n}]",
    "gcp_api_key":           lambda n: f"[REDACTED_GCP_KEY_{n}]",
    "firebase_fcm_key":      lambda n: f"[REDACTED_FCM_{n}]",
    "azure_client_secret":   lambda n: f"[REDACTED_AZURE_SECRET_{n}]",
    "azure_storage_key":     lambda n: f"[REDACTED_AZURE_STORAGE_{n}]",
    "azure_sas_token":       lambda n: f"[REDACTED_AZURE_SAS_{n}]",
    "digitalocean_token":    lambda n: f"[REDACTED_DO_TOKEN_{n}]",
    "heroku_api_key":        lambda n: f"[REDACTED_HEROKU_{n}]",
    "vault_token":           lambda n: f"[REDACTED_VAULT_{n}]",
    "twilio_key":            lambda n: f"[REDACTED_TWILIO_{n}]",
    "sendgrid_key":          lambda n: f"[REDACTED_SENDGRID_{n}]",
    "mailchimp_key":         lambda n: f"[REDACTED_MAILCHIMP_{n}]",
    "npm_token":             lambda n: f"[REDACTED_NPM_{n}]",
    "cloudflare_key":        lambda n: f"[REDACTED_CF_KEY_{n}]",
    "docker_registry_auth":  lambda n: f"[REDACTED_DOCKER_AUTH_{n}]",
    "k8s_service_token":     lambda n: f"[REDACTED_K8S_TOKEN_{n}]",
    "ansible_vault":         lambda n: f"[REDACTED_ANSIBLE_VAULT_{n}]",
    "terraform_state_secret": lambda n: f"[REDACTED_TF_SECRET_{n}]",
    "ftp_creds_url":         lambda n: f"ftp://anon{n}:REDACTED@target{n}.anon.local",
    "rdp_creds_url":         lambda n: f"rdp://anon{n}:REDACTED@target{n}.anon.local",
    "telnet_creds_url":      lambda n: f"telnet://anon{n}:REDACTED@target{n}.anon.local",
    "mqtt_creds_url":        lambda n: f"mqtt://anon{n}:REDACTED@target{n}.anon.local",
    "redis_creds_url":       lambda n: f"redis://:REDACTED@target{n}.anon.local",
    "mongodb_creds_url":     lambda n: f"mongodb://anon{n}:REDACTED@target{n}.anon.local",
    "rabbitmq_creds_url":    lambda n: f"amqp://anon{n}:REDACTED@target{n}.anon.local",
    "elasticsearch_creds":   lambda n: f"http://anon{n}:REDACTED@target{n}.anon.local:9200",
    "snmp_community":        lambda n: f"[REDACTED_SNMP_{n}]",
    "vpn_psk":               lambda n: f"[REDACTED_VPN_PSK_{n}]",
    "wifi_psk":              lambda n: f"[REDACTED_WIFI_PSK_{n}]",
    "radius_secret":         lambda n: f"[REDACTED_RADIUS_{n}]",
    "hostname_internal":     lambda n: f"host{n}.internal",
    "mssql_connection_string": lambda n: f"[REDACTED_MSSQL_CONN_{n}]",
    "mssql_database_name":   lambda n: f"[REDACTED_MSSQL_DB_{n}]",
    "odbc_dsn_password":     lambda n: f"[REDACTED_ODBC_{n}]",
    "kafka_sasl_password":   lambda n: f"[REDACTED_KAFKA_{n}]",
    "saml_response":         lambda n: f"[REDACTED_SAML_{n}]",
    "oauth_code":            lambda n: f"[REDACTED_OAUTH_CODE_{n}]",
    "ntlm_auth_blob":        lambda n: f"[REDACTED_NTLM_BLOB_{n}]",
    "kerberos_ticket":       lambda n: f"[REDACTED_KRB_TICKET_{n}]",
    "websocket_key":         lambda n: f"[REDACTED_WS_KEY_{n}]",
    "graphql_introspection": lambda n: f"[REDACTED_GQL_INTROSPECT_{n}]",
    "encryption_key":        lambda n: f"[REDACTED_ENC_KEY_{n}]",
    "hmac_signing_secret":   lambda n: f"[REDACTED_HMAC_{n}]",
    "crypto_key_hex":        lambda n: f"[REDACTED_CRYPTO_HEX_{n}]",
    "base64_secret_field":   lambda n: f"[REDACTED_B64_SECRET_{n}]",
    "french_insee_nir":      lambda n: f"1000000000000{n:02d}",
    "uk_ni_number":          lambda n: f"AA00000{n:01d}A",
    "passport_number":       lambda n: f"[REDACTED_PASSPORT_{n}]",
    "cvv_cvc":               lambda n: f"{n % 1000:03d}",
    "imei_number":           lambda n: f"[REDACTED_IMEI_{n}]",
    "dob_birthdate":         lambda n: f"2000-01-{(n % 28) + 1:02d}",
    "health_data":           lambda n: f"[REDACTED_HEALTH_{n}]",
    "bank_account_us":       lambda n: f"[REDACTED_BANK_{n}]",
    "uk_sort_code":          lambda n: f"00-00-{n:02d}",
    "french_address":        lambda n: f"{n} rue de Exemple 75000",
    "env_var_secret":        lambda n: f"[REDACTED_ENV_{n}]",
    "config_secret_yaml":    lambda n: f"[REDACTED_CFG_{n}]",
    "ldap_dn":               lambda n: f"CN=anon{n},OU=Users,DC=anon,DC=local",
    "ldap_bind_password":    lambda n: f"[REDACTED_LDAP_PASS_{n}]",
    "windows_path_sensitive": lambda n: f"C:\\Redacted\\Path{n}",
    "registry_key":          lambda n: f"HKLM\\SOFTWARE\\Redacted{n}",
    "stack_trace_java":      lambda n: f"at anon.Class{n}.method(Anon.java:{n})",
    "stack_trace_python":    lambda n: f'File "anon{n}.py", line {n}',
    "cli_password_arg":      lambda n: f"[REDACTED_CLI_PASS_{n}]",
    "otp_totp_secret":       lambda n: f"[REDACTED_OTP_{n}]",
    "debug_token":           lambda n: f"[REDACTED_DEBUG_{n}]",
    "hardcoded_default_creds": lambda n: f"[REDACTED_DEFAULT_CRED_{n}]",
    "commented_secret":      lambda n: f"[REDACTED_COMMENTED_{n}]",
    "template_unresolved":   lambda n: f"${{REDACTED_TEMPLATE_{n}}}",
    "base64_basic_auth":     lambda n: f"[REDACTED_BASIC_AUTH_{n}]",
    "s3_bucket_url":         lambda n: f"s3://redacted-bucket-{n}",
    # ── AI / LLM provider keys ──
    "anthropic_api_key":     lambda n: f"[REDACTED_ANTHROPIC_KEY_{n}]",
    "openrouter_api_key":    lambda n: f"[REDACTED_OPENROUTER_KEY_{n}]",
    "openai_project_key":    lambda n: f"[REDACTED_OPENAI_KEY_{n}]",
    "openai_api_key":        lambda n: f"[REDACTED_OPENAI_KEY_{n}]",
    "huggingface_token":     lambda n: f"[REDACTED_HF_TOKEN_{n}]",
    "replicate_token":       lambda n: f"[REDACTED_REPLICATE_{n}]",
    "groq_api_key":          lambda n: f"[REDACTED_GROQ_KEY_{n}]",
    "perplexity_api_key":    lambda n: f"[REDACTED_PPLX_KEY_{n}]",
    "xai_api_key":           lambda n: f"[REDACTED_XAI_KEY_{n}]",
    "cohere_api_key":        lambda n: f"[REDACTED_COHERE_KEY_{n}]",
    "llm_api_key_generic":   lambda n: f"[REDACTED_LLM_KEY_{n}]",
    # ── Dev / SaaS tokens ──
    "slack_webhook_url":     lambda n: f"https://hooks.slack.com/services/REDACTED/B0/{n:08d}",
    "github_oauth_token":    lambda n: f"[REDACTED_GH_TOKEN_{n}]",
    "stripe_pub_restricted": lambda n: f"[REDACTED_STRIPE_KEY_{n}]",
    "stripe_webhook_secret": lambda n: f"[REDACTED_STRIPE_WHSEC_{n}]",
    "shopify_token":         lambda n: f"[REDACTED_SHOPIFY_{n}]",
    "square_token":          lambda n: f"[REDACTED_SQUARE_{n}]",
    "square_access_token":   lambda n: f"[REDACTED_SQUARE_AT_{n}]",
    "sentry_dsn":            lambda n: f"https://REDACTED@o0.ingest.sentry.io/{n}",
    "newrelic_key":          lambda n: f"[REDACTED_NEWRELIC_{n}]",
    "postman_api_key":       lambda n: f"[REDACTED_POSTMAN_{n}]",
    "databricks_token":      lambda n: f"[REDACTED_DATABRICKS_{n}]",
    "doppler_token":         lambda n: f"[REDACTED_DOPPLER_{n}]",
    "atlassian_token":       lambda n: f"[REDACTED_ATLASSIAN_{n}]",
    "pypi_token":            lambda n: f"[REDACTED_PYPI_{n}]",
    "notion_token":          lambda n: f"[REDACTED_NOTION_{n}]",
    "dropbox_token":         lambda n: f"[REDACTED_DROPBOX_{n}]",
    "mapbox_token":          lambda n: f"[REDACTED_MAPBOX_{n}]",
    "linear_api_key":        lambda n: f"[REDACTED_LINEAR_{n}]",
    "telegram_bot_token":    lambda n: f"[REDACTED_TELEGRAM_{n}]",
    "algolia_admin_key":     lambda n: f"[REDACTED_ALGOLIA_{n}]",
    "datadog_api_key":       lambda n: f"[REDACTED_DATADOG_{n}]",
}
