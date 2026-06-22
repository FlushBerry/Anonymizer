# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AnonymizerGPT is a pentest-oriented anonymizer: it detects and replaces sensitive data (IPs, credentials, tokens, URLs, PII, keys…) with deterministic fake values **before** text is sent to an LLM, then de-anonymizes the LLM's reply using a per-project concordance table. Comments, docstrings, and UI strings are in **French** — match that when editing.

## Commands

A checked-in virtualenv historically lives at the repo root (`bin/`, `lib/`, `include/`, `pyvenv.cfg`, Python 3.13). The recommended setup is now `./install.sh`, which installs the OCR/clipboard system packages (tesseract, xclip, wl-clipboard, python3-tk) **and** creates `.venv` with the pip deps. Activate before running anything:

```bash
./install.sh                 # full setup (apt deps + .venv + pip)
source .venv/bin/activate    # or: source bin/activate (legacy root venv)
```

- **GUI:** `python3 proxy_gui.py` (thin launcher → `gui/` package)
- **Core engine (stdin/`.txt` → stdout, "prep for AI"):**
  `echo "Serveur 10.0.50.12" | python3 anonymizer_core.py --mode anonymize --project audit1 --pretty`
  `python3 anonymizer_core.py --mode anonymize --project audit1 --input-file r.txt --prompt` (wraps output in an AI instruction header via `build_ai_prompt`)
  `echo "Serveur 198.18.0.12" | python3 anonymizer_core.py --mode deanonymize --project audit1`
- **Demo / pipeline CLI (anonymize → mock AI → de-anonymize):** `python3 demo.py --demo --pretty`

### Tests / regression check

There is **no formal test suite and no linter config**. The de-facto regression harness is the built-in demo corpus (`DEMO_QUERY`) checked against `DEMO_MUST_NOT_LEAK` (both in `anonymizer_core.py`):

```bash
python3 demo.py --demo --verify-demo      # exits 1 + lists leaks if any raw secret survives anonymization
```

**Run this after any change to detection patterns or the candidate pipeline.** When you add a detection rule, add a representative sample to `DEMO_QUERY` and its raw secret to `DEMO_MUST_NOT_LEAK` so the leak check covers it.

A headless GUI smoke test (build window + anonymize + word lists) can be run under `xvfb-run -a python3 <script>` with `PYTHONPATH` set to the repo root.

## Architecture

Everything routes through the `Anonymizer` class in `anonymizer_core.py` (~2500 lines, the only real engine). `demo.py` and the `gui/` package are thin front-ends over it. The former pentest bridge has been folded into the core as a single helper, `build_ai_prompt()` (text/`.txt` → anonymized text wrapped as an AI-ready prompt); there is no separate execution/runner module.

### Detection pipeline (the core algorithm)

`anonymize(text)` → `_collect_candidates()` → `_apply_candidates()` → per-entity `_get_or_create()`.

1. **Collect** — every detector and specialized collector emits `Candidate(original, entity_type, start, end, priority)` objects. Sources: the regex `self.detectors` table, plus hand-written collectors for HTTP URLs, custom words, URL credentials, key=value secrets, CLI tool credentials (hydra/nikto/proxy-cred), XML/SOAP, and IPv6. Many candidates overlap on purpose.
2. **Resolve conflicts** — `_apply_candidates()` sorts by `(-priority, -length, start)` and greedily keeps non-overlapping candidates (`_overlaps`). **Priority is everything**: a higher-priority detector wins the same span. Priority bands are documented at the top of `detection_rules.py` (100 = keys/certs down to 52–60 = dates/domains/stack traces).
3. **Substitute** — replacements are applied **right-to-left** (reversed by offset) so earlier offsets stay valid. `_get_or_create()` produces the fake value and records `mappings`/`reverse`/`types`.

`deanonymize(text)` is the inverse: replace each anonymized token with its original, **longest-first** to avoid prefix collisions. There is no re-detection on the way back — it's pure table lookup.

`anonymize()` deliberately runs **a single pass** (`max_passes` is ignored) and `_looks_already_anonymized()` skips fake-looking values, so re-anonymizing already-anonymized text is idempotent. Preserve this property.

### Two-tier rule system (extension point)

- **24 core detectors** are built inline in `Anonymizer._compile_patterns()` as `{pattern, group, priority}` dicts, with fake generators in `self.fake_generators`. These stay in the core because they're coupled to structural validators (`_is_valid_iban/ip/mac`) and special collectors (`_collect_*`).
- **~109 extended rules** live in `detection_rules.py` as `EXTENDED_RULES` (tuples `(type, regex, group, priority)`) + `EXTENDED_FAKES` (`{type: lambda n: ...}`), organized by category (keys/certs, cloud, SaaS, **AI/LLM provider keys** — OpenAI/Anthropic/HuggingFace/…, **modern dev tokens** — GitHub/Stripe/Shopify/Telegram/…, network, DB, auth protocols, PII, system, behavioral). They are imported at compile time and merged in; if the file is missing, the engine silently falls back to core-only (`except ImportError`). This is **the** file to extend.

**To add a detection:** append a tuple to `EXTENDED_RULES` and (optionally) a generator to `EXTENDED_FAKES`. Don't add new detectors inline in the core unless they need custom collector logic.

### Determinism & consistency (why fakes look structured)

The same original always maps to the same fake **within a project**, and structurally-related values stay related:

- **IPs** (`_anonymize_ipv4/6`) map into `198.18.0.0/15` / `2001:db8::/…`, preserving network grouping via `ip_network_map` and keeping the host octet.
- **Domains** (`_anonymize_domain`) map roots to `test.local`, `test2.local`, … and subdomains to `hostN.<root>` via `domain_root_map` / `domain_fqdn_map`.
- **Custom blacklist words** use "families": every case/leet/separator variant of a seed word collapses to one alias (`[ANON_CUSTOM_<familyId>]`) via `custom_variant_family` / `custom_family_*`.
- **Format-preserving** types (passwords, tokens, cookies, hashes, dates…) run through `_preserve_value_format` / `_anonymize_date_like` so the fake keeps the shape of the original.
- `domain/email/ip/iban/bic/mac` match **case-insensitively** when reusing an existing mapping.
- IBAN/BIC/MAC/IP candidates are structurally **validated** (`_is_valid_*`) before being accepted, so regex false positives are dropped.

### Whitelist / blacklist

`whitelist_words` + `DEFAULT_CONFIG_WHITELIST` + `NON_SENSITIVE_WORDS` are checked in `_append_candidate` / `_is_whitelisted_*` to suppress detections (never anonymized). The blacklist (`custom_wordlist`) force-anonymizes arbitrary words, including substrings inside concatenated identifiers.

### Project state model

State lives in `projects/anonfile_<sanitized-name>.json` (resolved by `resolve_project_state_path`; legacy `<name>.json` is honored as a fallback). It holds the full mapping tables plus blacklist/whitelist (and, for the GUI, tabs/history). `export_state`/`import_state` serialize the engine.

**Critical invariant:** de-anonymization only works against the *same project state* used to anonymize — the mappings are the only record of what each fake means. `projects/` is gitignored.

The GUI stores its open **request tabs inside the project JSON** (via `save_project_state`'s `extra_payload={"requests": ...}`). Requests are therefore scoped to a project: loading a project restores its tabs and unloads the previous one's; a brand-new project starts with a single blank request.

### GUI (`proxy_gui.py` → `gui/` package)

`proxy_gui.py` is a thin launcher; the implementation is the modular `gui/` package:

- `theme.py` — palette/fonts/appearance (single place to re-theme).
- `widgets.py` — reusable components: `CopyableTextbox` (textbox + top-right copy icon), `HighlightView` (tk.Text with red entity highlighting), `WordRow` (word + red ✕ delete).
- `ocr.py` — standalone image→text (file + clipboard via xclip/wl-paste/PIL → tesseract).
- `topbar.py` — settings bar (project name always shown · "Lancer la démo" · "Paramètres").
- `panel_project.py` — left sidebar: project management (list/new/load/change-dir, double-click loads) + blacklist/whitelist manager (segmented toggle, scrollable `WordRow` list).
- `panel_request.py` — request tabs (CTkTabview, Burp-Repeater style, new/delete, **right-click → rename/delete** via `CTkTabview.rename` + a `tk.Menu` bound on each tab button's child widgets) + action buttons (Anonymiser / Dé-anonymiser / Import img→texte) + Ctrl+V image OCR.
- `panel_results.py` — results tabs: Anonymisée / Dé-anonymisée / Surlignée / Stats / Mapping.
- `app.py` — `App(ctk.CTk)` **is the controller**: it owns the single `Anonymizer`, builds a horizontal `tk.PanedWindow` (sidebar | right) and a nested one for requests/results (orientation is a setting — top/bottom or left/right). Theme, mono font size, and layout live in Paramètres; changing any of them calls `_apply_ui_settings()`, which **rebuilds the panels** (palettes come from `theme.set_theme()`, so a rebuild re-themes everything) while preserving the open request tabs. Auto-saves the project on every mutation and on window close.

The GUI does **not** reimplement detection; bug fixes to anonymization belong in `anonymizer_core.py`. The `demo` and `default` projects are created/loaded automatically (the demo button switches to a dedicated `demo` project so it never clobbers the user's current one).
