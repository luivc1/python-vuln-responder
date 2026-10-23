---
name: pyvr-advisory-update
description: Refresh an advisory file behind the Python vuln scanner (new fixed versions, backports, IDs) or add a new one for any PyPI package vulnerability, so the same scanner covers the next incident. Use for "is there an update on the Pillow issue", "add an advisory for <package>", "a new PyPI vulnerability", "actualiza el advisory".
---

# Advisory Update

Every value must come from a source read in this session.

## Sources, in priority order

1. The project's own security advisories / release notes (GitHub Security Advisories, changelog)
2. PyPI release page and JSON API (versions, `requires_python`, upload dates)
3. OSV.dev / GitHub Advisory Database entries (affected ranges, IDs)
4. Distro security trackers (backports for `python3-*` packages)
5. Press coverage only for context, never for version ranges

## Steps

1. Copy `advisories/pillow-2026-10.env` to `advisories/<package>-<yyyy>-<mm>.env` (or
   update it). Fields: `ADVISORY_ID`, `ADVISORY_NAME`, `PACKAGE` (PyPI name),
   `IMPORT_NAMES` (comma-separated modules), `SEVERITY`, `PUBLISHED`, `SUMMARY`,
   `AFFECTED` (comma = AND, `|` = OR), `FIXED`, `FIX_MIN_PYTHON`, `BACKPORTS`
   (`version@minpython|...`), `RISK_BINARIES` / `RISK_PACKAGES` (`name:why|...`),
   `CODE_HINTS` (`regex => label ;; ...`), `MITIGATIONS`, `IDS`, `RELOCK`, `SOURCES`,
   `LAST_VERIFIED`.
2. Validate against real installs: create one venv with a vulnerable and one with a
   fixed version (from PyPI) and run
   `pyvuln-scan.py --advisory <file> --python <venv-old> --python <venv-new>`: expect
   AFFECTED then OK. If `FIX_MIN_PYTHON` is set, check an older Python shows BLOCKED.
3. Show the user the diff and sources. Keep old advisory files.

Never take a version range from anywhere but a primary source. Never download exploit
code or crafted samples to "validate" an advisory.
