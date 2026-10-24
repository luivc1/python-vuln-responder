---
name: pyvr-scan
description: Find every Python environment, lockfile, Dockerfile and code path carrying a vulnerable PyPI package (advisories - Pillow < 13.0.0; HTTP2Shell Brotli < 1.2.1 and brotlicffi < 1.2.1.0) - system Pythons, python.org/Homebrew/pyenv/conda/uv installs, all virtualenvs, requirements, pyproject, uv/poetry/pdm/Pipfile/pylock locks, environment.yml, Dockerfiles, and code that imports the package. Flags Pythons too old for the fix. Use for "scan for the Pillow flaw", "which venvs have old Pillow", "check our repos", "escanea mis proyectos de Python".
---

# Scan (read-only)

Follow **pyvr-navigator** rules. The scanner is `scripts/pyvuln-scan.py` (Python 3.8+,
stdlib only, Linux/macOS/Windows). Its probe reads package metadata inside each
interpreter and never imports third-party packages.

## Commands

| Goal | Command |
|---|---|
| This machine | `python3 "$PYVR/scripts/pyvuln-scan.py" --local -o reports/python` |
| + project venvs | add `--venvs ~/code` (finds every `pyvenv.cfg` and conda env) |
| One interpreter / venv | `--python /path/to/venv` (repeatable) |
| Repos | `--project ~/code` (requirements*.txt/*.in, pyproject incl. poetry and requires-python, uv.lock, poetry.lock, pdm.lock, pylock.toml, Pipfile.lock, environment.yml, Dockerfiles, and .py files importing the package) |
| One advisory | `--advisory advisories/pillow-2026-10.env` (default: all) |
| Every other package too | add `--osv` (sends package names and versions, nothing else, to api.osv.dev; ask first) |

Windows: `py -3 pyvuln-scan.py --local ...` in PowerShell. Outputs: `.html`, `.csv`,
`-fix-plan.md`. Exit: 0 clean, 1 warnings, 2 affected or blocked, 3 usage error.

## Read the results

| Status | Meaning | Next |
|---|---|---|
| AFFECTED | A vulnerable version is installed or pinned, and a fix exists for that Python | pyvr-fix |
| BLOCKED | The fix needs a newer Python (Pillow 13.0.0 needs >= 3.11): a 3.10 env, `requires-python` or `FROM python:3.10` | pyvr-fix > BLOCKED |
| WARN | A range allows vulnerable versions (resolution depends on the lock), an extra pulls the package in without a pin (`httpx[brotli]`, `urllib3[brotli]`, `aiohttp[speedups]`), an image's Python is too old, OSV issue with no fix, or pip < 26.2.2 (upgrade it safely first) | pyvr-fix |
| CHECK | Could not parse or probe something | Confirm manually |
| OK | Fixed version installed or required | Verify later |
| INFO | Code imports the package; hints show risky calls (thumbnail/draft, EPS, TIFF to memory) | Prioritize these apps |

Risk lines under an environment: Ghostscript present (EPS path), olefile present (FPX
path); for Brotli, the HTTP clients in that environment that decode it automatically
(urllib3/requests, aiohttp, httpx, Scrapy). Packages installed by apt/dnf are matched to
their OS package: OK when its changelog lists the advisory's `BACKPORT_CVES`, otherwise
AFFECTED with the OS update command (not pip).

## Present

Group by machine and app. P1 = AFFECTED/BLOCKED environments that process untrusted
images (INFO hints, uploads, risk lines), then other AFFECTED, then BLOCKED plans,
then WARN. Hand off to **pyvr-fix** with the generated `-fix-plan.md`.
