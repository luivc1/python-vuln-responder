---
name: pyvr-fix
description: Fix vulnerable PyPI packages safely across environments and projects (upgrade Pillow to 13.0.0; Brotli to 1.2.1 and brotlicffi to 1.2.1.0 for HTTP2Shell) - per-venv upgrades, system/distro Pythons, conda, Docker images, requirements and lockfile re-locks, and Python 3.10 apps that cannot take the fix (upgrade path plus interim mitigations). Use for "fix Pillow", "upgrade Pillow in all venvs", "we're stuck on Python 3.10", "arreglar Pillow", "actualizar los lockfiles".
---

# Fix (changes systems: approval required at every step)

Follow **pyvr-navigator** rules: show each command, wait for a yes, never disable TLS
verification, never test with exploit files.

## 1. Start from the fix plan

`pyvuln-scan.py` writes `<out>-fix-plan.md` with exact commands per environment and a
checklist per project. Walk it in order. `references/playbooks.md` covers each
platform, BLOCKED Pythons and rollback.

## 2. Order

1. **Prerequisite:** where the scan warns pip < 26.2.2, upgrade pip safely first with
   python-cert-responder (`pycert-scan.py --python <env>` then its checksum-verified bootstrap).
2. **Environments (AFFECTED):** `<PY> -m pip install --upgrade "pillow>=13.0.0"`, then
   `<PY> -m pip check`. Record the old version for rollback.
3. **Projects:** bump pins and ranges to `>=13.0.0`, then re-lock with the right tool
   (`RELOCK` in the advisory: uv, poetry, pip-compile, pdm). Commit lock and manifest together.
4. **Dockerfiles:** move `FROM python:3.10` to 3.11 or newer where Pillow is used; bump
   pins; rebuild with `--pull`; redeploy.
5. **BLOCKED (Python 3.10):** plan the Python upgrade (playbooks > BLOCKED). Until it
   ships, apply the interim mitigations and record an owner and date.
6. **HTTP2Shell (Brotli):** `<PY> -m pip install --upgrade "Brotli>=1.2.1"` (and
   `"brotlicffi>=1.2.1.0"`); add `Brotli>=1.2.1` as a constraint wherever
   `urllib3[brotli]`, `httpx[brotli]` or `aiohttp[speedups]` is declared; OS copies via
   `apt`/`dnf`. Where Brotli is optional, uninstalling it is a valid fix (playbooks).
7. **Risk reducers, any time:** remove Ghostscript where EPS is not needed; uninstall
   `olefile` where FlashPix is not needed (only with approval and after checking dependents).

## 3. After each change

Re-scan that environment or project (`--python <venv>` / `--project <dir>`). Log what
changed. Finish with **pyvr-verify-close**.

## Never

- `--trusted-host`, `verify=False`, `curl -k` to get an install through.
- `--break-system-packages` on an OS Python without the user choosing it over the distro package or a venv.
- Downloading PoC code or crafted images to prove a fix.
