# Fix playbooks

Versions come from the advisory file. `<PY>` = the environment's python. Pillow
13.0.0 requires Python >= 3.11.

## Per environment

| Kind | Steps |
|---|---|
| **venv / virtualenv** | `<PY> -m pip install --upgrade "pillow>=13.0.0"` then `<PY> -m pip check`. Rollback: `<PY> -m pip install "pillow==<old>"` |
| **uv-managed project** | `uv lock --upgrade-package pillow` then `uv sync` |
| **Poetry** | Widen the constraint (a `^12.x` caret blocks 13): `poetry add "pillow>=13.0.0"` or edit and `poetry update pillow` |
| **pip-tools** | Bump the `.in` line, `pip-compile --upgrade-package pillow`, `pip-sync` |
| **PDM** | `pdm update pillow` |
| **Pipenv** | `pipenv update pillow` |
| **conda / mamba** | `conda install -n <env> -c conda-forge "pillow>=13.0.0"` (needs a python >= 3.11 env) |
| **pipx / uv tools** | `pipx upgrade <app>` / `uv tool upgrade <app>` once the app allows Pillow 13 |
| **OS Python (Debian/Ubuntu `python3-pil`, Fedora `python3-pillow`)** | Prefer the distro security update (`apt`/`dnf`). Distros may backport fixes without changing the major version: confirm in the distro's security tracker and mark the finding as a documented exception. Do not `pip install --break-system-packages` unless the user chooses it; moving the app into a venv is better |
| **Windows (python.org)** | `py -3.x -m pip install --upgrade "pillow>=13.0.0"` per version (`py -0p` lists them) |

## Containers and CI

- `FROM python:3.10*` images that use Pillow are BLOCKED: move to `python:3.12-slim`
  (or 3.11+), rebuild with `--pull`, run the test suite, redeploy.
- Pin in the image's requirements, not only in a `RUN pip install` line.
- CI caches: clear pip/uv caches or bump cache keys so old wheels are not reused.

## BLOCKED: Python 3.10 (or older)

Python 3.10 reaches end of life in October 2026, so this is the moment to move. In order:

1. **Upgrade the app's Python** to 3.12 or 3.13 (or at least 3.11): update
   `requires-python`, the Dockerfile base, CI matrix and runtime; re-lock; run tests.
2. **Split image handling** into a small service or worker on Python >= 3.11 if the whole
   app cannot move yet.
3. **Interim mitigations** (reduce risk, do not fix it), from the advisory:
   - Remove Ghostscript (`gs`) from hosts that process untrusted images.
   - Never pass user-controlled filenames to `Image.open()`; open file objects.
   - Restrict formats: `Image.open(fp, formats=["PNG", "JPEG", "WEBP"])`.
   - Avoid `draft()`/`thumbnail()` on untrusted JPEGs (call `load()` first or pass `reducing_gap=None`).
   - Treat saving user images as TIFF to `io.BytesIO` as sensitive.
   - Enforce size limits before decoding (`Image.MAX_IMAGE_PIXELS`, upload size caps) and
     run image processing in an isolated, low-privilege worker.
4. Record the exception: owner, date, mitigations applied, re-scan evidence.

## Rollback

Every upgrade records the previous version in the fix log. Roll back with
`<PY> -m pip install "pillow==<old>"` (or revert the lockfile commit) only if the
upgrade breaks the app, and treat the rollback as an open incident item.
