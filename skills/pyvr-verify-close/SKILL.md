---
name: pyvr-verify-close
description: Prove the Python package fix worked and close out - re-scan every machine, venv and project, run pip check, confirm BLOCKED items have a dated plan and mitigations, and complete the closure checklist. Use for "did the Pillow fix work", "verify all venvs are patched", "close the Pillow incident", "verificar que quedó arreglado".
---

# Verify and Close (read-only)

Follow **pyvr-navigator** rules. For many machines or client systems, let a separate
agent or person verify (the bundled `pyvr-verifier` agent in Claude Code).

## 1. Re-scan

```bash
python3 "$PYVR/scripts/pyvuln-scan.py" --local --venvs ~/code --project ~/code -o reports/after
```

| Result | Meaning | Action |
|---|---|---|
| OK everywhere, exit 0 | Fixed version installed or required | Done |
| AFFECTED left | Missed environment, stale lock or image | Back to pyvr-fix |
| BLOCKED left | Python too old for the fix | Accept only with a dated upgrade plan and mitigations |
| WARN range | A manifest still allows vulnerable versions | Tighten to `>=13.0.0` so future resolves cannot regress |

Also run `<PY> -m pip check` in each fixed environment and the app's tests.

## 2. Closure checklist

- [ ] Every machine scanned (laptops, servers, CI runners), no AFFECTED left
- [ ] Every repo scanned with `--project`; manifests require the fixed version and locks re-locked
- [ ] Dockerfiles on Python >= 3.11 where the package is used; images rebuilt with `--pull` and redeployed
- [ ] BLOCKED items: owner, upgrade date, mitigations applied
- [ ] Ghostscript removed (or justified) on hosts that process untrusted images
- [ ] `pip check` and app tests pass after upgrades
- [ ] Colleagues/clients informed (pyvr-comms)

## 3. Summary

Scope (machines, environments, projects), what was fixed and when, re-scan evidence,
open items with owners and dates.
