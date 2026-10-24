# python-vuln-responder

Find and fix every Python environment, lockfile and Docker image that still carries a
vulnerable PyPI package, with AI agents doing the legwork and a human approving every
change. Advisories included:

| Advisory | Affected | Fixed | Note |
|---|---|---|---|
| **Pillow** (October 2026) | `pillow` < 13.0.0 | 13.0.0 | Needs Python >= 3.11 (3.10 apps are BLOCKED) |
| **HTTP2Shell** (CVE-2026-111497) | `Brotli` < 1.2.1, `brotlicffi` < 1.2.1.0 | 1.2.1 / 1.2.1.0 | Reached through requests/urllib3, aiohttp, httpx, Scrapy |

> Pillow 13.0.0 fixes about 40 security issues, two rated critical: stale image storage
> after mode changes and JPEG decoder overflows, plus EPS filename injection into
> Ghostscript (command execution) and lossless-JPEG / in-memory TIFF overflows with a
> public proof of concept. Opening or saving a crafted image is enough.
> ([release notes](https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html),
> [The Hacker News](https://thehackernews.com/2026/10/critical-flaw-in-pythons-popular-pillow.html))

![Workflow](docs/workflow.svg)

## HTTP2Shell: Brotli in Python

HTTP2Shell is the Brotli decoder bug first fixed in Node.js (CVE-2026-111497, also
"Node2Shell"). PyPI's `Brotli` and `brotlicffi` bundle the same decoder. Most apps never
import them: **urllib3 (so requests, pip, botocore), aiohttp, httpx and Scrapy decode
Brotli automatically once one is installed**, so any fetch of an attacker-controlled URL
(webhooks, link previews, crawlers) or an aiohttp server receiving Brotli bodies reaches it.

| The scanner flags | Status |
|---|---|
| Brotli < 1.2.1 / brotlicffi < 1.2.1.0 in any environment, with the HTTP clients that make it reachable | AFFECTED + risk lines |
| Locks, `requirements`, Dockerfiles pinning old versions | AFFECTED |
| `urllib3[brotli]`, `httpx[brotli]`, `aiohttp[speedups]` without a Brotli pin | WARN |
| OS copies (`python3-brotli`): fixed when the distro changelog lists the CVE (Debian 12/13 yes, Ubuntu under evaluation) | OK / AFFECTED with the `apt` command |
| Code calling `brotli.decompress()` | INFO hint |

No confirmed attacks yet (not in CISA KEV as of October 24). Node.js, Bun and the
system Brotli library are covered by [node-vuln-responder](https://github.com/luivc1/node-vuln-responder).

## The catch for Pillow: Python 3.10

| | Status | What to do |
|---|---|---|
| **Pillow < 13.0.0** on Python >= 3.11 | **AFFECTED** | `pip install --upgrade "pillow>=13.0.0"`, re-lock |
| **Pillow < 13.0.0** on Python 3.10 or older | **BLOCKED**: 13.0.0 needs Python >= 3.11, no 12.x backport | Move to Python 3.11+ (3.10 reaches end of life in October 2026); interim mitigations meanwhile |
| `requires-python >=3.10` / `FROM python:3.10` with Pillow | **BLOCKED** | Raise the floor, rebuild the image |
| Ghostscript installed | Risk | EPS command-injection path is reachable |
| `olefile` installed | Risk | FlashPix decoding path is enabled |

## What the scanner does

```bash
python3 scripts/pyvuln-scan.py --local --venvs ~/code --project ~/code -o pyvuln
```

- **Finds every Python:** system, python.org, Homebrew, pyenv, conda, uv-managed,
  mise/asdf, Windows `py` launcher, plus every virtualenv and conda env under your folders.
- **Reads installed versions safely:** the probe inside each interpreter only reads
  package metadata; it never imports third-party code.
- **Projects:** requirements and `.in` files, `pyproject.toml` (PEP 621, Poetry carets,
  `requires-python`), uv / poetry / pdm / pylock / Pipfile locks, conda
  `environment.yml`, Dockerfiles (base image Python and pins), and code that imports
  the package, with hints for risky calls (`thumbnail()`/`draft()`, EPS, TIFF to memory).
- **Advisory-driven:** each `advisories/*.env` describes one package. Add a file and the
  same scanner covers the next PyPI incident.
- **Distro backports:** packages installed by apt/dnf are checked against their
  changelog, so a patched `python3-brotli` with an old version number is not a false alarm.
- **Optional `--osv`:** checks every other installed package against OSV.dev (sends
  only names and versions).
- **Fix plan:** exact upgrade commands per environment, a checklist per project,
  BLOCKED upgrade paths and mitigations.

Outputs: `.html` (color report), `.csv`, `-fix-plan.md`. Python 3.8+, standard library
only, Linux / macOS / Windows (`py -3 pyvuln-scan.py ...`).

## What's inside

| | |
|---|---|
| **Scanner** | `scripts/pyvuln-scan.py` |
| **Skills** | `pyvr-navigator` (start here), `pyvr-scan`, `pyvr-fix` (+ playbooks), `pyvr-verify-close`, `pyvr-comms` (EN/ES), `pyvr-advisory-update` |
| **Claude Code** | `/pyvr`, `/pyvr-scan`, `/pyvr-fix`, `/pyvr-verify`; `pyvr-verifier` agent; a hook that **asks before every install, re-lock or rebuild** and blocks disabling TLS verification or fetching exploit files |
| **Advisories** | `advisories/pillow-2026-10.env`, `brotli-2026-10.env`, `brotlicffi-2026-10.env`: range, fix, minimum Python, backport CVEs, risk factors, extras that pull the package in, code hints, mitigations, IDs |

## Install

```bash
# Claude Code (full plugin)
/plugin marketplace add luivc1/python-vuln-responder
/plugin install python-vuln-responder@python-vuln-responder

# Hermes, or any Agent Skills folder
./install.sh --target hermes
./install.sh --dest /path/to/skills
```

Other agents: point them at [`AGENTS.md`](AGENTS.md). Or ask: *"Are my Python apps
affected by the Pillow vulnerability?"*, *"Is my Python affected by HTTP2Shell?"* /
*"¿Mis apps de Python están afectadas por HTTP2Shell?"*

## Safety

- The scanner is read-only; every install, re-lock or rebuild is approved one step at a time.
- Fixes are verified by version, never with exploit code or crafted images.
- Only scan systems you own or are authorized to manage.

Related: if a scan warns that pip is older than 26.2.2, upgrade it safely first with
[python-cert-responder](https://github.com/luivc1/python-cert-responder). Siblings:
[php-vuln-responder](https://github.com/luivc1/php-vuln-responder) ·
[node-vuln-responder](https://github.com/luivc1/node-vuln-responder) ·
[railway-secrets-responder](https://github.com/luivc1/railway-secrets-responder)

## License

[MIT](LICENSE) © 2026 Innovatask LLC
