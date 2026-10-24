#!/usr/bin/env python3
"""
pyvuln-scan  v1.0.0  (python-vuln-responder)

Find every Python environment, lockfile, requirements file and container image
that still uses a vulnerable PyPI package, across a whole machine or fleet of
repos, and print how to fix each one. Driven by advisory files (ships with
Pillow < 13.0.0, October 2026). Python 3.8+ standard library only.
Works on Linux, macOS and Windows.

USAGE
  python3 pyvuln-scan.py --local                        # this machine: Pythons + common venv homes
  python3 pyvuln-scan.py --local --venvs ~/code         # also every virtualenv/conda env under ~/code
  python3 pyvuln-scan.py --python /path/to/venv         # one interpreter or venv (repeatable)
  python3 pyvuln-scan.py --project ~/code               # requirements, pyproject, locks, conda, Dockerfiles, code hints
  python3 pyvuln-scan.py --local --osv                  # ALSO check every installed package against OSV.dev
  python3 pyvuln-scan.py --advisory advisories/x.env    # only these advisories (default: all in advisories/)
  ... -o reports/python                                 # -> .html  .csv  -fix-plan.md

  The probe inside each interpreter only reads package metadata; it never imports
  third-party packages. --osv sends package names and versions (nothing else) to
  api.osv.dev.

EXIT  0 nothing affected, 1 warnings/manual checks, 2 affected or blocked, 3 usage error
"""

import argparse, csv, glob, gzip, html, json, os, re, shutil, subprocess, sys, urllib.request, urllib.error
from datetime import datetime

VERSION = "1.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ADV_DIR = os.path.join(HERE, "..", "advisories")
IS_WIN = os.name == "nt"
HOME = os.path.expanduser("~")
OSV_URL = os.environ.get("OSV_API_URL", "https://api.osv.dev")

TTY = sys.stdout.isatty() and not IS_WIN
def c(code, s): return "\033[%sm%s\033[0m" % (code, s) if TTY else s
RED = lambda s: c("31", s); YEL = lambda s: c("33", s); GRN = lambda s: c("32", s)
CYA = lambda s: c("36", s); DIM = lambda s: c("2", s); BLD = lambda s: c("1", s)

def die(msg, code=3):
    print("error: " + msg, file=sys.stderr); sys.exit(code)

def norm(name):
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()

# ---------------------------------------------------------------------------
# Versions (PEP 440 subset: release, pre a/b/rc, post, dev, local ignored)
# ---------------------------------------------------------------------------
def pv(v):
    v = (v or "").strip().lower().lstrip("v").split("+")[0]
    m = re.match(r"^(\d+(?:\.\d+)*)(?:[-_.]?(a|alpha|b|beta|rc|c|pre|preview)[-_.]?(\d*))?(?:[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?dev[-_.]?(\d*))?", v)
    if not m:
        return None
    rel = [int(x) for x in m.group(1).split(".")]
    while len(rel) > 1 and rel[-1] == 0: rel.pop()
    pre = m.group(2)
    if pre:
        pre = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}.get(pre, pre)
        pre_t = ({"a": 0, "b": 1, "rc": 2}[pre], int(m.group(3) or 0))
    else:
        pre_t = (9, 0)
    post = int(m.group(5) or 0) if m.group(4) else -1
    dev = None if m.group(6) is None else int(m.group(6) or 0)
    if dev is not None and not pre and post < 0:
        pre_t = (-1, 0)          # 1.0.dev1 sorts before 1.0a1
    return (tuple(rel), pre_t, post, (1, 0) if dev is None else (0, dev))

def vcmp(a, b):
    x, y = pv(a), pv(b)
    if x is None or y is None:
        return 0
    rx, ry = list(x[0]), list(y[0])
    n = max(len(rx), len(ry)); rx += [0] * (n - len(rx)); ry += [0] * (n - len(ry))
    xa, ya = (tuple(rx),) + x[1:], (tuple(ry),) + y[1:]
    return (xa > ya) - (xa < ya)

def in_range(ver, spec):
    """spec: '>=2.6,<13.0.0|==1.2.3' (comma AND, pipe OR)."""
    if pv(ver) is None:
        return None
    for alt in spec.split("|"):
        ok = True
        for cond in alt.split(","):
            cond = cond.strip()
            if not cond: continue
            m = re.match(r"^(<=|>=|==|!=|<|>|~=)\s*(\S+)$", cond)
            if not m: continue
            op, b = m.groups()
            r = vcmp(ver, b)
            ok = ok and {"<": r < 0, "<=": r <= 0, ">": r > 0, ">=": r >= 0, "==": r == 0, "!=": r != 0,
                          "~=": r >= 0 and vcmp(ver, ".".join(b.split(".")[:-1] + ["999999"])) <= 0}[op]
        if ok:
            return True
    return False

def py_ok(pyver, minv):
    return not minv or vcmp(pyver, minv) >= 0

# ---------------------------------------------------------------------------
# Advisories
# ---------------------------------------------------------------------------
def load_advisory(path):
    adv = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r'^\s*([A-Z0-9_]+)\s*=\s*"(.*)"\s*$', line)
                if m: adv[m.group(1)] = m.group(2)
    except OSError:
        die("advisory not readable: %s" % path)
    for k in ("ADVISORY_ID", "PACKAGE", "AFFECTED", "FIXED"):
        if not adv.get(k):
            die("%s: missing %s" % (path, k))
    adv["_pkg"] = norm(adv["PACKAGE"])
    adv["_risk_bins"] = [tuple(x.split(":", 1)) for x in adv.get("RISK_BINARIES", "").split("|") if ":" in x]
    adv["_risk_pkgs"] = [tuple(x.split(":", 1)) for x in adv.get("RISK_PACKAGES", "").split("|") if ":" in x]
    hints = []
    for part in adv.get("CODE_HINTS", "").split(";;"):
        if "=>" in part:
            rx, label = part.split("=>", 1)
            try: hints.append((re.compile(rx.strip()), label.strip()))
            except re.error: pass
    adv["_hints"] = hints
    adv["_pulled"] = [x.strip() for x in adv.get("PULLED_BY", "").split("|") if x.strip()]
    adv["_backport_cves"] = adv.get("BACKPORT_CVES", "").split()
    adv["_file"] = path
    return adv

def load_advisories(paths):
    files = paths or sorted(glob.glob(os.path.join(DEFAULT_ADV_DIR, "*.env")))
    if not files:
        die("no advisory files found (looked in %s)" % DEFAULT_ADV_DIR)
    return [load_advisory(p) for p in files]

def fix_for(adv, pyver):
    """Best fixed version this Python can install, or None."""
    if py_ok(pyver, adv.get("FIX_MIN_PYTHON")):
        return adv["FIXED"]
    for bp in [b.strip() for b in adv.get("BACKPORTS", "").split("|") if b.strip()]:
        ver, _, minpy = bp.partition("@")      # "12.3.1@3.9"
        if py_ok(pyver, minpy or "0"):
            return ver
    return None

# ---------------------------------------------------------------------------
# Probe (runs inside each interpreter; reads metadata only)
# ---------------------------------------------------------------------------
PROBE = r'''
import sys, os, json, glob, re
out = {"version": "%d.%d.%d" % sys.version_info[:3], "executable": sys.executable, "prefix": sys.prefix,
       "base_prefix": getattr(sys, "base_prefix", sys.prefix), "platform": sys.platform}
out["is_venv"] = out["prefix"] != out["base_prefix"] or hasattr(sys, "real_prefix")
dists = {}
try:
    from importlib import metadata as md
    for d in md.distributions():
        try:
            n = d.metadata["Name"]; v = d.version
        except Exception:
            continue
        if n and v:
            loc = ""
            try: loc = str(d.locate_file(""))
            except Exception: pass
            dists.setdefault(re.sub(r"[-_.]+", "-", n).lower(), [v, n, loc])
except ImportError:
    for sp in [p for p in sys.path if p.endswith("-packages") and os.path.isdir(p)]:
        for di in glob.glob(os.path.join(sp, "*.dist-info")) + glob.glob(os.path.join(sp, "*.egg-info")):
            m = re.match(r"(.+?)-(\d[^-]*?)(?:-py\d.*)?\.(?:dist|egg)-info$", os.path.basename(di))
            if m: dists.setdefault(re.sub(r"[-_.]+", "-", m.group(1)).lower(), [m.group(2), m.group(1), sp])
out["dists"] = dists
print(json.dumps(out))
'''

def run_probe(python, timeout=30):
    try:
        cp = subprocess.run([python, "-E", "-c", PROBE], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, e.__class__.__name__
    if cp.returncode != 0:
        msg = (cp.stderr or "").strip().splitlines()
        return None, (msg[-1] if msg else "exit %d" % cp.returncode)[:160]
    try:
        return json.loads(cp.stdout.strip().splitlines()[-1]), None
    except (ValueError, IndexError):
        return None, "unreadable probe output"

# ---------------------------------------------------------------------------
# Discovery (same coverage as python-cert-responder)
# ---------------------------------------------------------------------------
SKIP_DIRS = {"node_modules", ".git", ".hg", "__pycache__", ".cache", "Library", ".Trash", "dist", "build", ".tox", ".nox",
             ".mypy_cache", ".pytest_cache", "site-packages", "AppData"}

def venv_python(d):
    for rel in (("bin", "python"), ("bin", "python3"), ("Scripts", "python.exe"), ("python.exe",)):
        p = os.path.join(d, *rel)
        if os.path.isfile(p): return p
    return None

def find_venvs(root, max_depth=6):
    root = os.path.expanduser(root); found = []
    if not os.path.isdir(root): return found
    base = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        if "pyvenv.cfg" in filenames or "conda-meta" in dirnames:
            py = venv_python(dirpath)
            if py: found.append(py)
            dirnames[:] = [d for d in dirnames if d == "envs"]
            continue
        if dirpath.count(os.sep) - base >= max_depth:
            dirnames[:] = []; continue
        dirnames[:] = [d for d in dirnames if (d not in SKIP_DIRS and not d.startswith(".")) or d in (".venv", ".virtualenvs", ".pyenv", ".conda")]
    return found

def discover_interpreters():
    cands = []
    for d in os.environ.get("PATH", "").split(os.pathsep):
        for pat in (("python3*", "python") if not IS_WIN else ("python.exe", "python3*.exe")):
            cands += glob.glob(os.path.join(d, pat))
    pats = ["/usr/bin/python3*", "/usr/local/bin/python3*", "/opt/homebrew/bin/python3*", "/opt/homebrew/opt/python@*/bin/python3*",
            "/usr/local/opt/python@*/bin/python3*", "/Library/Frameworks/Python.framework/Versions/*/bin/python3",
            "/opt/conda/bin/python", "/opt/python*/bin/python3", HOME + "/.pyenv/versions/*/bin/python",
            HOME + "/.local/share/uv/python/*/bin/python3", HOME + "/.local/share/mise/installs/python/*/bin/python",
            HOME + "/.asdf/installs/python/*/bin/python", HOME + "/miniconda3/bin/python", HOME + "/anaconda3/bin/python",
            HOME + "/miniforge3/bin/python", HOME + "/mambaforge/bin/python", HOME + "/opt/anaconda3/bin/python"]
    if IS_WIN:
        la = os.environ.get("LOCALAPPDATA", "")
        pats += [la + r"\Programs\Python\Python3*\python.exe", r"C:\Python3*\python.exe", r"C:\Program Files\Python3*\python.exe",
                 la + r"\uv\python\*\python.exe", HOME + r"\miniconda3\python.exe", HOME + r"\anaconda3\python.exe"]
        if shutil.which("py"):
            try:
                cp = subprocess.run(["py", "-0p"], capture_output=True, text=True, timeout=10)
                cands += re.findall(r"([A-Za-z]:\\[^\r\n*]+?python(?:w)?\.exe)", cp.stdout)
            except (OSError, subprocess.TimeoutExpired):
                pass
    for p in pats: cands += glob.glob(p)
    out = []
    for p in cands:
        b = os.path.basename(p).lower()
        if not os.path.isfile(p) or not os.access(p, os.X_OK): continue
        if not re.match(r"^python(3(\.\d+)?t?)?(\.exe)?$", b): continue
        out.append(p)
    return out

def default_venv_roots():
    roots = [HOME + "/.virtualenvs", HOME + "/.local/pipx/venvs", HOME + "/.local/share/pipx/venvs", HOME + "/.local/share/virtualenvs",
             HOME + "/.cache/pypoetry/virtualenvs", HOME + "/Library/Caches/pypoetry/virtualenvs", HOME + "/.local/share/uv/tools",
             HOME + "/miniconda3/envs", HOME + "/anaconda3/envs", HOME + "/miniforge3/envs", HOME + "/opt/anaconda3/envs", "/opt/conda/envs"]
    if IS_WIN:
        la = os.environ.get("LOCALAPPDATA", "")
        roots += [la + r"\pypoetry\Cache\virtualenvs", HOME + r"\.virtualenvs", HOME + r"\pipx\venvs", la + r"\pipx\pipx\venvs"]
    return [r for r in roots if os.path.isdir(r)]

def host_binaries(names):
    found = {}
    for n in names:
        p = shutil.which(n) or next((x for x in ("/usr/bin/" + n, "/usr/local/bin/" + n, "/opt/homebrew/bin/" + n) if os.path.isfile(x)), None)
        if not p and IS_WIN and n == "gs":
            p = next(iter(glob.glob(r"C:\Program Files\gs\gs*\bin\gswin64c.exe")), None)
        if p: found[n] = p
    return found

# ---------------------------------------------------------------------------
# OS-managed copies (Debian/Ubuntu dist-packages, RHEL/Fedora site-packages)
# ---------------------------------------------------------------------------
_OWNER_CACHE = {}

def os_owner(loc, dist_name):
    """(os_package, changelog_text) when a distro package owns this distribution, else None."""
    if IS_WIN or not loc or not loc.startswith("/usr/") or loc.startswith("/usr/local/"):
        return None
    key = (loc, norm(dist_name))
    if key in _OWNER_CACHE:
        return _OWNER_CACHE[key]
    res = None
    for meta in glob.glob(os.path.join(loc, "*.dist-info")) + glob.glob(os.path.join(loc, "*.egg-info")):
        stem = re.sub(r"\.(dist|egg)-info$", "", os.path.basename(meta))
        if norm(re.split(r"-(?=\d)", stem)[0]) != norm(dist_name):
            continue
        try:
            if shutil.which("dpkg"):
                cp = subprocess.run(["dpkg", "-S", meta], capture_output=True, text=True, timeout=20)
                pkg = cp.stdout.split(":", 1)[0].strip() if cp.returncode == 0 else ""
                if pkg:
                    log = ""
                    for f in ("/usr/share/doc/%s/changelog.Debian.gz" % pkg, "/usr/share/doc/%s/changelog.gz" % pkg):
                        if os.path.isfile(f):
                            with gzip.open(f, "rt", encoding="utf-8", errors="replace") as fh: log = fh.read()
                            break
                    res = (pkg, log); break
            if shutil.which("rpm"):
                cp = subprocess.run(["rpm", "-qf", "--qf", "%{NAME}", meta], capture_output=True, text=True, timeout=20)
                if cp.returncode == 0 and cp.stdout.strip() and "not owned" not in cp.stdout:
                    pkg = cp.stdout.strip()
                    log = subprocess.run(["rpm", "-q", "--changelog", pkg], capture_output=True, text=True, timeout=20).stdout
                    res = (pkg, log); break
        except (OSError, subprocess.TimeoutExpired):
            pass
    _OWNER_CACHE[key] = res
    return res

def os_update_cmd(pkg):
    if shutil.which("apt-get"): return "sudo apt-get update && sudo apt-get install --only-upgrade %s" % pkg
    if shutil.which("dnf"): return "sudo dnf upgrade %s" % pkg
    if shutil.which("yum"): return "sudo yum update %s" % pkg
    if shutil.which("zypper"): return "sudo zypper update %s" % pkg
    return "update the OS package %s" % pkg

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
SEV = {"AFFECTED": 0, "BLOCKED": 1, "WARN": 2, "CHECK": 3, "OK": 4, "INFO": 5}

def analyze_env(py, info, advisories, hostbins):
    findings = []
    pyver = info["version"]
    d = info.get("dists", {})
    for adv in advisories:
        rec = d.get(adv["_pkg"])
        if not rec:
            continue
        ver = rec[0]
        aff = in_range(ver, adv["AFFECTED"])
        risk = []
        for b, desc in adv["_risk_bins"]:
            if b in hostbins: risk.append(desc + " (%s)" % hostbins[b])
        for p, desc in adv["_risk_pkgs"]:
            if norm(p) in d: risk.append(desc + " (%s %s)" % (p, d[norm(p)][0]))
        base = {"advisory": adv["ADVISORY_ID"], "package": rec[1], "version": ver, "risk": risk, "severity": adv.get("SEVERITY", "?"),
                "location": rec[2], "source": "advisory"}
        if aff is None:
            findings.append(dict(base, status="CHECK", detail="could not parse version %s" % ver, fix="Check manually against %s" % adv["AFFECTED"]))
        elif aff and os_owner(rec[2], rec[1]):
            pkg, log = os_owner(rec[2], rec[1])
            cves = adv["_backport_cves"]
            if cves and all(cv in log for cv in cves):
                findings.append(dict(base, status="OK", detail="%s %s comes from the OS package %s, whose changelog lists %s (distro backport)" % (
                    rec[1], ver, pkg, " ".join(cves)), fix=""))
            else:
                findings.append(dict(base, status="AFFECTED", os_pkg=pkg,
                    detail="%s %s is vulnerable (%s); installed by the OS package %s%s" % (rec[1], ver, adv["ADVISORY_NAME"], pkg,
                        ", no backport listed in its changelog" if cves else ""),
                    fix="Apply the OS security update: %s. Distros often fix without changing the version number%s. If no update exists yet, move the app to a venv with %s>=%s." % (
                        os_update_cmd(pkg), (", so a re-scan shows OK once the changelog lists " + " ".join(cves)) if cves else "", adv["PACKAGE"], adv["FIXED"])))
        elif aff:
            fx = fix_for(adv, pyver)
            if fx:
                findings.append(dict(base, status="AFFECTED", detail="%s %s is vulnerable (%s)" % (rec[1], ver, adv["ADVISORY_NAME"]),
                                     fix='python -m pip install "%s>=%s"' % (adv["PACKAGE"], fx), target=fx))
            else:
                findings.append(dict(base, status="BLOCKED", detail="%s %s is vulnerable and the fix (%s) needs Python >= %s; this is Python %s" % (
                    rec[1], ver, adv["FIXED"], adv.get("FIX_MIN_PYTHON"), pyver),
                    fix="Upgrade this environment to Python >= %s, then install %s>=%s. Until then apply the mitigations." % (adv.get("FIX_MIN_PYTHON"), adv["PACKAGE"], adv["FIXED"])))
        else:
            findings.append(dict(base, status="OK", detail="%s %s is not affected" % (rec[1], ver), fix=""))
    # pip itself: cross-reference to the CA incident so the upgrade is safe
    pipv = (d.get("pip") or [None])[0]
    if pipv and vcmp(pipv, "26.2.2") < 0 and any(f["status"] == "AFFECTED" and not f.get("os_pkg") for f in findings):
        findings.append({"advisory": "emudhra-2026-10", "package": "pip", "version": pipv, "risk": [], "severity": "high", "location": "", "source": "note",
                         "status": "WARN", "detail": "pip %s is older than 26.2.2 (eMudhra CA fix): if this pip uses its own CA bundle, upgrading over the network is exposed to interception" % pipv,
                         "fix": "Check with python-cert-responder (pycert-scan.py --python <this env>) and use its checksum-verified pip bootstrap if needed"})
    status = min((f["status"] for f in findings), key=lambda s: SEV[s]) if findings else "INFO"
    return {"python": py, "info": info, "status": status, "findings": findings}

# ---------------------------------------------------------------------------
# OSV.dev (optional): every installed package, any published vulnerability
# ---------------------------------------------------------------------------
def osv_post(path, body, timeout=60):
    req = urllib.request.Request(OSV_URL.rstrip("/") + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json",
                                 "User-Agent": "python-vuln-responder/" + VERSION}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def osv_get(path, timeout=30):
    req = urllib.request.Request(OSV_URL.rstrip("/") + path, headers={"User-Agent": "python-vuln-responder/" + VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def osv_scan(envs):
    pairs = sorted({(name, rec[0]) for e in envs for name, rec in e["info"].get("dists", {}).items()})
    if not pairs:
        return {}, None
    print(DIM("OSV.dev: checking %d unique package versions..." % len(pairs)))
    hits, details = {}, {}
    try:
        for i in range(0, len(pairs), 900):
            chunk = pairs[i:i + 900]
            res = osv_post("/v1/querybatch", {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]})
            for (n, v), r in zip(chunk, res.get("results", [])):
                ids = [x["id"] for x in (r.get("vulns") or [])]
                if ids: hits[(n, v)] = ids
        for vid in sorted({x for ids in hits.values() for x in ids})[:400]:
            try:
                details[vid] = osv_get("/v1/vulns/" + vid)
            except (urllib.error.URLError, ValueError, OSError):
                details[vid] = {}
    except (urllib.error.URLError, ValueError, OSError) as e:
        return {}, "OSV.dev not reachable (%s)" % e.__class__.__name__
    out = {}
    for (n, v), ids in hits.items():
        items = []
        for vid in ids:
            dd = details.get(vid) or {}
            fixed = []
            for a in dd.get("affected", []):
                if norm((a.get("package") or {}).get("name")) != n: continue
                for rg in a.get("ranges", []):
                    for ev in rg.get("events", []):
                        if "fixed" in ev: fixed.append(ev["fixed"])
            aliases = [x for x in dd.get("aliases", []) if x.startswith("CVE-")]
            items.append({"id": vid, "aliases": aliases, "summary": (dd.get("summary") or "")[:140], "fixed": sorted(set(fixed), key=lambda x: pv(x) or ((0,), (0, 0), 0, 0))})
        out[(n, v)] = items
    return out, None

def merge_osv(envs, osv, advisories):
    covered = {a["_pkg"] for a in advisories}
    for e in envs:
        for name, rec in e["info"].get("dists", {}).items():
            if name in covered: continue
            items = osv.get((name, rec[0]))
            if not items: continue
            fixes = [f for it in items for f in it["fixed"] if vcmp(f, rec[0]) > 0]
            target = max(fixes, key=lambda x: pv(x) or ((0,), (0, 0), 0, 0)) if fixes else None
            ids = ", ".join((it["aliases"][0] if it["aliases"] else it["id"]) for it in items[:6]) + (" +%d more" % (len(items) - 6) if len(items) > 6 else "")
            e["findings"].append({"advisory": "osv", "package": rec[1], "version": rec[0], "risk": [], "severity": "see OSV", "location": rec[2], "source": "osv",
                                  "status": "AFFECTED" if target else "WARN",
                                  "detail": "%s %s: %d known vulnerabilit%s (OSV): %s" % (rec[1], rec[0], len(items), "y" if len(items) == 1 else "ies", ids),
                                  "fix": ('python -m pip install "%s>=%s"' % (rec[1], target)) if target else "No fixed version published; review the advisories", "target": target or ""})
        if e["findings"]:
            e["status"] = min((f["status"] for f in e["findings"]), key=lambda s: SEV[s])

# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------
PROJECT_SKIP = SKIP_DIRS | {".venv", "venv", "env", "vendor"}
SPEC_RE = r"((?:\s*(?:===|==|>=|<=|~=|!=|<|>)\s*[\w.*+!-]+\s*,?)+)"

def spec_status(spec, adv):
    """Classify a requirement specifier against an advisory."""
    spec = re.sub(r"\s+", "", spec)
    m = re.fullmatch(r"===?([\w.+!-]+)", spec)
    if m:
        ver = m.group(1)
        return ("AFFECTED", "pinned to %s" % ver) if in_range(ver, adv["AFFECTED"]) else ("OK", "pinned to fixed %s" % ver)
    conds = [x for x in spec.split(",") if x]
    def sat(ver):
        return all(in_range(ver, cnd) for cnd in conds)
    fx = pv(adv["FIXED"])[0] if pv(adv["FIXED"]) else (0,)
    fx = list(fx) + [0] * (3 - len(fx))
    cands = [adv["FIXED"], "%d.%d.%d" % (fx[0], fx[1], fx[2] + 1), "%d.%d.0" % (fx[0], fx[1] + 1), "%d.0.0" % (fx[0] + 1), "%d.0.0" % (fx[0] + 50)]
    allows_fix = any(sat(v) for v in cands)
    # requires the fix = no affected version can satisfy it (probe affected boundary versions)
    probe_vulns = ["0.1", "2.6.0", "%d.0.0" % max(fx[0] - 1, 0), "%d.%d.0" % (fx[0], max(fx[1] - 1, 0)) if fx[1] else "%d.99.99" % max(fx[0] - 1, 0),
                   "%d.%d.%d" % (fx[0], fx[1], fx[2] - 1) if fx[2] else "%d.%d.99" % (fx[0], max(fx[1] - 1, 0)), adv["FIXED"] + "rc1"]
    lower_fixed = conds and not any(sat(v) and in_range(v, adv["AFFECTED"]) for v in probe_vulns)
    if not allows_fix:
        return "AFFECTED", "range %s excludes the fixed %s" % (spec, adv["FIXED"])
    if lower_fixed:
        return "OK", "range %s requires the fix" % spec
    return "WARN", "range %s allows vulnerable versions; resolved version depends on the lockfile/install" % (spec or "(unpinned)")

def project_scan(root, advisories):
    root = os.path.abspath(os.path.expanduser(root)); out = []
    def add(status, path, line, adv, what, detail, fix):
        out.append({"status": status, "file": os.path.relpath(path, root), "line": line, "advisory": adv["ADVISORY_ID"] if adv else "", "what": what, "detail": detail, "fix": fix})
    pkgs = {a["_pkg"]: a for a in advisories}
    pkg_alt = "|".join(re.escape(a["PACKAGE"]) for a in advisories)
    req_re = re.compile(r"^\s*(%s)(\[[^\]]*\])?\s*%s?\s*(;.*)?$" % (pkg_alt, SPEC_RE), re.I)
    usage = {}   # dir -> set of hint labels
    pulled = []  # (regex, adv, trigger)
    for a in advisories:
        for trig in a["_pulled"]:
            m = re.match(r"^([\w.-]+)(?:\[([\w.,-]+)\])?$", trig)
            if not m: continue
            extra = (r"\[[^\]]*\b%s\b[^\]]*\]" % re.escape(m.group(2))) if m.group(2) else r"(\[[^\]]*\])?"
            pulled.append((re.compile(r"(?<![\w.-])%s%s" % (re.escape(m.group(1)), extra), re.I), a, trig))
    def check_pulled(path, text, adv_pinned):
        for rx, a, trig in pulled:
            if a["ADVISORY_ID"] in adv_pinned: continue
            mm = rx.search(text)
            if mm:
                add("WARN", path, text[:mm.start()].count("\n") + 1, a, mm.group(0)[:60],
                    "%s installs %s, but this file does not pin it: the resolved version depends on the lockfile or install date" % (trig, a["PACKAGE"]),
                    "Add %s>=%s as a constraint (or re-lock) so it cannot resolve to a vulnerable version" % (a["PACKAGE"], a["FIXED"]))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in PROJECT_SKIP and not (d.startswith(".") and d != ".github")]
        for fn in filenames:
            p = os.path.join(dirpath, fn); low = fn.lower()
            try:
                if (low.endswith((".txt", ".in")) and ("requirement" in low or "constraint" in low)):
                    txt_all = open(p, encoding="utf-8", errors="replace").read()
                    pinned = {pkgs[norm(m.group(1))]["ADVISORY_ID"] for m in (req_re.match(l.split("#")[0].rstrip()) for l in txt_all.splitlines()) if m}
                    check_pulled(p, "\n".join(l.split("#")[0] for l in txt_all.splitlines()), pinned)
                    for i, line in enumerate(txt_all.splitlines(), 1):
                        m = req_re.match(line.split("#")[0].rstrip())
                        if m:
                            adv = pkgs[norm(m.group(1))]; st, why = spec_status((m.group(3) or ""), adv)
                            if st != "OK" or (m.group(3) or "").strip().startswith("=="):
                                add(st, p, i, adv, line.strip()[:60], why, "Set %s>=%s, reinstall; for compiled files re-run %s" % (adv["PACKAGE"], adv["FIXED"], "pip-compile --upgrade-package " + adv["PACKAGE"]))
                elif low == "pyproject.toml":
                    txt = open(p, encoding="utf-8", errors="replace").read()
                    rp = re.search(r'requires-python\s*=\s*"([^"]+)"', txt)
                    check_pulled(p, txt, {a["ADVISORY_ID"] for a in advisories if re.search(r'["\'\s]%s\b' % re.escape(a["PACKAGE"]), txt, re.I)})
                    for adv in advisories:
                        for m in re.finditer(r'["\'](%s)(\[[^\]]*\])?\s*%s?\s*(;[^"\']*)?["\']' % (re.escape(adv["PACKAGE"]), SPEC_RE), txt, re.I):
                            st, why = spec_status(m.group(3) or "", adv)
                            ln = txt[:m.start()].count("\n") + 1
                            if st != "OK": add(st, p, ln, adv, m.group(0)[:60], why, "Require %s>=%s and re-lock" % (adv["PACKAGE"], adv["FIXED"]))
                        for m in re.finditer(r'^\s*(%s)\s*=\s*["\{]([^"\n}]*)' % re.escape(adv["PACKAGE"]), txt, re.I | re.M):   # poetry style
                            spec = re.sub(r'version\s*=\s*"?', "", m.group(2)).strip('" ')
                            spec = re.sub(r"^\^(\d+)(\.[\d.]+)?", lambda mm: ">=%s%s,<%d" % (mm.group(1), mm.group(2) or "", int(mm.group(1)) + 1), spec)
                            st, why = spec_status(spec if re.match(r"[<>=!~]", spec) else ("==" + spec if spec and spec != "*" else ""), adv)
                            if st != "OK": add(st, p, txt[:m.start()].count("\n") + 1, adv, m.group(0).strip()[:60], why, "Require %s>=%s and re-lock" % (adv["PACKAGE"], adv["FIXED"]))
                        if rp and adv.get("FIX_MIN_PYTHON") and re.search(r'["\']%s' % re.escape(adv["PACKAGE"]), txt, re.I):
                            if in_range("3.10.99", rp.group(1).replace(" ", "")) and not py_ok("3.10.99", adv["FIX_MIN_PYTHON"]):
                                add("BLOCKED", p, txt[:rp.start()].count("\n") + 1, adv, 'requires-python = "%s"' % rp.group(1),
                                    "project still supports Python versions that cannot install %s %s" % (adv["PACKAGE"], adv["FIXED"]),
                                    "Raise requires-python to >=%s (or document that older Pythons stay vulnerable)" % adv["FIX_MIN_PYTHON"])
                elif low in ("uv.lock", "poetry.lock", "pdm.lock") or low.startswith("pylock"):
                    txt = open(p, encoding="utf-8", errors="replace").read()
                    for m in re.finditer(r'name\s*=\s*"([^"]+)"\s*\n\s*version\s*=\s*"([^"]+)"', txt):
                        adv = pkgs.get(norm(m.group(1)))
                        if adv and in_range(m.group(2), adv["AFFECTED"]):
                            add("AFFECTED", p, txt[:m.start()].count("\n") + 1, adv, "%s %s" % (m.group(1), m.group(2)), "locked to a vulnerable version",
                                adv.get("RELOCK", "re-lock").split("|")[0].strip() if low == "uv.lock" else (adv.get("RELOCK", "").split("|")[1].strip() if low == "poetry.lock" and "|" in adv.get("RELOCK", "") else "re-lock with %s>=%s" % (adv["PACKAGE"], adv["FIXED"])))
                elif low == "pipfile.lock":
                    data = json.load(open(p, encoding="utf-8"))
                    for sec in ("default", "develop"):
                        for name, meta in (data.get(sec) or {}).items():
                            adv = pkgs.get(norm(name)); v = (meta or {}).get("version", "")
                            if adv and v.startswith("==") and in_range(v[2:], adv["AFFECTED"]):
                                add("AFFECTED", p, 0, adv, "%s %s" % (name, v), "locked to a vulnerable version", "pipenv update %s" % adv["PACKAGE"])
                elif low in ("environment.yml", "environment.yaml"):
                    for i, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
                        m = re.match(r"^\s*-\s*([\w.-]+)\s*(==?|>=|<=|<|>)?\s*([\w.*]+)?", line)
                        if m and norm(m.group(1)) in pkgs:
                            adv = pkgs[norm(m.group(1))]
                            if m.group(3) and m.group(2) in ("=", "==") and in_range(m.group(3).rstrip(".*"), adv["AFFECTED"]):
                                add("AFFECTED", p, i, adv, line.strip()[:60], "conda pin to a vulnerable version", "conda update %s (conda-forge >= %s)" % (adv["PACKAGE"], adv["FIXED"]))
                elif low.startswith(("dockerfile", "containerfile")) or low.endswith(".dockerfile"):
                    txt = open(p, encoding="utf-8", errors="replace").read()
                    for adv in advisories:
                        mentions = re.search(r"\b%s\b" % re.escape(adv["PACKAGE"]), txt, re.I)
                        for m in re.finditer(r"^\s*FROM\s+(?:--\S+\s+)*\S*python:(\d+\.\d+)\S*", txt, re.I | re.M):
                            if not py_ok(m.group(1), adv.get("FIX_MIN_PYTHON")) and (mentions or True):
                                add("BLOCKED" if mentions else "WARN", p, txt[:m.start()].count("\n") + 1, adv, "FROM python:%s" % m.group(1),
                                    "Python %s cannot install %s %s%s" % (m.group(1), adv["PACKAGE"], adv["FIXED"], "" if mentions else " (if the image ends up with it)"),
                                    "Move the base image to python:%s or newer" % adv["FIX_MIN_PYTHON"])
                        for m in re.finditer(r"%s\s*(==|<=|<)\s*([\w.]+)" % re.escape(adv["PACKAGE"]), txt, re.I):
                            if in_range(m.group(2), adv["AFFECTED"]) or m.group(1) == "<":
                                add("AFFECTED", p, txt[:m.start()].count("\n") + 1, adv, m.group(0), "image installs a vulnerable version", "Pin %s>=%s and rebuild with --pull" % (adv["PACKAGE"], adv["FIXED"]))
                elif low.endswith(".py") and os.path.getsize(p) < 2_000_000:
                    txt = open(p, encoding="utf-8", errors="replace").read()
                    for adv in advisories:
                        imps = [x.strip() for x in adv.get("IMPORT_NAMES", "").split(",") if x.strip()]
                        if imps and re.search(r"^\s*(from|import)\s+(%s)\b" % "|".join(map(re.escape, imps)), txt, re.M):
                            key = (os.path.relpath(dirpath, root).split(os.sep)[0], adv["ADVISORY_ID"])
                            u = usage.setdefault(key, {"files": 0, "hints": {}, "adv": adv})
                            u["files"] += 1
                            for rx, label in adv["_hints"]:
                                mm = rx.search(txt)
                                if mm: u["hints"].setdefault(label, "%s:%d" % (os.path.relpath(p, root), txt[:mm.start()].count("\n") + 1))
            except (OSError, ValueError, UnicodeDecodeError, KeyError, IndexError):
                continue
    for (top, _), u in sorted(usage.items()):
        adv = u["adv"]
        hint = "; ".join("%s (%s)" % (k, v) for k, v in u["hints"].items())
        out.append({"status": "INFO", "file": top if top != "." else os.path.basename(root), "line": 0, "advisory": adv["ADVISORY_ID"],
                    "what": "imports %s in %d file(s)" % (adv.get("IMPORT_NAMES"), u["files"]),
                    "detail": "direct use of %s" % adv["PACKAGE"] + ("; exposure hints: " + hint if hint else ""),
                    "fix": adv.get("MITIGATIONS", "") if u["hints"] else ""})
    return out

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
COL = {"AFFECTED": RED, "BLOCKED": RED, "WARN": YEL, "CHECK": YEL, "OK": GRN, "INFO": DIM}

def floc(f): return "%s:%s" % (f["file"], f["line"]) if f.get("line") else f["file"]
def env_label(e):
    i = e["info"]; return "%s %s  %s" % ("venv" if i.get("is_venv") else "python", i["version"], i["prefix"])

def print_report(envs, projects, errors, advisories, hostbins, osv_err):
    print()
    print(BLD(CYA("Python package vulnerability check")))
    for a in advisories:
        print(DIM("  %s: %s < %s affected%s" % (a["ADVISORY_ID"], a["PACKAGE"], a["FIXED"], (" (fix needs Python >= %s)" % a["FIX_MIN_PYTHON"]) if a.get("FIX_MIN_PYTHON") else "")))
    if hostbins: print(DIM("  host risk factors: " + ", ".join("%s=%s" % kv for kv in hostbins.items())))
    if osv_err: print(YEL("  " + osv_err))
    print()
    for e in envs:
        if e["status"] == "INFO": continue
        print(COL[e["status"]](BLD("%-9s" % e["status"])) + " " + BLD(env_label(e)))
        for f in e["findings"]:
            if f["status"] == "OK" and e["status"] == "OK": continue
            print("          %s %s" % (COL[f["status"]](f["status"].lower()), f["detail"]))
            for r in f.get("risk", []): print(YEL("            risk: " + r))
            if f["fix"] and f["status"] in ("AFFECTED", "BLOCKED", "WARN"): print(DIM("            fix: " + f["fix"]))
        print()
    for f in projects:
        print(COL[f["status"]](BLD("%-9s" % f["status"])) + " " + BLD(floc(f)) + "  " + f["what"])
        print("          " + f["detail"] + (("\n" + DIM("            fix: " + f["fix"])) if f["fix"] else "") + "\n")
    for py, err in errors:
        print(YEL(BLD("%-9s" % "CHECK")) + " " + BLD(py) + DIM("  could not probe: " + err) + "\n")
    cnt = {k: 0 for k in SEV}
    for e in envs: cnt[e["status"]] += 1
    for f in projects: cnt[f["status"]] += 1
    clean = sum(1 for e in envs if e["status"] == "INFO")
    print(BLD("Summary: ") + RED("%d affected" % cnt["AFFECTED"]) + ", " + RED("%d blocked by old Python" % cnt["BLOCKED"]) + ", " +
          YEL("%d warnings" % (cnt["WARN"] + cnt["CHECK"] + len(errors))) + ", " + GRN("%d ok" % cnt["OK"]) + DIM(", %d environments without the packages" % clean))
    return cnt

def write_csv(path, envs, projects):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["kind", "target", "python", "advisory", "package", "version", "status", "detail", "risk", "fix"])
        for e in envs:
            for x in e["findings"]:
                w.writerow(["venv" if e["info"].get("is_venv") else "python", e["info"]["prefix"], e["info"]["version"], x["advisory"], x["package"], x["version"], x["status"], x["detail"], "; ".join(x.get("risk", [])), x["fix"]])
        for p in projects:
            w.writerow(["project", floc(p), "", p["advisory"], "", "", p["status"], p["what"] + ": " + p["detail"], "", p["fix"]])

def shq(p): return '"%s"' % p if (" " in p or IS_WIN) else p

def write_fix_plan(path, envs, projects, advisories):
    L = ["# Fix plan", "", "Generated %s by pyvuln-scan. Run each block yourself; nothing here was executed." % datetime.now().strftime("%Y-%m-%d %H:%M"), ""]
    for a in advisories:
        L += ["**%s**: %s < %s is affected.%s" % (a["ADVISORY_ID"], a["PACKAGE"], a["FIXED"], (" The fix needs Python >= %s." % a["FIX_MIN_PYTHON"]) if a.get("FIX_MIN_PYTHON") else ""), ""]
    todo = [e for e in envs if e["status"] in ("AFFECTED", "BLOCKED", "WARN")]
    if todo:
        L += ["## Environments", ""]
        for e in todo:
            py = shq(e["python"])
            L.append("### %s  [%s]" % (env_label(e), e["status"]))
            pins, notes = [], []
            for f in e["findings"]:
                if f["status"] == "AFFECTED" and f.get("os_pkg"):
                    notes.append("- %s (OS package `%s`): `%s`" % (f["package"], f["os_pkg"], os_update_cmd(f["os_pkg"])))
                elif f["status"] == "AFFECTED" and f.get("target") and '"%s>=%s"' % (f["package"], f["target"]) not in pins:
                    pins.append('"%s>=%s"' % (f["package"], f["target"]))
                elif f["status"] in ("BLOCKED", "WARN"):
                    notes.append("- %s: %s" % (f["package"], f["fix"]))
                for r in f.get("risk", []): notes.append("- risk: " + r)
            if pins:
                ext = " --break-system-packages" if not e["info"].get("is_venv") and e["info"]["prefix"].startswith("/usr") else ""
                L += ["```bash", "%s -m pip install%s --upgrade %s" % (py, ext, " ".join(pins)), "%s -m pip check" % py, "```"]
                if ext: L.append("System Python managed by the OS: prefer the distro package update (e.g. `apt upgrade python3-pil`); use pip only if no update is offered.")
            L += notes + [""]
    pr = [p for p in projects if p["status"] in ("AFFECTED", "BLOCKED", "WARN")]
    if pr:
        L += ["## Projects", ""] + ["- [ ] `%s` %s: %s. Fix: %s" % (floc(p), p["what"], p["detail"], p["fix"]) for p in pr] + [""]
    mit = [a for a in advisories if a.get("MITIGATIONS")]
    if mit:
        L += ["## Until everything is upgraded", ""] + ["- **%s**: %s" % (a["PACKAGE"], a["MITIGATIONS"]) for a in mit] + [""]
    L += ["## Verify", "", "```bash", "python3 pyvuln-scan.py --local --venvs <code dir> --project <code dir>", "```", ""]
    with open(path, "w", encoding="utf-8") as f: f.write("\n".join(L))

def write_html(path, envs, projects, errors, advisories, hostbins, cnt, osv_used, osv_err):
    e = html.escape
    def badge(s): return "<span class='b %s'>%s</span>" % (s, e(s))
    advs = "".join("<div class=adv><b>%s</b> <span class=mut>%s</span><div>%s</div><div class=mut>Fixed: %s %s%s · %s</div></div>" % (
        e(a["ADVISORY_NAME"]), e(a.get("SEVERITY", "")), e(a.get("SUMMARY", "")), e(a["PACKAGE"]), e(a["FIXED"]),
        (" (needs Python &ge; %s)" % e(a["FIX_MIN_PYTHON"])) if a.get("FIX_MIN_PYTHON") else "", e(a.get("IDS", "").replace(" | ", " · "))) for a in advisories)
    cards = ""
    for env in envs:
        if env["status"] == "INFO": continue
        i = env["info"]
        rows = "".join("<tr><td>%s</td><td>%s %s</td><td>%s%s%s</td></tr>" % (badge(f["status"]), e(f["package"]), e(f["version"]), e(f["detail"]),
                       "".join("<div class=risk>risk: %s</div>" % e(r) for r in f.get("risk", [])),
                       ("<div class=fix>fix: %s</div>" % e(f["fix"])) if f["fix"] and f["status"] in ("AFFECTED", "BLOCKED", "WARN") else "") for f in env["findings"])
        cards += "<div class='card %s'><div class=top>%s <b>%s %s</b> <span class=mut>%s</span></div><table>%s</table></div>" % (
            env["status"], badge(env["status"]), "venv" if i.get("is_venv") else "Python", e(i["version"]), e(i["prefix"]), rows)
    cards += "".join("<div class='card CHECK'><div class=top>%s <b>%s</b></div><div class=mut>could not probe: %s</div></div>" % (badge("CHECK"), e(p), e(m)) for p, m in errors)
    proj = ""
    if projects:
        proj = "<h2>Projects</h2><table class=proj>" + "".join("<tr><td>%s</td><td><code>%s</code></td><td>%s<div class=mut>%s</div>%s</td></tr>" % (
            badge(p["status"]), e(floc(p)), e(p["what"]), e(p["detail"]), ("<div class=fix>fix: %s</div>" % e(p["fix"])) if p["fix"] else "") for p in projects) + "</table>"
    clean = sum(1 for x in envs if x["status"] == "INFO")
    risk = ("<div class=note>Host risk factors: %s</div>" % e(", ".join("%s (%s)" % kv for kv in hostbins.items()))) if hostbins else ""
    osvn = ("<div class=note>OSV.dev: %s</div>" % e(osv_err or "all installed packages were also checked against OSV.dev")) if osv_used else ""
    doc = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Python Vulnerability Report</title>
<style>
:root{--bg:#f5f7fb;--fg:#141821;--mut:#5c6474;--card:#fff;--line:#e2e6ee;--aff:#d92d20;--blk:#9f1239;--warn:#dc8a00;--chk:#a16207;--ok:#16a34a;--info:#7a828e;--py1:#3776ab;--py2:#f2c230}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0e1117;--fg:#ecf0f6;--mut:#9aa4b5;--card:#171b23;--line:#283041}}
:root[data-theme=dark]{--bg:#0e1117;--fg:#ecf0f6;--mut:#9aa4b5;--card:#171b23;--line:#283041}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px 16px}
.wrap{max-width:1040px;margin:0 auto}h1{margin:0 0 4px;font-size:24px}h1 span{color:var(--py1)}.mut{color:var(--mut);font-size:13px}.sub{color:var(--mut);font-size:13px;margin:0 0 14px}
.adv{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--py2);border-radius:0;padding:10px 14px;margin:0 0 10px;font-size:14px}
.note{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 12px;margin:0 0 10px;font-size:13.5px}
.sum{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:14px 0 20px}
.stat{background:var(--card);border:1px solid var(--line);border-top:5px solid var(--c);border-radius:14px;padding:12px 14px}.stat b{display:block;font-size:28px;color:var(--c)}.stat span{font-size:13px;color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--c);border-radius:12px;padding:12px 14px;margin:10px 0;overflow-x:auto}
.top{display:flex;flex-wrap:wrap;gap:8px;align-items:center;word-break:break-all}
table{width:100%%;border-collapse:collapse;margin-top:8px;font-size:13.5px}td{border-top:1px solid var(--line);padding:6px;vertical-align:top;word-break:break-word}td:first-child{width:96px}
.b{background:var(--c);color:#fff;font-weight:700;font-size:11px;letter-spacing:.05em;padding:2px 8px;border-radius:6px;white-space:nowrap}
.fix{color:var(--mut);font-size:12.5px;margin-top:3px}.risk{color:var(--warn);font-size:12.5px;margin-top:3px}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
.AFFECTED{--c:var(--aff)}.BLOCKED{--c:var(--blk)}.WARN{--c:var(--warn)}.CHECK{--c:var(--chk)}.OK{--c:var(--ok)}.INFO{--c:var(--info)}
h2{font-size:18px;margin:24px 0 6px}footer{color:var(--mut);font-size:12px;margin-top:26px}
</style></head><body><div class=wrap>
<h1><span>Python</span> vulnerability report</h1>
<p class=sub>generated %s · %d environment(s) scanned, %d without the affected packages</p>
%s%s%s
<div class=sum><div class='stat AFFECTED'><b>%d</b><span>affected</span></div><div class='stat BLOCKED'><b>%d</b><span>blocked by old Python</span></div><div class='stat WARN'><b>%d</b><span>warnings / checks</span></div><div class='stat OK'><b>%d</b><span>ok</span></div></div>
%s%s
<footer>AFFECTED: a vulnerable version is installed or pinned and a fix is available for that Python. BLOCKED: the fix needs a newer Python. WARN: a range allows vulnerable versions, an image needs a newer Python, or a safe-upgrade prerequisite. The probe only reads package metadata.</footer>
</div></body></html>""" % (e(datetime.now().strftime("%Y-%m-%d %H:%M")), len(envs), clean, advs, risk, osvn,
        cnt["AFFECTED"], cnt["BLOCKED"], cnt["WARN"] + cnt["CHECK"] + len(errors), cnt["OK"], cards, proj)
    with open(path, "w", encoding="utf-8") as f: f.write(doc)

# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Find vulnerable PyPI packages across every Python environment and project.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("USAGE", 1)[1])
    ap.add_argument("--local", action="store_true", help="discover Python installs and common venv homes on this machine")
    ap.add_argument("--venvs", action="append", metavar="DIR", help="also every virtualenv/conda env under DIR (repeatable)")
    ap.add_argument("--python", action="append", metavar="PATH", help="this interpreter or venv dir (repeatable)")
    ap.add_argument("--project", action="append", metavar="DIR", help="scan requirements, pyproject, lockfiles, conda, Dockerfiles and code")
    ap.add_argument("--advisory", action="append", metavar="FILE", help="advisory file(s) to use (default: all in advisories/)")
    ap.add_argument("--osv", action="store_true", help="also check every installed package against OSV.dev (sends names+versions)")
    ap.add_argument("-o", "--out", default="pyvuln-report")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args()
    if not (a.local or a.venvs or a.python or a.project):
        ap.print_help(); sys.exit(3)
    advisories = load_advisories(a.advisory)
    hostbins = host_binaries(sorted({b for adv in advisories for b, _ in adv["_risk_bins"]}))

    targets = []
    if a.local:
        targets += discover_interpreters()
        for r in default_venv_roots(): targets += find_venvs(r, 3)
    for r in a.venvs or []: targets += find_venvs(r)
    for p in a.python or []:
        p = os.path.expanduser(p); targets.append((venv_python(p) or p) if os.path.isdir(p) else p)
    envs, errors, seen = [], [], set()
    if targets: print(DIM("Probing %d interpreter path(s)..." % len(set(targets))))
    for py in dict.fromkeys(targets):
        info, err = run_probe(py)
        if err:
            errors.append((py, err)); continue
        key = os.path.realpath(info["prefix"]) + "|" + info["version"]
        if key in seen: continue
        seen.add(key)
        envs.append(analyze_env(py, info, advisories, hostbins))
    osv_err = None
    if a.osv and envs:
        osv, osv_err = osv_scan(envs)
        if not osv_err: merge_osv(envs, osv, advisories)
    envs.sort(key=lambda x: (SEV[x["status"]], x["info"].get("prefix", "")))
    projects = []
    for d in a.project or []: projects += project_scan(d, advisories)
    projects.sort(key=lambda f: (SEV[f["status"]], f["file"]))

    cnt = print_report(envs, projects, errors, advisories, hostbins, osv_err)
    d = os.path.dirname(a.out)
    if d: os.makedirs(d, exist_ok=True)
    write_html(a.out + ".html", envs, projects, errors, advisories, hostbins, cnt, a.osv, osv_err)
    write_csv(a.out + ".csv", envs, projects)
    write_fix_plan(a.out + "-fix-plan.md", envs, projects, advisories)
    print("Reports: %s.html | %s.csv | %s-fix-plan.md\n" % (a.out, a.out, a.out))
    if cnt["AFFECTED"] or cnt["BLOCKED"]: sys.exit(2)
    sys.exit(1 if (cnt["WARN"] or cnt["CHECK"] or errors or osv_err) else 0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted"); sys.exit(3)
