#!/usr/bin/env bash
# PreToolUse guard (Claude Code) for python-vuln-responder.
#  DENY: disabling TLS verification while installing fixes (--trusted-host,
#        verify=False, PYTHONHTTPSVERIFY=0, curl -k, UV_INSECURE_HOST...), and
#        fetching exploit/PoC code or crafted test images.
#  ASK:  package installs, upgrades, re-locks (pip, uv, poetry, pdm, conda, pipx),
#        --break-system-packages, OS package changes, image builds.
#  Read-only commands and the scanner pass through.
IN=$(cat)
if command -v jq >/dev/null 2>&1; then
  CMD=$(printf '%s' "$IN" | jq -r '.tool_input.command // empty' 2>/dev/null)
elif command -v python3 >/dev/null 2>&1; then
  CMD=$(printf '%s' "$IN" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))' 2>/dev/null)
else
  CMD=$IN
fi
[ -z "$CMD" ] && exit 0
LC=$(printf '%s' "$CMD" | tr 'A-Z' 'a-z')
decide() { printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}\n' "$1" "$2"; exit 0; }

if echo "$LC" | grep -qE -- '--trusted-host|pip_trusted_host|verify[[:space:]]*=[[:space:]]*false|pythonhttpsverify=0|(^|[[:space:];&])curl[[:space:]]([^|;&]*[[:space:]])?(-[a-z]*k[a-z]*|--insecure)([[:space:]]|$)|--no-check-certificate|uv_insecure_host|--allow-insecure-host|_create_unverified_context|cert_none|ssl_verify[[:space:]]*(=|:)[[:space:]]*(false|0)|git[[:space:]]+-c[[:space:]]+http\.sslverify=false'; then
  decide deny "python-vuln-responder: this disables TLS certificate verification. Install fixes over verified connections only (see python-cert-responder if pip reports certificate errors)."
fi
if echo "$LC" | grep -qE '(git clone|curl|wget|pip install)[^|;&]*(poc|exploit|crafted|malicious)'; then
  decide deny "python-vuln-responder: fetching exploit/PoC code or crafted test files is not allowed. Verify fixes by version, not by exploitation."
fi
if echo "$LC" | grep -qE -- '--break-system-packages'; then
  decide ask "python-vuln-responder: --break-system-packages changes the OS-managed Python. Prefer the distro package update or a venv. Approve this exact command?"
fi
if echo "$LC" | grep -qE '(-m[[:space:]]+pip|(^|[[:space:]/])pip3?)[[:space:]]+(install|uninstall|download)|uv[[:space:]]+(pip[[:space:]]+install|tool[[:space:]]+(install|upgrade)|python[[:space:]]+(install|upgrade)|lock|sync|add|remove)|(conda|mamba|micromamba)[[:space:]]+(install|update|upgrade|remove)|pipx[[:space:]]+(install|upgrade|reinstall)|poetry[[:space:]]+(update|lock|add|install)|pdm[[:space:]]+(update|lock|add|install)|pipenv[[:space:]]+(install|update|lock)|pip-compile|pip-sync'; then
  decide ask "python-vuln-responder: package install/upgrade/re-lock. Approve this exact command?"
fi
if echo "$LC" | grep -qE '(apt(-get)?|dnf|yum|zypper|apk|brew|port)[[:space:]]+(install|upgrade|update|reinstall|remove|uninstall)|docker[[:space:]]+(build|compose[[:space:]]+(build|up))|docker-compose[[:space:]]+(build|up)|buildah[[:space:]]+bud|podman[[:space:]]+build'; then
  decide ask "python-vuln-responder: system package or image change. Approve this exact command?"
fi
exit 0
