#!/usr/bin/env bash
# =====================================================================
#  install.sh  -  one-shot installer for python-vuln-responder
#
#  ./install.sh --target claude          # skills -> ~/.claude/skills
#  ./install.sh --target hermes          # skills -> ~/.hermes/skills
#  ./install.sh --dest /path/to/skills   # any Agent Skills loader / project
#  ./install.sh --uninstall [--target X | --dest DIR]
#
#  Always installs the toolkit (scripts, advisories) to ~/.python-vuln-responder
#  (override with PYVR_HOME=...). Skills look there automatically.
#
#  Claude Code users can instead install as a plugin (adds slash commands,
#  the pyvr-verifier agent and the safety hook):
#    /plugin marketplace add <this folder or GitHub repo>
#    /plugin install python-vuln-responder@python-vuln-responder
# =====================================================================
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
PYVR_HOME="${PYVR_HOME:-$HOME/.python-vuln-responder}"
DEST=""; UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --target)
      case "$2" in
        claude) DEST="$HOME/.claude/skills";;
        hermes) DEST="$HOME/.hermes/skills";;
        *) echo "Unknown target '$2' (use claude, hermes, or --dest DIR)"; exit 3;;
      esac; shift 2;;
    --dest) DEST="$2"; shift 2;;
    --uninstall) UNINSTALL=1; shift;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^#//'; exit 0;;
    *) echo "Unknown option: $1"; exit 3;;
  esac
done

if [ "$UNINSTALL" -eq 1 ]; then
  if [ -n "$DEST" ]; then
    for s in "$SRC"/skills/pyvr-*; do rm -rf "$DEST/$(basename "$s")"; done
    echo "Removed pyvr-* skills from $DEST"
  fi
  rm -rf "$PYVR_HOME"; echo "Removed $PYVR_HOME"
  exit 0
fi

mkdir -p "$PYVR_HOME"
cp -R "$SRC/scripts" "$SRC/advisories" "$SRC/AGENTS.md" "$PYVR_HOME/"
chmod +x "$PYVR_HOME"/scripts/*.py
echo "Toolkit installed: $PYVR_HOME"

if [ -n "$DEST" ]; then
  mkdir -p "$DEST"
  for s in "$SRC"/skills/pyvr-*; do
    rm -rf "$DEST/$(basename "$s")"
    cp -R "$s" "$DEST/"
  done
  echo "Skills installed: $DEST ($(ls -d "$SRC"/skills/pyvr-* | wc -l | tr -d ' ') skills)"
fi

echo
echo "Quick start:  python3 $PYVR_HOME/scripts/pyvuln-scan.py --local --venvs ~/code --project ~/code -o pyvuln   (Windows: py -3 ...)"
echo "Ask your agent:  \"Are my Python apps affected by the Pillow vulnerability?\"  /  \"¿Mis apps de Python están afectadas por la vulnerabilidad de Pillow?\""
