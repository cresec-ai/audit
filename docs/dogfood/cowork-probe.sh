#!/bin/sh
# Cowork probe — stage 1. Answers one question: DO CLAUDE CODE HOOKS FIRE IN
# COWORK AT ALL? Everything mcp-recorder can do on a Cowork session depends on
# that, and we have never tested it. docs/connector-coverage.md currently says
# hooks are "not known to fire here, and the evidence points against it".
#
# This installs a hook that does nothing but append a line to a file. No
# recorder, no network, no policy. It is deliberately the smallest thing that
# can distinguish "hooks fire" from "hooks do not fire", because a negative
# result from a complicated probe tells you nothing about which part failed.
#
#   sh cowork-probe.sh install     # then use Cowork normally for a few minutes
#   sh cowork-probe.sh report      # what fired
#   sh cowork-probe.sh uninstall   # puts your settings back
set -eu
S="$HOME/.claude/settings.json"
M="$HOME/.claude/cowork-probe.log"
B="$HOME/.claude/settings.json.cowork-probe-backup"

case "${1:-report}" in
install)
  mkdir -p "$HOME/.claude"
  [ -f "$S" ] || echo '{}' > "$S"
  [ -f "$B" ] || cp "$S" "$B"
  CMD="printf '%s %s\\n' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"\${CLAUDE_HOOK_EVENT:-?} \${CLAUDE_TOOL_NAME:-?}\" >> $M"
  python3 - "$S" "$CMD" <<'PY'
import json,sys
p,cmd=sys.argv[1],sys.argv[2]
d=json.load(open(p))
h=d.setdefault('hooks',{})
for ev,matcher in (('PreToolUse','.*'),('PostToolUse','.*'),('SessionStart',None),('Stop',None)):
    grp={'hooks':[{'type':'command','command':cmd}]}
    if matcher: grp['matcher']=matcher
    h.setdefault(ev,[]).append(grp)
json.dump(d,open(p,'w'),indent=2); open(p,'a').write('\n')
print(f'probe installed into {p}: PreToolUse, PostToolUse, SessionStart, Stop')
PY
  : > "$M"
  echo "Now START A NEW COWORK SESSION (hooks are captured at session start, so an"
  echo "already-open session will not pick this up) and do a few things in it —"
  echo "ideally something that calls a connector (Gmail, Drive, ClickUp...)."
  echo "Then run:  sh $0 report"
  ;;
report)
  echo "=== $M ==="
  if [ ! -f "$M" ]; then echo "(no file — probe not installed?)"; exit 0; fi
  if [ ! -s "$M" ]; then
    echo "(EMPTY — no hook fired)"
    echo
    echo "That is the informative result: Cowork did not run a hook that a Claude Code"
    echo "session would have run. Check you started a NEW session after installing."
    exit 0
  fi
  wc -l < "$M" | tr -d ' ' | sed 's/^/lines: /'
  echo "--- distinct events ---"; awk '{print $2}' "$M" | sort | uniq -c | sort -rn
  echo "--- any MCP tool calls seen? ---"; grep -c 'mcp__' "$M" 2>/dev/null || echo 0
  echo "--- first 10 ---"; head -10 "$M"
  ;;
uninstall)
  if [ -f "$B" ]; then mv "$B" "$S"; echo "settings.json restored from backup"; else echo "no backup found; edit $S by hand"; fi
  rm -f "$M"; echo "probe log removed"
  ;;
*) echo "usage: sh $0 install|report|uninstall"; exit 2 ;;
esac
