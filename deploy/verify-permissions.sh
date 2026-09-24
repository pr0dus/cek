#!/bin/sh
# Agent Room S3 permission-boundary check. READ-ONLY.
#
# Run as `pr0` immediately after deployment. It asks one question in several
# ways: can a shell as pr0 — which is what a write to the old bridge's control
# repo already gets you — reach Agent Room's trust state?
#
# It reads metadata and attempts harmless denied reads. It writes nothing,
# installs nothing and prints no secret values.
#
# IMPORTANT: this check is meaningless while `sudo -n true` succeeds. If pr0
# can become root without a password, every "denied" below is one `sudo` away
# from allowed, and the boundary this script measures does not exist. That is
# checked first and reported as a blocker rather than a warning.

set -u
PASS=0; FAIL=0; BLOCK=0
ok()    { echo "  ok       $*"; PASS=$((PASS+1)); }
bad()   { echo "  FAIL     $*"; FAIL=$((FAIL+1)); }
block() { echo "  BLOCKER  $*"; BLOCK=$((BLOCK+1)); }

echo "== 0. root escalation (decides whether anything below means anything) =="
if sudo -n true >/dev/null 2>&1; then
  block "pr0 has non-interactive root (sudo -n true succeeds)."
  block "Unix-user separation CANNOT protect Agent Room state from a shell as pr0."
  block "Resolve this with the human before activation; see docs/AGENT_ROOM_TRANSPORT.md."
else
  ok "pr0 has no non-interactive root"
fi

echo "== 1. frozen code is root-owned and not writable by pr0 =="
for p in /opt/agent-room /opt/agent-room/current /etc/agent-room \
         /etc/agent-room/transport.json /etc/agent-room/trust-policy.json; do
  [ -e "$p" ] || { echo "  skip     $p (not deployed)"; continue; }
  owner=$(stat -c '%U:%G %a' "$p")
  case "$owner" in root:*) ok "$p owned by root ($owner)" ;;
                   *)      bad "$p is $owner, expected root" ;; esac
  if [ -w "$p" ]; then bad "$p is writable by pr0"; else ok "$p not writable by pr0"; fi
done

echo "== 2. service state is owner-only and unreadable by pr0 =="
for p in /var/lib/agent-room /var/lib/agent-room/keys \
         /var/lib/agent-room/checkpoint.json \
         /var/lib/agent-room/keys/openai-research.ed25519.pem \
         /var/lib/agent-room/room /var/lib/agent-room/control \
         /var/lib/agent-room/state; do
  [ -e "$p" ] || { echo "  skip     $p (not deployed)"; continue; }
  meta=$(stat -c '%U:%G %a' "$p")
  case "$meta" in agentroom:agentroom\ 700|agentroom:agentroom\ 600)
        ok "$p is $meta" ;;
     *) bad "$p is $meta, expected agentroom owner-only (700/600)" ;; esac
  if [ -d "$p" ]; then
    if ls "$p" >/dev/null 2>&1; then bad "pr0 can list $p"; else ok "pr0 cannot list $p"; fi
  else
    if head -c 1 "$p" >/dev/null 2>&1; then bad "pr0 can read $p"; else ok "pr0 cannot read $p"; fi
  fi
done

echo "== 3. pr0 is not in the service group =="
if id -nG pr0 2>/dev/null | tr ' ' '\n' | grep -qx agentroom; then
  bad "pr0 is a member of group agentroom"
else
  ok "pr0 is not in group agentroom"
fi

echo "== 4. the service is not an arbitrary command runner =="
unit=/etc/systemd/system/agent-room-transport.service
if [ -f "$unit" ]; then
  grep -q '^User=agentroom' "$unit" && ok "unit runs as agentroom" || bad "unit does not set User=agentroom"
  grep -q '^KillMode=control-group' "$unit" && ok "unit uses cgroup kill" || bad "unit does not set KillMode=control-group"
  grep -q '^UMask=0077' "$unit" && ok "unit umask is 0077" || bad "unit umask is not 0077"
  grep -q '^InaccessiblePaths=/home/pr0' "$unit" && ok "unit cannot see /home/pr0" || bad "unit does not block /home/pr0"
  grep -qE '^ExecStart=.*transport_worker' "$unit" && ok "ExecStart is the fixed worker" || bad "ExecStart is not the fixed worker"
  grep -qE '^ExecStart=.*(\$|%[a-zA-Z])' "$unit" && bad "ExecStart interpolates a variable" || ok "ExecStart takes no variable argument"
else
  echo "  skip     $unit (not installed)"
fi

echo "== 5. the old bridge is not in the Agent Room path =="
if [ -f "$unit" ] && grep -qi "bridge" "$unit"; then
  bad "the transport unit references the generic bridge"
else
  ok "the transport unit does not reference the generic bridge"
fi

echo
echo "pass=$PASS fail=$FAIL blockers=$BLOCK"
[ "$BLOCK" -gt 0 ] && echo "RESULT: BLOCKED — do not activate" && exit 2
[ "$FAIL" -gt 0 ] && echo "RESULT: FAILED" && exit 1
echo "RESULT: boundary holds"
