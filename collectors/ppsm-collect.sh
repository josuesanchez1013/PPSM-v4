#!/usr/bin/env bash
# ppsm-collect.sh — PPSM data collection for Linux
#
# Collects listening ports and active connections with the owning process,
# plus the local name sources, into one results folder that PPSM Builder
# reads directly. Nothing is uploaded; everything stays on the machine.
#
#   ./ppsm-collect.sh                        # this host
#   ./ppsm-collect.sh -o /tmp/ppsm           # choose the output folder
#   ./ppsm-collect.sh -H hosts.txt           # also collect over SSH
#   ./ppsm-collect.sh -L                     # listeners only, no connections
#
# Run with sudo where you can: without it the process name against each port
# is missing, and that is the field that proves a port is a real service.

set -uo pipefail

OUT="./ppsm-results"
HOSTLIST=""
LISTEN_ONLY=0
SSH_USER="${USER:-root}"

while getopts ":o:H:u:Lh" opt; do
  case $opt in
    o) OUT="$OPTARG" ;;
    H) HOSTLIST="$OPTARG" ;;
    u) SSH_USER="$OPTARG" ;;
    L) LISTEN_ONLY=1 ;;
    h) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option -$OPTARG"; exit 1 ;;
  esac
done

mkdir -p "$OUT/hosts" "$OUT/inventory" "$OUT/network"
STARTED=$(date '+%Y-%m-%d %H:%M:%S')
MANIFEST=""
REACHED=0
FAILED=""

say()  { printf '[%s] %s\n' "$1" "$2"; }
ok()   { printf '    ok   %s\n' "$1"; }
skip() { printf '    skip %s\n' "$1"; }
bad()  { printf '    FAIL %s\n' "$1"; }

# The one command that does the most work. ss reports listeners, active
# connections, and the process behind each socket in a single pass.
collect_cmd() {
  # one pass: listeners, active connections and the process behind each socket
  if [ "$LISTEN_ONLY" -eq 1 ]; then
    echo 'ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null'
  else
    echo 'ss -tuanp 2>/dev/null || netstat -tunapl 2>/dev/null'
  fi
}

printf '\nPPSM collection\n'
printf '  output : %s\n\n' "$OUT"

# ---------------------------------------------------------------- local host
say 1 "Collecting listening ports and active connections"
HN=$(hostname -s 2>/dev/null || hostname 2>/dev/null || cut -d. -f1 /etc/hostname)
if command -v ss >/dev/null 2>&1 || command -v netstat >/dev/null 2>&1; then
  # awk rather than grep -P: PCRE is not guaranteed to be compiled in
  MYIP=$(ip route get 192.0.2.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1); exit}')
  { printf '# ppsm-host: %s\n# ppsm-ip: %s\n' "$HN" "${MYIP:-}"; eval "$(collect_cmd)"; } \
    > "$OUT/hosts/${HN}-sockets.txt" 2>/dev/null
  N=$(grep -cE 'LISTEN|ESTAB' "$OUT/hosts/${HN}-sockets.txt" 2>/dev/null || echo 0)
  MANIFEST="${MANIFEST}hosts/${HN}-sockets.txt  ${N} sockets\n"
  ok "$HN — $N sockets"
  REACHED=$((REACHED+1))
  [ "$(id -u)" -ne 0 ] && skip "not root, so process names are missing — re-run with sudo for a defensible register"
else
  bad "neither ss nor netstat is available on this host"
fi

# ---------------------------------------------------------------- remote hosts
if [ -n "$HOSTLIST" ] && [ -f "$HOSTLIST" ]; then
  say 2 "Collecting from the hosts in $HOSTLIST over SSH"
  while IFS= read -r h; do
    h="$(echo "$h" | tr -d '\r' | sed 's/#.*//' | xargs)"
    [ -z "$h" ] && continue
    if { printf '# ppsm-host: %s\n' "$h"; \
         ssh -o BatchMode=yes -o ConnectTimeout=8 "${SSH_USER}@${h}" "$(collect_cmd)"; } \
         > "$OUT/hosts/${h}-sockets.txt" 2>/dev/null; then
      N=$(grep -cE 'LISTEN|ESTAB' "$OUT/hosts/${h}-sockets.txt" 2>/dev/null || echo 0)
      MANIFEST="${MANIFEST}hosts/${h}-sockets.txt  ${N} sockets\n"
      ok "$h — $N sockets"
      REACHED=$((REACHED+1))
    else
      rm -f "$OUT/hosts/${h}-sockets.txt"
      bad "$h — unreachable or SSH key not accepted"
      FAILED="${FAILED}${h} "
    fi
  done < "$HOSTLIST"
else
  say 2 "No host list given, so only this machine was collected"
fi

# ---------------------------------------------------------------- name sources
say 3 "Collecting name sources"
if [ -f /etc/hosts ]; then
  cp /etc/hosts "$OUT/inventory/hosts-file.txt" 2>/dev/null && \
    { MANIFEST="${MANIFEST}inventory/hosts-file.txt\n"; ok "/etc/hosts"; }
fi
# net-tools (arp) is not installed on RHEL 8/9; ip is always there
if command -v ip >/dev/null 2>&1; then
  ip neigh > "$OUT/inventory/arp-table.txt" 2>/dev/null && \
    { MANIFEST="${MANIFEST}inventory/arp-table.txt\n"; ok "neighbour table"; }
elif command -v arp >/dev/null 2>&1; then
  arp -a > "$OUT/inventory/arp-table.txt" 2>/dev/null && \
    { MANIFEST="${MANIFEST}inventory/arp-table.txt\n"; ok "arp table"; }
fi
# DNS zone files, forward and reverse, if this host serves DNS
ZN=0
for d in /var/named /etc/bind /var/lib/bind /etc/named /var/named/chroot/var/named; do
  [ -d "$d" ] || continue
  for z in "$d"/*.zone "$d"/*.db "$d"/db.* "$d"/*.rev "$d"/*.in-addr.arpa "$d"/*.hosts; do
    [ -f "$z" ] || continue
    case "$(basename "$z")" in db.local|db.127|db.0|db.255|db.empty|db.root|named.*) continue;; esac
    cp "$z" "$OUT/inventory/zone-$(basename "$z")" 2>/dev/null && ZN=$((ZN+1))
  done
done
if [ "$ZN" -gt 0 ]; then MANIFEST="${MANIFEST}inventory/zone-*  ${ZN} zone files\n"; ok "$ZN DNS zone file(s)"; fi

for f in /var/lib/dhcp/dhcpd.leases /var/lib/dhcpd/dhcpd.leases; do
  [ -f "$f" ] && cp "$f" "$OUT/inventory/dhcpd.leases" 2>/dev/null && \
    { MANIFEST="${MANIFEST}inventory/dhcpd.leases\n"; ok "DHCP leases"; break; }
done

# ---------------------------------------------------------------- readme
cat > "$OUT/READ-ME.txt" <<EOF
PPSM collection results
=======================
Collected : $STARTED
By        : $(id -un)@$(hostname)
Reached   : $REACHED host(s)
$( [ -n "$FAILED" ] && echo "Unreachable: $FAILED" )

WHAT TO DO WITH THIS FOLDER
  1. Start PPSM Builder (python3 ppsm.py).
  2. Set the subnet-to-enclave map under Settings.
  3. Select every file in hosts/ and inventory/ and drop them on the Ingest box.
  4. Press Finish Register.

FILES
$(printf "$MANIFEST")

STILL TO COLLECT BY HAND (the two the script cannot reach)
  - Firewall connection table:  show conn all                              -> network/
  - Switch NetFlow cache:       show flow monitor <name> cache format csv  -> network/
  Save both as .txt or .csv in the network/ folder, then re-import.
EOF

printf '\nDone. %s host(s) collected.\n' "$REACHED"
printf 'Results: %s\n' "$(cd "$OUT" && pwd)"
[ -n "$FAILED" ] && printf 'Unreachable: %s\n' "$FAILED"
printf '\n'
