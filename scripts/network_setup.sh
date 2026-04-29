#!/usr/bin/env bash
set -euo pipefail

NAT_COMMENT="ChainReconNAT"
ETH_INTERFACE=""
INTERNET_INTERFACE=""
STATIC_IP="192.168.123.100"
SUBNET_PREFIX="24"
REMOVE=0

usage() {
  cat <<'USAGE'
ChainRecon - Linux Network Setup

Configures a Linux host as a NAT router for IoT traffic interception.
Requires root privileges.

Options:
  --eth-interface NAME        Interface connected to the IoT router.
  --internet-interface NAME   Interface with internet access.
  --static-ip IP              Static IPv4 address for the IoT-side interface.
  --subnet-prefix PREFIX      CIDR prefix length, default 24.
  --remove                    Remove ChainRecon forwarding/NAT rules.
  -h, --help                  Show this help.

Example:
  sudo bash scripts/network_setup.sh \
    --eth-interface eth0 \
    --internet-interface wlan0 \
    --static-ip 192.168.123.100 \
    --subnet-prefix 24
USAGE
}

log() {
  printf '[*] %s\n' "$1"
}

ok() {
  printf '    [+] %s\n' "$1"
}

warn() {
  printf '    [!] %s\n' "$1"
}

fail() {
  printf '    [!] %s\n' "$1" >&2
  exit 1
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    fail "Please run as root, for example: sudo bash scripts/network_setup.sh ..."
  fi
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "Required tool not found: $1"
}

iface_exists() {
  ip link show "$1" >/dev/null 2>&1
}

subnet_cidr() {
  python3 - "$STATIC_IP" "$SUBNET_PREFIX" <<'PY'
import ipaddress
import sys

ip = sys.argv[1]
prefix = int(sys.argv[2])
print(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
PY
}

has_iptables_rule() {
  iptables "$@" >/dev/null 2>&1
}

add_iptables_rule_once() {
  local table_flag=()
  if [ "$1" = "-t" ]; then
    table_flag=("-t" "$2")
    shift 2
  fi
  local chain="$1"
  shift
  if has_iptables_rule "${table_flag[@]}" -C "$chain" "$@"; then
    ok "Rule already present: ${table_flag[*]} $chain $*"
  else
    iptables "${table_flag[@]}" -A "$chain" "$@"
    ok "Added rule: ${table_flag[*]} $chain $*"
  fi
}

delete_iptables_rule_if_present() {
  local table_flag=()
  if [ "$1" = "-t" ]; then
    table_flag=("-t" "$2")
    shift 2
  fi
  local chain="$1"
  shift
  while has_iptables_rule "${table_flag[@]}" -C "$chain" "$@"; do
    iptables "${table_flag[@]}" -D "$chain" "$@"
    ok "Removed rule: ${table_flag[*]} $chain $*"
  done
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --eth-interface)
      ETH_INTERFACE="${2:-}"
      shift 2
      ;;
    --internet-interface)
      INTERNET_INTERFACE="${2:-}"
      shift 2
      ;;
    --static-ip)
      STATIC_IP="${2:-}"
      shift 2
      ;;
    --subnet-prefix)
      SUBNET_PREFIX="${2:-}"
      shift 2
      ;;
    --remove)
      REMOVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

require_root
require_tool ip
require_tool iptables
require_tool sysctl
require_tool python3

[ -n "$ETH_INTERFACE" ] || fail "--eth-interface is required"
[ -n "$INTERNET_INTERFACE" ] || fail "--internet-interface is required"
iface_exists "$ETH_INTERFACE" || fail "Interface not found: $ETH_INTERFACE"
iface_exists "$INTERNET_INTERFACE" || fail "Interface not found: $INTERNET_INTERFACE"

STATIC_CIDR="${STATIC_IP}/${SUBNET_PREFIX}"
NETWORK_CIDR="$(subnet_cidr)"

if [ "$REMOVE" -eq 1 ]; then
  log "Removing ChainRecon Linux network configuration"
  delete_iptables_rule_if_present -t nat POSTROUTING -s "$NETWORK_CIDR" -o "$INTERNET_INTERFACE" -m comment --comment "$NAT_COMMENT" -j MASQUERADE
  delete_iptables_rule_if_present FORWARD -i "$ETH_INTERFACE" -o "$INTERNET_INTERFACE" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -m comment --comment "$NAT_COMMENT" -j ACCEPT
  delete_iptables_rule_if_present FORWARD -i "$INTERNET_INTERFACE" -o "$ETH_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$NAT_COMMENT" -j ACCEPT
  ip addr del "$STATIC_CIDR" dev "$ETH_INTERFACE" >/dev/null 2>&1 || warn "Static IP $STATIC_CIDR was not present on $ETH_INTERFACE"
  ok "Linux network teardown complete"
  exit 0
fi

log "Applying ChainRecon Linux network configuration"
printf '  Ethernet (IoT):  %s\n' "$ETH_INTERFACE"
printf '  Internet:        %s\n' "$INTERNET_INTERFACE"
printf '  Static IP:       %s\n' "$STATIC_CIDR"
printf '  NAT prefix:      %s\n' "$NETWORK_CIDR"

log "Bringing up $ETH_INTERFACE"
ip link set "$ETH_INTERFACE" up
ok "$ETH_INTERFACE is up"

log "Assigning static IP"
if ip addr show dev "$ETH_INTERFACE" | grep -q " ${STATIC_CIDR}"; then
  ok "$STATIC_CIDR already assigned to $ETH_INTERFACE"
else
  ip addr flush dev "$ETH_INTERFACE"
  ip addr add "$STATIC_CIDR" dev "$ETH_INTERFACE"
  ok "Assigned $STATIC_CIDR to $ETH_INTERFACE"
fi

log "Enabling IPv4 forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
ok "IPv4 forwarding enabled"

log "Configuring NAT and forwarding rules"
add_iptables_rule_once -t nat POSTROUTING -s "$NETWORK_CIDR" -o "$INTERNET_INTERFACE" -m comment --comment "$NAT_COMMENT" -j MASQUERADE
add_iptables_rule_once FORWARD -i "$ETH_INTERFACE" -o "$INTERNET_INTERFACE" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -m comment --comment "$NAT_COMMENT" -j ACCEPT
add_iptables_rule_once FORWARD -i "$INTERNET_INTERFACE" -o "$ETH_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$NAT_COMMENT" -j ACCEPT

ok "Network setup complete"
printf 'IoT devices can use %s as their gateway.\n' "$STATIC_IP"
printf 'Traffic flow: %s -> %s\n' "$ETH_INTERFACE" "$INTERNET_INTERFACE"
