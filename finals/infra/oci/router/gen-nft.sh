#!/usr/bin/env bash
# gen-nft.sh N > /etc/nftables.d/h7.nft
# generates the h7ctf'26 finals nftables ruleset.
# based on ECSC 2025 ctfroute, ENO rate limits, saarCTF prio.
#
# additions vs base recipe:
#   - hills subnet 10.60.210.0/24: team attacks allowed, prod blocked
#   - staging secondary IPs (10.60.T.3): checker-only, teams blocked
#
# [TESTED] nft -c exit 0, no errors: docker run --cap-add NET_ADMIN ubuntu:24.04, nftables 1.0.9 (22 Oct 2026).
# [LIVE] run `bash gen-nft.sh 15 | nft -c -f /dev/stdin` as root on r1 before rehearsal.
set -euo pipefail
N=${1:-15}; NOP=$((N+1))

s2t=(); owb=(); oprod=()
for t in $(seq 1 "$N"); do
  s2t+=("10.61.$t.0/24 : $t" "10.80.$t.0/24 : $t")
  owb+=("10.80.$t.0/24 . 10.61.$t.2")
  oprod+=("10.80.$t.0/24 . 10.60.$t.2" "10.61.$t.2 . 10.60.$t.2")
done
j() { local IFS=,; echo "$*"; }

cat <<NFT
destroy table inet h7
table inet h7 {
  # --- address sets ---
  set org       { type ipv4_addr; flags interval; elements = { 10.60.200.0/24, 10.60.201.20, 10.80.250.0/24 } }
  set prod      { type ipv4_addr; flags interval; elements = { 10.60.1.2-10.60.$NOP.2 } }
  # staging secondary IPs (.3 on every prod subnet); only checker may reach these
  set prod_stg  { type ipv4_addr; flags interval; elements = { 10.60.1.3-10.60.$NOP.3 } }
  set wb        { type ipv4_addr; flags interval; elements = { 10.61.1.2-10.61.$N.2 } }
  set boxes     { type ipv4_addr; flags interval; elements = { 10.60.1.2-10.60.$NOP.2, 10.61.1.2-10.61.$N.2 } }
  # hills: .2=GridWatch II, .3=Hostile Takeover II, .4=Harbor Master (each on a dedicated VM)
  set hills     { type ipv4_addr; flags interval; elements = { 10.60.210.0/24 } }
  set teamsrc   { type ipv4_addr; flags interval; elements = { 10.61.1.0-10.61.$N.255, 10.80.1.0-10.80.$N.255 } }
  # svc_ports: ports teams attack on prod (services on 7000-7007 + deployer hooks)
  set svc_ports { type inet_service; flags interval; elements = { 80, 1337, 5000-5099, 7000-7007, 8000-8099 } }
  map src2team  { type ipv4_addr : mark; flags interval; elements = { $(j "${s2t[@]}") } }
  set own_wb    { type ipv4_addr . ipv4_addr; flags interval; elements = { $(j "${owb[@]}") } }
  set own_prod  { type ipv4_addr . ipv4_addr; flags interval; elements = { $(j "${oprod[@]}") } }
  set ssh_ok    { type ipv4_addr . ipv4_addr; flags interval; }
  set game_open { type ipv4_addr; flags interval; }
  set bw        { type mark; size 64; flags dynamic,timeout; timeout 1m; }
  set newconn   { type mark . ipv4_addr; size 4096; flags dynamic,timeout; timeout 1m; }
  set concur    { type mark . ipv4_addr; size 4096; flags dynamic; }

  # --- input: traffic destined for the router itself ---
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    iifname "ens3" udp dport 443 accept                                    # WireGuard + wstunnel
    iifname "ens3" tcp dport 443 accept
    tcp dport 22 ip saddr { 193.123.254.10, 10.80.250.0/24, 10.60.200.0/24 } accept
    tcp dport 8081 ip saddr { 10.61.0.0/16, 10.80.0.0/16, 10.60.200.0/24 } accept  # pcap nginx
    tcp dport 9100 ip saddr 10.60.200.0/24 accept                          # prometheus scrape
    icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 50/second accept
    limit rate 10/second log prefix "h7-in-drop " level info
  }

  # --- forward: routed game traffic ---
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state invalid drop

    # anti-spoof: WireGuard packets must come from the WG address space
    iifname "wg0" ip saddr != 10.80.0.0/16 drop
    # nothing from the internet should have a 10.80.x source
    iifname "ens3" ip saddr 10.80.0.0/16 drop

    # organizer traffic (Anvil, ops, checker, staff) - unlimited, never paused
    ip saddr @org accept
    ip daddr @org ct state established,related accept

    # only TCP and ICMP from team sources; drop UDP/other (no DNS tunnels, no raw sockets)
    meta l4proto != { tcp, icmp } ip saddr @teamsrc counter drop

    # team byte policer: 6 MB/s per source team, burst 12 MB (ENO precedent)
    meta mark set ip saddr map @src2team
    jump pause
    meta mark != 0 update @bw { meta mark limit rate over 6 mbytes/second burst 12 mbytes } counter drop

    # established/related after the policer so every byte is counted
    ct state established,related accept

    # shared services: Anvil, mirror, Gitea, checker gate
    ip daddr 10.60.200.10 tcp dport { 80, 443, 1337, 4141 } accept        # Anvil (web, scoreboard, TCP flag submission :4141)
    ip daddr 10.60.202.10 tcp dport { 80, 3141, 3142, 4873, 5000, 8080, 9292 } accept  # mirror
    ip daddr 10.60.201.30 tcp dport 3000 accept                            # Gitea HTTP
    ip saddr @teamsrc ip daddr 10.60.201.30 tcp dport 2222 accept          # Gitea SSH (team push)
    ip saddr 10.60.201.30 ip daddr @prod tcp dport 9000 accept             # webhook: Gitea -> deployer
    ip saddr @prod ip daddr 10.60.202.10 tcp dport 5001 accept             # prod -> archive registry
    ip saddr @prod ip daddr 10.60.201.20 tcp dport 8000 accept             # prod -> checker gate API
    # prod can only initiate to mirror/Gitea/registry/checker; block everything else
    ip saddr @prod counter drop

    # staging secondary IPs: only checker runner may reach them
    ip saddr 10.60.201.20 ip daddr @prod_stg tcp dport @svc_ports accept
    ip daddr @prod_stg counter drop                                         # everyone else blocked

    # hills: teams can attack, prod blocked (prod already dropped above)
    ip saddr @teamsrc ip daddr @hills tcp dport { 80, 443, 8080, 9000-9099 } accept
    ip saddr @hills ip daddr 10.60.200.10 tcp dport { 80, 443, 4141 } accept  # hills -> Anvil (KOTH_VERIFY + flag submit)
    ip saddr @hills ip daddr != 10.60.200.10 counter drop                  # hills can't reach anything else

    # own-team access
    ip saddr . ip daddr @own_wb accept                                     # laptop/wg -> own workbench
    ip saddr . ip daddr @own_prod tcp dport @svc_ports accept              # own team -> own prod services
    ip saddr . ip daddr @own_prod tcp dport { 9100, 9101 } accept          # own team -> prod: metrics :9100, log stream :9101
    ip saddr . ip daddr @ssh_ok tcp dport 22 accept                        # fallback A SSH

    # cross-team attacks
    ip saddr @teamsrc ip daddr @prod tcp dport @svc_ports jump xteam
    ip saddr @teamsrc ip daddr @prod icmp type echo-request limit rate 20/second accept
    limit rate 20/second log prefix "h7-fwd-drop " level info
  }

  # pause chain: empty at start; "nft add rule inet h7 pause ..." to block all except Anvil
  chain pause {
  }

  # cross-team rate limits
  chain xteam {
    ct state new add @concur { meta mark . ip daddr ct count over 256 } counter drop  # conn-hold DoS
    ct state new update @newconn { meta mark . ip daddr limit rate over 50/second burst 100 packets } counter drop
    ip saddr @game_open accept
  }

  # normalization on packets leaving towards game boxes (checker hygiene)
  # [LIVE] ip ttl set, ip dscp set, ip ecn set require root; tested parse-only in user ns
  chain norm {
    type filter hook postrouting priority mangle; policy accept;
    oifname "ens3" ip daddr @boxes jump norm_game
    oifname "wg0" tcp flags & syn == syn tcp option maxseg size set rt mtu
  }

  chain norm_game {
    # TTL set AFTER kernel's decrement, so arriving boxes see exactly 48
    ip ttl set 48
    ip dscp set 0
    ip ecn set 0
    # MSS 1240 = WireGuard MTU 1280 - 40 bytes; kernel never raises MSS
    tcp flags & syn == syn tcp option maxseg size set 1240
    # blank TCP timestamps, window scaling and SACK-permitted for the whole connection (RFC 7323/2018)
    tcp flags & syn == syn reset tcp option timestamp
    tcp flags & syn == syn reset tcp option window
    tcp flags & syn == syn reset tcp option sack-perm
  }

  # SNAT: everything forwarded into the VCN leaves from the float IP
  # fully-random to hide attacker OS port patterns
  chain nat_out {
    type nat hook postrouting priority srcnat; policy accept;
    # exclude router IPs and org WG range; anonymize only team attack traffic
    oifname "ens3" ip saddr != { 10.60.250.10, 10.60.250.11, 10.60.250.100, 10.80.250.0/24 } \
      ip daddr 10.60.0.0/15 snat ip to 10.60.250.100 fully-random
  }
}
NFT
