#!/usr/bin/env bash
# Shared H7 Qwen endpoint lifecycle: a STABLE, named-tunnel endpoint at
# qwen.h7tex.com serving both the Ollama API (argus) and the OpenAI-compat API
# (echo_chamber) off one qwen2.5-coder:7b blob.
#
#   ./service.sh spin      # rent A40, wait for ssh
#   ./service.sh tunnel    # ensure the named cf tunnel + qwen.h7tex.com DNS (on atom)
#   ./service.sh setup     # ollama+model+proxy+tunnel on the pod
#   ./service.sh verify    # external checks against https://qwen.h7tex.com
#   ./service.sh up        # spin + tunnel + setup + verify
#   ./service.sh status    # pod + endpoint reachability
#   ./service.sh teardown  # delete the pod (billing stops); tunnel+DNS persist
#
# The pod runs the named tunnel itself (scoped creds copied in). Cloudflare fronts
# it; the pod proxy path-allowlists the inference surface only. Not player-exposed.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="$HERE/.qwen_state"
ENVFILE="${ENVFILE:-/home/abu/Main/Projects/CTF26/.env}"
SSHKEY="${SSHKEY:-$HOME/.ssh/id_ed25519}"
UA="eris-harness/1.0"; API="https://rest.runpod.io/v1"
GPU="${GPU:-NVIDIA A40}"; DC="${DC:-EU-SE-1}"; DISK=50
IMAGE="runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404"
HOSTNAME_="${QWEN_HOSTNAME:-qwen.h7tex.com}"   # canonical; qwen.abu.rocks was a fallback alias
TUNNEL_NAME="${TUNNEL_NAME:-anvil-qwen}"
NETWORK_VOLUME_ID="${NETWORK_VOLUME_ID:-}"   # if set: mount at /workspace, persist ollama models across pod delete/recreate
WANT_DIGEST="dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"

KEY=$(grep -E '^RUNPOD_API_KEY=' "$ENVFILE" | cut -d= -f2- | tr -d '"'\'' ')
[ -n "$KEY" ] || { echo "no RUNPOD_API_KEY in $ENVFILE"; exit 1; }
rp()  { curl -s -H "Authorization: Bearer $KEY" -H "User-Agent: $UA" -H "Content-Type: application/json" "$@"; }
pod() { ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o ServerAliveInterval=15 -i "$SSHKEY" -p "$2" "root@$1" "${@:3}"; }
say() { echo -e "[qwen] $*"; }
sv()  { grep "^$1=" "$STATE" 2>/dev/null | cut -d= -f2-; }

spin() {
  local existing; existing=$(sv POD_ID)
  if [ -n "$existing" ]; then say "pod already in state: $existing (teardown first to replace)"; return 0; fi
  local pub; pub=$(cat "$SSHKEY.pub")
  say "creating $GPU pod in $DC ..."
  local body resp pid
  body=$(NETWORK_VOLUME_ID="$NETWORK_VOLUME_ID" python3 -c "import json,os,sys
b={'cloudType':'SECURE','gpuTypeIds':[sys.argv[1]],'gpuCount':1,'imageName':sys.argv[2],'containerDiskInGb':int(sys.argv[3]),'volumeInGb':0,'ports':['22/tcp'],'name':'anvil-qwen','dataCenterIds':[sys.argv[4]],'env':{'PUBLIC_KEY':sys.argv[5]}}
vid=os.environ.get('NETWORK_VOLUME_ID','')
if vid:
    b['networkVolumeId']=vid; b['volumeMountPath']='/workspace'; b['env']['OLLAMA_MODELS']='/workspace/ollama'
print(json.dumps(b))" "$GPU" "$IMAGE" "$DISK" "$DC" "$pub")
  resp=$(rp -X POST -d "$body" "$API/pods")
  pid=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  [ -n "$pid" ] || { echo "create failed: $resp"; exit 1; }
  say "pod $pid - waiting for ssh endpoint ..."
  local ip port
  for _ in $(seq 1 60); do
    read -r ip port < <(rp "$API/pods/$pid" | python3 -c "import sys,json
d=json.load(sys.stdin); pm=d.get('portMappings') or {}
ip=d.get('publicIp'); p=pm.get('22') if isinstance(pm,dict) else None
print(ip,p) if ip and p else print('')" 2>/dev/null)
    [ -n "${ip:-}" ] && [ -n "${port:-}" ] && break; sleep 8
  done
  [ -n "${ip:-}" ] || { echo "no ssh endpoint after wait; pod=$pid (check runpod console)"; echo "POD_ID=$pid" > "$STATE"; exit 1; }
  for _ in $(seq 1 40); do pod "$ip" "$port" echo ok 2>/dev/null | grep -q ok && break; sleep 5; done
  { echo "POD_ID=$pid"; echo "SSH=$ip:$port"; } > "$STATE"
  say "ssh up ($ip:$port)"
}

tunnel() {
  say "ensuring named tunnel '$TUNNEL_NAME' + DNS $HOSTNAME_ (on atom) ..."
  # create tunnel if absent, route DNS, emit TUNNEL_ID + base64 creds
  local out; out=$(ssh atom "export PATH=\$PATH:/usr/local/bin:/usr/bin
tid=\$(cloudflared tunnel list 2>/dev/null | awk '\$2==\"$TUNNEL_NAME\"{print \$1}')
[ -n \"\$tid\" ] || { cloudflared tunnel create $TUNNEL_NAME >/tmp/cft.log 2>&1; tid=\$(cloudflared tunnel list 2>/dev/null | awk '\$2==\"$TUNNEL_NAME\"{print \$1}'); }
[ -n \"\$tid\" ] || { echo 'TUNNEL_CREATE_FAILED'; cat /tmp/cft.log; exit 1; }
cloudflared tunnel route dns $TUNNEL_NAME $HOSTNAME_ >/tmp/cfdns.log 2>&1
dns_rc=\$?
echo TID=\$tid
echo DNS_RC=\$dns_rc
grep -qiE 'already|created|added|CNAME' /tmp/cfdns.log && echo DNS_OK=true || { echo DNS_OK=false; echo DNS_LOG:; cat /tmp/cfdns.log; }
echo CRED_B64=\$(base64 -w0 ~/.cloudflared/\$tid.json 2>/dev/null)
" 2>&1)
  echo "$out" | grep -vE '^CRED_B64=' | sed 's/^/    /'
  local tid cred
  tid=$(echo "$out"  | grep '^TID='      | cut -d= -f2-)
  cred=$(echo "$out" | grep '^CRED_B64=' | cut -d= -f2-)
  [ -n "$tid" ] && [ -n "$cred" ] || { echo "tunnel setup failed (see above)"; exit 1; }
  grep -v '^TUNNEL_ID=\|^TUNNEL_CRED_B64=' "$STATE" > "$STATE.tmp" 2>/dev/null; mv "$STATE.tmp" "$STATE" 2>/dev/null
  { echo "TUNNEL_ID=$tid"; echo "TUNNEL_CRED_B64=$cred"; } >> "$STATE"
  say "tunnel id=$tid  dns=$HOSTNAME_"
}

setup() {
  local ssh_ip ssh_port; ssh_ip=$(sv SSH | cut -d: -f1); ssh_port=$(sv SSH | cut -d: -f2)
  local tid cred; tid=$(sv TUNNEL_ID); cred=$(sv TUNNEL_CRED_B64)
  [ -n "$ssh_ip" ] && [ -n "$tid" ] && [ -n "$cred" ] || { echo "need spin + tunnel first"; exit 1; }
  say "pushing setup to pod (ollama pull ~5 min) ..."
  pod "$ssh_ip" "$ssh_port" "rm -f /tmp/qwen_ready" 2>/dev/null
  base64 -w0 "$HERE/setup.sh" | pod "$ssh_ip" "$ssh_port" "base64 -d > /tmp/setup.sh; \
QWEN_HOSTNAME='$HOSTNAME_' TUNNEL_ID='$tid' TUNNEL_CRED_B64='$cred' \
setsid nohup bash /tmp/setup.sh >/tmp/setup.log 2>&1 </dev/null & echo launched" >/dev/null
  local ready=""
  for _ in $(seq 1 60); do
    ready=$(pod "$ssh_ip" "$ssh_port" 'cat /tmp/qwen_ready 2>/dev/null' 2>/dev/null)
    echo "$ready" | grep -q 'QWEN_URL=' && break; sleep 10
  done
  [ -n "$ready" ] || { echo "setup did not finish; ssh -p $ssh_port root@$ssh_ip 'tail /tmp/setup.log'"; exit 1; }
  echo "$ready" | sed 's/^/    /'
}

verify() {
  local u="https://$(echo "$HOSTNAME_" | cut -d, -f1)"
  say "external checks against $u ..."
  local d chat models blocked
  d=$(curl -s --max-time 25 "$u/api/tags" | grep -oE 'dae161[a-f0-9]{58}' | head -1)
  models=$(curl -s --max-time 15 "$u/v1/models" | grep -c 'Qwen2.5-Coder-7B-Instruct')
  chat=$(curl -s --max-time 90 "$u/v1/chat/completions" -H 'Content-Type: application/json' \
    -d '{"model":"Qwen2.5-Coder-7B-Instruct","messages":[{"role":"user","content":"reply with the single word: pong"}],"max_tokens":8,"temperature":0}' \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['choices'][0]['message']['content'].strip())" 2>/dev/null)
  blocked=$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' "$u/api/ps")
  echo "    /api/tags digest : ${d:-MISSING} (want ${WANT_DIGEST:0:12}..)"
  echo "    /v1/models alias : $([ "${models:-0}" -ge 1 ] && echo present || echo MISSING)"
  echo "    /v1 chat reply   : ${chat:-FAILED}"
  echo "    allowlist (/api/ps -> want 404): $blocked"
  [ "$d" = "$WANT_DIGEST" ] && [ "${models:-0}" -ge 1 ] && [ -n "$chat" ] && [ "$blocked" = 404 ] \
    && say "ENDPOINT OK" || { say "WARN: verify above"; return 1; }
}

status() {
  [ -f "$STATE" ] && grep -vE '^TUNNEL_CRED_B64=' "$STATE" || echo "(no state)"
  local u="https://$(echo "$HOSTNAME_" | cut -d, -f1)"
  echo "reachable digest: $(curl -s --max-time 15 "$u/api/tags" | grep -oE 'dae161[a-f0-9]{58}' | head -1 || echo DOWN)"
}

teardown() {
  local pid; pid=$(sv POD_ID)
  [ -n "$pid" ] || { echo "no POD_ID in state"; exit 0; }
  say "deleting pod $pid ..."; rp -X DELETE "$API/pods/$pid" >/dev/null; sleep 2
  grep -vE '^POD_ID=|^SSH=' "$STATE" > "$STATE.tmp" 2>/dev/null; mv "$STATE.tmp" "$STATE" 2>/dev/null
  say "pod deleted (billing stops). tunnel '$TUNNEL_NAME' + DNS $HOSTNAME_ kept for reuse."
}

case "${1:-}" in
  spin) spin ;; tunnel) tunnel ;; setup) setup ;; verify) verify ;;
  up) spin && tunnel && setup && verify ;;
  status) status ;; teardown) teardown ;;
  *) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
