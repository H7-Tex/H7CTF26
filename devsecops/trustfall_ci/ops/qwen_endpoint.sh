#!/usr/bin/env bash
# Trustfall CI — Qwen endpoint lifecycle for testing (and event bring-up).
#
#   ./qwen_endpoint.sh spin       # rent a GPU pod, serve ollama qwen2.5-coder:7b
#                                  # behind a secret-path tunnel, print OLLAMA_URL
#   ./qwen_endpoint.sh patch      # point the trustfall-ci challenge at that URL
#   ./qwen_endpoint.sh test       # launch instance -> solve -> submit -> stop
#   ./qwen_endpoint.sh teardown   # delete the pod (and any volume) — bills stop
#   ./qwen_endpoint.sh status     # pod + endpoint reachability
#   ./qwen_endpoint.sh all        # spin + patch + test  (leaves pod up)
#
# The Ollama API is reachable ONLY at  https://<tunnel>/<secret>  — the bare
# tunnel 404s, so participants who learn the hostname still can't hit the GPU.
# The secret lives only in the agents pod's OLLAMA_URL env.
#
# Prereqs: RUNPOD_API_KEY in CTF26/.env (this repo's account key), this machine's
# ssh key registered on the RunPod account (it is: "abu-eris-gpu"), ssh access to
# `atom` for the platform calls (dbq/start_instance/submit).
#
# NOTE ON podguard: atom runs /tmp/podguard*.sh which kills any RunPod pod with
# no live `gpufarm` job (a training-cost safety) — it will kill this pod too.
# This script names the pod "anvil-qwen"; for the event, whitelist that name in
# podguard (skip pods named anvil-qwen) or run challenge GPUs on a separate key.
# For a test run, ensure podguard is disabled first.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="$HERE/.qwen_state"
ENVFILE="${ENVFILE:-/home/abu/Main/Projects/CTF26/.env}"
SSHKEY="${SSHKEY:-$HOME/.ssh/id_ed25519}"
UA="eris-harness/1.0"
API="https://rest.runpod.io/v1"
GQL="https://api.runpod.io/graphql"
GPU="NVIDIA A40"; DC="EU-SE-1"; DISK=50
IMAGE="runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404"
MODEL="qwen2.5-coder:7b"
WANT_DIGEST="dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"
SLUG="trustfall-ci"; ADMIN="d48ab2e3-424c-4ac9-904a-7dcb1dab936c"
AR_IMAGE="asia-south1-docker.pkg.dev/project-c36a8ca6-dbc7-4a90-9d2/anvil/h7ctf26/trustfall_ci"

KEY=$(grep -E '^RUNPOD_API_KEY=' "$ENVFILE" | cut -d= -f2- | tr -d '"'\'' ')
[ -n "$KEY" ] || { echo "no RUNPOD_API_KEY in $ENVFILE"; exit 1; }
rp() { curl -s -H "Authorization: Bearer $KEY" -H "User-Agent: $UA" -H "Content-Type: application/json" "$@"; }
sshpod() { ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o ServerAliveInterval=15 -i "$SSHKEY" -p "$2" "root@$1" "${@:3}"; }
say() { echo -e "[qwen] $*"; }

spin() {
  local pub; pub=$(cat "$SSHKEY.pub")
  say "creating $GPU pod in $DC ..."
  local body resp pid
  body=$(python3 -c "import json,sys;print(json.dumps({'cloudType':'SECURE','gpuTypeIds':[sys.argv[1]],'gpuCount':1,'imageName':sys.argv[2],'containerDiskInGb':int(sys.argv[3]),'volumeInGb':0,'ports':['22/tcp'],'name':'anvil-qwen','dataCenterIds':[sys.argv[4]],'env':{'PUBLIC_KEY':sys.argv[5]}}))" "$GPU" "$IMAGE" "$DISK" "$DC" "$pub")
  resp=$(rp -X POST -d "$body" "$API/pods")
  pid=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  [ -n "$pid" ] || { echo "create failed: $resp"; exit 1; }
  say "pod $pid — waiting for ssh ..."
  local ip port
  for _ in $(seq 1 60); do
    read -r ip port < <(rp "$API/pods/$pid" | python3 -c "import sys,json
d=json.load(sys.stdin); pm=d.get('portMappings') or {}
ip=d.get('publicIp'); p=pm.get('22') if isinstance(pm,dict) else None
print(ip,p) if ip and p else print('')" 2>/dev/null)
    [ -n "${ip:-}" ] && [ -n "${port:-}" ] && break; sleep 8
  done
  [ -n "${ip:-}" ] || { echo "no ssh endpoint; pod $pid"; echo "POD_ID=$pid" > "$STATE"; exit 1; }
  for _ in $(seq 1 30); do sshpod "$ip" "$port" echo ok 2>/dev/null | grep -q ok && break; sleep 5; done
  say "ssh up ($ip:$port) — running secure setup (model pull ~5 min) ..."
  base64 -w0 "$HERE/pod_setup_secure.sh" | sshpod "$ip" "$port" 'base64 -d > /tmp/setup.sh; setsid nohup bash /tmp/setup.sh >/tmp/setup.log 2>&1 </dev/null & echo launched' >/dev/null
  local ready=""
  for _ in $(seq 1 60); do
    ready=$(sshpod "$ip" "$port" 'cat /tmp/qwen_ready 2>/dev/null' 2>/dev/null)
    echo "$ready" | grep -q 'OLLAMA_URL=' && break; sleep 10
  done
  local url; url=$(echo "$ready" | grep '^OLLAMA_URL=' | cut -d= -f2-)
  [ -n "$url" ] || { echo "setup did not finish; check pod $pid /tmp/setup.log"; exit 1; }
  { echo "POD_ID=$pid"; echo "SSH=$ip:$port"; echo "$ready"; } > "$STATE"
  say "verifying external gate ..."
  local sd bare
  sd=$(curl -s --max-time 20 "$url/api/tags" | grep -oE 'dae161[a-f0-9]{58}' | head -1)
  bare=$(curl -s --max-time 15 -o /dev/null -w '%{http_code}' "${url%/*}/api/tags")
  echo "-----------------------------------------------------------"
  echo "OLLAMA_URL      = $url"
  echo "external digest = ${sd:-MISSING} (want ${WANT_DIGEST:0:12}..)"
  echo "external bare   = HTTP $bare (want 404)"
  echo "-----------------------------------------------------------"
  [ "$sd" = "$WANT_DIGEST" ] && [ "$bare" = "404" ] && say "endpoint OK + locked down" || say "WARN: verify above"
}

patch() {
  local url; url=$(grep '^OLLAMA_URL=' "$STATE" 2>/dev/null | cut -d= -f2-)
  [ -n "$url" ] || { echo "no OLLAMA_URL in $STATE — run spin first"; exit 1; }
  say "pointing $SLUG at $url"
  # container_spec is a bare JSON array of service objects; rewrite the agents role's OLLAMA_URL
  ssh atom "bash ~/dbq.sh \"UPDATE challenges SET container_image='$AR_IMAGE', container_spec=(select jsonb_agg(case when e->>'name'='agents' then jsonb_set(e,'{env,OLLAMA_URL}',to_jsonb('$url'::text)) else e end) from jsonb_array_elements(container_spec) e) WHERE slug='$SLUG'\"" 2>&1 | grep -iE 'UPDATE|ERROR'
}

test_e2e() {
  say "launching instance ..."
  local resp portal; resp=$(ssh atom "bash ~/start_instance.sh $ADMIN $SLUG" 2>/dev/null | grep -viE 'psql-tmp|pod anvil|warning:|falling back|===')
  portal=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin)['instance']['endpoints'][0]['connect'])" 2>/dev/null)
  [ -n "$portal" ] || { echo "launch failed: $resp"; exit 1; }
  local iid; iid=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin)['instance']['id'])")
  say "portal=$portal instance=$iid — waiting for readiness ..."
  for _ in $(seq 1 15); do [ "$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' "$portal/api/repository")" = 200 ] && break; sleep 8; done
  say "running solve ..."
  local flag; flag=$(cd "$HERE/../solution" && TRUSTFALL_URL="$portal" timeout 220 python3 solve.py 2>/dev/null | tail -1)
  say "flag=$flag"
  echo "$flag" | grep -q '^H7CTF{' || { echo "solve failed"; ssh atom "bash ~/stop_instance.sh $ADMIN $iid" >/dev/null 2>&1; exit 1; }
  say "submitting ..."
  ssh atom "bash ~/submit_flag.sh $ADMIN $SLUG '$flag'" 2>/dev/null | grep -iE 'correct|message'
  say "stopping instance $iid ..."
  ssh atom "bash ~/stop_instance.sh $ADMIN $iid" 2>/dev/null | grep -iE 'stopped|message' || true
}

teardown() {
  local pid; pid=$(grep '^POD_ID=' "$STATE" 2>/dev/null | cut -d= -f2)
  [ -n "$pid" ] || { echo "no POD_ID in $STATE"; exit 0; }
  say "deleting pod $pid ..."
  rp -X DELETE "$API/pods/$pid" >/dev/null
  sleep 2
  local pods vols; pods=$(rp "$API/pods" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d if isinstance(d,list) else d.get('pods',[])))" 2>/dev/null)
  say "pods now: ${pods:-?} (network volumes: check console). state cleared."
  rm -f "$STATE"
}

status() {
  [ -f "$STATE" ] && cat "$STATE" || echo "(no active endpoint)"
  local url; url=$(grep '^OLLAMA_URL=' "$STATE" 2>/dev/null | cut -d= -f2-)
  [ -n "$url" ] && echo "reachable digest: $(curl -s --max-time 15 "$url/api/tags" | grep -oE 'dae161[a-f0-9]{58}' | head -1 || echo DOWN)"
}

case "${1:-}" in
  spin) spin ;;
  patch) patch ;;
  test) test_e2e ;;
  teardown) teardown ;;
  status) status ;;
  all) spin && patch && test_e2e ;;
  *) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
