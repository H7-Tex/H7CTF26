#!/bin/bash
# On-pod setup for the shared H7 Qwen endpoint (qwen.h7tex.com).
# Ollama on localhost only; a path-allowlisting stdlib proxy on :8888 fronts it;
# a NAMED cloudflared tunnel publishes :8888 as qwen.h7tex.com. Serves BOTH the
# Ollama API (/api/*, model qwen2.5-coder:7b — argus) AND the OpenAI-compat API
# (/v1/*, model Qwen2.5-Coder-7B-Instruct — echo_chamber) off one model blob.
# Idempotent. Writes /tmp/qwen_ready. Inputs via env:
#   QWEN_HOSTNAME   (e.g. qwen.h7tex.com)
#   TUNNEL_ID       (cloudflared named-tunnel UUID)
#   TUNNEL_CRED_B64 (base64 of the tunnel credentials json)
set +e
export DEBIAN_FRONTEND=noninteractive
MODEL=qwen2.5-coder:7b
ALIAS=Qwen2.5-Coder-7B-Instruct         # echo_chamber's required /v1 model name
WANT=dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364
HOSTNAME_="${QWEN_HOSTNAME:?set QWEN_HOSTNAME}"
TID="${TUNNEL_ID:?set TUNNEL_ID}"
[ -n "$TUNNEL_CRED_B64" ] || { echo "set TUNNEL_CRED_B64"; exit 1; }

# --- ollama (localhost only) ---
command -v zstd   >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq zstd; }
command -v ollama >/dev/null 2>&1 || curl -fsSL https://ollama.com/install.sh | sh
pkill -x ollama 2>/dev/null; sleep 2
# store models on the network volume (mounted at /workspace) so they survive
# pod delete/recreate — no 5-min re-pull on the next bring-up. Falls back to
# container disk if no volume is mounted.
export OLLAMA_MODELS="${OLLAMA_MODELS:-/workspace/ollama}"
mkdir -p "$OLLAMA_MODELS" 2>/dev/null || export OLLAMA_MODELS=/root/.ollama
OLLAMA_HOST=127.0.0.1:11434 setsid nohup ollama serve >/tmp/ollama.log 2>&1 &
sleep 8
ollama list 2>/dev/null | grep -q "$MODEL" || ollama pull "$MODEL" >/tmp/pull.log 2>&1
# alias so the OpenAI-compat /v1 path accepts echo_chamber's model name (same blob)
ollama list 2>/dev/null | grep -qi "$ALIAS" || ollama cp "$MODEL" "$ALIAS" >/tmp/cp.log 2>&1

# --- path-allowlisting reverse proxy on :8888 ---
export QWEN_ALLOW_IPS="${QWEN_ALLOW_IPS:-8.234.96.51,193.123.254.10}"   # GKE egress (Cloud NAT) + atom
cat > /tmp/qwen_proxy.py <<'PY'
import http.server, socketserver, urllib.request, urllib.error, threading, time, os
OLLAMA = 'http://127.0.0.1:11434'
# only our internal callers may run inference. All tunnel traffic arrives via
# Cloudflare, which sets CF-Connecting-IP (the tunnel accepts nothing else), so
# it is trustworthy here. A request with no such header is a pod-local/direct
# call (127.0.0.1) and is allowed. Non-allowlisted public IPs get 403.
ALLOW_IPS = {ip for ip in os.environ.get('QWEN_ALLOW_IPS', '').split(',') if ip}
# only the inference surface both challenges use; everything else 404s
ALLOW_GET  = {'/api/tags', '/api/version', '/v1/models'}
ALLOW_POST = {'/api/chat', '/api/generate', '/api/embeddings', '/api/embed',
              '/v1/chat/completions', '/v1/completions', '/v1/embeddings'}
# crude global rate cap: token bucket, refill 8/s, burst 24 (challenges are low-QPS;
# this only bites if the hostname leaks and someone hammers it)
_lock = threading.Lock(); _tok = 24.0; _ts = time.time()
def allow():
    global _tok, _ts
    with _lock:
        now = time.time(); _tok = min(24.0, _tok + (now - _ts) * 8.0); _ts = now
        if _tok >= 1: _tok -= 1; return True
        return False
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def _send(self, code, body=b'', ct='application/json'):
        self.send_response(code); self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(body))); self.end_headers()
        if body: self.wfile.write(body)
    def _err(self, code):
        msgs = {404: b'{"error":"not found"}', 403: b'{"error":"forbidden"}', 429: b'{"error":"rate limited"}'}
        self._send(code, msgs.get(code, ('{"error":%d}' % code).encode()))
    def _ip_ok(self):
        cf = self.headers.get('CF-Connecting-IP')
        return (not cf) or (cf in ALLOW_IPS)   # no header = pod-local; else must be allowlisted
    def _proxy(self, allowed):
        # ALWAYS drain the request body first, before any early return — otherwise
        # an unread POST body corrupts the next request on a kept-alive connection
        # (the leftover bytes get parsed as the next request line → 501).
        n = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(n) if n else None
        if not self._ip_ok(): return self._err(403)               # gates every path, root included
        path = self.path.split('?', 1)[0]
        if path == '/': return self._send(200, b'{"service":"qwen","status":"ok"}')
        if path not in allowed: return self._err(404)
        if not allow(): return self._err(429)
        req = urllib.request.Request(OLLAMA + self.path, data=body, method=self.command)
        for h in ('Content-Type', 'Accept', 'Authorization'):
            if self.headers.get(h): req.add_header(h, self.headers[h])
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                data = r.read(); code, ct = r.status, r.headers.get('Content-Type', 'application/json')
        except urllib.error.HTTPError as e:
            data = e.read(); code, ct = e.code, e.headers.get('Content-Type', 'application/json')
        except Exception:
            return self._err(502)
        self.send_response(code); self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):  self._proxy(ALLOW_GET)
    def do_POST(self): self._proxy(ALLOW_POST)
    def log_message(self, *a): pass
class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True; allow_reuse_address = True
TS(('127.0.0.1', 8888), H).serve_forever()
PY
pkill -f qwen_proxy.py 2>/dev/null; sleep 1
PYB=$(command -v python3 || command -v python); setsid nohup "$PYB" /tmp/qwen_proxy.py >/tmp/proxy.log 2>&1 &
sleep 2

# --- named cloudflared tunnel -> the proxy ---
mkdir -p /root/.cloudflared
echo "$TUNNEL_CRED_B64" | base64 -d > "/root/.cloudflared/$TID.json"
# QWEN_HOSTNAME may be comma-separated (e.g. "qwen.h7tex.com,qwen.abu.rocks")
{
  echo "tunnel: $TID"
  echo "credentials-file: /root/.cloudflared/$TID.json"
  echo "ingress:"
  IFS=',' read -ra HS <<< "$HOSTNAME_"
  for h in "${HS[@]}"; do h=$(echo "$h" | tr -d ' '); [ -n "$h" ] && { echo "  - hostname: $h"; echo "    service: http://localhost:8888"; }; done
  echo "  - service: http_status:404"
} > /root/.cloudflared/config.yml
[ -x /usr/local/bin/cloudflared ] || { curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared; }
pkill -x cloudflared 2>/dev/null; sleep 1
setsid nohup /usr/local/bin/cloudflared --no-autoupdate --config /root/.cloudflared/config.yml tunnel run >/tmp/cf.log 2>&1 &
sleep 8

# --- verify locally (via the proxy) ---
D=$(curl -s --max-time 20 "http://127.0.0.1:8888/api/tags" | grep -oE 'dae161[a-f0-9]{58}' | head -1)
HAS_ALIAS=$(curl -s --max-time 15 "http://127.0.0.1:8888/v1/models" | grep -c "$ALIAS")
BLOCKED=$(curl -s --max-time 8 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8888/api/ps")
PRIMARY=$(echo "$HOSTNAME_" | cut -d, -f1)
{
  echo "QWEN_URL=https://$PRIMARY"
  echo "MODEL_OLLAMA=$MODEL"
  echo "MODEL_OPENAI=$ALIAS"
  echo "DIGEST=$D"
  echo "DIGEST_OK=$([ "$D" = "$WANT" ] && echo true || echo false)"
  echo "ALIAS_VISIBLE=$([ "${HAS_ALIAS:-0}" -ge 1 ] && echo true || echo false)"
  echo "ALLOWLIST_BLOCKS_OTHER=$([ "$BLOCKED" = 404 ] && echo true || echo false)"
} > /tmp/qwen_ready
cat /tmp/qwen_ready
