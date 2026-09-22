#!/bin/bash
# Canonical secure on-pod setup for the trustfall_ci Qwen endpoint.
# Ollama listens on localhost ONLY; a tiny stdlib Python reverse proxy exposes
# just /<secret>/... to the cloudflared tunnel (everything else 404s). The agents
# role gets OLLAMA_URL = https://<tunnel>/<secret>. Idempotent; writes /tmp/qwen_ready.
set +e
export DEBIAN_FRONTEND=noninteractive
WANT=dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364
MODEL=qwen2.5-coder:7b

# stable per-pod secret path
SECRET=$(cat /tmp/qwen_secret 2>/dev/null)
[ -n "$SECRET" ] || { SECRET=$(openssl rand -hex 24); echo "$SECRET" > /tmp/qwen_secret; }

# ollama installer needs zstd (the pytorch image lacks it)
command -v zstd   >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq zstd; }
command -v ollama >/dev/null 2>&1 || curl -fsSL https://ollama.com/install.sh | sh

# ollama bound to localhost only (never on a public interface)
pkill -x ollama 2>/dev/null; sleep 2
OLLAMA_HOST=127.0.0.1:11434 setsid nohup ollama serve >/tmp/ollama.log 2>&1 &
sleep 8
ollama list 2>/dev/null | grep -q "$MODEL" || ollama pull "$MODEL" >/tmp/pull.log 2>&1

# secret-path reverse proxy (stdlib; no service-manager surprises like nginx had)
cat > /tmp/qwen_proxy.py <<'PY'
import http.server, socketserver, urllib.request, urllib.error
SECRET = open('/tmp/qwen_secret').read().strip()
PREFIX = '/' + SECRET
OLLAMA = 'http://127.0.0.1:11434'
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def _proxy(self):
        if self.path != PREFIX and not self.path.startswith(PREFIX + '/'):
            self.send_response(404); self.send_header('Content-Length','0'); self.end_headers(); return
        target = OLLAMA + (self.path[len(PREFIX):] or '/')
        n = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(n) if n else None
        req = urllib.request.Request(target, data=body, method=self.command)
        for h in ('Content-Type', 'Accept'):
            if self.headers.get(h): req.add_header(h, self.headers[h])
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                data = r.read(); code, ct = r.status, r.headers.get('Content-Type','application/json')
        except urllib.error.HTTPError as e:
            data = e.read(); code, ct = e.code, 'application/json'
        except Exception:
            self.send_response(502); self.send_header('Content-Length','0'); self.end_headers(); return
        self.send_response(code); self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
    do_GET = _proxy; do_POST = _proxy
    def log_message(self, *a): pass
class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True; allow_reuse_address = True
TS(('127.0.0.1', 8888), H).serve_forever()
PY
pgrep -f qwen_proxy.py >/dev/null 2>&1 || { PYB=$(command -v python3 || command -v python); setsid nohup "$PYB" /tmp/qwen_proxy.py >/tmp/proxy.log 2>&1 & }
sleep 2

# cloudflared quick tunnel -> the proxy (NOT ollama directly)
[ -x /usr/local/bin/cloudflared ] || { curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared; }
pgrep -x cloudflared >/dev/null 2>&1 || { setsid nohup cloudflared tunnel --no-autoupdate --url http://localhost:8888 >/tmp/cf.log 2>&1 & }
for i in $(seq 1 80); do U=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/cf.log 2>/dev/null | head -1); [ -n "$U" ] && break; sleep 3; done

# verify: secret path serves the model, bare path is blocked
D=$(curl -s --max-time 15 "http://127.0.0.1:8888/$SECRET/api/tags" | grep -oE 'dae161[a-f0-9]{58}' | head -1)
UNAUTH=$(curl -s --max-time 8 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8888/api/tags")
{
  echo "TUNNEL_BASE=$U"
  echo "SECRET=$SECRET"
  echo "OLLAMA_URL=$U/$SECRET"
  echo "DIGEST=$D"
  echo "DIGEST_OK=$([ "$D" = "$WANT" ] && echo true || echo false)"
  echo "UNAUTH_STATUS=$UNAUTH"
} > /tmp/qwen_ready
