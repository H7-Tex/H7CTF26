import http.server
import os
import socketserver

HERE = os.path.dirname(os.path.abspath(__file__))
ROM = os.path.join(HERE, "panel.rom")
PORT = int(os.environ.get("PORT", "8080"))

PAGE = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>PLASMASOFT Panel Recovery</title>
<style>
:root{color-scheme:dark;--bg:#0a0e0a;--fg:#c8f7c8;--dim:#5f8f5f;--acc:#39ff14}
body{background:var(--bg);color:var(--fg);font-family:ui-monospace,Menlo,Consolas,monospace;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.6}
h1{color:var(--acc);font-size:20px;letter-spacing:1px}
a{color:var(--acc)}
code,pre{background:#04120490;border:1px solid #1c3c1c;border-radius:6px}
pre{padding:12px;overflow-x:auto}
.dim{color:var(--dim)}
</style></head><body>
<h1>PLASMASOFT PANEL BIOS v2.1</h1>
<p>Recovered boot flash from a dead departure board. It POSTs, it flickers, it
prints a service tag along the top. That band is not your unit's tag.</p>
<p>Grab the flash image and boot it on your own bench:</p>
<pre>curl -O http://HOSTPLACEHOLDER/panel.rom
qemu-system-i386 -drive format=raw,file=panel.rom</pre>
<p class="dim">The panel sits in standby until a field tech enters the service
code on the keypad. No code, no tag.</p>
<p><a href="/panel.rom">panel.rom</a></p>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = PAGE.replace(b"HOSTPLACEHOLDER", self.headers.get("Host", "localhost").encode())
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/panel.rom":
            data = open(ROM, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", "attachment; filename=panel.rom")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_error(404)

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("0.0.0.0", PORT), Handler).serve_forever()
