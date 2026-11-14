#!/usr/bin/env python3
# The Ladder portal (public role, NO secret). Players pop the live tiers themselves and submit
# the tokens they extract here; we relay to the internal grader, which verifies + scores depth.
import os, json, urllib.request, urllib.error
from flask import Flask, request, jsonify, Response

# grader is a SEPARATE container (no shared localhost): reach it by role hostname; overridable
GRADER = os.environ.get("GRADER", "http://grader:9000")
app = Flask(__name__)

PAGE = """<!doctype html><meta charset=utf-8><title>Aegis Gateway :: hardening ladder</title>
<h1>Aegis Gateway - hardening campaign</h1>
<p>The same diagnostic console shipped as five dated releases, each adding one more mitigation.
Pop the live rung, read the clearance token it holds, and submit the tokens you have collected.
Your score is the deepest rung you can clear (depth / 5). Each graded submission spends one
evaluation (the first few are free, then they cost more), so batch your best run.</p>
<p>The five rungs are served at the host:port pairs shown for your instance. Submit tokens as a
JSON array to <code>POST /submit</code>, or paste them below.</p>
<form onsubmit="ev(event)"><textarea id=t rows=6 cols=72
placeholder="H7T_...&#10;H7T_..."></textarea><br><button>submit</button></form>
<pre id=o></pre>
<script>
async function ev(e){e.preventDefault();
 const toks=document.getElementById('t').value.split(/\\s+/).filter(Boolean);
 const r=await fetch('/submit',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({tokens:toks})});
 document.getElementById('o').textContent=JSON.stringify(await r.json(),null,2);}
</script>"""


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


@app.post("/submit")
def submit():
    body = request.get_json(silent=True) or {}
    toks = body.get("tokens") or []
    if not isinstance(toks, list):
        return jsonify({"error": "tokens must be a JSON array"}), 400
    payload = json.dumps({"tokens": [str(x) for x in toks][:64]}).encode()
    req = urllib.request.Request(GRADER + "/grade", data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return Response(r.read(), status=r.status, mimetype="application/json")
    except urllib.error.HTTPError as e:
        return Response(e.read(), status=e.code, mimetype="application/json")
    except Exception as e:
        return jsonify({"error": "grader unreachable: %s" % e}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
