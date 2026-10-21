# template service, not an event service: a tiny notes app with two flag stores,
# kept stdlib-only so it builds offline anywhere. copy the shape, not the bugs.
import json
import os
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB = os.environ.get("NOTEBOOK_DB", "/data/notebook.db")
PORT = int(os.environ.get("NOTEBOOK_PORT", "7000"))
lock = threading.Lock()


def db():
    conn = sqlite3.connect(DB, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    with db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, display TEXT,
                bio TEXT, joined INTEGER DEFAULT (strftime('%s','now')));
            CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, name TEXT);
            CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, owner TEXT, title TEXT, body TEXT,
                private INTEGER, created INTEGER DEFAULT (strftime('%s','now')));
        """)
    # per-box secret, generated on first boot into the volume, never baked in the image
    path = os.path.join(os.path.dirname(DB), "instance.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(16))


def prune():
    with lock, db() as c:
        c.execute("DELETE FROM notes WHERE created < strftime('%s','now') - 1800")


def pruner():
    while True:
        prune()
        time.sleep(300)


class H(BaseHTTPRequestHandler):
    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def user(self):
        tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
        with db() as c:
            row = c.execute("SELECT name FROM sessions WHERE token = ?", (tok,)).fetchone()
        return row["name"] if row else None

    def do_POST(self):
        path, data = urlparse(self.path).path, self.body()
        if path == "/register":
            name, pw = str(data.get("user", "")), str(data.get("password", ""))
            if not (3 <= len(name) <= 32 and pw):
                return self.reply(400, {"error": "bad user or password"})
            with lock, db() as c:
                if c.execute("SELECT 1 FROM users WHERE name = ?", (name,)).fetchone():
                    return self.reply(409, {"error": "taken"})
                c.execute("INSERT INTO users (name, password, display, bio) VALUES (?, ?, ?, ?)",
                          (name, pw, str(data.get("display", name))[:64], str(data.get("bio", ""))[:256]))
            return self.reply(201, {"user": name})
        if path == "/login":
            with db() as c:
                row = c.execute("SELECT password FROM users WHERE name = ?", (str(data.get("user", "")),)).fetchone()
            if not row or row["password"] != str(data.get("password", "")):
                return self.reply(403, {"error": "bad login"})
            tok = secrets.token_hex(16)
            with lock, db() as c:
                c.execute("INSERT INTO sessions VALUES (?, ?)", (tok, data["user"]))
            return self.reply(200, {"token": tok})
        if path == "/notes":
            me = self.user()
            if not me:
                return self.reply(401, {"error": "login"})
            nid = secrets.token_hex(8)
            with lock, db() as c:
                c.execute("INSERT INTO notes (id, owner, title, body, private) VALUES (?, ?, ?, ?, ?)",
                          (nid, me, str(data.get("title", ""))[:128], str(data.get("body", ""))[:2048],
                           1 if data.get("private", True) else 0))
            return self.reply(201, {"id": nid})
        self.reply(404, {"error": "not found"})

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        me = self.user()
        if url.path.startswith("/notes/"):
            with db() as c:
                note = c.execute("SELECT * FROM notes WHERE id = ?", (url.path[7:],)).fetchone()
            if not note:
                return self.reply(404, {"error": "no such note"})
            if q.get("preview") == ["1"]:
                # store 0 bug: the preview path skips the owner check
                return self.reply(200, {"id": note["id"], "title": note["title"], "body": note["body"][:64]})
            if note["private"] and note["owner"] != me:
                return self.reply(403, {"error": "private"})
            return self.reply(200, dict(note))
        if url.path.startswith("/users/"):
            name = url.path[7:]
            with db() as c:
                row = c.execute("SELECT name, display, bio, joined FROM users WHERE name = ?", (name,)).fetchone()
            if not row:
                return self.reply(404, {"error": "no such user"})
            fields = (q.get("fields") or ["name,display"])[0].split(",")
            # store 1 bug: field selection is not limited to public fields for other users
            return self.reply(200, {f: row[f] for f in fields if f in row.keys()})
        if url.path == "/health":
            return self.reply(200, {"ok": True})
        self.reply(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        print("%s %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    init()
    threading.Thread(target=pruner, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
