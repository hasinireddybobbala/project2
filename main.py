"""JWKS server backed by SQLite (CSCE 3550 Project 2).

Private keys are generated at start-up, serialized to PKCS1 PEM and stored in
``totally_not_my_privateKeys.db``.  All SQL uses bound parameters so that no
value is ever concatenated into a query string (prevents SQL injection).

Endpoints:
    POST /auth                 -> signed JWT (``?expired`` uses an expired key)
    GET  /.well-known/jwks.json -> JWKS of all unexpired public keys
"""
import base64
import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOST_NAME = "localhost"
SERVER_PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"
HOUR = 3600

CREATE_TABLE_SQL = """CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)"""


# --------------------------------------------------------------------------
# Key helpers
# --------------------------------------------------------------------------
def generate_pem():
    """Generate an RSA-2048 key and return it as PKCS1 PEM bytes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem):
    """Deserialize PEM bytes read from the database into a key object."""
    return serialization.load_pem_private_key(bytes(pem), password=None)


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string (no padding)."""
    value_hex = format(value, "x")
    if len(value_hex) % 2 == 1:  # ensure even length
        value_hex = "0" + value_hex
    encoded = base64.urlsafe_b64encode(bytes.fromhex(value_hex))
    return encoded.rstrip(b"=").decode("utf-8")


# --------------------------------------------------------------------------
# Database layer
# --------------------------------------------------------------------------
def init_db(db_file=DB_FILE):
    """Create/open the DB file and make sure the keys table exists."""
    conn = sqlite3.connect(db_file)
    conn.execute(CREATE_TABLE_SQL)
    conn.commit()
    conn.close()


def save_key(pem, exp, db_file=DB_FILE):
    """Insert a PEM-encoded private key with its expiry; return its kid."""
    conn = sqlite3.connect(db_file)
    cur = conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp))
    conn.commit()
    kid = cur.lastrowid
    conn.close()
    return kid


def seed_keys(db_file=DB_FILE, now=None):
    """Store one expired key and one key valid for an hour."""
    now = int(time.time()) if now is None else now
    save_key(generate_pem(), now - HOUR, db_file)
    save_key(generate_pem(), now + HOUR, db_file)


def get_key(expired=False, db_file=DB_FILE, now=None):
    """Return ``(kid, pem, exp)`` for one valid or expired key (or None)."""
    now = int(time.time()) if now is None else now
    if expired:
        sql = ("SELECT kid, key, exp FROM keys WHERE exp <= ? "
               "ORDER BY exp DESC LIMIT 1")
    else:
        sql = ("SELECT kid, key, exp FROM keys WHERE exp > ? "
               "ORDER BY exp DESC LIMIT 1")
    conn = sqlite3.connect(db_file)
    row = conn.execute(sql, (now,)).fetchone()
    conn.close()
    return row


def get_valid_keys(db_file=DB_FILE, now=None):
    """Return a list of ``(kid, pem, exp)`` for every unexpired key."""
    now = int(time.time()) if now is None else now
    conn = sqlite3.connect(db_file)
    rows = conn.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ?", (now,)
    ).fetchall()
    conn.close()
    return rows


# --------------------------------------------------------------------------
# JWT / JWKS construction
# --------------------------------------------------------------------------
def build_jwks(rows):
    """Build a JWKS dict from DB rows of private keys."""
    keys = []
    for kid, pem, _exp in rows:
        numbers = load_private_key(pem).private_numbers().public_numbers
        keys.append({
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid),
            "n": int_to_base64(numbers.n),
            "e": int_to_base64(numbers.e),
        })
    return {"keys": keys}


def make_token(expired=False, db_file=DB_FILE):
    """Sign a JWT with a key from the DB; return None if no key matches."""
    row = get_key(expired=expired, db_file=db_file)
    if row is None:
        return None
    kid, pem, exp = row
    payload = {"user": "username", "exp": exp}
    return jwt.encode(payload, load_private_key(pem), algorithm="RS256",
                      headers={"kid": str(kid)})


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------
class MyServer(BaseHTTPRequestHandler):
    """Request handler; ``db_file`` is configured on the class."""

    db_file = DB_FILE

    def _reply(self, status, body=b"", content_type=None):
        self.send_response(status)
        if content_type:
            self.send_header("Content-type", content_type)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_PUT(self):
        self._reply(405)

    def do_PATCH(self):
        self._reply(405)

    def do_DELETE(self):
        self._reply(405)

    def do_HEAD(self):
        self._reply(405)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/auth":
            self._reply(405)
            return
        # Drain any request body (Basic auth / JSON); auth is mocked.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        expired = "expired" in parse_qs(parsed.query, keep_blank_values=True)
        token = make_token(expired=expired, db_file=self.db_file)
        if token is None:
            self._reply(500, b"no suitable key")
            return
        self._reply(200, token.encode("utf-8"))

    def do_GET(self):
        if self.path != "/.well-known/jwks.json":
            self._reply(405)
            return
        jwks = build_jwks(get_valid_keys(self.db_file))
        self._reply(200, json.dumps(jwks).encode("utf-8"),
                    "application/json")

    def log_message(self, format, *args):  # noqa: A002
        """Keep console output quiet."""


def make_server(port=SERVER_PORT, db_file=DB_FILE, host=HOST_NAME):
    """Initialise the DB, seed keys and return a ready HTTPServer."""
    init_db(db_file)
    seed_keys(db_file)
    handler = type("Handler", (MyServer,), {"db_file": db_file})
    return HTTPServer((host, port), handler)


if __name__ == "__main__":  # pragma: no cover
    web_server = make_server()
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass
    web_server.server_close()
