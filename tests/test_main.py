"""Test suite for the SQLite-backed JWKS server."""
import json
import os
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import main  # noqa: E402


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "keys.db")
    main.init_db(path)
    main.seed_keys(path)
    return path


@pytest.fixture()
def server(db):
    srv = main.make_server(port=0, db_file=db)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield "http://localhost:%d" % srv.server_address[1], db
    srv.shutdown()
    srv.server_close()


def request(url, method="GET", data=None):
    req = urllib.request.Request(url, method=method, data=data)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def public_key_for(jwks, kid):
    for jwk in jwks["keys"]:
        if jwk["kid"] == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    return None


def test_init_db_creates_schema(tmp_path):
    path = str(tmp_path / "x.db")
    main.init_db(path)
    cols = [r[1] for r in sqlite3.connect(path).execute(
        "PRAGMA table_info(keys)")]
    assert cols == ["kid", "key", "exp"]


def test_seed_has_expired_and_valid_key(db):
    assert main.get_key(expired=False, db_file=db) is not None
    assert main.get_key(expired=True, db_file=db) is not None


def test_pem_round_trip_through_db(db):
    kid, pem, _ = main.get_key(db_file=db)
    key = main.load_private_key(pem)
    assert key.key_size == 2048
    assert kid >= 1


def test_get_key_none_when_empty(tmp_path):
    path = str(tmp_path / "empty.db")
    main.init_db(path)
    assert main.get_key(db_file=path) is None
    assert main.make_token(db_file=path) is None


def test_get_valid_keys_excludes_expired(db):
    now = int(time.time())
    rows = main.get_valid_keys(db, now=now)
    assert rows and all(r[2] > now for r in rows)


def test_sql_injection_is_inert(db):
    # Bound parameters: a hostile "timestamp" is treated as a plain value.
    conn = sqlite3.connect(db)
    before = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    conn.close()
    main.get_key(db_file=db, now="0; DROP TABLE keys;--")
    conn = sqlite3.connect(db)
    after = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    conn.close()
    assert before == after


def test_int_to_base64_pads_odd_hex():
    assert main.int_to_base64(0x123) == "ASM"
    assert main.int_to_base64(65537) == "AQAB"


def test_jwks_endpoint_only_valid_keys(server):
    base, db = server
    status, body = request(base + "/.well-known/jwks.json")
    assert status == 200
    jwks = json.loads(body)
    valid_kids = {str(r[0]) for r in main.get_valid_keys(db)}
    assert {k["kid"] for k in jwks["keys"]} == valid_kids
    assert all(k["alg"] == "RS256" and k["kty"] == "RSA"
               for k in jwks["keys"])


def test_auth_returns_jwt_verifiable_with_jwks(server):
    base, _ = server
    status, token = request(base + "/auth", "POST", b'{"username":"u"}')
    assert status == 200
    token = token.decode()
    kid = jwt.get_unverified_header(token)["kid"]
    jwks = json.loads(request(base + "/.well-known/jwks.json")[1])
    pub = public_key_for(jwks, kid)
    assert pub is not None
    claims = jwt.decode(token, pub, algorithms=["RS256"])
    assert claims["user"] == "username"


def test_auth_expired_uses_expired_key(server):
    base, db = server
    status, token = request(base + "/auth?expired=true", "POST")
    assert status == 200
    token = token.decode()
    header = jwt.get_unverified_header(token)
    jwks = json.loads(request(base + "/.well-known/jwks.json")[1])
    assert public_key_for(jwks, header["kid"]) is None  # not published
    row = main.get_key(expired=True, db_file=db)
    pub = main.load_private_key(row[1]).public_key()
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, pub, algorithms=["RS256"])
    claims = jwt.decode(token, pub, algorithms=["RS256"],
                        options={"verify_exp": False})
    assert claims["exp"] < time.time()


def test_auth_500_when_no_key(tmp_path):
    path = str(tmp_path / "e.db")
    main.init_db(path)
    handler = type("H", (main.MyServer,), {"db_file": path})
    srv = main.HTTPServer(("localhost", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = "http://localhost:%d" % srv.server_address[1]
        assert request(base + "/auth", "POST")[0] == 500
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE", "HEAD"])
def test_unsupported_methods_405(server, method):
    base, _ = server
    assert request(base + "/auth", method)[0] == 405


def test_wrong_paths_405(server):
    base, _ = server
    assert request(base + "/nope")[0] == 405
    assert request(base + "/nope", "POST")[0] == 405


def test_saved_key_is_pkcs1_pem(db):
    _, pem, _ = main.get_key(db_file=db)
    assert bytes(pem).startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    assert serialization.load_pem_private_key(bytes(pem), None)
