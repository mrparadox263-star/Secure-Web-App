import os
import tempfile

import pytest

from secureapp import create_app
from secureapp.db import get_db
from secureapp.security import _failed_logins

PASSWORD = "correct-horse-battery"


@pytest.fixture
def app():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    app = create_app({"TESTING": True, "DATABASE": path, "SECRET_KEY": "test-secret-key-0123456789abcdef"})
    yield app
    os.remove(path)
    _failed_logins.clear()


@pytest.fixture
def client(app):
    return app.test_client()


def register_and_login(client, username, password=PASSWORD):
    client.post("/api/register", json={"username": username, "password": password})
    resp = client.post("/api/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {resp.get_json()['token']}"}


def test_register_and_login(client):
    r = client.post("/api/register", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 201
    assert "password" not in r.get_json()
    r = client.post("/api/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 200
    assert r.get_json()["token"]


def test_password_stored_hashed(app, client):
    client.post("/api/register", json={"username": "alice", "password": PASSWORD})
    with app.app_context():
        row = get_db().execute("SELECT password_hash FROM users WHERE username = 'alice'").fetchone()
    assert PASSWORD not in row["password_hash"]
    assert row["password_hash"].startswith("scrypt:")


def test_weak_input_rejected(client):
    assert client.post("/api/register", json={"username": "ab", "password": PASSWORD}).status_code == 400
    assert client.post("/api/register", json={"username": "bob!", "password": PASSWORD}).status_code == 400
    assert client.post("/api/register", json={"username": "bobby", "password": "short"}).status_code == 400


def test_duplicate_username_rejected_case_insensitive(client):
    client.post("/api/register", json={"username": "alice", "password": PASSWORD})
    r = client.post("/api/register", json={"username": "ALICE", "password": PASSWORD})
    assert r.status_code == 409


def test_wrong_password_rejected(client):
    client.post("/api/register", json={"username": "alice", "password": PASSWORD})
    r = client.post("/api/login", json={"username": "alice", "password": "wrong-password-xx"})
    assert r.status_code == 401


def test_login_rate_limited(client):
    client.post("/api/register", json={"username": "alice", "password": PASSWORD})
    for _ in range(5):
        client.post("/api/login", json={"username": "alice", "password": "wrong-password-xx"})
    r = client.post("/api/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 429


def test_protected_routes_require_token(client):
    assert client.get("/api/notes").status_code == 401
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/notes", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_tampered_token_rejected(client):
    headers = register_and_login(client, "alice")
    token = headers["Authorization"].split(" ", 1)[1]
    header, payload, sig = token.split(".")
    forged = f"{header}.{payload}.{'A' * len(sig)}"
    assert client.get("/api/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_alg_none_rejected(client):
    import base64
    import json

    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': '1', 'role': 'admin', 'exp': 9999999999})}."
    assert client.get("/api/notes", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_user_cannot_read_others_notes(client):
    alice = register_and_login(client, "alice")
    bob = register_and_login(client, "bobby")
    note = client.post("/api/notes", json={"title": "secret", "body": "alice only"}, headers=alice).get_json()

    assert client.get(f"/api/notes/{note['id']}", headers=bob).status_code == 403
    assert client.delete(f"/api/notes/{note['id']}", headers=bob).status_code == 403
    assert client.get("/api/notes", headers=bob).get_json() == []
    assert client.get(f"/api/notes/{note['id']}", headers=alice).status_code == 200


def test_missing_note_returns_404(client):
    headers = register_and_login(client, "alice")
    assert client.get("/api/notes/9999", headers=headers).status_code == 404


def test_admin_can_see_all_notes(app, client):
    alice = register_and_login(client, "alice")
    client.post("/api/notes", json={"title": "t", "body": "b"}, headers=alice)
    admin = register_and_login(client, "adminuser")
    with app.app_context():
        get_db().execute("UPDATE users SET role = 'admin' WHERE username = 'adminuser'")
        get_db().commit()
    # Re-login so the new role is embedded in a fresh token.
    resp = client.post("/api/login", json={"username": "adminuser", "password": PASSWORD})
    admin = {"Authorization": f"Bearer {resp.get_json()['token']}"}
    assert len(client.get("/api/notes", headers=admin).get_json()) == 1


def test_role_in_db_not_trusted_from_client_body(client):
    r = client.post("/api/register", json={"username": "mallory", "password": PASSWORD, "role": "admin"})
    assert r.status_code == 201
    headers = register_and_login(client, "mallory2")
    assert client.get("/api/notes", headers=headers).status_code == 200


def test_sql_injection_payloads_are_inert(client):
    payload = "x' OR '1'='1"
    client.post("/api/register", json={"username": "alice", "password": PASSWORD})
    r = client.post("/api/login", json={"username": payload, "password": payload})
    assert r.status_code == 401
    headers = register_and_login(client, "carol")
    client.post("/api/notes", json={"title": "'); DROP TABLE notes; --", "body": "x"}, headers=headers)
    assert client.get("/api/notes", headers=headers).status_code == 200


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp


def test_update_note_by_owner(client):
    headers = register_and_login(client, "alice")
    note = client.post("/api/notes", json={"title": "old", "body": "old body"}, headers=headers).get_json()
    r = client.put(f"/api/notes/{note['id']}", json={"title": "new", "body": "new body"}, headers=headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["title"] == "new"
    assert body["body"] == "new body"
    stored = client.get(f"/api/notes/{note['id']}", headers=headers).get_json()
    assert stored["title"] == "new"
    assert stored["body"] == "new body"


def test_update_note_by_other_user_forbidden(client):
    alice = register_and_login(client, "alice")
    bob = register_and_login(client, "bobby")
    note = client.post("/api/notes", json={"title": "t", "body": "alice only"}, headers=alice).get_json()
    r = client.put(f"/api/notes/{note['id']}", json={"title": "hacked", "body": "x"}, headers=bob)
    assert r.status_code == 403
    still = client.get(f"/api/notes/{note['id']}", headers=alice).get_json()
    assert still["title"] == "t"
    assert still["body"] == "alice only"


def test_update_missing_note_returns_404(client):
    headers = register_and_login(client, "alice")
    r = client.put("/api/notes/9999", json={"title": "t", "body": "b"}, headers=headers)
    assert r.status_code == 404


def test_update_note_invalid_fields_rejected(client):
    headers = register_and_login(client, "alice")
    note = client.post("/api/notes", json={"title": "t", "body": "b"}, headers=headers).get_json()
    url = f"/api/notes/{note['id']}"
    assert client.put(url, json={"title": "", "body": "b"}, headers=headers).status_code == 400
    assert client.put(url, json={"title": "x" * 201, "body": "b"}, headers=headers).status_code == 400
    assert client.put(url, json={"title": "t", "body": "x" * 10001}, headers=headers).status_code == 400
    assert client.put(url, json={"title": 123, "body": "b"}, headers=headers).status_code == 400
    assert client.put(url, data="not json", content_type="application/json", headers=headers).status_code == 400
    assert client.get(url, headers=headers).get_json()["title"] == "t"


def test_update_note_requires_token(client):
    headers = register_and_login(client, "alice")
    note = client.post("/api/notes", json={"title": "t", "body": "b"}, headers=headers).get_json()
    r = client.put(f"/api/notes/{note['id']}", json={"title": "x", "body": "y"})
    assert r.status_code == 401


def test_index_serves_app_shell(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.mimetype == "text/html"
    assert "Secure Notes" in r.get_data(as_text=True)
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_static_assets_served(client):
    for path, mimetype in (("/static/app.js", "javascript"), ("/static/style.css", "css")):
        r = client.get(path)
        assert r.status_code == 200, path
        assert mimetype in r.mimetype


def test_oversized_body_rejected(client):
    r = client.post("/api/register", data="x" * (20 * 1024), content_type="application/json")
    assert r.status_code == 413


def test_error_responses_hide_internals(client):
    r = client.post("/api/register", data="not json", content_type="application/json")
    assert r.status_code == 400
    assert "Traceback" not in r.get_data(as_text=True)
