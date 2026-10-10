import re
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from .config import Config
from .db import get_db, init_db
from .security import (
    auth_required,
    clear_login_failures,
    hash_password,
    issue_token,
    login_rate_limited,
    record_login_failure,
    verify_password,
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
MIN_PASSWORD_LEN = 12
NOTE_TITLE_MAX = 200
NOTE_BODY_MAX = 10000


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH

    init_db(app)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'"
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(HTTPException)
    def handle_http_error(err):
        return jsonify({"error": err.description or err.name}), err.code

    @app.errorhandler(Exception)
    def handle_unexpected(err):
        app.logger.exception("unhandled error")
        return jsonify({"error": "internal server error"}), 500

    def json_body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return None
        return data

    def _note_fields(data):
        title = data.get("title")
        body = data.get("body", "")
        if not isinstance(title, str) or not 1 <= len(title) <= NOTE_TITLE_MAX:
            return None, (jsonify({"error": f"title must be 1-{NOTE_TITLE_MAX} characters"}), 400)
        if not isinstance(body, str) or len(body) > NOTE_BODY_MAX:
            return None, (jsonify({"error": f"body must be at most {NOTE_BODY_MAX} characters"}), 400)
        return (title, body), None

    @app.post("/api/register")
    def register():
        data = json_body()
        if data is None:
            return jsonify({"error": "JSON object required"}), 400
        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            return jsonify({"error": "username must be 3-32 letters, digits or underscores"}), 400
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN or len(password) > 128:
            return jsonify({"error": f"password must be {MIN_PASSWORD_LEN}-128 characters"}), 400

        db = get_db()
        try:
            cur = db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "username already taken"}), 409
        return jsonify({"id": cur.lastrowid, "username": username}), 201

    @app.post("/api/login")
    def login():
        data = json_body()
        if data is None:
            return jsonify({"error": "JSON object required"}), 400
        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"error": "invalid credentials"}), 401

        key = f"{request.remote_addr}:{username.lower()}"
        if login_rate_limited(key):
            return jsonify({"error": "too many failed attempts, try again later"}), 429

        row = get_db().execute(
            "SELECT id, password_hash, role FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None or not verify_password(row["password_hash"], password):
            record_login_failure(key)
            return jsonify({"error": "invalid credentials"}), 401

        clear_login_failures(key)
        token = issue_token(row["id"], row["role"])
        return jsonify({"token": token, "token_type": "Bearer"})

    @app.get("/api/me")
    @auth_required
    def me():
        row = get_db().execute(
            "SELECT id, username, role, created_at FROM users WHERE id = ?", (g.user_id,)
        ).fetchone()
        if row is None:
            return jsonify({"error": "user not found"}), 404
        return jsonify(dict(row))

    @app.get("/api/notes")
    @auth_required
    def list_notes():
        db = get_db()
        if g.role == "admin":
            rows = db.execute("SELECT id, owner_id, title, body, created_at FROM notes ORDER BY id").fetchall()
        else:
            rows = db.execute(
                "SELECT id, owner_id, title, body, created_at FROM notes WHERE owner_id = ? ORDER BY id",
                (g.user_id,),
            ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.post("/api/notes")
    @auth_required
    def create_note():
        data = json_body()
        if data is None:
            return jsonify({"error": "JSON object required"}), 400
        fields, err = _note_fields(data)
        if err:
            return err
        title, body = fields
        db = get_db()
        cur = db.execute(
            "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
            (g.user_id, title, body),
        )
        db.commit()
        return jsonify({"id": cur.lastrowid, "owner_id": g.user_id, "title": title, "body": body}), 201

    def _load_note(note_id):
        row = get_db().execute(
            "SELECT id, owner_id, title, body, created_at FROM notes WHERE id = ?", (note_id,)
        ).fetchone()
        if row is None:
            return None, (jsonify({"error": "note not found"}), 404)
        if row["owner_id"] != g.user_id and g.role != "admin":
            return None, (jsonify({"error": "forbidden"}), 403)
        return row, None

    @app.get("/api/notes/<int:note_id>")
    @auth_required
    def get_note(note_id):
        row, err = _load_note(note_id)
        if err:
            return err
        return jsonify(dict(row))

    @app.delete("/api/notes/<int:note_id>")
    @auth_required
    def delete_note(note_id):
        row, err = _load_note(note_id)
        if err:
            return err
        db = get_db()
        db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        db.commit()
        return "", 204

    @app.put("/api/notes/<int:note_id>")
    @auth_required
    def update_note(note_id):
        data = json_body()
        if data is None:
            return jsonify({"error": "JSON object required"}), 400
        row, err = _load_note(note_id)
        if err:
            return err
        fields, err = _note_fields(data)
        if err:
            return err
        title, body = fields
        db = get_db()
        db.execute("UPDATE notes SET title = ?, body = ? WHERE id = ?", (title, body, note_id))
        db.commit()
        return jsonify(
            {
                "id": note_id,
                "owner_id": row["owner_id"],
                "title": title,
                "body": body,
                "created_at": row["created_at"],
            }
        )

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    return app
