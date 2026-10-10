import datetime as dt
import functools
import time
from collections import defaultdict, deque

import jwt
from flask import current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

_failed_logins = defaultdict(deque)


def hash_password(password):
    return generate_password_hash(password, method="scrypt")


def verify_password(password_hash, password):
    return check_password_hash(password_hash, password)


def issue_token(user_id, role):
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": now,
        "exp": now + dt.timedelta(minutes=current_app.config["JWT_EXP_MINUTES"]),
        "aud": "secureapp",
        "iss": "secureapp",
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm=current_app.config["JWT_ALGORITHM"])


def decode_token(token):
    return jwt.decode(
        token,
        current_app.config["SECRET_KEY"],
        algorithms=[current_app.config["JWT_ALGORITHM"]],
        audience="secureapp",
        issuer="secureapp",
        options={"require": ["exp", "iat", "sub"]},
    )


def _error(message, status):
    return jsonify({"error": message}), status


def login_rate_limited(key):
    window = current_app.config["LOGIN_WINDOW_SECONDS"]
    attempts = _failed_logins[key]
    now = time.monotonic()
    while attempts and now - attempts[0] > window:
        attempts.popleft()
    return len(attempts) >= current_app.config["LOGIN_MAX_FAILURES"]


def record_login_failure(key):
    _failed_logins[key].append(time.monotonic())


def clear_login_failures(key):
    _failed_logins.pop(key, None)


def auth_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme != "Bearer" or not token:
            return _error("authentication required", 401)
        try:
            claims = decode_token(token)
        except jwt.PyJWTError:
            return _error("invalid or expired token", 401)
        g.user_id = int(claims["sub"])
        g.role = claims.get("role", "user")
        return view(*args, **kwargs)

    return wrapper
