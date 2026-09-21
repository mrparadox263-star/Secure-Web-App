from urllib.parse import urlparse

from authlib.integrations.base_client.errors import OAuthError
from email_validator import EmailNotValidError, validate_email
from flask import Blueprint, current_app, jsonify, redirect, request, url_for
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_csrf_token,
    jwt_required,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
)

from ..extensions import db, limiter, oauth
from ..models import User


auth_bp = Blueprint("auth", __name__)


def _json_body():
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def _validate_credentials(body):
    username = str(body.get("username", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not 3 <= len(username) <= 80:
        return None, ("username must be 3-80 characters", 400)
    if len(password) < 12:
        return None, ("password must be at least 12 characters", 400)
    try:
        email = validate_email(email, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        return None, (str(exc), 400)
    return (username, email, password), None


def _issue_tokens(response, user):
    claims = {"role": user.role}
    access = create_access_token(identity=str(user.id), additional_claims=claims)
    refresh = create_refresh_token(identity=str(user.id), additional_claims=claims)
    set_access_cookies(response, access)
    set_refresh_cookies(response, refresh)
    return response


@auth_bp.post("/register")
@limiter.limit("5 per minute")
def register():
    credentials, error = _validate_credentials(_json_body())
    if error:
        return jsonify(error="validation_error", message=error[0]), error[1]
    username, email, password = credentials
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify(error="conflict", message="Username or email is already registered"), 409
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    response = jsonify(user={"id": user.id, "username": user.username, "email": user.email})
    return _issue_tokens(response, user), 201


@auth_bp.post("/login")
@limiter.limit("10 per minute")
def login():
    body = _json_body()
    identifier = str(body.get("identifier", "")).strip().lower()
    password = str(body.get("password", ""))
    user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()
    if not user or not user.check_password(password):
        return jsonify(error="invalid_credentials", message="Invalid credentials"), 401
    response = jsonify(message="Logged in")
    return _issue_tokens(response, user)


@auth_bp.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    user = db.session.get(User, int(get_jwt_identity()))
    if not user:
        return jsonify(error="unauthorized", message="User no longer exists"), 401
    response = jsonify(message="Access token refreshed")
    access = create_access_token(identity=str(user.id), additional_claims={"role": user.role})
    set_access_cookies(response, access)
    return response


@auth_bp.post("/logout")
@jwt_required()
def logout():
    response = jsonify(message="Logged out")
    unset_jwt_cookies(response)
    return response


@auth_bp.get("/me")
@jwt_required()
def me():
    user = db.session.get(User, int(get_jwt_identity()))
    if not user:
        return jsonify(error="unauthorized", message="User no longer exists"), 401
    return jsonify(id=user.id, username=user.username, email=user.email, role=user.role)


@auth_bp.get("/csrf")
@jwt_required()
def csrf_token():
    return jsonify(csrf_token=get_csrf_token(request.cookies.get("access_token_cookie")))


def _register_oauth_clients():
    if current_app.config.get("GOOGLE_CLIENT_ID") and not oauth.google:
        oauth.register(
            name="google",
            client_id=current_app.config["GOOGLE_CLIENT_ID"],
            client_secret=current_app.config["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )
    if current_app.config.get("GITHUB_CLIENT_ID") and not oauth.github:
        oauth.register(
            name="github",
            client_id=current_app.config["GITHUB_CLIENT_ID"],
            client_secret=current_app.config["GITHUB_CLIENT_SECRET"],
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "user:email"},
        )


@auth_bp.get("/oauth/<provider>")
def oauth_login(provider):
    if provider not in {"google", "github"}:
        return jsonify(error="not_found", message="Unsupported OAuth provider"), 404
    _register_oauth_clients()
    client = getattr(oauth, provider, None)
    if client is None:
        return jsonify(error="not_configured", message=f"{provider} OAuth is not configured"), 503
    redirect_uri = url_for("auth.oauth_callback", provider=provider, _external=True)
    return client.authorize_redirect(redirect_uri)


@auth_bp.get("/oauth/<provider>/callback")
def oauth_callback(provider):
    _register_oauth_clients()
    client = getattr(oauth, provider, None)
    if client is None:
        return jsonify(error="not_configured", message="OAuth provider is not configured"), 503
    try:
        token = client.authorize_access_token()
        if provider == "google":
            profile = token.get("userinfo") or client.get("userinfo").json()
            email = profile["email"].lower()
            username = profile.get("preferred_username") or email.split("@")[0]
        else:
            profile = client.get("user").json()
            email = str(profile.get("email") or f"github-{profile['id']}@oauth.local").lower()
            username = profile.get("login") or f"github-{profile['id']}"
    except (OAuthError, KeyError, TypeError):
        return jsonify(error="oauth_error", message="OAuth sign-in failed"), 401

    user = User.query.filter_by(email=email).first()
    if not user:
        base = "".join(ch for ch in username if ch.isalnum() or ch in "-_")[:70] or "oauth-user"
        candidate, suffix = base, 1
        while User.query.filter_by(username=candidate).first():
            candidate = f"{base}-{suffix}"
            suffix += 1
        user = User(username=candidate, email=email)
        db.session.add(user)
        db.session.commit()
    response = redirect("/")
    return _issue_tokens(response, user)
