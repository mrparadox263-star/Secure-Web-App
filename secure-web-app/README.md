# Building a Secure Web Application

A small secure task application built with **Flask**, **SQLAlchemy**, JWT cookies, optional Google/GitHub OAuth, and a Vite frontend.

## Included security controls

- Passwords are hashed with Werkzeug `scrypt`; plaintext passwords are never stored.
- Short-lived access JWT plus rotating-on-demand refresh JWT are stored in `HttpOnly`, `SameSite=Lax` cookies.
- Cookie JWT requests use Flask-JWT-Extended CSRF protection.
- Authorization is enforced on every task query using the authenticated owner ID.
- An example role-protected admin endpoint demonstrates RBAC.
- SQLAlchemy ORM queries are used instead of string-concatenated SQL, preventing SQL injection in the included API.
- Input length/type validation is applied at the API boundary.
- Login and registration are rate-limited.
- Response security headers include CSP, `X-Frame-Options`, `X-Content-Type-Options`, and Referrer-Policy.
- OAuth integrations are optional and only enabled when credentials are configured.
- `ProxyFix` is included for a trusted reverse proxy deployment; only enable it behind your own proxy.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

The API runs at `http://127.0.0.1:5000`.

### Register and use the API

```bash
curl -i -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.com","password":"correct horse battery staple"}' \
  http://127.0.0.1:5000/auth/register

curl -b cookies.txt http://127.0.0.1:5000/api/tasks
```

For state-changing requests with cookie JWTs, first call `/auth/csrf` and send the returned value as `X-CSRF-TOKEN`.

## OAuth setup

1. Copy `.env.example` to `.env`.
2. Create OAuth credentials with Google and/or GitHub.
3. Register these callback URLs for your local development app:
   - `http://127.0.0.1:5000/auth/oauth/google/callback`
   - `http://127.0.0.1:5000/auth/oauth/github/callback`
4. Set the matching client ID and secret variables in `.env`.
5. Start sign-in at `/auth/oauth/google` or `/auth/oauth/github`.

For production, use HTTPS, set `JWT_COOKIE_SECURE=true`, use a managed database, rotate secrets through a secret manager, configure a persistent rate-limit store, and add migrations/observability before deployment.

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_URL` if the API is not on `http://127.0.0.1:5000`. The sample frontend expects the user to authenticate through the API first.

## Tests

```bash
pytest -q
```

## Suggested next milestones

1. Add database migrations with Alembic/Flask-Migrate.
2. Add email verification and password-reset flows with one-time, expiring tokens.
3. Add refresh-token revocation/rotation storage for stronger session control.
4. Add structured audit logs and alerting for auth failures.
5. Add dependency scanning, secret scanning, SAST, and a DAST smoke test to CI.
6. Put the API behind HTTPS and a reverse proxy with a persistent Redis-backed rate limiter.
