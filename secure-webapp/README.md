# Secure Notes

A notes web app built as a security demonstration: Flask + SQLite backend, vanilla
HTML/CSS/JS frontend, JWT authentication, role-based authorization, and hardened
data handling.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py            # serves http://127.0.0.1:5000
```

Optional environment variables:

- `SECRET_KEY` — JWT signing key (random per-process if unset; set it in production)
- `JWT_EXP_MINUTES` — token lifetime (default 30)
- `DATABASE` — SQLite path (default `secureapp.db`)
- `PORT` — listen port (default 5000)

## Tests

```bash
pytest -q        # 24 tests
```

## Features

- Register / login / logout, per-user notes with create, edit, delete, search,
  previews, character counter, unsaved-changes guard (confirm dialog +
  `beforeunload`), Ctrl/Cmd+S to save, light/dark theme.

## Security measures

| Area | Implementation |
| --- | --- |
| Password storage | `werkzeug` scrypt hashes, never plaintext; 12-128 char policy |
| Authentication | JWT (HS256) Bearer tokens with `exp`, `iat`, `sub`, `aud`, `iss`; algorithm and audience/issuer pinned, so `alg=none` and token-confusion attacks fail |
| Authorization | Every note query is owner-scoped (`WHERE owner_id = ?`); cross-user access returns 403. Role comes from the signed token / DB, never the request body. `admin` role can list all notes |
| SQL injection | 100% parameterized queries (`?` placeholders), no string-built SQL |
| XSS | Frontend renders only via `textContent` / `createElement` (no `innerHTML`); strict CSP `default-src 'self'`, no `unsafe-inline`, `object-src 'none'`, `frame-ancestors 'none'` |
| Brute force | Login rate limiting: 5 failures per (IP, username) per 5-minute window -> 429 |
| Input validation | Username regex `^[A-Za-z0-9_]{3,32}$`, title 1-200, body <= 10000 chars, JSON-object-only bodies, 16 KB request cap (413) |
| Transport/UI headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` |
| Token storage | Frontend keeps the JWT in `sessionStorage` (cleared on tab close), not `localStorage` |
| Error handling | Generic error bodies; stack traces never reach the client |

## API

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| POST | `/api/register` | - | Create account (201, 409 if taken) |
| POST | `/api/login` | - | Returns `{token, token_type}` |
| GET | `/api/me` | Bearer | Current user |
| GET | `/api/notes` | Bearer | Own notes (all notes for admin) |
| POST | `/api/notes` | Bearer | Create note |
| GET/PUT/DELETE | `/api/notes/<id>` | Bearer | Read / update / delete (owner or admin only) |
| GET | `/api/health` | - | Liveness |
