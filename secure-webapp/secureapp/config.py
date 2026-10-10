import os
import secrets


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    JWT_ALGORITHM = "HS256"
    JWT_EXP_MINUTES = int(os.environ.get("JWT_EXP_MINUTES", "30"))
    DATABASE = os.environ.get("DATABASE", "secureapp.db")
    MAX_CONTENT_LENGTH = 16 * 1024
    LOGIN_MAX_FAILURES = 5
    LOGIN_WINDOW_SECONDS = 300
