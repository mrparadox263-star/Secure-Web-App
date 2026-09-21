from flask import Flask, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .extensions import db, jwt, limiter, oauth


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    oauth.init_app(app)

    from .auth.routes import auth_bp
    from .api.routes import api_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        if app.config.get("JWT_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify(error="bad_request", message=str(error.description)), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify(error="not_found", message="Resource not found"), 404

    @app.errorhandler(429)
    def rate_limited(error):
        return jsonify(error="rate_limited", message="Too many requests"), 429

    with app.app_context():
        db.create_all()

    return app
