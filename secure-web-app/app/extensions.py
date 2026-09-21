from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth


db = SQLAlchemy()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)
oauth = OAuth()
