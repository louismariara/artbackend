from flask import Flask
from flask_cors import CORS
from .extensions import db, jwt, ma, migrate
from .config import Config
from .models import Role, Artwork, Member
from .routes.auth import auth_bp
from .routes.artwork import artwork_bp
from .routes.inventory import inventory_bp
from .routes.profile import profile_bp
from .routes.role import role_bp
from .routes.upload import upload_bp  # Add this
from .utils.helpers import initialize_roles
from .utils.logging import logger
import os

def create_app():
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(Config)

    CORS(app, resources={r"/*": {"origins": app.config['CORS_ORIGINS']}}, supports_credentials=True)

    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    ma.init_app(app)
    migrate.init_app(app, db)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(artwork_bp)
    app.register_blueprint(inventory_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(role_bp)
    app.register_blueprint(upload_bp)  # Add this

    # Seed default roles via `flask init-roles` (run once, after `flask db upgrade`).
    # This is NOT called automatically here — doing so broke `flask db migrate`
    # on a fresh database, since it tried to query a table that doesn't exist yet.
    @app.cli.command("init-roles")
    def init_roles_command():
        initialize_roles(db)
        print("Roles initialized.")

    return app