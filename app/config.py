import os
import re
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()
# Placeholder values that must never be used for real. create_app() refuses to
# start in production if a secret key is one of these (or too short).
INSECURE_DEFAULTS = {'your-secret-key', 'your-jwt-secret-key'}

class Config:
    APP_ENV = os.getenv('APP_ENV', 'production')
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-jwt-secret-key')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = os.getenv('DB_PORT')
    DB_NAME = os.getenv('DB_NAME')
    SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
    SENDGRID_FROM_EMAIL = os.getenv('SENDGRID_FROM_EMAIL')
    

    if DB_HOST:
        SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    else:
        # No Postgres configured in .env — fall back to a local SQLite file
        # so the app is still runnable for quick testing. Add DB_HOST etc.
        # back to .env whenever Postgres is ready to use again.
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'local.db'
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

    # Exact origins, comma-separated in .env, e.g. CORS_ORIGINS=http://localhost:5173,https://yourdomain.com
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv('CORS_ORIGINS', 'http://localhost:5173').split(',')
        if origin.strip()
    ]

    # Base domains whose gallery subdomains may call the API, comma-separated,
    # e.g. CORS_SUBDOMAIN_BASES=localhost:5173,yourdomain.com
    # Each base allows exactly one subdomain label in front of it
    # (jiu-gallery.yourdomain.com). Plain http is only accepted for localhost
    # bases; everything else must be https.
    _cors_bases = [
        base.strip().lower()
        for base in os.getenv('CORS_SUBDOMAIN_BASES', 'localhost:5173').split(',')
        if base.strip()
    ]
    CORS_ORIGINS += [
        rf"^{'https?' if base.startswith('localhost') else 'https'}://[a-z0-9-]+\.{re.escape(base)}$"
        for base in _cors_bases
    ]
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5173')
    FRONTEND_URL_TEMPLATE = os.getenv('FRONTEND_URL_TEMPLATE')
    # How often one network address may create galleries (stops scripts from
    # grabbing many addresses). For demos or tests, raise it in .env, e.g.
    # GALLERY_CREATE_LIMIT=100 per hour
    GALLERY_CREATE_LIMIT = os.getenv('GALLERY_CREATE_LIMIT', '5 per hour')
    # The platform's own domain, e.g. yoursite.co.ke. Leave empty in development.
    BASE_DOMAIN = os.getenv('BASE_DOMAIN')
